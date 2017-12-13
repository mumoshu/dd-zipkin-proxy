package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/dd-trace-go/tracer"
	"github.com/flachnetz/dd-zipkin-proxy"
	"github.com/flachnetz/dd-zipkin-proxy/iptables"
	"github.com/openzipkin/zipkin-go-opentracing/thrift/gen-go/zipkincore"
	"github.com/sirupsen/logrus"
	"net/url"
)

var env string

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel)

	magicIp := os.Getenv("DDZK_MAGIC_IP")
	hostIf := os.Getenv("DDZK_HOST_INTERFACE")
	hostIp := os.Getenv("DDZK_HOST_IP")
	env = os.Getenv("DDZK_ENV")

	var err error
	err = iptables.AddRule("udp", "8125", magicIp, hostIf, hostIp)
	if err != nil {
		panic(fmt.Errorf("magicIp=%s, hostIf=%s, hostIp=%s: %v", magicIp, hostIf, hostIp, err))
	}
	err = iptables.AddRule("udp", "8126", magicIp, hostIf, hostIp)
	if err != nil {
		panic(fmt.Errorf("magicIp=%s, hostIf=%s, hostIp=%s: %v", magicIp, hostIf, hostIp, err))
	}
	err = iptables.AddRule("tcp", "9411", magicIp, hostIf, hostIp)
	if err != nil {
		panic(fmt.Errorf("magicIp=%s, hostIf=%s, hostIp=%s: %v", magicIp, hostIf, hostIp, err))
	}
	converter := DefaultSpanConverter{}
	zipkinproxy.Main(converter.Convert)
}

type DefaultSpanConverter struct {
}

func findAnnotationByName(annotations []*zipkincore.Annotation, name string) *zipkincore.Annotation {
	for _, a := range annotations {
		if a.Value == name {
			return a
		}
	}
	return nil
}

func (converter *DefaultSpanConverter) Convert(span *zipkincore.Span) []*tracer.Span {
	spans := []*zipkincore.Span{}

	annotations := span.Annotations

	cs := findAnnotationByName(annotations, "cs")
	cr := findAnnotationByName(annotations, "cr")

	if cs != nil && cr != nil {
		updatedAnnotations := []*zipkincore.Annotation{}

		for _, a := range annotations {
			if a.Value != "cs" && a.Value != "cr" {
				updatedAnnotations = append(updatedAnnotations, a)
			}
		}

		span.Annotations = updatedAnnotations

		duration := cr.Timestamp - cs.Timestamp
		clientSpan := &zipkincore.Span{
			Name:              span.Name,
			TraceID:           span.TraceID,
			ID:                span.ID - 1,
			ParentID:          span.ParentID,
			Annotations:       []*zipkincore.Annotation{cs, cr},
			BinaryAnnotations: span.BinaryAnnotations,
			Debug:             span.Debug,
			Timestamp:         &cs.Timestamp,
			Duration:          &duration,
			TraceIDHigh:       span.TraceIDHigh,
		}

		span.ParentID = &clientSpan.ID

		spans = []*zipkincore.Span{clientSpan, span}
	} else {
		spans = []*zipkincore.Span{span}
	}

	result := []*tracer.Span{}
	for _, s := range spans {
		converted := converter.convert(s)
		if converted != nil {
			result = append(result, converted)
		}
	}
	return result
}

func (converter *DefaultSpanConverter) convert(span *zipkincore.Span) *tracer.Span {
	logrus.WithFields(logrus.Fields{"zipkinSpan": span}).Info("Convert started")

	// ignore long running consul update tasks.
	if span.Name == "watch-config-key-values" || span.Name == "catalog-services-watch" {
		return nil
	}

	//name := SimplifyResourceName(span.Name)
	name := span.Name

	converted := &tracer.Span{
		SpanID:   uint64(span.ID),
		ParentID: uint64(span.GetParentID()),
		TraceID:  uint64(span.TraceID),
		Name:     name,
		Resource: name,
		Start:    1000 * span.GetTimestamp(),
		Duration: 1000 * span.GetDuration(),
		Sampled:  true,
	}

	// datadog traces use zero for a root span
	if converted.ParentID == converted.SpanID {
		converted.ParentID = 0
	}

	// convert binary annotations (like tags)
	if len(span.BinaryAnnotations) > 0 {
		converted.Meta = make(map[string]string, len(span.BinaryAnnotations))
		for _, an := range span.BinaryAnnotations {
			tpe := an.AnnotationType
			if tpe == zipkincore.AnnotationType_STRING || tpe == zipkincore.AnnotationType_BOOL {
				key := an.Key

				// rename keys to better match the datadog one.
				switch key {
				case "http.status":
					key = "http.status_code"

				case "client.url":
					key = "http.url"
				}

				converted.Meta[key] = string(an.Value)
			}

			if an.Host != nil && an.Host.ServiceName != "" {
				converted.Service = an.Host.ServiceName
			}
		}

		httpRequestPath := ""

		if urlStr := converted.Meta["http.url"]; urlStr != "" {
			//converted.Resource = SimplifyResourceName(urlStr)
			converted.Meta["http.url"] = RemoveQueryString(urlStr)

			u, err := url.Parse(converted.Resource)
			if err != nil {
				logrus.Errorf(`failed to parse url "%s": %v`, urlStr, err)
			}
			httpRequestPath = u.Path
		}

		httpRequestMethod := ""

		if method := converted.Meta["http.method"]; method != "" {
			httpRequestMethod = strings.ToLower(method)
		}

		if status := converted.Meta["http.status_code"]; status != "" {
			if len(status) > 0 && '3' <= status[0] && status[0] <= '9' {
				if statusValue, err := strconv.Atoi(status); err == nil && statusValue >= 400 {
					converted.Error = int32(statusValue)
				}
			}
		}

		if _, exists := converted.Meta["env"]; !exists {
			converted.Meta["env"] = env
		}

		// Infer services, timestamps, durations from annotations
		updateInfoFromAnnotations(span, converted)

		isClient := false
		for _, a := range span.Annotations {
			if a.Value == "cs" || a.Value == "cr" {
				isClient = true
			}
		}

		// Prettify istio-proxy spans
		if nodeId := converted.Meta["node_id"]; nodeId != "" {
			regex := regexp.MustCompile(`^sidecar~\d+\.\d+\.\d+\.\d+~(?P<kube_pod_name>[^\.]+).(?P<kube_namespace>[^\.~]+).[^\.]+.svc.cluster.local`)
			fmt.Printf("regex: '%v'\n", regex)
			match := regex.FindStringSubmatch(nodeId)
			if len(match) > 0 {
				for i, name := range regex.SubexpNames() {
					if i != 0 {
						converted.Meta[name] = match[i]
					}
				}
				converted.Meta["docker_container_name"] = "istio-proxy"

				if httpRequestMethod != "" && httpRequestPath != "" {
					if isClient {
						converted.Name = fmt.Sprintf("proxy.req_%s_%s", httpRequestMethod, httpRequestPath)
					} else {
						converted.Name = fmt.Sprintf("proxy.res_%s_%s", httpRequestMethod, httpRequestPath)
					}
				}

				converted.Type = "web"
			}
		}

		// Prettify istio-ingress spans
		if nodeId := converted.Meta["node_id"]; nodeId != "" {
			regex := regexp.MustCompile(`^ingress~~(?P<kube_pod_name>[^\.]+).(?P<kube_namespace>[^\.~]+).[^\.]+.svc.cluster.local`)
			fmt.Printf("regex: '%v'\n", regex)
			match := regex.FindStringSubmatch(nodeId)
			if len(match) > 0 {
				for i, name := range regex.SubexpNames() {
					if i != 0 {
						converted.Meta[name] = match[i]
					}
				}
				converted.Meta["docker_container_name"] = "istio-ingress"

				if isClient {
					converted.Service = "istio-ingress"
					converted.Name = fmt.Sprintf("proxy.req_%s_%s", httpRequestMethod, httpRequestPath)
				} else {
					converted.Name = fmt.Sprintf("proxy.res_%s_%s", httpRequestMethod, httpRequestPath)
				}

				converted.Type = "web"
			}
		}
	}

	if ddService := converted.Meta["dd.service"]; ddService != "" {
		converted.Service = ddService
		delete(converted.Meta, "dd.service")
	}

	if ddName := converted.Meta["dd.name"]; ddName != "" {
		converted.Name = ddName
		delete(converted.Meta, "dd.name")
	}

	if ddResource := converted.Meta["dd.resource"]; ddResource != "" {
		converted.Resource = SimplifyResourceName(ddResource)
		delete(converted.Meta, "dd.resource")
	}

	// if name and service differ than the overview page in datadog will only show the one with
	// most of the time spend. This is why we just rename it to the service here so that we can get a nice
	// overview of all resources belonging to the service. Can be removed in the future
	// when datadog is changing things
	//converted.Name = converted.Service

	logrus.WithFields(logrus.Fields{"zipkinSpan": span, "datadogSpan": converted}).Info("Convert finished")

	return converted
}

func updateInfoFromAnnotations(span *zipkincore.Span, converted *tracer.Span) {
	// try to get the service from the cs/cr or sr/ss annotations
	var minTimestamp, maxTimestamp int64
	for _, an := range span.Annotations {
		if an.Value == "sr" && an.Host != nil && an.Host.ServiceName != "" {
			converted.Service = an.Host.ServiceName
		}

		if an.Value == "cr" && an.Host != nil && an.Host.ServiceName != "" {
			converted.Service = an.Host.ServiceName
		}

		if an.Timestamp < minTimestamp || minTimestamp == 0 {
			minTimestamp = an.Timestamp
		}

		if an.Timestamp > maxTimestamp {
			maxTimestamp = an.Timestamp
		}
	}

	if converted.Start == 0 || converted.Duration == 0 {
		logrus.Warnf("Span had no start/duration, guessing from annotations: %s", identifySpan(span))
		converted.Start = 1000 * minTimestamp
		converted.Duration = 1000 * (maxTimestamp - minTimestamp)
	}
}

// Tries to get some identification for this span. The method tries
// to include the value of the local-component tag and the value of the tags name.
func identifySpan(span *zipkincore.Span) string {
	var name string
	for _, an := range span.BinaryAnnotations {
		if an.Key == "lc" {
			name = string(an.Value) + ":"
		}
	}

	return name + span.Name
}

var reHash = regexp.MustCompile(`\b(?:[a-f0-9]{32}|[a-f0-9]{24}|[a-f0-9-]{8}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{4}-[a-f0-9-]{12})\b`)
var reNumber = regexp.MustCompile(`b[0-9]{2,}\b`)

func SimplifyResourceName(value string) string {
	// check if we need to apply the (costly) regexp by checking if a match is possible or not
	digitCount := 0
	hashCharCount := 0
	for idx, char := range value {
		isDigit := char >= '0' && char <= '9'
		if isDigit {
			digitCount++
		}

		if isDigit || char >= 'a' && char <= 'f' {
			hashCharCount++
		}
		if char == '?' {
			value = value[:idx]
			break
		}
	}

	// only search for hash, if we have enough chars for it
	if hashCharCount >= 24 {
		value = reHash.ReplaceAllString(value, "_HASH_")
	}

	// only replace numbers, if we have enough digits for a match
	if digitCount >= 2 {
		value = reNumber.ReplaceAllString(value, "_NUMBER_")
	}

	return value
}

func RemoveQueryString(value string) string {
	idx := strings.IndexByte(value, '?')
	if idx >= 0 {
		return value[:idx]
	}
	return value
}
