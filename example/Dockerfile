FROM alpine:3.6

RUN apk --no-cache add \
    iptables

COPY dd-zipkin-proxy /dd-zipkin-proxy

EXPOSE 9411/tcp

ENTRYPOINT ["/dd-zipkin-proxy"]
