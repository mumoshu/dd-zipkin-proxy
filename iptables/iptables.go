package iptables

import (
    "errors"
    "fmt"
    "net"
    "strings"

    "github.com/coreos/go-iptables/iptables"
    log "github.com/sirupsen/logrus"
)

// AddRule adds the required rule to the host's nat table.
func AddRule(proto, appPort, magicIp, hostInterface, hostIP string) error {

    if err := checkInterfaceExists(hostInterface); err != nil {
        return err
    }

    if hostIP == "" {
        return errors.New("--host-ip must be set")
    }

    ipt, err := iptables.New()
    if err != nil {
        return err
    }

	  table := "nat"
	  chain := "PREROUTING"
 	  rules, err := ipt.List(table, chain)
    for _, r := range rules {
			dMatched := strings.Contains(r, fmt.Sprintf("-d %s", magicIp))
			iMatched := strings.Contains(r, fmt.Sprintf("-i %s", hostInterface))
			dportMatched := strings.Contains(r, fmt.Sprintf("--dport %d", appPort))
			protoMatched := strings.Contains(r, fmt.Sprintf("-p %s", proto))

			if !dMatched {
				log.Infof("Skipping %s from deletion because it doesn't match: -d %s", r, magicIp)
				return nil
			}

			if !iMatched {
				log.Infof("Skipping %s from deletion because it doesn't match: -i %s", r, hostInterface)
				return nil
			}

			if !dportMatched {
				log.Infof("Skipping %s from deletion because it doesn't match: --dport %s", r, appPort)
				return nil
			}

			if !protoMatched {
				log.Infof("Skipping %s from deletion because it doesn't match: -p %s", r, proto)
				return nil
			}

    	specstr := strings.Replace(r, fmt.Sprintf("-A %s ", chain), "", 1)
    	spec := strings.Split(specstr, " ")

			err = ipt.Delete(table, chain, spec...)
			if err != nil {
				return fmt.Errorf("failed while deleting old iptable rule \"%s\": %v", specstr, err)
			}
		}

    return ipt.AppendUnique(
			table, chain, "-p", proto, "-d", magicIp, "--dport", appPort,
        "-j", "DNAT", "--to-destination", hostIP+":"+appPort, "-i", hostInterface,
    )
}

// checkInterfaceExists validates the interface passed exists for the given system.
// checkInterfaceExists ignores wildcard networks.
func checkInterfaceExists(hostInterface string) error {

    if strings.Contains(hostInterface, "+") {
        // wildcard networks ignored
        return nil
    }

    _, err := net.InterfaceByName(hostInterface)
    return err
}
