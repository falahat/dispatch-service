// The egress guard assigns an ACL role from the client's source network. Compose gives
// model downloads and untrusted ingest separate internal networks. Unknown sources use
// the deny-all default role.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

// roleForNet maps a client source-IP range to the egress role its members receive.
type roleForNet struct {
	net  *net.IPNet
	role string
}

// parseRoleNets reads SMOKESCREEN_ROLE_NETS, a comma-separated list of "CIDR=role"
// entries, for example "10.30.0.0/24=model,10.31.0.0/24=ingest". Invalid maps fail boot.
func parseRoleNets(raw string) ([]roleForNet, error) {
	var out []roleForNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		cidr, role, ok := strings.Cut(entry, "=")
		role = strings.TrimSpace(role)
		if !ok || role == "" {
			return nil, fmt.Errorf("SMOKESCREEN_ROLE_NETS entry %q must be CIDR=role", entry)
		}
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("SMOKESCREEN_ROLE_NETS entry %q: %w", entry, err)
		}
		out = append(out, roleForNet{net: ipnet, role: role})
	}
	return out, nil
}

// roleFromNetwork classifies a proxy client by the source network it connects from.
func roleFromNetwork(nets []roleForNet, fallback string) func(*http.Request) (string, error) {
	return func(req *http.Request) (string, error) {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			host = req.RemoteAddr
		}
		if ip := net.ParseIP(host); ip != nil {
			for _, rn := range nets {
				if rn.net.Contains(ip) {
					return rn.role, nil
				}
			}
		}
		return fallback, nil
	}
}

func main() {
	roleNets, err := parseRoleNets(os.Getenv("SMOKESCREEN_ROLE_NETS"))
	if err != nil {
		logrus.Fatalf("Could not parse SMOKESCREEN_ROLE_NETS: %v", err)
	}

	conf, err := cmd.NewConfiguration(nil, nil)
	if err != nil {
		logrus.Fatalf("Could not create configuration: %v", err)
	} else if conf != nil {
		conf.RoleFromRequest = roleFromNetwork(roleNets, "default")

		conf.Log.Formatter = &logrus.JSONFormatter{}

		adapter := &smokescreen.Log2LogrusWriter{
			Entry: conf.Log.WithField("stdlog", "1"),
		}

		// Route the standard logger through our structured logger.
		log.SetOutput(adapter)
		log.SetFlags(0)
		smokescreen.StartWithConfig(conf, nil)
	}
	// nil conf: --help / --version was handled inside NewConfiguration.
}
