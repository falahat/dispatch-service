// The plane's egress guard: stripe/smokescreen embedded with the one customization the
// vendor designed for — RoleFromRequest. Clients speak plain HTTP to the proxy, so the
// role can't come from an mTLS client certificate yet; instead the internal network's
// membership IS the identity — only known, single-purpose peers share an egress network,
// and the ACL pins each role to exactly the hosts that role may reach (deny otherwise).
//
// Two egress lanes exist, each its own role and allowlist stanza, each a DIFFERENT threat:
//   - "worker"  worker-net GPU compute pulling model weights (a fixed, known host set).
//   - "ingest"  the coordinator fetching feeds/covers from ARBITRARY attacker-controlled
//               public URLs — SSRF is the risk, so its stanza is `action: open` (allow all
//               PUBLIC hosts) and the config's deny_ranges is the control (internal /
//               loopback / link-local / metadata / CGNAT denied on the RESOLVED IP, at
//               CONNECT, on every redirect hop).
//
// Role is assigned by the client's source network (SMOKESCREEN_ROLE_NETS: CIDR=role),
// falling back to SMOKESCREEN_DEFAULT_ROLE (default "worker" — so a worker-only deploy
// with no env set behaves EXACTLY as before). When client certificates arrive, the CN
// replaces this source-network mapping as the cleaner identity.
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

// defaultRole is the role for a client whose source IP matches no configured network.
// "worker" keeps the historical single-lane deploy byte-identical (no env → every
// client is "worker", exactly as the static hook did before).
func defaultRole() string {
	if r := strings.TrimSpace(os.Getenv("SMOKESCREEN_DEFAULT_ROLE")); r != "" {
		return r
	}
	return "worker"
}

// parseRoleNets reads SMOKESCREEN_ROLE_NETS, a comma-separated list of "CIDR=role"
// entries (e.g. "10.30.0.0/24=worker,10.31.0.0/24=ingest"). A malformed entry is fatal
// at boot — a misconfigured role map must fail closed, never silently mis-role a client.
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
		conf.RoleFromRequest = roleFromNetwork(roleNets, defaultRole())

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
