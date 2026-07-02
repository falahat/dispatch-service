// The plane's egress guard: stripe/smokescreen embedded with the one customization the
// vendor designed for — RoleFromRequest. Worker-net clients speak plain HTTP to the
// proxy (the internal network's membership is the identity: only a runner and its
// compute pair live there), so every client gets the static "worker" role and the ACL
// pins that role to the known model hosts, deny otherwise. Everything else is verbatim
// the upstream main. When lanes with different egress needs appear, roles come from
// mTLS client certificates instead of this constant.
package main

import (
	"log"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

func workerRole(*http.Request) (string, error) { return "worker", nil }

func main() {
	conf, err := cmd.NewConfiguration(nil, nil)
	if err != nil {
		logrus.Fatalf("Could not create configuration: %v", err)
	} else if conf != nil {
		conf.RoleFromRequest = workerRole

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
