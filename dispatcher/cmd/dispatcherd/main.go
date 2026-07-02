// Command dispatcherd runs the dispatch-plane dispatcher: the durable work
// service. Config comes from a plane.toml (change = restart). In production it
// sits behind the Rust PEP on the runner surface and exposes its app surface on
// a Unix socket to the co-located app.
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/falahat/dispatch-service/dispatcher"
)

func main() {
	cfgPath := flag.String("config", "", "path to plane.toml (defaults apply if empty)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := dispatcher.LoadConfig(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	store, err := dispatcher.OpenStore(cfg.DBPath)
	if err != nil {
		log.Error("store", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	d, err := dispatcher.New(store, cfg, dispatcher.RealClock)
	if err != nil {
		log.Error("dispatcher", "err", err)
		os.Exit(1)
	}

	srv := dispatcher.NewServer(d, log)
	if err := srv.Start(); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info("shutting down")
	srv.Close()
}
