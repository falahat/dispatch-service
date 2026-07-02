// Command runner is the shared worker client. `runner run` joins the fleet and
// drives its paired compute container; `runner check <image>` validates any
// compute image against the invoke contract locally.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/falahat/dispatch-service/runner"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:], log)
	case "check":
		checkCmd(os.Args[2:], log)
	case "keygen":
		keygenCmd()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: runner run [flags] | runner check <image> [--fixture dir] | runner keygen")
	os.Exit(2)
}

// keygenCmd mints a fresh Ed25519 keypair; enroll the printed pubkey with the
// signer, then assemble a credential file {biscuit, pubkey_hex, seed_b64}.
func keygenCmd() {
	seed, pub, err := runner.GenerateKeypair()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	fmt.Printf("pubkey_hex=%s\nseed_b64=%s\n", pub, seed)
	fmt.Fprintln(os.Stderr, "next: signer enroll --pubkey "+pub+" --rights ... --lanes ...  then write {biscuit, pubkey_hex, seed_b64} to a credential file")
}

func runCmd(args []string, log *slog.Logger) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var cfg runner.Config
	fs.StringVar(&cfg.RunnerID, "id", env("RUNNER_ID", ""), "runner id (public-key fingerprint)")
	fs.StringVar(&cfg.Node, "node", env("RUNNER_NODE", hostname()), "node name")
	fs.StringVar(&cfg.Version, "version", env("RUNNER_VERSION", "runner/0.1.0"), "runner version")
	fs.StringVar(&cfg.DispatcherAddr, "dispatcher", env("DISPATCHER_ADDR", "127.0.0.1:7700"), "dispatcher runner-surface addr")
	fs.StringVar(&cfg.CASBaseURL, "cas", env("CAS_URL", "http://127.0.0.1:8080"), "CAS base URL")
	fs.StringVar(&cfg.ComputeAddr, "compute", env("INVOKE_ADDR", "127.0.0.1:8081"), "paired compute INVOKE_ADDR")
	fs.StringVar(&cfg.WorkRoot, "work", env("WORK_ROOT", "/work"), "shared workdir root")
	lanes := fs.String("lanes", env("LANES", ""), "comma-separated lanes")
	fs.IntVar(&cfg.Capacity, "capacity", 1, "concurrent capacity")
	fs.IntVar(&cfg.LeaseWaitS, "wait", 30, "lease long-poll seconds")
	fs.StringVar(&cfg.GPU, "gpu", env("GPU", ""), "GPU descriptor (optional)")
	credPath := fs.String("credential", env("CREDENTIAL", ""), "credential file for PEP mode (omit for direct/trusted mode)")
	_ = fs.Parse(args)

	if *lanes != "" {
		cfg.Lanes = splitComma(*lanes)
	}
	if cfg.RunnerID == "" || len(cfg.Lanes) == 0 {
		fmt.Fprintln(os.Stderr, "runner run: -id and -lanes are required")
		os.Exit(2)
	}

	// PEP mode when a credential is provided (Biscuit + PoP signer + frame
	// wrapper); otherwise direct/trusted mode.
	var signer runner.Signer
	var wrapper runner.FrameWrapper
	if *credPath != "" {
		cred, err := runner.LoadCredential(*credPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "runner run:", err)
			os.Exit(2)
		}
		ps, err := runner.NewPoPSigner(cred)
		if err != nil {
			fmt.Fprintln(os.Stderr, "runner run:", err)
			os.Exit(2)
		}
		signer, wrapper = ps, ps
		if cfg.RunnerID == "" {
			cfg.RunnerID = cred.PubkeyHex
		}
	}
	rn := runner.New(cfg, signer, wrapper, log)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		cancel()
	}()
	if err := rn.Run(ctx); err != nil {
		log.Error("runner exited", "err", err)
		os.Exit(1)
	}
}

func checkCmd(args []string, log *slog.Logger) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	fixture := fs.String("fixture", "", "fixture dir (invocation.json + inputs/); default extracts /fixture from the image")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: runner check <image> [--fixture dir]")
		os.Exit(2)
	}
	image := fs.Arg(0)
	rep, err := runner.Check(context.Background(), image, *fixture)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", image, err)
		os.Exit(1)
	}
	fmt.Printf("image=%s health=%v fixture=%v deadline=%v malformed=%v single_flight=%s\n",
		rep.Image, rep.HealthOK, rep.FixtureOK, rep.DeadlineOK, rep.MalformedOK, rep.SingleFlight)
	for _, n := range rep.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	if !rep.OK() {
		fmt.Fprintln(os.Stderr, "FAIL: mandatory checks did not pass")
		os.Exit(1)
	}
	fmt.Println("PASS")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
