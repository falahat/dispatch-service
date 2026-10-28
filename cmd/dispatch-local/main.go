//go:build linux

// dispatch-local composes the existing dispatcher and runner for trusted local
// executors. Both queue sockets and the byte store stay inside one private root.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/falahat/dispatch-service/dispatcher"
	"github.com/falahat/dispatch-service/runner"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	root := flag.String("root", "", "owned private queue directory")
	config := flag.String("config", "", "plane.toml")
	capacity := flag.String("workers-file", "", "positive integer worker capacity; reload with SIGHUP")
	lanes := flag.String("lanes", "work", "comma-separated lanes")
	reserved := flag.String("reserve-lane", "", "dedicate one additional consumer to this lane")
	noDeadline := flag.Bool("no-deadline", false, "allow execution until completion or explicit cancellation")
	flag.Parse()
	if !filepath.IsAbs(*root) || *capacity == "" || flag.NArg() == 0 {
		return fmt.Errorf("root, workers-file and a trusted executable after -- are required")
	}
	syscall.Umask(0077)
	if err := os.MkdirAll(*root, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(*root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Getuid() {
		return fmt.Errorf("queue root must be an owned private directory")
	}
	lock, err := os.OpenFile(filepath.Join(*root, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("queue root already in use: %w", err)
	}
	command := append([]string(nil), flag.Args()...)
	command[0], err = exec.LookPath(command[0])
	if err != nil {
		return err
	}
	command[0], err = filepath.Abs(command[0])
	if err != nil {
		return err
	}
	cfg, err := dispatcher.LoadConfig(*config)
	if err != nil {
		return err
	}
	cfg.DBPath = filepath.Join(*root, "dispatch.db")
	cfg.WaitForExecutor = true
	cfg.RunnerListen, cfg.AppSocket, cfg.AppListen = "unix:"+filepath.Join(*root, "runner.sock"), filepath.Join(*root, "app.sock"), ""
	store, err := dispatcher.OpenStore(cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	d, err := dispatcher.New(store, cfg, dispatcher.RealClock)
	if err != nil {
		return err
	}
	server := dispatcher.NewServer(d, slog.Default())
	if err := server.Start(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	var running sync.WaitGroup
	defer func() { cancel(); server.Close(); running.Wait() }()
	failures := make(chan error, 1)
	report := func(err error) {
		if err != nil {
			select {
			case failures <- err:
			case <-ctx.Done():
			}
		}
	}
	running.Add(1)
	go func() { defer running.Done(); report(d.AcknowledgeLocal(ctx)) }()
	pool := []*runner.Runner{}
	serial := 0
	start := func(lanes []string) *runner.Runner {
		serial++
		worker := runner.New(runner.Config{RunnerID: fmt.Sprintf("local-%d", serial), Node: "local", Version: "runner/local-command/1",
			DispatcherAddr: cfg.RunnerListen, CASBaseURL: (&url.URL{Scheme: "file", Path: filepath.Join(*root, "cas")}).String(),
			WorkRoot: filepath.Join(*root, "work"), Lanes: lanes,
			Command: command, NoDeadline: *noDeadline, OnSettled: d.ExecutionSettled}, nil, nil, slog.Default())
		running.Add(1)
		go func() {
			defer running.Done()
			report(worker.Run(ctx))
		}()
		return worker
	}
	normalLanes := strings.Split(*lanes, ",")
	for _, lane := range normalLanes {
		if lane == "" || lane == *reserved {
			return fmt.Errorf("normal and reserved lanes must be nonempty and distinct")
		}
	}
	if *reserved != "" {
		start([]string{*reserved})
	}
	reload := func() error {
		data, err := os.ReadFile(*capacity)
		if err != nil {
			return err
		}
		count, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || count < 1 {
			return fmt.Errorf("worker capacity must be a positive integer")
		}
		if count < len(pool) {
			return fmt.Errorf("capacity decrease requires an idle restart")
		}
		for len(pool) < count {
			pool = append(pool, start(normalLanes))
		}
		return nil
	}
	if err := reload(); err != nil {
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	if address := os.Getenv("NOTIFY_SOCKET"); address != "" {
		connection, err := net.Dial("unixgram", address)
		if err != nil {
			return err
		}
		_, err = connection.Write([]byte("READY=1"))
		connection.Close()
		if err != nil {
			return err
		}
	}
	for {
		select {
		case signal := <-signals:
			if signal != syscall.SIGHUP {
				return nil
			}
			if err := reload(); err != nil {
				slog.Error("capacity reload rejected; current executions preserved", "err", err)
			}
		case err := <-failures:
			return err
		}
	}
}
