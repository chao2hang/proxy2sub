package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// `probe` 子命令：子进程隔离测活（见 #10 与 probe.go）。
	// 由 SubprocessTester 以 `proxy2sub probe` 启动，stdin 收节点 JSON。
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		runProbe()
		return
	}

	cfg := loadConfig()

	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	geo, err := newGeoResolver(cfg.GeoIPDB)
	if err != nil {
		log.Fatalf("geoip: %v", err)
	}

	tester, err := NewTester(cfg.TestTimeout, cfg.TestURL)
	if err != nil {
		log.Fatalf("tester: %v", err)
	}
	// 子进程隔离测活（#10）：每次测活一个 probe 子进程，挂死的探测由父进程在
	// 2×TestTimeout 硬 kill，主进程不再被卡死的 sing-box 底层调用拖住。
	exe := probeExePath()
	if exe == "" {
		log.Fatalf("probe: cannot resolve executable path (os.Executable)")
	}
	srv := &Server{
		cfg:        cfg,
		store:      store,
		geo:        geo,
		tester:     NewSubprocessTester(tester, exe, cfg.TestTimeout),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.checkLoop(ctx, cfg.CheckInterval, cfg.CheckOnStart)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/push", srv.handlePush)
	mux.HandleFunc("/api/check", srv.handleCheck)
	mux.HandleFunc("/api/stats", srv.handleStats)
	mux.HandleFunc("/sub", srv.handleSub)
	mux.HandleFunc("/healthz", srv.handleHealth)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("proxy2sub listening on %s (check interval=%s, check_on_start=%v, test timeout=%s, concurrency=%d)",
		cfg.Addr, cfg.CheckInterval, cfg.CheckOnStart, cfg.TestTimeout, cfg.Concurrency)
	log.Printf("test url: %s", cfg.TestURL)
	if cfg.PushToken != "" {
		log.Printf("push token: enabled")
	}
	if cfg.SubToken != "" {
		log.Printf("sub token: enabled")
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-serveErr:
		log.Fatalf("http server: %v", err)
	case <-sig:
		fmt.Println("\nshutting down...")
		cancel()
		_ = server.Close()
	}
}
