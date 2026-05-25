// main.go — AuralisAPI eBPF Sensor
// Entrypoint: reads SENSOR_MODE env var and delegates to either
// the live kernel loader or the mock event replayer.
//
// SENSOR_MODE=live  → attaches eBPF programs to the kernel via cilium/ebpf
// SENSOR_MODE=mock  → reads from fixtures/events.jsonl and replays to Redis
//
// Also starts a lightweight HTTP metrics server (default :9090) exposing:
//   GET /drift/stats — per-endpoint Page-Hinkley drift state (JSON array)
//   GET /health      — liveness probe used by Docker HEALTHCHECK
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go.uber.org/zap"

	"auralisapi/ebpf-sensor/sensor"
)

func main() {
	healthCheck := flag.Bool("health-check", false, "Run health check and exit")
	flag.Parse()

	// ── Health-check mode (used by Docker HEALTHCHECK) ──────────────────────
	// Ping the running service's /health endpoint rather than blindly exiting 0,
	// so Docker correctly marks the container unhealthy when the HTTP server
	// fails to start or the process has crashed.
	if *healthCheck {
		port := os.Getenv("METRICS_PORT")
		if port == "" {
			port = "9090"
		}
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get("http://127.0.0.1:" + port + "/health")
		if err != nil {
			fmt.Fprintf(os.Stderr, "health check failed: %v\n", err)
			os.Exit(1)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "health check: unexpected status %d\n", resp.StatusCode)
			os.Exit(1)
		}
		fmt.Println("OK")
		os.Exit(0)
	}

	// ── Logger ───────────────────────────────────────────────────────────────
	logLevel := os.Getenv("LOG_LEVEL")
	var log *zap.Logger
	var err error
	if logLevel == "debug" {
		log, err = zap.NewDevelopment()
	} else {
		log, err = zap.NewProduction()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	// ── Configuration ─────────────────────────────────────────────────────────
	replayDelayMs, _ := strconv.Atoi(getEnv("REPLAY_DELAY_MS", "100"))

	cfg := sensor.Config{
		Mode:          getEnv("SENSOR_MODE", "mock"),
		RedisAddr:     getEnv("REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""), // empty = no auth (dev default)
		RedisStream:   getEnv("REDIS_STREAM", "auralis:events"),
		FixturesDir:   getEnv("FIXTURES_DIR", "./fixtures"),
		ReplayDelayMs: replayDelayMs,                // inter-event delay in mock mode
		BrainURL:      getEnv("BRAIN_URL", ""),      // e.g. "https://auralisapi.dev" — company install mode
		CompanyToken:  getEnv("COMPANY_TOKEN", ""),  // Bearer token from onboarding
		SensorID:      getEnv("SENSOR_ID", ""),      // auto-generated from hostname if empty
	}

	log.Info("AuralisAPI eBPF Sensor starting",
		zap.String("mode", cfg.Mode),
		zap.String("redis_addr", cfg.RedisAddr),
		zap.String("stream", cfg.RedisStream),
		zap.String("brain_url", cfg.BrainURL),
	)

	// ── Context with graceful shutdown ────────────────────────────────────────
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Run sensor ────────────────────────────────────────────────────────────
	s, err := sensor.New(cfg, log)
	if err != nil {
		log.Fatal("failed to initialize sensor", zap.Error(err))
	}

	// ── Metrics HTTP server ────────────────────────────────────────────────────
	// Lightweight endpoint for intelligence-ui and liveness probes.
	// Uses http.Server so it can be shut down gracefully when ctx is cancelled.
	metricsPort := getEnv("METRICS_PORT", "9090")
	mux := http.NewServeMux()

	// GET /drift/stats — returns JSON array of EndpointStats for all
	// observed API paths. Consumed by intelligence-ui dashboard to render
	// per-endpoint drift scores and dormancy status in real time.
	mux.HandleFunc("/drift/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*") // permit dashboard cross-origin fetch
		if err := json.NewEncoder(w).Encode(s.DriftStats()); err != nil {
			log.Warn("failed to encode drift stats response", zap.Error(err))
		}
	})

	// GET /health — simple liveness probe for Docker HEALTHCHECK and k8s.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// GET /metrics — Prometheus text-format 0.0.4 counter exposition.
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(sensor.PrometheusMetrics()))
	})

	srv := &http.Server{
		Addr:         ":" + metricsPort,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info("metrics server listening", zap.String("port", metricsPort))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Warn("metrics server error", zap.Error(err))
		}
	}()

	// Shut down the metrics server cleanly when the context is cancelled.
	// This runs concurrently with s.Run() and ensures the goroutine above exits.
	go func() {
		<-ctx.Done()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Warn("metrics server shutdown error", zap.Error(err))
		}
	}()

	if err := s.Run(ctx); err != nil {
		log.Error("sensor exited with error", zap.Error(err))
		os.Exit(1)
	}

	log.Info("AuralisAPI eBPF Sensor stopped gracefully")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
