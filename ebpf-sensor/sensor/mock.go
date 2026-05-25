// sensor/mock.go — Mock sensor for local development on non-Linux hosts.
//
// Reads events from fixtures/events.jsonl and replays them to Redis in a loop
// with configurable inter-event delay, simulating a live eBPF sensor.
//
// Additional behaviour:
//   - Feeds each replayed event into the DriftEngine for change-point detection.
//   - After 5 full replay loops, injects a "zombie burst": 20 rapid requests to
//     deprecated legacy-payments endpoints (simulating attacker reconnaissance
//     after an API goes dormant). This should trigger a DriftAlert with
//     alarm_type "resurrection" or "resurrection+ph_threshold".
//   - Publishes DriftAlerts to the same Redis stream so remediation-brain can
//     consume them in mock/demo mode.
package sensor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type mockSensor struct {
	cfg       Config
	log       *zap.Logger
	rdb       *redis.Client
	drift     *DriftEngine
	reporter  *BrainReporter
	loopCount int // tracks how many full replay cycles have completed
}

func newMockSensor(cfg Config, log *zap.Logger) (*mockSensor, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
	})

	// Fail fast: verify Redis is reachable before the mock sensor starts replaying.
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		return nil, fmt.Errorf("redis not reachable at %s: %w", cfg.RedisAddr, err)
	}

	drift := NewDriftEngine(DefaultDriftConfig(), log.Named("drift"))
	reporter := NewBrainReporter(cfg, log.Named("reporter"))
	return &mockSensor{cfg: cfg, log: log, rdb: rdb, drift: drift, reporter: reporter}, nil
}

func (s *mockSensor) Run(ctx context.Context) error {
	s.log.Info("Mock sensor starting — replaying fixtures",
		zap.String("fixtures_dir", s.cfg.FixturesDir),
		zap.String("stream", s.cfg.RedisStream),
	)

	// Register with remote brain if BRAIN_URL is configured.
	if s.cfg.BrainURL != "" {
		s.reporter.Register(ctx)
		s.log.Info("remote brain connection",
			zap.String("brain_url", s.cfg.BrainURL),
			zap.String("sensor_id", s.reporter.SensorID()),
			zap.Bool("connected", s.reporter.Connected()),
		)
	}

	// Start the drift detection engine.
	go s.drift.Run(ctx, s.publishDriftAlert)

	fixturePath := filepath.Join(s.cfg.FixturesDir, "events.jsonl")
	zombieBurstFired := false

	for {
		if err := s.replayFile(ctx, fixturePath); err != nil {
			return err
		}
		s.loopCount++

		// After 2 complete replay loops, wait 35 more seconds. This guarantees
		// MinDormantWins=3 consecutive 10s windows with zero legacy-payments traffic
		// before the zombie burst, so the drift engine marks the endpoint dormant.
		//
		// Timeline (25 fixture events × 100ms = ~2.5s/loop):
		//   Loop 0 (0–2.5s)  → /api/v1/legacy-payments observed 3× (drift state created)
		//   Loop 1 (4.5–7s)  → /api/v1/legacy-payments observed 3× more
		//   t=10s  tick 1    → count=6, dormCnt=0  (traffic present)
		//   t=20s  tick 2    → count=0, dormCnt=1
		//   t=30s  tick 3    → count=0, dormCnt=2
		//   t=40s  tick 4    → count=0, dormCnt=3 → dormant=true ✓
		//   t=42s  burst     → 20 events published to drift engine
		//   t=50s  tick 5    → count=20, wasDormant=true → "resurrection" alarm ✓
		if s.loopCount >= 2 && !zombieBurstFired {
			zombieBurstFired = true
			s.log.Info("waiting 35s for dormancy to establish before zombie burst",
				zap.Int("loop_count", s.loopCount),
			)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(35 * time.Second):
			}
			s.log.Info("zombie burst trigger: injecting resurrection traffic",
				zap.Int("loop_count", s.loopCount),
			)
			if err := s.injectZombieBurst(ctx); err != nil {
				s.log.Error("zombie burst injection failed", zap.Error(err))
			}
		}

		// Wait before starting the next cycle.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}


// replayFile reads events.jsonl line by line, injects current timestamps,
// publishes each to Redis, and observes each path in the drift engine.
func (s *mockSensor) replayFile(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open fixture file %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		// Validate JSON and extract fields.
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			s.log.Warn("skipping malformed fixture line", zap.String("line", line))
			continue
		}

		// Inject current timestamp before publishing.
		raw["timestamp_ns"] = time.Now().UnixNano()
		payload, err := json.Marshal(raw)
		if err != nil {
			s.log.Warn("fixture marshal failed", zap.Error(err))
			continue
		}

		if err := s.rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: s.cfg.RedisStream,
			Values: map[string]any{"data": string(payload)},
		}).Err(); err != nil {
			s.log.Error("redis publish failed", zap.Error(err))
			continue
		}

		// Forward to remote brain if configured (company install mode).
		s.reporter.Report(ctx, payload)

		// Extract path for drift observation.
		if pathVal, ok := raw["path"].(string); ok && pathVal != "" {
			s.drift.Observe(pathVal)
		}

		s.log.Debug("published mock event", zap.String("path", fmt.Sprintf("%v", raw["path"])))

		// Simulate ~100ms inter-event delay.
		time.Sleep(100 * time.Millisecond)
	}

	return scanner.Err()
}

// injectZombieBurst simulates attacker reconnaissance against a dormant legacy
// API endpoint. Sends 20 rapid requests to /api/v1/legacy-payments and its
// sub-paths using randomised methods (GET/POST) and slight path variations.
//
// The inter-event delay is 50ms (faster than normal replay) to simulate a
// scanner or automated tool. Each request is observed in the drift engine,
// which should fire a "resurrection" alarm after the first non-zero window
// following multiple zero-count windows.
func (s *mockSensor) injectZombieBurst(ctx context.Context) error {
	// Realistic path variations simulating an attacker enumerating endpoints.
	paths := []string{
		"/api/v1/legacy-payments",
		"/api/v1/legacy-payments/charge",
		"/api/v1/legacy-payments/refund",
		"/api/v1/legacy-payments",
		"/api/v1/legacy-payments/charge",
		"/api/v1/legacy-payments",
	}
	methods := []string{"GET", "POST"}

	s.log.Info("injecting zombie burst", zap.Int("events", 20))

	for i := range 20 {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Randomise method and path for realistic variation.
		method := methods[rand.Intn(len(methods))]
		path := paths[rand.Intn(len(paths))]

		evt := map[string]any{
			"method":       method,
			"path":         path,
			"status_code":  200,
			"pid":          9000 + i,
			"source":       "plain",
			"direction":    "ingress", // attacker inbound traffic — not egress
			"timestamp_ns": time.Now().UnixNano(),
		}
		payload, err := json.Marshal(evt)
		if err != nil {
			s.log.Warn("zombie burst marshal failed", zap.Error(err))
			continue
		}

		if err := s.rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: s.cfg.RedisStream,
			Values: map[string]any{"data": string(payload)},
		}).Err(); err != nil {
			s.log.Error("zombie burst redis publish failed", zap.Error(err))
		}

		// Observe each path for drift detection. The burst of traffic to a
		// previously-zero endpoint should trigger a resurrection alarm.
		s.drift.Observe(path)

		s.log.Debug("zombie burst event",
			zap.Int("i", i+1),
			zap.String("method", method),
			zap.String("path", path),
		)

		// 50ms inter-event delay — faster than normal replay, mimics scanner.
		time.Sleep(50 * time.Millisecond)
	}

	return nil
}

// publishDriftAlert marshals a DriftAlert and writes it to the Redis stream.
// The remediation-brain consumes drift_alert events to trigger LangGraph workflows.
func (s *mockSensor) publishDriftAlert(ctx context.Context, alert DriftAlert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("json marshal drift alert: %w", err)
	}

	s.log.Info("drift alert fired",
		zap.String("endpoint", alert.Endpoint),
		zap.String("alarm_type", alert.AlarmType),
		zap.Float64("count", alert.WindowCount),
		zap.Float64("ph_score", alert.PHScore),
	)

	// Forward alert to remote brain if configured.
	s.reporter.ReportAlert(ctx, alert)

	return s.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: s.cfg.RedisStream,
		Values: map[string]any{"data": string(payload)},
	}).Err()
}

// DriftStats returns a snapshot of all endpoint drift states.
// Called from the /drift/stats HTTP handler in main.go.
func (s *mockSensor) DriftStats() []EndpointStats {
	return s.drift.Stats()
}
