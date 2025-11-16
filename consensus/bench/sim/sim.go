package sim

import (
	"math"
	"math/rand"
)

// Options configures the synthetic network benchmark.
type Options struct {
	Miners           int
	PayloadBytes     int
	Iterations       int
	PQSignatureBytes int
	Seed             int64
}

// Metrics captures the outcome of a benchmark run.
type Metrics struct {
	Miners           int     `json:"miners"`
	PayloadBytes     int     `json:"payload_bytes"`
	Iterations       int     `json:"iterations"`
	PQSignatureBytes int     `json:"pq_signature_bytes"`
	MessagesPerSec   float64 `json:"messages_per_second"`
	AvgLatencyMs     float64 `json:"avg_latency_ms"`
	DurationMs       int     `json:"duration_ms"`
}

// Simulate estimates throughput and latency budgets for gossiping PQ-sized payloads.
func Simulate(opts Options) Metrics {
	cfg := normalize(opts)
	rng := rand.New(rand.NewSource(cfg.Seed))
	totalMessages := cfg.Iterations * cfg.Miners
	if totalMessages == 0 {
		totalMessages = 1
	}
	perMessageBytes := cfg.PayloadBytes + cfg.PQSignatureBytes
	bandwidthBytesPerSec := 25 * 1024 * 1024 // 25 MiB/s of usable gossip capacity.
	totalBytes := perMessageBytes * totalMessages
	durationSeconds := float64(totalBytes) / float64(bandwidthBytesPerSec)
	if durationSeconds <= 0 {
		durationSeconds = float64(totalMessages) / 1000.0
	}
	baseLatency := 5.0 + float64(perMessageBytes)/4096.0
	jitter := (rng.Float64()*2.0 - 1.0) * 0.5
	avgLatency := math.Max(1.0, baseLatency+jitter)
	throughput := float64(totalMessages) / math.Max(durationSeconds, 1e-9)
	return Metrics{
		Miners:           cfg.Miners,
		PayloadBytes:     cfg.PayloadBytes,
		Iterations:       cfg.Iterations,
		PQSignatureBytes: cfg.PQSignatureBytes,
		MessagesPerSec:   throughput,
		AvgLatencyMs:     avgLatency,
		DurationMs:       int(math.Round(durationSeconds * 1000.0)),
	}
}

func normalize(opts Options) Options {
	cfg := opts
	if cfg.Miners <= 0 {
		cfg.Miners = 1
	}
	if cfg.PayloadBytes <= 0 {
		cfg.PayloadBytes = 1024
	}
	if cfg.Iterations <= 0 {
		cfg.Iterations = 1
	}
	if cfg.PQSignatureBytes <= 0 {
		cfg.PQSignatureBytes = 3293
	}
	if cfg.Seed == 0 {
		cfg.Seed = 1
	}
	return cfg
}
