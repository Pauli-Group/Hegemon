package sim

import "testing"

func TestSimulateDeterministic(t *testing.T) {
	metrics := Simulate(Options{Miners: 16, PayloadBytes: 2048, Iterations: 128, Seed: 42})
	if metrics.Miners != 16 {
		t.Fatalf("unexpected miner count: %d", metrics.Miners)
	}
	if metrics.MessagesPerSec <= 0 {
		t.Fatalf("messages per second should be positive")
	}
	// Running the same options should yield the same throughput for determinism.
	other := Simulate(Options{Miners: 16, PayloadBytes: 2048, Iterations: 128, Seed: 42})
	if metrics.MessagesPerSec != other.MessagesPerSec {
		t.Fatalf("expected deterministic throughput")
	}
}
