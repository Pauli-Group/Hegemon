package sim

import "testing"

func TestSimulateDeterministic(t *testing.T) {
    metrics := Simulate(Options{Validators: 16, PayloadBytes: 2048, Iterations: 128, Seed: 42})
    if metrics.Validators != 16 {
        t.Fatalf("unexpected validator count: %d", metrics.Validators)
    }
    if metrics.MessagesPerSec <= 0 {
        t.Fatalf("messages per second should be positive")
    }
    // Running the same options should yield the same throughput for determinism.
    other := Simulate(Options{Validators: 16, PayloadBytes: 2048, Iterations: 128, Seed: 42})
    if metrics.MessagesPerSec != other.MessagesPerSec {
        t.Fatalf("expected deterministic throughput")
    }
}
