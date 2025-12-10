package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/Pauli-Group/Hegemon/consensus/bench/sim"
)

func main() {
	var (
		miners       = flag.Int("miners", 64, "number of miners to simulate")
		payloadBytes = flag.Int("payload-bytes", 4096, "payload size per message")
		pqBytes      = flag.Int("pq-signature-bytes", 3293, "size of PQ signatures appended to payloads")
		iterations   = flag.Int("iterations", 512, "messages per validator")
		seed         = flag.Int64("seed", 42, "random seed for jitter")
		smoke        = flag.Bool("smoke", false, "run a short smoke benchmark")
		jsonOut      = flag.Bool("json", false, "emit JSON instead of text")
	)
	flag.Parse()

	iterCount := *iterations
	if *smoke {
		if iterCount > 64 {
			iterCount = 64
		}
	}

	metrics := sim.Simulate(sim.Options{
		Miners:           *miners,
		PayloadBytes:     *payloadBytes,
		Iterations:       iterCount,
		PQSignatureBytes: *pqBytes,
		Seed:             *seed,
	})

	if *jsonOut {
		blob, err := json.MarshalIndent(metrics, "", "  ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(blob))
		return
	}

	fmt.Printf(
		"netbench: miners=%d payload=%dB pq_sig=%dB iterations=%d msgs/s=%.2f latency=%.2fms duration=%dms\n",
		metrics.Miners,
		metrics.PayloadBytes,
		metrics.PQSignatureBytes,
		metrics.Iterations,
		metrics.MessagesPerSec,
		metrics.AvgLatencyMs,
		metrics.DurationMs,
	)
}
