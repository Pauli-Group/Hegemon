# Event stream monitoring runbook

This runbook describes how to watch runtime events and correlate them with node health signals. Use it during upgrades, incident response, and new pallet rollouts.

## Tooling
- **Node RPC/WebSocket:** connect to the validator or archival node for the target network.
- **Prometheus/Grafana:** dashboards for block production, peer count, and event dispatch rates.
- **CLI helpers:** `scripts/subscribe-events.sh` (websocket subscription) and `cargo test -p runtime -- --list` to confirm event-emitting pallets are included.

## Subscribing
1. Point the WebSocket client to the network endpoint (e.g., `wss://testnet1-rpc.synth/`).
2. Subscribe to `chain_subscribeFinalizedHeads` and `state_subscribeStorage` for the keys:
   - `System::Events`
   - `pallet-observability` metrics keys
   - pallet-specific queues (`pallet-settlement` nullifiers, `pallet-identity` role updates)
3. Record the subscription IDs and confirm heartbeats every 30 seconds.

## What to watch
- **Upgrade events:** look for `system.CodeUpdated` and pallet-specific migration logs. Cross-check storage versions after the first finalized block.
- **Settlement:** `Settlement::BatchSubmitted`, nullifier reuse attempts, and off-chain worker dispatch rates.
- **Oracles:** feed update cadence per key and gaps longer than 2 minutes.
- **Feature flags:** activation/deactivation events and cohort sizes to ensure staged rollouts.

## Alerting thresholds
- Missing finalized heads for >60 seconds.
- Event backlog >500 entries or growth without clearing in 5 minutes.
- Nullifier replay or oracle feed gaps exceed thresholds above.

## Escalation
1. Page the on-call SRE if thresholds breach; include subscription IDs and the last 10 events in the ticket.
2. Notify the runtime team if migrations fail or storage versions stall after upgrade height.
3. If event streams halt, restart the subscription client, then recycle the RPC endpoint if heartbeats are still missing.
