# Dashboard troubleshooting guide

Use this runbook when the dashboard does not reflect node activity. The Substrate node exposes JSON-RPC on port 9944 by default, which the dashboard queries for state.

## What to expect

- `hegemon-node` serves JSON-RPC on the configured `--rpc-port` (default `9944`).
- Dashboard fetches data via standard Substrate RPC methods (`system_health`, `chain_getHeader`, etc.).

## Common fixes

### Dashboard shows no data
- **Symptom:** Tiles remain empty or show connection errors.
- **Fix:**
  1. Verify the node is running: `ps -ef | grep hegemon-node` or:
     ```bash
     curl -s -H "Content-Type: application/json" \
       -d '{"id":1, "jsonrpc":"2.0", "method": "system_health"}' \
       http://127.0.0.1:9944
     ```
  2. Check that the dashboard is pointed at the correct RPC endpoint.
  3. Ensure the node has started with `--rpc-external` if accessing from a different host.

### Port or bind conflicts
- **Symptom:** Browser cannot connect, or another service already binds the RPC port.
- **Fix:** Restart with an explicit port: `./target/release/hegemon-node --rpc-port 9945`. If running multiple nodes, ensure each uses a unique port combination.

### CORS errors in browser
- **Symptom:** Dashboard shows network errors; browser console reports CORS rejection.
- **Fix:** Start the node with `--rpc-cors all` to allow browser requests:
  ```bash
  ./target/release/hegemon-node --dev --rpc-cors all
  ```

### Checking node status via CLI
If the dashboard is unavailable, query the node directly:

```bash
# Health check
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "system_health"}' \
  http://127.0.0.1:9944

# Latest block
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "chain_getHeader"}' \
  http://127.0.0.1:9944

# Peer list
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "system_peers"}' \
  http://127.0.0.1:9944
```
