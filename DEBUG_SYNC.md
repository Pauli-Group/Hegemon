# Debug Sync

## MAC: Run these and put results below

```bash
echo "CHAINSPEC_SHA256:"; ./target/release/hegemon-node build-spec --chain dev --raw 2>/dev/null | shasum -a 256
echo "RUNTIME_WASM_SHA256:"; shasum -a 256 target/release/wbuild/hegemon-runtime/hegemon_runtime.compact.compressed.wasm
echo "GENESIS_FROM_NODE:"; curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[0]}' -H "Content-Type: application/json" http://127.0.0.1:9944
```

### MAC RESULTS:


---

## WINDOWS RESULTS:

(will be filled by Windows agent)
