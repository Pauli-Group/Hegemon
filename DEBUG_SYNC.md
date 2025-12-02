# Debug Sync

## MAC: Run these and put results below

```bash
echo "CHAINSPEC_SHA256:"; ./target/release/hegemon-node build-spec --chain dev --raw 2>/dev/null | shasum -a 256
echo "RUNTIME_WASM_SHA256:"; shasum -a 256 target/release/wbuild/hegemon-runtime/hegemon_runtime.compact.compressed.wasm
echo "GENESIS_FROM_NODE:"; curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[0]}' -H "Content-Type: application/json" http://127.0.0.1:9944
```

### MAC RESULTS:

```
CHAINSPEC_SHA256:
b56e00779f52ad40ae9f0e5c42d727468298ea76f4a3e8d6c5681c7a428fa83d  -

RUNTIME_WASM_SHA256:
(file not found: target/release/wbuild/hegemon-runtime/hegemon_runtime.compact.compressed.wasm)

GENESIS_FROM_NODE:
{"jsonrpc":"2.0","id":1,"result":"0x24352eb30ac2a11de1b4a71250cce8176c0c3c9aa7aa100d90a6b4e24998869f"}
```

---

## WINDOWS RESULTS:

```
CHAINSPEC_SHA256:
22e7fa88dbd59870dee5504cd9960c6af95ab059a6069eaae8e8eff4bc9ce013

DIAGNOSIS: Chainspecs differ - Mac and Windows compile different WASM bytecode.
```

## FIX

Mac agent: Export the raw chainspec to a file:
```bash
./target/release/hegemon-node build-spec --chain dev --raw > config/dev-chainspec.json
```

Then both machines use:
```bash
--chain config/dev-chainspec.json
```
instead of `--chain dev`
