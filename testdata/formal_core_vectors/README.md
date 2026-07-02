# Formal Core Vectors

`bridge_messages.json` contains fixed bridge message vectors for the formal-core release gate.

Each case commits:

- the source and destination chain ids,
- the application family id,
- the message nonce and source height,
- the payload bytes,
- the expected payload hash,
- the expected bridge message hash,
- the expected single-message root,
- the expected inbound replay key.

The checker in `scripts/hegemon_formal_core` recalculates every expected value without importing `protocol-kernel`. Update this file only when bridge wire semantics intentionally change, and update `DESIGN.md`, `METHODS.md`, and `config/formal-security-claims.json` in the same change.
