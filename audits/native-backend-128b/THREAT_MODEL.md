# Native Backend 128-Bit Threat Model

Reviewer target:

- forge a verifying native `TxLeaf` artifact without the claimed witness/opening relation
- forge a verifying `ReceiptRoot` artifact without the claimed verified-leaf aggregation relation
- make production and reference verifiers disagree on the same fixed vector
- find a noncanonical encoding that changes semantics without changing accepted meaning
- find a transcript/domain-separation alias that preserves bytes while changing proof meaning

Out of scope:

- the full transaction AIR beyond the serialized public-input commitments used here
- wallet UX and key-management issues
- network-layer denial of service outside artifact parsing and verification

In scope:

- native artifact parsing
- commitment opening binding/hiding under the claimed parameter regime
- fold transcript derivation, verified-leaf replay, and domain separation
- spec identity / manifest identity drift
- prover-side timing drift on the exercised native tx-leaf build path
