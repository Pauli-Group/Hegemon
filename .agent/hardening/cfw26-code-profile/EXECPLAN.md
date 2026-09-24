# Exact CFW26 105-oracle code/profile screen

This local plan is complete. It does not alter shared architecture documents
or claim production authority.

## Progress

- [x] Visually verify the relevant CFW26 Section 11 and BCS privacy/compiler pages.
- [x] Select explicit plain-RS main, inner, and outer encodings over local Goldilocks E320.
- [x] Enumerate all 105 Section 11 codewords and the 105 Construction 7.2 second-layer codewords.
- [x] Compute exact interactive `p(x)`, BCS privacy term, and minimum byte-aligned lambda.
- [x] Compute all 30 theorem-faithful bit-tree roots, query counts, path depths, salts, siblings, and wire bytes.
- [x] Retain a clearly non-theorem field-symbol batching sensitivity row.
- [x] Implement dependency-free small-field RS encoding, simulation, query verification, and mutations.
- [x] Freeze a canonical ledger, checker, tests, and artifact hashes.
- [x] Keep theorem inheritance, QROM composition, proof bytes, and production authority false.

## Decision

The plain-RS/non-succinct theorem path is disqualified. Its exact interactive
proof is 6,721,606,600 bytes before compilation. The theorem-faithful bit-leaf
BCS projection is 32,252,325,377,789 bytes, and even the unproved field-symbol
batching projection is 1,458,868,874 bytes. Missing CFW theorem inheritance,
MCA bounds, QROM Fiat--Shamir, and deployed SHAKE terms independently keep the
candidate closed.

