# Strict M4 refold PCS screen

Status: executable design screen, not a strict proof artifact.

The fixed `q=319` rectangular refold family cannot meet the 124,068-byte raw
proof cap. Exhaustive search over every ordered partition of the 14 variables
finds an authentication-free lower bound of **126,800 bytes** at folds `[3,1]`
and a 10-variable terminal. This already exceeds the cap by 2,732 bytes while
charging zero bytes for every Merkle opening. Charging exact worst-case compact
Merkle frontiers moves the best plan to `[4]` and **190,032 bytes**. Therefore
another nominal 64-byte joint opening is not a solution.

The next screened core is a one-level, mixed-field Ligerito-style opening. A
toy executable exercises its field, code, Merkle, sumcheck, transcript, and
wire grammar, but no complete M4/PCS integration exists:

1. Encode the exact log-14 source as 32 interleaved B128 Reed-Solomon rows at
   rate `rho=2^-8`; SHAKE256-512 commits the 131,072 columns.
2. After the root and evaluation claim are transcript-bound, derive a random
   functional of every inactive source symbol with public claim zero, then
   derive five E384 sumcheck challenges and fold the 32 B128 rows into one
   E384 row. The toy has no real M4 reduction binding the evaluation claim.
3. Send the 512-element E384 residual, derive 68 distinct query columns, open
   all 32 B128 values in each column, and authenticate the canonical compact
   frontier. The verifier re-encodes the folded residual, checks all queried
   coordinates, and checks the sumcheck residual against the exact M4 claim.
4. Fiat-Shamir, roots, challenges, query sampling, statement/profile binding,
   and all semantic tags use SHAKE256-512; algebraic challenges and claims use
   GF(2^384). There is no setup, pairing, group, sidecar, aggregation, or
   verifier-only projection.

With `eta=1/256`, the Johnson radius is
`gamma=1-sqrt(rho)-eta`. The query error is
`(sqrt(rho)+eta)^68 <= 2^-264`. The executable BCHKS/Flock Appendix C MCA
calculation uses `m=ceil(sqrt(rho)/eta)=16` and charges all 31 nonempty fold
events, giving more than 264 component bits over GF(2^384). The OOD component
would also exceed 264 bits only if the production protocol instantiates the
same post-root E384 point, binds the exact M4 claim, and proves that the B128
encoder is the scalar extension of the E384 Reed-Solomon code. The toy executes
the field/encoder equality and post-claim inactive-tail challenge, but does not
provide the M4 binding or a proof of those bridges. The component values are
not a composed union/QROM theorem; `strict_admitted` is therefore hard false
regardless of the individual minima. SHAKE256 with a 512-bit output provides at
most 256-bit generic classical collision binding (128-bit under collision
search with a quadratic quantum speedup), separately from the 264-bit algebra
budget.

Exact non-ZK core wire:

```text
     64  fixed profile/count header
     64  SHAKE256-512 root
  5,424  113 frozen M4 E384 reduction values
    480  5 quadratic sumcheck messages, 2 E384 values each
 24,576  512-element E384 terminal
 34,816  68 * 32 opened B128 values
 47,360  worst-case 740-node SHAKE256-512 compact frontier
-------
112,784  raw proof
  12     HGSP envelope
-------
112,796  envelope; 11,284 bytes remain
```

Complete ZK is one remaining hard gate, not the only one. Flock explicitly is not ZK. VEIL is
the concrete compiler candidate because it masks non-oracle algebraic
messages and proves their verifier constraints while routing oracle reads
through a hiding PCS. Its public proof-of-concept uses transparent BaseFold,
so an E384/SHAKE256-512 port is implementable in principle, but no such port or
measured wire exists. The checked-in model therefore leaves
`complete_zero_knowledge=false` and `strict_admitted=false`; the 11,284-byte
remainder is a hard budget the wrapper must actually earn. The public VEIL
Hadamard benchmark's 127,545-byte overhead is recorded only as non-transferable
evidence that the current proof-of-concept does not fit, not as a lower bound.

The 112,784-byte count is Pay1x2/n14-specific. It is not a production relation
estimate. An unfrozen n15 screen reaches 117,488 bytes only with a 32 GiB
encoded oracle; with a 512 MiB oracle cap it is 133,200 bytes. The n16 screen is
144,496 bytes even with a 64 GiB oracle and 168,688 bytes under that cap. Both
remain non-ZK models with no full-relation statistics.

`strict_refold_pcs_prototype.py --toy-check` runs only a 16 KiB encoded oracle.
It binds a caller-supplied public-context digest before the root, serializes in
transcript order, sorts distinct openings canonically, binds padding nodes to
the profile/root/query set/real frontier length, and exact-consumes the proof.
Its verifier challenges the inactive source suffix with a post-claim random
multilinear functional whose public claim is zero. This is exercised, but has
no composed ROM/QROM/formal proof. It also does not bind a real M4 claim and is
not a ZK or strict verifier. The adversarial test mutates the header, root,
every wide field, every serialized sumcheck message, the verifier-derived
terminal checksum, terminal, opened row, real
frontier node, padding node, context, and trailing bytes. A separate test
parses and reserializes the 112,784-byte Pay1x2 size fixture without allocating
its 64 MiB oracle; the fixture remains invalid and is never a frontier point.

Run:

```sh
python3 .agent/hardening/binius-pq128-proof-size/strict_refold_pcs_model.py --check
python3 .agent/hardening/binius-pq128-proof-size/test_strict_refold_pcs_model.py
python3 .agent/hardening/binius-pq128-proof-size/strict_refold_pcs_prototype.py --toy-check
python3 .agent/hardening/binius-pq128-proof-size/test_strict_refold_pcs_prototype.py
```

`--write-size-fixture PATH` emits a deterministic all-zero 112,784-byte parser
fixture and labels it invalid. It verifies the byte grammar only; it is never
accepted as a proof or frontier point.
