# VEIL / one-level Ligerito complete-ZK audit

## Verdict

**No-go for the current transcript.** VEIL is a plausible design source for a
new zero-knowledge Ligerito commitment layer, but neither the exact Hegemon
one-level Ligerito transcript nor the published `slop-veil 6.4.0` crate is a
drop-in complete-ZK wrapper for the mixed `B128`/`E384` M4 backend.

The current Hegemon masks fail an exact fixed-transcript rank gate. At one
fully active residual coordinate they span rank one over `B128`, while
same-relation witness differences span rank three. A left-null functional
distinguishes two valid witness views with conditional total variation one.
Three independent `B128` mask coordinates can close this *one* `E384` block,
but that local equality is not a whole-view simulator or a Fiat--Shamir/QROM
proof.

Every authority flag in `ligerito_veil_audit.py` remains false. The current
transcript is not frontier-eligible and must not be admitted to production.

## Exact observation surface audited

The pinned one-level implementation serializes or verifies all of the
following witness-dependent views:

1. wide `E384` target and reduction values;
2. two `E384` coefficients for every lane-fold sumcheck round;
3. the complete folded residual vector as `E384` values;
4. `q * 2^p` raw `B128` Reed--Solomon row values;
5. the Merkle root/frontier and the Fiat--Shamir query schedule as
   computational views.

The implementation sets `terminal = tuple(values)`, opens each selected row
unchanged, checks the folded row against an RS evaluation of that full
terminal, and also performs a supplemental SHAKE-derived check of the root and
target. Compact multiproof encoding changes authentication bytes only. It adds
no hiding entropy and leaves the raw leaf values and canonical terminal clear.

This is an audit of the checked-in one-level proof model, not a claim that the
full maximum M4 transaction relation has already been compiled into that
model.

## Executable rank counterexample

Use the `B128` basis `(1,Y,Y^2)` for
`E384 = B128[Y]/(Y^3 + Y + 1)` and take the first two lane-fold challenges to
be `Y`. The four lane weights are

```
(1 + Y^2, Y + Y^2, Y + Y^2, Y^2).
```

For the toy public relation `lane0 = lane1`, three valid witness directions map
to `(1+Y, Y+Y^2, Y^2)`, which have rank three over `B128`. At a fully active
prefix residual coordinate:

- the suffix random-tail patch has rank zero;
- the global constant-coefficient mask has image `Span{1}`, rank one; and
- the `Y`-coordinate functional annihilates `Span{1}` but detects `1+Y`.

Therefore

```
rank(O G_r) = 1
rank([O G_r | O G_w]) = 3,
```

and two same-relation witnesses induce disjoint conditional cosets. Their
conditional total variation is exactly one. The checker also confirms that
three coordinate masks `{1,Y,Y^2}` close this local rank, while a zero
coefficient on the random column drops its contribution back to rank zero.

For query padding, the necessary fixed-query condition is the analogous
projection equality for every admitted distinct query set. The executable
`GF(2^4)` analogue shows that `q` fresh high coefficients give a full-rank
`q * q` Vandermonde projection and `q-1` do not. Production still needs this
theorem over the actual `B128` Ligerito code and adaptive transcript.

## What the VEIL theorem actually requires

The primary paper proves an honest-verifier/semi-malicious interactive
zero-knowledge compiler under a specific interface, not a theorem about any
already Fiat--Shamirized proof byte string. A source-faithful Hegemon port must
discharge all of these premises:

| Premise | Paper role | Hegemon status |
| --- | --- | --- |
| Fixed-format public-coin MIOP | Prover messages are field elements or multilinear oracles; verifier messages are fixed-format random coins; acceptance is polynomial | **False** for the current proof object |
| One declared field | All multilinear oracles and polynomial checks live over the theorem field | **False/unrefined** for mixed `B128` commitments and `E384` challenges |
| At most one evaluation query per commitment | Needed directly or via the cited conversion | **Unproved** for the extracted M4 protocol |
| `k`-ZK code | Every projection of up to the base query count is full rank | **Unproved** for the actual additive/binary Ligerito code |
| ZK proximity generator | The extra random-column coefficient is nonzero and the malformed-oracle soundness terms are bounded | **Unimplemented** |
| Simple MCS binding and IOPP strength | Binds the masked stacked oracle and its opening | **Uninstantiated** at PQ128 |
| Partial PCS simulator | Simulates every shielded opening for fixed verifier randomness | **Absent** |
| Independent masks for direct fields | Each exposed field message is shifted by fresh independent entropy | **Absent** for the full Hegemon view |
| Arithmetic verifier predicate | All remaining acceptance logic is represented by polynomial constraints | **False** while supplemental SHAKE/parser/Merkle logic remains outside the declared circuit |
| ZK circuit-evaluation scheme | Proves the polynomial predicate on committed masks and has its own simulator/binding error | **Absent** |
| Whole-view composition | The PCS and non-oracle simulators compose with abort/retry and transcript scheduling | **Absent** |
| Fiat--Shamir/QROM theorem | Converts the interactive HVZK proof and charges all quantum hash queries and bad events | **Absent from the paper and crate** |

The paper mentions Ligerito as an example of a constrained RS proximity test,
but its concrete theorem is parameterized by a qualifying base simple MCS and
proximity generator. It does not establish that this Hegemon transcript is
such an MIOP.

The current proof is already noninteractive and includes SHAKE/Merkle/parser
logic. A correct port must first extract the underlying interactive M4 MIOP,
replace its oracle commitment/opening protocol with a binary-field zk-MCS, and
wrap every direct algebraic message. Applying VEIL after serialization is not
the construction in the paper.

## Published crate provenance and substitution boundary

The audited archive is `slop-veil 6.4.0`, supplied with archive SHA-512

```
a550dad8843bd826d2e05151c8707b09f979c979593c71a2e2b900d925726236e
f6566a7769fd6eb4ad20f93b4ca9037e267fff4dfaa0e5fd312e31fe80976ba
```

The extracted crate records VCS commit
`f66b4bff51d0ccff51d152e0f7f66b2ffedf3529`, `dirty: true`, at
`slop/crates/veil`. Its README calls the code experimental, unaudited, and
unsuitable for production. The checker pins the staged paper and every relevant
crate file by SHA-256.

There is a generic-looking trait boundary:
`ZkPcsProver`/`ZkPcsVerifier`. That is not a supported generic PCS substitution
in the published crate:

- `ZkIopCtx` requires `F` and `EF` to implement `TwoAdicField`;
- the only shipped `ZkIopCtx` implementation is
  `KoalaBearDegree4Duplex`;
- the concrete proof contains `BasefoldProof`, and the crate directly depends
  on `slop-basefold` and `slop-basefold-prover`;
- verifier code explicitly calls two-adic generators and checks two-adicity;
- no `B128`/`E384`, additive-code/Ligerito, or SHA-512 backend is present.

For `GF(2^128)`, the multiplicative group has odd order `2^128-1`, so the
positive-size multiplicative two-adic domains used by the concrete code cannot
be supplied by the exact Hegemon base field. A new binary/additive PCS and a
new proof of the code, proximity generator, binding, IOPP strength, and
serializer refinement are required; changing the trait implementation alone
is not enough.

The crate also has no simulator API or QROM theorem. Its source explicitly
notes bad values for an RLC coefficient without conditioning the protocol, and
the stacked PCS multiplies the random mask row by an unrestricted batching
power. If that coefficient is zero, the local mask disappears. Those events
need explicit nonzero sampling or an abort/selective-failure analysis before
they can enter any privacy bound.

The paper's public PoC uses a 31-bit prime field, a degree-four extension,
BaseFold, Poseidon2, and a 100-bit target. Its reported percentage overhead is
not evidence for `B128`/`E384`, Ligerito, SHA-512/SHAKE, PQ128, or QROM.

## Conservative geometry and byte ledger

Let `C = 2^p` be the data-column count, `R = 2^(n-p)` the unpadded row count,
`q` the base proximity-query count, and `D = 3` the degree of `E384` over
`B128`. The published source structure consumes at least:

```
random private B128 elements = q*C + D*(R+q)
extra opened mask-column bytes = q*D*16 = 48q
combined padding-vector bytes = q*48
mask-column evaluation bytes = D*48 = 144
combined evaluation-claim bytes = 48
gross direct payload floor = 96q + 192 bytes.
```

This is a gross source-structure floor against an analogous base stacked proof
with the same query and path geometry. It excludes the non-oracle constraint
proof, new roots and authentication paths, framing, alignment, domain tags,
distance loss, changed rate/query counts, and any duplicated values. It is not
an incremental serializer measurement.

| Existing non-ZK screen | Existing modeled bytes | Direct floor | Baseline plus floor only |
| --- | ---: | ---: | ---: |
| `n=16, p=6, q=38`, 64-GiB oracle | 144,496 | 3,840 | 148,336 |
| `n=16, p=6, q=61`, 512-MiB screen | 168,688 | 6,048 | 174,736 |

Neither total is a complete-ZK estimate. Both omit the dominant unknown
arithmetic constraint wrapper and must be recomputed after code distance,
soundness, and QROM queries fix the real `q`.

For a source-faithful full VEIL compiler, Section 5.2.3 gives the symbolic
additional proof inventory

```
hash digests = q0*m + lambda*(ceil_log2(m_plus)+ceil_log2(m_times)) + 3
field values = (q0+1)*(2^p+1) + 3*m_prime + n_prime
               + 11*lambda + k + p + 25.
```

Using Hegemon wire widths would charge 64 bytes per SHA-512 digest and 48 bytes
per `E384` value. No numeric total is authorized because `q0`, `m`, `lambda`,
`m_plus`, `m_times`, `m_prime`, `n_prime`, and `k` have not been derived for the
full M4 relation or composed PQ128/QROM target.

## Minimum viable source-faithful port

1. Export the full interactive M4 verifier before Fiat--Shamir as a typed MIOP
   with fixed coin formats and a single declared mixed-field refinement.
2. Arithmetize every non-oracle acceptance check, including supplemental hash,
   parser, domain, and statement logic, or prove it public and
   witness-independent outside the wrapper.
3. Implement an additive `B128` zk-Ligerito MCS: `q` random coordinates per
   data column, three full random base-field columns, a nonzero random-column
   coefficient, exact query-without-replacement handling, and code/PG/IOPP
   theorems.
4. Emit the exact observation matrices `O`, witness generator `G_w`, and mask
   generator `G_r` after the actual adaptive challenges and prove
   `rank(O G_r)=rank([O G_r|O G_w])` for every transcript branch.
5. Add independent masks for every direct field message and a ZK
   circuit-evaluation proof for the full verifier predicate.
6. Implement a joint whole-view simulator covering commitments, direct
   messages, raw openings, Merkle paths, queries, aborts/retries, and padding.
7. Compose PCS, IOPP, circuit-wrapper, hash, Fiat--Shamir, grinding, union, and
   selective-failure terms in the QROM at at least 128 bits.
8. Freeze the serializer, measure one self-contained proof, add mutation and
   restart vectors, and only then revisit capability flags.

## Reproduction

These checks are dependency-free and create no build artifacts when bytecode
is disabled:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  .agent/hardening/ligerito-e384-veil-complete-zk/ligerito_veil_audit.py

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s .agent/hardening/ligerito-e384-veil-complete-zk \
  -p 'test_*.py' -v
```

Expected checker status:

```
REJECT_CURRENT_TRANSCRIPT_SOURCE_FAITHFUL_PORT_REQUIRED
complete_zk=false
strict_pq128=false
production_authorized=false
```

## Primary and local evidence

- `/private/tmp/veil-2026-683.txt`: paper text, SHA-256
  `c08a7e40861a082cf7362d07e067e8fd790eb07701a39781e3ba3ab6bd46b790`.
- `/private/tmp/slop-veil-6.4.0.kJf1od/slop-veil-6.4.0`: staged authors'
  crate source; no import or build was performed.
- `.agent/hardening/binius-pq128-proof-size/strict_refold_pcs_prototype.py`:
  exact one-level observation surface.
- `prototypes/standalone-shake256-binius/char2-hvzk-sumcheck-kernel/` and
  the `m4-zk-*`, random-tail, and compact-multiproof patches: existing masking
  components and their explicit claim boundaries.

