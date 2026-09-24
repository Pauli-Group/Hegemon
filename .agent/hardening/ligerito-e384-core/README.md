# Exact one-level E384 Ligerito opening core

## Verdict

Option A is implemented at the authenticated-opening boundary, with every
production and privacy capability false. The owned module contains a complete
parameterized prover, verifier, SHA-512 transcript and Merkle commitment,
canonical parser/serializer, exact byte/resource ledger, adversarial tests, a
typed interactive-MIOP view, and an exact raw observation-row export for a
future complete-ZK compiler.

This does **not** make Ligerito the architecture winner. Even an optimistic
source-only 128-bit equation-(15) target gives a smallest `n=16` one-level core
of **136,048 bytes** under the 512-MiB oracle cap. That is 17,978 bytes (15.23%)
larger than the checked-in active-like SmallWood report of 118,070 bytes and
11,980 bytes above the historical 124,068-byte raw cap, before a full Hegemon
relation reduction or complete zero knowledge. The VEIL audit's minimum direct
payload structure adds 6,336 bytes at `q=64`, producing **142,384 bytes before
the dominant missing constraint/simulator wrapper**.

The inherited conservative 264-bit source screen is larger again:
**208,400 bytes**, or 90,330 bytes (76.51%) above the active-like SmallWood
report. Its VEIL direct-structure floor is 12,864 bytes at `q=132`, giving
**221,264 bytes** before the missing wrapper. Neither the optimistic 128-bit
source target nor the 264-bit source target is a composed Fiat--Shamir/QROM
certificate; the first is an optimistic floor and the second is a conservative
local convention whose sufficiency/necessity remains unproved.

That is a concrete disadvantage for this fixed maximum-frontier grammar, not
an architecture lower bound or absolute final-size theorem. The optimistic
wire excluding authentication is 115,568 bytes; a different canonical
variable-length multiproof could charge fewer than the fixed 20,480
authentication bytes on a particular transcript, although it would no longer
have this fixed proof length and its expected/worst distribution is not
measured here. The 118,070-byte SmallWood report is itself not
production-qualified, and neither candidate has a measured exact new relation
plus complete-ZK artifact. The old 1,344,828-byte M4/Binius artifact is also
not a same-relation, same-security comparator.

## What is implemented

[`ligerito_e384_core.py`](./ligerito_e384_core.py) implements the base case in
Section 5 of the primary Ligerito source, which the paper also identifies as
the `ell=2` base case of the full protocol:

1. Interpret the source as a matrix `X_tilde` with `R=2^(n-p)` rows and
   `C=2^p` columns. The external order is exactly the paper's column-stacked
   `vec(X_tilde)`: source index `row + R*column`.
2. Encode each `B128` column with a coefficient Reed--Solomon generator and
   commit to the encoded rows. Each leaf contains exactly `C` base-field
   values and binds the profile, row index, width, and bytes.
3. Prove the externally supplied `E384` public-functional claim with `p`
   partial-sumcheck rounds. In characteristic two, each degree-two round is
   canonically represented by its constant and quadratic coefficients; the
   linear coefficient is `previous_claim + quadratic`, which enforces
   `g(0)+g(1)=previous_claim`.
4. Send the full `R`-element `E384` partial evaluation, sample `q` distinct
   encoded rows after that message, authenticate them with a canonical compact
   multiproof, and check each folded row against the Reed--Solomon evaluation
   of the terminal vector.

The field tower is fixed to
`B128 = GF(2)[x]/(x^128+x^7+x^2+x+1)` and
`E384 = B128[Y]/(Y^3+Y+1)`. All field encodings are little-endian fixed-width
polynomial-basis encodings. All profile, statement, transcript, query, Merkle,
and padding hashes use the full 64-byte output of conventional SHA-512 with
length-delimited domain separation. There is no Poseidon or SHAKE transcript
in this module.

The prover is guarded by an explicit encoded-oracle allocation limit. Import,
parsing, reporting, and the full-bucket screen allocate no proof oracle.

## Exact source parameter screen

The authoritative error expression for this screen is Ligerito equation (15):

```text
((M - R - 1) / (2M))^q + M*p/2^384 + 2p/2^384.
```

The first search fixes `n=16`, asks only for 128 modeled source-equation bits,
limits the encoded oracle to at most 512 MiB, and minimizes the exact fixed wire
grammar. This is deliberately optimistic because it charges no QROM/FS/hash or
complete-ZK union loss. It chooses `p=6`, rate `1/2`, `q=64`, a 2-MiB oracle,
and the following wire:

| Wire component | Bytes |
| --- | ---: |
| fixed header/profile | 128 |
| statement identifier | 64 |
| commitment root | 64 |
| claimed `E384` value | 48 |
| 6 compact sumcheck messages | 576 |
| 1,024-value terminal | 49,152 |
| 64 opened rows of 64 `B128` values | 65,536 |
| padded maximum authentication frontier | 20,480 |
| **optimistic source-128 total** | **136,048** |

The conservative source-only screen asks for 264 equation-(15) bits and
chooses:

| Quantity | Exact value |
| --- | ---: |
| source symbols | 65,536 |
| folded column variables `p` | 5 |
| data columns `C` | 32 |
| message rows `R` | 2,048 |
| inverse rate | 2 |
| encoded rows `M` | 4,096 |
| distinct queries `q` | 132 |
| encoded oracle | 2,097,152 bytes |
| equation-(15) query log2 error | -264.0930089129 |
| equation-(15) field-term log2 error | -369.6773676361 |
| modeled source-equation union bits | at least 264 |
| maximum compact frontier | 652 SHA-512 digests |

For the literal coefficient-evaluation implementation retained here, the exact
geometry-derived resource ledger is 65,536 source `B128` elements (1 MiB),
65,536 public `E384` weights (3 MiB external statement data), 131,072 encoded
`B128` elements (2 MiB), 131,072 codeword symbol evaluations, 268,435,456
Reed--Solomon Horner steps, 4,096 leaf hashes, 4,095 internal hashes, 63,488
pair terms in each full sumcheck/fold pass, 4,224 opened base-field values,
270,336 verifier terminal-RS Horner steps, and 4,092 verifier row-fold pairs.
These are operation counts for this source algorithm, not elapsed-time
measurements or an optimized FFT implementation. The exact number of SHA-512
query-sampler draws is transcript-dependent because rejection sampling and
duplicate suppression are unbounded; it can only be measured from an executed
artifact and is explicitly not claimed by the formula screen.

Its exact proof ledger is:

| Wire component | Bytes |
| --- | ---: |
| fixed header/profile | 128 |
| statement identifier | 64 |
| commitment root | 64 |
| claimed `E384` value | 48 |
| 5 compact sumcheck messages | 480 |
| 2,048-value terminal | 98,304 |
| 132 opened rows of 32 `B128` values | 67,584 |
| padded maximum authentication frontier | 41,728 |
| **total** | **208,400** |

This is the fixed worst-case grammar, not one lucky multiproof. Unused frontier
slots are deterministic SHA-512 padding bound to the profile, root, canonical
query set, actual frontier length, and slot position.

## Why the old `q=68` result is not retained as authority

The previous local model calls a `q=68`, rate-`1/256` construction
"Johnson-Ligerito". Its query equation is the Flock/BCHKS list-decoding term
`(sqrt(rho)+eta)^q`, not equation (15) in the Ligerito source. A Flock/Johnson
optimization could still be researched, but it needs a separately pinned
mixed-field list-decoding and OOD-binding refinement. This implementation does
not silently import that theorem, so its source-authoritative screen uses the
unique-decoding bound above.

The primary TensorSwitch route is also not this one-level protocol. TensorSwitch
Lemma 8.3 assumes `M>=2` recursive iterations, multiple tensor-code oracles, and
a different commitment/opening recurrence. Calling the Section 5 Ligerito base
case "TensorSwitch" would hide missing protocol messages and oracle costs.

## Canonical parser and mutation boundary

The proof starts with a 128-byte fixed header that carries the exact version,
zero flags, 64-byte profile identifier, geometry, source-security target,
counts, resource total, and zero reserved bytes. `Proof.parse` requires the
externally expected `Parameters`, exact total length, byte-identical header,
and byte-identical canonical re-encoding. Every 384-bit and 128-bit string is a
canonical element of the declared binary fields; there is no modulus-reduction
alias.

[`test_ligerito_e384_core.py`](./test_ligerito_e384_core.py) contains tiny,
dependency-free negative cases for:

- truncation, trailing bytes, profile and reserved-bit drift;
- context, public functional, statement identifier, and expected-claim replay;
- commitment root, claim, every sumcheck boundary, terminal, raw opening,
  actual authentication node, and deterministic padding mutations;
- non-satisfying source input and the explicit allocation gate;
- query distinctness/order, exact parse/re-encode, and byte-ledger equality;
- exact reproduction of every direct `E384` message and raw `B128` opening by
  the exported observation rows; and
- attempts to treat any missing complete-ZK or production premise as true.

Per the delegated disk/build constraint, only AST parsing and the formula-only
`--report` path were run in this workstream. No proof generation, Cargo, Lake,
rustc, remote dependency, or production-size allocation was executed. The
tests are retained for the root/release gate to execute when that authority is
available; they are not represented here as runtime evidence.

## Interactive and complete-ZK interface

`OneLevelInteractiveProver` is the underlying stateful protocol before
Fiat--Shamir. It will not accept a verifier coin before emitting the direct
message on which that coin depends, will not emit the terminal before every
round completes, and will not open rows before the terminal. The SHA-512
`prove` wrapper drives this API in order. `verify_interactive` checks the same
algebra and authentication at caller-supplied fixed public coins.

`extract_interactive_view` then separates an accepted wrapped proof into:

- one `B128` row-oracle commitment;
- the public claim, witness-dependent degree-two sumcheck messages, and full
  terminal as typed direct `E384` messages;
- fixed `E384` verifier coins;
- the actual sampled and canonical distinct query indexes;
- each raw authenticated row opening; and
- polynomial row/terminal constraints separated from parser, SHA-512
  transcript, and SHA-512 Merkle checks.

`export_observation_rows` exports the exact linear observation operator `O`
after the concrete challenges and query set. Sumcheck and terminal rows are
sparse `E384` rows over the raw source. Reed--Solomon openings are exact lazy
`B128` rows whose coefficient function and evaluator are part of the API.

That closes only the core-side interface. The relation-specific witness
generator `G_w` and wrapper mask generator `G_r` are not supplied. A future
wrapper must compose them and prove, for every admitted adaptive branch,

```text
rank(O * G_r) = rank([O * G_r | O * G_w]).
```

`complete_zk_contract` permanently reports all missing gates. In particular:

- the protocol still mixes a `B128` committed oracle with `E384` direct
  messages and has no one-field theorem refinement;
- one commitment receives `q` point openings and no VEIL-compatible
  one-evaluation conversion is proved;
- parser/transcript/Merkle acceptance is not an all-polynomial predicate;
- `q` independent padding coordinates per data column, three independent
  `B128` mask columns, and proved nonzero mixing are absent;
- direct messages are unmasked;
- no joint commitment, fixed-randomness whole-view simulator, abort/selective
  failure bound, or FS/QROM composition exists; and
- `complete_zk`, `strict_pq128`, `frontier_eligible`, and
  `production_authorized` are all false with no enabling API.

The current raw transcript therefore remains completely non-zero-knowledge.
The existing VEIL audit's rank counterexample applies: a one-dimensional
global base-field mask cannot hide a three-dimensional `E384` witness view.

## Reproduction boundary

The source-only report, which never allocates an oracle, is:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  .agent/hardening/ligerito-e384-core/ligerito_e384_core.py --report
```

The retained source-screen checker AST-parses the implementation/tests, reruns
only the formula report, checks its exact ledger against `source_screen.json`,
and rejects any promoted capability flag:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  .agent/hardening/ligerito-e384-core/check_source_screen.py
```

The tiny executable tests are intentionally retained but were not run under
this delegation:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s .agent/hardening/ligerito-e384-core \
  -p 'test_ligerito_e384_core.py' -v
```

Neither command authorizes a production backend. The module has no production
call site and allocates no Hegemon version/action/network identity.

## Evidence anchors

- `/private/tmp/ligerito.txt`, Section 3 and equations (4)--(7): encode columns,
  commit rows, sample logarithmic randomness, send the partial evaluation, and
  check sampled encoded rows.
- `/private/tmp/ligerito.txt`, Section 5 and equations (15)--(16): exact
  matrix-vector plus partial-sumcheck protocol and unique-decoding error.
- `/private/tmp/ligerito.txt`, Section 6.2 discussion: `ell=2` reduces exactly
  to the Section 5 prover/verifier; Section 6.5 permits a first-round subfield.
- `/private/tmp/tensorswitch-2025-2065.txt:2532`: TensorSwitch Lemma 8.3 assumes
  at least two iterations.
- `.agent/hardening/binius-pq128-proof-size/strict_refold_pcs_model.py` and
  `strict_refold_pcs_prototype.py`: previous Johnson/Flock model and SHAKE toy
  implementation, used only as local comparison evidence.
- `.agent/hardening/ligerito-e384-veil-complete-zk/README.md`: exact current
  rank failure, VEIL theorem/crate boundary, and `96q+192` direct payload floor.
- `docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json:14`:
  checked-in 118,070-byte active-like SmallWood report, explicitly not a
  production-qualified same-gate artifact.
