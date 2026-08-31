# Ligero-family backup architecture tournament

## Verdict

No transparent Ligero-family construction inspected here passes the frozen
Hegemon gate.  `architecture_winner=null`, every authority Boolean is false,
and `proof_bytes`, its lower bound, and its upper bound are all null.

Original Ligero is the only candidate in this lane with the right combined
theorem shape: its primary source provides an explicit simulator and an
identical-view zero-knowledge theorem for the interactive oracle protocol,
then analyzes its own round-by-round soundness and cites the BCS statistical-ZK
compiler for a classical-ROM NIZK.  This is genuine zero-knowledge evidence,
not an appeal to random masks.  It does not close a concrete construction over
the exact Hegemon relation, finite-QROM Fiat-Shamir, a conventional wide-hash
instantiation, canonical proof bytes, or native verifier refinement.

The exact conditional evaluation of Ligero's printed communication expression
is large: 16,437,920 bytes for the conservative source-264/640-bit-output
screen.  This value is an arithmetic receipt for the paper expression, not a
proof measurement or bound.

## Frozen relation

The screen is tied to the SHA-512-pinned `blake2b448-mixed` Goldilocks macro
R1CS:

| Quantity | Exact value |
| --- | ---: |
| constraints `m` | 20,457,227 |
| nonconstant variables `n` | 19,311,555 |
| public variables `l` | 10,152 |
| private transport variables | 77,376 |
| derived auxiliary variables | 19,224,027 |
| matrix nonzeros | 94,551,238 |
| field modulus | 18,446,744,069,414,584,321 |

This is still a source-only macro program.  Four host predicates remain
outside the relation: policy-identity recomputation, whole-manifest
recomputation, selected-entry membership, and authentication of the expected
root/height.  Consequently even a proof backend for the matrix as written
would not yet establish the exact full production relation.

## Candidate tournament

### Original Ligero

[Ligero ePrint 2022/1608](https://eprint.iacr.org/2022/1608.pdf) is the closest
candidate.  Theorem 4.7 gives perfect completeness, an explicit statistical
soundness expression, and an identical-view ZK claim; Lemma 4.15 constructs a
simulator.  Sections 5.1 and 5.2 distinguish the statistically hiding
commitment layer from the Merkle compression and discuss the BCS statistical-ZK
ROM compilation.  Section 5.2 also derives a protocol-specific classical
round-by-round bound.

These results leave concrete gates open:

- The paper proves an arithmetic-circuit construction.  The natural map
  `z -> (A*z,B*z,C*z)` is only a paper-level adapter; no compiler, mutation
  suite, or refinement theorem connects it to the frozen Hegemon R1CS.
- The optimized `e=k,n=3k` profile does not directly satisfy Theorem 4.7's
  printed `e<(n-k)/4` premise.  Section 5.3 instead relies on the later
  Appendix C refinement for `e<d/2`, whose general query bound is
  `(1-e/n)^t+((k+ell)/n)^t+(2k/n)^t+(n+3)/|F|^sigma`.  The screen evaluates
  Section 5.3's resulting `3*(2/3)^t+(n+4)/|F|^sigma` upper bound; it does not
  mislabel that later derivation as a direct Theorem 4.7 instantiation.
- The implementation reported by the paper uses a 30-bit prime field and
  SHA-256.  It is neither this relation nor a SHA-512/SHAKE finite-QROM
  instantiation.
- CMS gives a QROM theorem under exact RBR and compiler premises, but the
  augmented query conversion, base-game arity, total IOP proof length, and
  exact constants are not instantiated here.
- The paper's communication expression is not a canonical consensus wire.  It
  supplies no Hegemon framing, byte parser, statement/context binding,
  verifier refinement, or retained artifact.

### BooLigero

[BooLigero ePrint 2021/121](https://eprint.iacr.org/2021/121.pdf) gives a
modified public-coin perfect-HVZK IOP for Boolean circuits and a concrete
simulator argument.  Its size improvement comes from packing in binary
extension fields `GF(2^w)`.  The frozen relation is an odd-field Goldilocks
R1CS.  Reusing BooLigero would therefore require a new field/compiler
refinement, not a backend adapter for the same relation.  No exact finite-QROM,
wide-hash, or same-relation artifact is supplied.

### Ligero++

The [CCS 2020 bibliographic record](https://doi.org/10.1145/3372297.3417893)
describes an optimized Ligero-family R1CS/FRI construction.  A pinned full
primary construction and implementation source supporting all relevant claims
were not available in this bounded lane.  An abstract is not evidence for a
whole-view simulator, finite-QROM composition, exact adapter, or proof bytes,
so every qualifying field remains false or null.

The current official [Ligero prover repository](https://github.com/ligeroinc/ligero-prover)
was observed at `a40868f6045ddf27a488f65498a9f17832c1cda0`.  Its public README describes
the Ligetron build stack; no exact Hegemon relation, complete security ledger,
or retained same-relation proof was identified.  No clone or build was run.

### Ligerito

[Ligerito ePrint 2025/1187](https://eprint.iacr.org/2025/1187.pdf) is a
transparent polynomial commitment/inner-product scheme, not a zero-knowledge
proof system.  Equation (15) gives the ordinary unique-decoding error

```text
((M-R-1)/(2M))^q + M*p/|F| + 2*p/|F|,
```

and Equation (19) gives a communication expression.  Neither supplies a
complete-ZK wrapper or an applicable generalized-special/RBR premise for the
exact one-level core.  The local 136,048-byte optimistic and 208,400-byte
source-264 artifacts cover only 65,536 source symbols and explicitly exclude
the full relation and complete ZK.  They are not same-relation comparators.

### Flock

The primary [Flock paper](https://eprint.iacr.org/2026/1329.pdf) explicitly
scopes the system as succinct but not zero knowledge.  Its evaluated targets
are 100/120 bits and its commitment/transcript profiles use SHA-256.  Its batch
binary-field R1CS design is not the exact frozen Goldilocks relation.  Flock is
therefore disqualified before proof-size comparison.

## Exact conditional Ligero expression

For a source capacity `N=max(m,n)=20,457,227`, the screen uses the improved
parameters printed in Ligero Section 5.3:

```text
e = k
n_code = 3*k
rows = floor(N/ell) + 1              # rows*ell > N
k > ell+t
epsilon_IOP = 3*(2/3)^t + (n_code+4)/|F|^sigma

core_bits =
  [k*sigma + (k+ell-1)*sigma + (2*k-1)*sigma
   + t*(4*rows+3*sigma)] * ceil(log2|F|)
  + t*ceil(log2(n_code))*h.
```

The implementation searches exact `Fraction` values, powers-of-two `k`, and
every quotient interval for `ell`; decimal security bits are display only.

| Source target | `h` | `k` | `ell` | rows | `sigma` | `t` | field transcript | Merkle paths | paper core expression |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 512 | 32,768 | 32,524 | 629 | 3 | 222 | 8,410,656 B | 241,536 B | 8,652,192 B |
| 128 | 640 | 32,768 | 32,524 | 629 | 3 | 222 | 8,410,656 B | 301,920 B | 8,712,576 B |
| 264 | 512 | 32,768 | 32,267 | 634 | 5 | 455 | 15,819,120 B | 495,040 B | 16,314,160 B |
| 264 | 632 | 32,768 | 32,267 | 634 | 5 | 455 | 15,819,120 B | 611,065 B | 16,430,185 B |
| 264 | 640 | 32,768 | 32,267 | 634 | 5 | 455 | 15,819,120 B | 618,800 B | 16,437,920 B |

The exact evaluations of the Section 5.3/Appendix C upper bound are about
`2^-128.2767` and `2^-264.5730`.  They are not retained proof-system
certificates and do not include Fiat-Shamir, commitments, hash instantiation,
grinding, retry, or union losses.

No lower/upper proof bound is claimed.  The expression is conditional on an
unimplemented padding/adapter map and omits an exact canonical BCS/CMS wire,
fixed commitment/root/salt/domain framing, and the production envelope.  A
retained serializer and proof are necessary before `proof_bytes` can be
non-null.

## Complete-ZK and finite-QROM accounting

[BCS ePrint 2016/116](https://eprint.iacr.org/2016/116.pdf), Lemmas 3.4 and
7.5, contributes the direct statistical-ZK term

```text
p(x) * 2^(-lambda/4 + 2),
```

in addition to the underlying IOP's ZK error.  Here `p(x)` is total IOP proof
length in bits, not a Merkle leaf count and not serialized NIZK bytes.  For the
source-264 screen, the prover field transcript alone gives the optimistic floor
`p(x) >= 126,552,960` bits.  The floor yields:

| `lambda` | BCS floor-term security | Local partial-floor security | Verdict |
| ---: | ---: | ---: | --- |
| 512 | 99.0848 bits | 99.0848 bits | definitively below 128 |
| 632 | 129.0848 bits | 128.9915 bits | passes the floor only; actual `p(x)` unknown |
| 640 | 131.0848 bits | 130.7430 bits | passes the floor only; actual `p(x)` unknown |

Lambda 628 is the first multiple of four and lambda 632 the first byte-aligned
value that make this floor term alone smaller than `2^-128`.  Neither is a
sufficient parameter: the actual IOP proof length may be much larger.

[CMS ePrint 2019/834](https://eprint.iacr.org/2019/834.pdf), Theorem 8.6,
establishes adaptive QROM security for its modified BCS compiler under RBR
premises with an asymptotic loss of shape
`O(T^2*epsilon + T^3/2^lambda)`.  The retained local arithmetic also displays
the conservative, non-authoritative corollary

```text
12*T^2*epsilon + 48*T^3/2^lambda + 2*a/2^lambda.
```

At `T=2^64` the source-264 Ligero IOP term has about 132.988 bits.  This does
not close the theorem: CMS does not print 12/48 as exact theorem constants,
the exact base-game arity `a` is missing, and the external-to-augmented query
conversion hides `O(q log ell)` overhead.

The full required ledger keeps every following advantage null:

- PCS salted-Merkle binding, selective-opening hiding, and collision union;
- instantiated IOP/RBR soundness and any knowledge notion;
- complete noninteractive whole-view simulation and exact BCS `p(x)`;
- CMS compiler applicability, augmented query budget, and arity;
- SHA-512/SHAKE ideal-QRO to concrete-hash loss;
- challenge sampling, abort, grinding, adaptive retry, and RNG failure;
- semantic hash roles, physical calls, masks, modes, actions, blocks, epochs,
  multi-proof history, and lifetime union;
- parser, native verifier, network lifecycle, formal, and release refinement.

Thus `composed_security_bits=null`.  A 384-bit output also has only a 128-bit
generic quantum collision ceiling before any composition; the screen uses
512+ bit outputs for arithmetic comparisons but does not treat generic ceilings
as a reduction.

## Comparison to CFW26 and ProveKit

The frozen CFW carrier has exactly one witness oracle, 78 inner-mask oracles,
and 26 outer-mask oracles: 105 total.  Its printed theorem is not inherited.
The retained defects include a coefficient mismatch, an ill-typed Step 9/main
linear form unless `row_M(M,alpha)` is defined, and an endpoint error:
`st2=(0,1,0,...)` selects the coefficient of `X`, not `s(1)`.  The honest
polynomial `s=X^2-X` has `s(0)=s(1)=0` but fails that printed check.  Repair
requires `st2=pow(1)=(1,1,...)`; even that local repair does not supply a full
theorem, PCS, QROM composition, or proof artifact.  CFW proof bytes remain
null.

ProveKit has a substantive generic nonrecursive R1CS/WHIR stack and packages
its two transcript streams into one logical object.  It still lacks a primary
whole-view simulator theorem for the exact construction, a finite-QROM
composition, an exact Hegemon relation artifact, and a canonical bounded
consensus wire.  Its 256-bit commitment surfaces have a generic quantum
collision ceiling of `256/3 = 85.333...` bits.  Same-relation proof bytes are
null, so it is not a tournament baseline.

## Reproduction

No Cargo build, proof generation, clone, or dependency install is needed:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/ligero-backup-screen/check_screen.py --require-local-pdfs
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s .agent/hardening/ligero-backup-screen -p 'test_*.py' -v
```

The canonical `ledger.json` pins the exact arithmetic, source hashes, candidate
matrix, no-go comparators, and all fail-closed authority gates.
