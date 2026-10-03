# Salted BCS/QROM zero-knowledge audit

Status: **the 32-byte salt charge is unproved for PQ128 and is not sufficient
evidence for complete zero knowledge**. The direct BCS Merkle-privacy theorem
does not apply to the declared `salt=256 bits, SHAKE256-512 output=512 bits`
pair. A different, lazy QROM simulator might prove this construction with a
different bound, so this is not a universal impossibility result. It is a hard
rejection of the current security promotion.

Nothing in this directory is a proof-size frontier point, a PCS, a QROM
reduction, or a SHAKE instantiation theorem.

## Exact source and framing

The audit pins both current sources:

- `prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs/random_padding_pcs.py`
  at SHA-256
  `e8311b5b00458f6bd1182637e812e7d879c3fbda9743c5445527e30859975548`;
- `prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs-fri/random_padding_fri.py`
  at SHA-256
  `71800fed15607ff9399c42a522c0741e49bc74da4429e77e2cec0bab3c96e3c4`.

The executable controls call the first module's real `salted_leaf_hash`; they
do not substitute another leaf grammar. They also load the second module's
actual report and recompute the theorem-scoped salt rows from its tree sizes.

One leaf hashes a domain tag, a length-framed 64-bit leaf index, a 32-byte
salt, and four canonical little-endian B128 symbols (64 payload bytes) to a
64-byte SHAKE256 output. Internal nodes use another domain and bind level,
index, and both 64-byte children. This is good framing. It does not itself
prove hiding, QROM programmability, or independence of the challenge schedule.

At rate `1/32`, the declared n15 univariate RS tree has

    2^15 * 32 / 4 = 2^18 = 262,144 leaves.

The compact precursor screen opens 66 leaf groups. The executable separate-tree
one-round FRI topology opens 132 groups: 66 from the base tree and 33 from each
of two folded trees. The combined-fold-tree best case opens 66 base groups and
33 combined folded groups. None of these counts is an authorized count of QROM
reprogramming points; they are sensitivity cases.

## The two hiding jobs must not be conflated

Random high coefficients and leaf salts solve different problems.

For a fixed B128-linear observation schedule, the random-padding prototype
correctly proves that

    Y = W_active*x + W_pad*r

is witness-independent exactly when the active shifts lie in the padding
image. Full row rank of `W_pad` gives a uniform view. That statement controls
the values the verifier opens.

The salt is intended to hide unopened leaf inputs and let a Merkle simulator
replace unseen subtrees. It does not add rank to `W_pad`. Conversely, uniform
opened values do not show that the Merkle root or the Fiat--Shamir schedule is
witness-independent.

The schedule here is adaptive: the root is a function of `x`, the random tail,
all leaf salts, and the random oracle, and the verifier derives query indices
from that root. Checking the realized matrix after those indices have been
selected is unsound. The inherited one-bit control makes every selected row
rank one while leaving a `3/4` witness bias.

## Concrete simulator contract

A complete proof has to define the real and simulated distributions and then
give hybrids with one explicit bound each.

The real prover must sample one fresh independent random tail and one fresh
uniform salt with 256 bits of **conditional min-entropy** per leaf and per
proof. No salt may be derived from the witness, root, Fiat--Shamir transcript,
another salt, or a repeated deterministic RNG state. It then builds exactly
one immutable root, derives every challenge in a frozen order, and emits the
canonical union opening without witness-dependent retry.

The simulator must, without the witness:

1. produce the entire interactive M4/PCS view, not only the point openings;
2. cover point, terminal, FRI/fold, characteristic-two-mask, and ring-switch
   rows in one adaptive observation theorem;
3. simulate the root and every authentication frontier while preserving exact
   verification under the same oracle;
4. identify every random-oracle point it changes, the point's conditional
   maximum probability `p_max`, the number `R` of changes, and the number of
   quantum hash queries before each change;
5. program all Fiat--Shamir challenges in their exact transcript order and
   prove that the final query schedule has the real distribution;
6. include aborts, retries, malformed openings, and rejection sampling in the
   view, with a witness-independent distribution; and
7. union this distance with interactive-HVZK, rank-bad, hash collision,
   binding, proximity/extraction, multi-proof, and SHAKE-instantiation terms.

Only source pinning and framing are true in the machine-readable report; the
security obligations are false or unavailable. In particular, `q_H` must
count the adversary's total quantum queries
to the physical domain-separated SHAKE interface, not merely verifier calls.
Domain tags prevent syntactic cross-use; they do not create independent random
oracles without a reduction.

## Why the classical BCS argument does not apply

Ben-Sasson, Chiesa, and Spooner Section 3.2 stores
`rho(value || r_i)` with a fresh `r_i` of `2*lambda` bits while `rho` outputs
`lambda` bits. Lemma 3.4 proves classical statistical Merkle privacy

    z(n, lambda) = n * 2^(-lambda/4 + 2).

Lemma 7.5 uses this inside a zero-knowledge compiler in the
**explicitly-programmable classical random-oracle model**. It is not a QROM
theorem.

The actual strict pair has two incompatible values of the paper's one
parameter:

    lambda from 256-bit salt / 2 = 128
    lambda from 512-bit oracle output = 512.

If `lambda=128`, the oracle output would have to be 128 bits and the rate-32
tree bound is only `12` bits. If `lambda=512`, the salt would have to be 1,024
bits and even that hypothetical rate-32 bound is only `108` bits. Requiring
the stated lemma itself to reach 128 bits at `n=2^18` gives

    lambda >= 4 * (128 + 2 + 18) = 592,
    salt >= 1184 bits = 148 bytes per leaf.

These numbers diagnose direct theorem applicability; they are not a claim that
every possible Merkle simulator needs 148-byte salts.

### The salt floor is per tree

For a power-of-two tree with `n` leaves, solving the displayed BCS bound for a
128-bit classical statistical target gives the exact byte diagnostic

    salt_bytes = 128 + 2 + log2(n).

It must be applied separately to every tree. Thus the `2^18` base tree and each
separate `2^18` folded tree use 148 bytes in this diagnostic, while the
combined `2^19` folded tree uses 149 bytes. The executable FRI artifact now
applies this rule directly and matches this audit's independent recomputation:
**101,261 bytes** for the combined one-round row and **387,427 bytes** for the
base tree plus all fifteen progressively smaller folded trees. The later trees
need 147 down to 135 bytes.

These corrected rows are still classical theorem-scope screens only. A
149-byte salt corresponds to `lambda=596`, a 148-byte salt to `lambda=592`,
and the physical strict digest remains 512 bits, so there is no common BCS
parameter. The BCS result is not a QROM theorem. Every strict-security and
frontier gate therefore remains false.

## Current exact byte rows

The pinned source reports the following strict SHAKE256-512 rows:

| topology | 32-byte salt | direct-BCS per-tree diagnostic |
|---|---:|---:|
| precursor conditional q33 | 69,632 | 77,288 (one `2^18` tree) |
| precursor double-full q66 | 128,512 | 143,824 (one `2^18` tree) |
| one-round separate folded trees q33 | 118,192 | 133,504 (three `2^18` trees) |
| one-round separate folded trees q66 | 219,056 | 249,680 (three `2^18` trees) |
| one-round combined folded tree q33 best case | 89,744 | **101,261** (`2^18` base + `2^19` fold) |
| all fifteen combined rounds q33 structural floor | 325,424 | **387,427** (per-tree salts) |

The precursor is not FRI. The one-round rows halve the degree only once. The
all-round row is merely an authenticated Merkle/opening structural floor and
omits the local-consistency proof, production PIOP messages, characteristic-two
ZK, extraction, adaptive simulation, two-branch product theorem, and QROM
composition. None is a proof-size or security result.

## QROM screens and their limits

Grilo, Hoevelmanns, Huelsing, and Majenz Theorem 1 bounds adaptive QROM
reprogramming. For a conservative uniform hidden salt position with
`p_max=2^-s`, replacing each prefix query count by total `q` gives the screen

    Adv <= R * (sqrt(q / 2^s) + q / 2^(s+1)).

This theorem requires the exact reprogramming distributions, side information,
classical reprogramming triggers, `R`, and query prefixes. None is frozen for
this PCS. The calculator therefore reports the bound but keeps theorem
instantiation false.

With `s=256`, illustrative results are:

| programmed-point sensitivity | quantum queries | bound bits | minimum salt bits for a 128-bit bound |
|---|---:|---:|---:|
| 1 | `2^0` | just below 128 | 257 |
| 1 | `2^32` | just below 112 | 289 |
| 66 | `2^32` | 105.96 | 301 |
| 132 | `2^32` | 104.96 | 303 |
| `2^18` | `2^0` | just below 110 | 293 |

The crude Grover work screen for finding any of `2^18` independent 256-bit
salts is `(256-18)/2 = 119` bits; reaching 128 in that all-leaf scenario needs
at least 274 salt bits before constants. That all-leaf attack/reprogramming set
is not proved to be the correct set for a lazy simulator, which is why the
final verdict is `UNPROVED_FOR_PQ128`, not a categorical impossibility.

SHAKE256-512's generic quantum preimage and collision work screens are 256 and
`512/3 = 170.67` bits. Those output-width numbers do not amplify a 256-bit
salt's input entropy and are not a composed transcript proof.

Dominique Unruh's QROM Fiat--Shamir zero-knowledge Theorem 20 and concrete
Corollary 35 require a sigma protocol with HVZK, completeness, and
unpredictable commitments. The concrete unpredictability term is

    (4 + sqrt(2)) * q_P * sqrt(q_P + q_H) * epsilon_u^(1/4).

Even granting an optimistic uniform 512-bit root and setting `q_P=1, q_H=0`,
that first term has under 128 bits. More importantly, Hegemon's multi-round
IOP/Merkle transcript is not the sigma protocol covered by that theorem.

Don, Fehr, and Majenz Corollary 15 covers multi-round Fiat--Shamir preservation
of soundness and proof of knowledge. It does not provide this zero-knowledge
simulator. Neither result can be pasted onto the classical BCS hybrid.

## Adaptive openings, selective failure, and reuse

An adaptive verifier may choose a leaf whose linear functional falls outside
the padding image, or choose among individually full-rank rows in a
padding-correlated way. The full transcript theorem must precede the rank
claim; post-selection rank is not enough.

The prover must not retry salts, padding, roots, or challenge counters until a
rank check, low byte length, favorable query set, or acceptance condition
passes. Conditioning on success can expose the witness through the accepted
challenge, through whether a proof appears, through an attempt counter, or
through timing. The executable selective-failure control has equal `1/2`
abort rates for both witnesses, yet every accepted transcript reveals the
witness exactly.

Salt and padding freshness are separate requirements. Reusing the same salt at
the same leaf index makes equal payloads deterministically linkable across
proofs. Reusing the random high-coefficient tail makes matching linear views
cancel the mask exactly in characteristic two. A production grammar needs
fresh OS randomness, deterministic-test-seed separation, and fail-closed
duplicate/restart handling; the current prototype does not enforce these.

## Validation

From the repository root:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-pq128-proof-size/salted-bcs-zk-audit/salted_bcs_zk_audit.py \
      --check --report

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-pq128-proof-size/salted-bcs-zk-audit/test_salted_bcs_zk_audit.py \
      -v

The first command prints `SALTED_BCS_ZK_AUDIT_PASS`; the second runs 18 tests.
The controls pin the real framing, bind the index, demonstrate deterministic
reuse linkage, find a forced toy truncated-hash collision, reproduce the
adaptive-row leak, reproduce selective failure, show exact padding
cancellation, and keep every authority gate closed.

## Primary sources and exact scope

- Eli Ben-Sasson, Alessandro Chiesa, and Nicholas Spooner, *Interactive Oracle
  Proofs*, ePrint 2016/116: <https://eprint.iacr.org/2016/116>. Section 3.2,
  Definition 3.3, and Lemma 3.4 give the `2*lambda`-salt classical Merkle
  privacy construction and bound. Remark 1.4 and Lemma 7.5 place its ZK result
  in the explicitly-programmable random-oracle model.
- Dominique Unruh, *Post-Quantum Security of Fiat-Shamir*, ePrint 2017/398:
  <https://eprint.iacr.org/2017/398>. Theorem 20 and Corollary 35 prove QROM ZK
  for Fiat--Shamir applied to a sigma protocol under HVZK, completeness, and
  unpredictable commitments, with the concrete fourth-root term shown above.
- Jelle Don, Serge Fehr, and Christian Majenz, *The Measure-and-Reprogram
  Technique 2.0: Multi-Round Fiat-Shamir and More*, ePrint 2020/282:
  <https://eprint.iacr.org/2020/282>. Corollary 13 is the multi-round
  measure-and-reprogram statement; Corollary 15 transfers soundness/PoK, not a
  complete ZK simulator for a salted IOP.
- Alex B. Grilo, Kathrin Hoevelmanns, Andreas Huelsing, and Christian Majenz,
  *Tight Adaptive Reprogramming in the QROM*, ePrint 2020/1361:
  <https://eprint.iacr.org/2020/1361>. Theorem 1 gives the exact
  entropy/query/reprogramming bound screened by the calculator. Its
  applications do not instantiate this Merkle/IOP transcript or SHAKE256.

## Final decision

Keep the 32-byte field in the byte model as the current candidate charge, but
do not label it sufficient. Production admission requires either:

1. a source-bound lazy Merkle/Fiat--Shamir QROM simulator whose exact `R`,
   `q_H`, conditional entropy, adaptive rank, abort, reuse, and SHAKE terms
   compose to at least 128 bits with this 32-byte salt; or
2. a larger salt and/or changed commitment transform justified by an explicit
   theorem and re-priced in every opening.

Until then: complete ZK `false`, strict PQ128 `false`, frontier eligibility
`false`.
