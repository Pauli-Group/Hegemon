# E256 parallel-product contract

Status: conditional theorem, executable counterexamples, and byte calculator.
The strict frontier remains empty. This directory does not implement a PCS,
FRI, Fiat--Shamir compiler, QROM reduction, zero-knowledge simulator, parser,
or production verifier.

## Verdict

Two complete 132-bit branch errors do multiply to 264 classical bits over one
immutable B128 commitment, but only under a history-conditional soundness
premise that the current source does not establish. The one-root/two-label
plumbing is necessary and insufficient. In particular, domain-separated
SHAKE256 calls do not prove that the prover cannot grind commitments, correlate
post-challenge messages, reuse proximity queries, or drive branch two into a
history on which its error is larger.

The rate-`1/16`, `q=44` and rate-`1/32`, `q=33` rows therefore remain
conditional byte screens. They are not strict proof-size points.

## Exact information-theoretic theorem

Fix a false statement, a canonically parsed immutable oracle commitment `C`,
the complete prover state chosen before verifier randomness, and all profile
parameters in a sigma-algebra `F0`. Let `E1` be the event that branch one
accepts. Let `F1` contain the full first-branch history, including every
cross-branch message, abort choice, and residual prover state chosen before
branch two's fresh verifier coins. Let `E2` be branch-two acceptance. If

    Pr[E1 | F0] <= epsilon1

and, for every positive-probability reachable `F1` history on `E1`,

    Pr[E2 | F1] <= epsilon2,

then

    Pr[E1 and E2 | F0]
      = E[1_E1 * Pr(E2 | F1) | F0]
      <= epsilon2 * Pr[E1 | F0]
      <= epsilon1 * epsilon2.

Setting both complete conditional errors to `2^-132` gives exactly `2^-264`.
The word complete matters: each `epsilon_i` must already include every
sumcheck, folding, FRI/proximity, opening, abort, and branch-local parser event.
A `q` chosen to make only the leading proximity term 132 bits is not such a
certificate.

A stricter parallel corollary is available. Condition on the full prechallenge
prover state `S`. If the verifier coins `R_A` and `R_B` are independent, branch
`A`'s accept predicate depends only on `(S,R_A)`, branch `B`'s only on
`(S,R_B)`, and each conditional acceptance probability is pointwise bounded,
then the two events are independent conditional on `S` and the same product
follows. If a response depends on both challenges, this corollary does not
apply. The more general filtration theorem applies only if branch two retains
its bound after the resulting full history and receives genuinely fresh hidden
coins.

The shared commitment is compatible with the proof because it is inside the
conditioning state. It is not sufficient. Binding must make the same B128
oracle immutable, and each branch must soundly check the same complete invalid
relation. Splitting constraint families between branches gives an oracle that
violates only one family a single detection chance, not two.

## Required transcript order

The ideal interactive experiment must obey the following order.

1. The prover sends the canonical statement, exact profile identity, one B128
   oracle root, and all branch commitment messages required before the first
   challenge. The parser freezes their counts, byte lengths, order, and root.
2. At every later challenge boundary, both branches' preceding commitments are
   fixed before either corresponding challenge. A message that depends on the
   other branch's prior challenge is forbidden unless the conditional theorem
   explicitly quantifies over it.
3. Every verifier coin is branch-independent. This includes E256 algebraic
   samples, FRI coins, query indices, rejection-sampling retries, and abort
   coins. Independent algebraic samples with one shared query schedule do not
   qualify.
4. The verifier authenticates the complete `2q` query union against the one
   root and checks the entire relation in both branches.

For the noninteractive candidate, use disjoint, length-framed SHAKE256-512
challenge domains. A concrete shape is

    common = "HEG-E256-PRODUCT-v1\0"
             || frame(profile)
             || frame(statement)
             || frame(shared_root)
             || frame(all_prechallenge_commitments)

    seed_i_j = SHAKE256(common
                        || frame(branch_label_i)
                        || frame(round_j)
                        || frame(branch_local_prefix_i_j), 64 bytes)

where `branch_label_i` is exactly `branch-A` or `branch-B`, every frame contains
a distinct one-byte tag and an eight-byte little-endian payload length, and the
E256 sample is a specified 32-byte projection of the 64-byte seed. Query
schedules require separate labels and canonical rejection sampling; they may
not use the current `Shared` mode. This grammar is a requirement, not current
implementation evidence.

The source audit finds two incompatible research grammars that still need one
canonical realization: `strict-e256x2-iop` uses a 64-byte SHAKE256-512 Merkle
root and draws each E256 challenge directly from 32 XOF bytes, while the older
random-padding screen prices a 56-byte SHAKE256-448 root. The latter is retained
only as a named non-strict negative control. The conditional strict rows below
charge 64 bytes for every root and frontier node. No current production parser
implements that compact grammar.

## Why Fiat--Shamir does not inherit the theorem for free

For fixed distinct random-oracle inputs, branch-prefixed outputs are independent
random variables in the ideal ROM. A Fiat--Shamir prover chooses those inputs.
It can query many candidate roots, inspect both branch outputs, and select a
favorable root. The finite checker gives exact success `7/16` for two candidate
roots even though each fixed root succeeds with probability `1/4`.

In the QROM, a prover may query superpositions spanning both prefixes. A proof
must convert such a prover into one for the underlying interactive protocol and
price the number of adaptive reprogrammings, rounds, oracle queries, aborts,
and additive failures. Don, Fehr, and Majenz prove a multi-round
measure-and-reprogram result with a multiplicative loss that grows as
`O(q_H^(2n))` for a `(2n+1)`-round public-coin proof. That result shows what a
real compiler theorem looks like; it is not automatically instantiated by two
labels in this codebase. The exact Hegemon protocol, round-by-round or special
soundness premise, transcript inputs, and concrete `q_H` ledger are absent.

The existing Hegemon scaffold's `264 -> 132` square-root conversion is retained
only as an engineering screen. Grover intuition is not a multi-round
Fiat--Shamir/QROM reduction. If a future reviewed theorem gives an effective
132-bit product term, only four bits remain before PQ128. Shared failures add:

    Adv <= 2^-264
           + delta_binding
           + delta_hash
           + delta_parser
           + delta_FS/QROM
           + sum(delta_other).

They do not square merely because there are two E256 branches. Sixteen equal
132-bit terms union to exactly 128 bits; seventeen fall to about 127.913 bits.
The calculator reports no composed bound because the external failure ledger
and QROM theorem do not exist.

## Executable counterexamples

`parallel_product.py` exhausts small finite games rather than relying on labels:

- fixed oracle plus independent branch-local queries reaches the exact product
  `1/4` from two `1/2` errors;
- a shared query schedule leaves the joint miss probability at `1/2`;
- an adaptive cross-branch selector over independent challenge bits gives both
  marginals `1/2` and joint acceptance `1/2`;
- average-only soundness over shared prover state gives `1/2`, not `1/4`;
- two post-hash candidate roots raise success from `1/4` to `7/16`; and
- splitting the invalid relation gives the violated family only one detection
  chance.

Exhaustion over every branch-local Boolean accept set with error at most `1/2`
finds maximum joint error `1/4`. Allowing arbitrary joint predicates while
keeping both marginals at most `1/2` raises that maximum to `1/2`.

## Byte implications

The calculator independently derives the four-symbol salted-leaf formula with
strict SHAKE256-512 commitments. Query indices cost zero bytes, the complete
worst-case `2q` union is opened, each branch carries `5q+2` E256 elements, and
the separate 1,920-byte local char-2 plus 128-byte fused-ring-switch floors are
charged.

The first table keeps the candidate's 32-byte salt only as an unproved
sensitivity row:

| rate | q per branch | actual leading bits per branch | raw bytes | envelope bytes | raw headroom | tree storage |
|---|---:|---:|---:|---:|---:|---:|
| 1/16 | 44 | 134.015 | 83,712 | 83,724 | 40,356 | 20,971,456 |
| 1/32 | 33 | 132.750 | 69,632 | 69,644 | 54,436 | 41,942,976 |

The direct classical BCS Lemma 3.4 parameter screen at `2^18` leaves requires
at least 1,184 salt bits, or 148 bytes, to make its stated statistical term
reach 128 bits. Repricing that salt while retaining strict 64-byte commitment
nodes gives:

| rate | q per branch | salt per opened leaf | raw bytes | envelope bytes | raw headroom | tree storage |
|---|---:|---:|---:|---:|---:|---:|
| 1/16 | 44 | 148 | 93,920 | 93,932 | 30,148 | 36,175,808 |
| 1/32 | 33 | 148 | 77,288 | 77,300 | 46,780 | 72,351,680 |

The 148-byte row is not a QROM theorem and does not by itself reconcile the
paper's single `lambda` parameter with a 512-bit digest; it is a direct-theorem
salt-cost screen. The 32-byte salt has no complete adaptive BCS/QROM simulator.
The previous 63,320-byte rate-`1/32` number used 56-byte SHAKE256-448
commitments and is explicitly rejected as non-strict.

These counts are model rows, not canonical proof artifacts. The query formula
is still an optimistic leading term rather than a proved FRI/proximity bound.
Neither row has a complete per-branch 132-bit certificate, the product theorem
is uninstantiated, and the rate-`1/32` row is still short 960 random B128
symbols at the conservative maximum active-prefix endpoint.

## Source boundary

The checker pins and rehashes the stable inputs:

- `prototypes/standalone-shake256-binius/strict-e256x2-iop/src/lib.rs` implements
  the genuine E256 arithmetic, two labels, shared/independent query modes, and
  one root. Its own documentation says it proves no product theorem.
- `prototypes/standalone-shake256-binius/strict-e256x2-iop/security-manifest.json`
  leaves dual-stream conditional independence, product soundness, and QROM
  composition false.
- `.agent/hardening/binius-pq128-proof-size/strict_pq_profile.py` supplies the
  fail-closed square-root and union-bound scaffold, not a reduction.

The evolving random-padding source and the salted-BCS audit are hashed and
reported as explicitly unpinned research inputs. Their current bytes are not
frozen because they are active concurrent research artifacts. The calculator
derives the corrected 64-byte formulas locally and rejects the old 56-byte
numbers regardless of those moving source hashes.

Primary literature used to calibrate the claim boundary:

- Eli Ben-Sasson, Alessandro Chiesa, and Nicholas Spooner, [Interactive Oracle
  Proofs](https://eprint.iacr.org/2016/116). Section 3.2 and Lemma 3.4 are the
  source of the direct classical Merkle-privacy salt screen; they do not prove
  the QROM row.
- Jelle Don, Serge Fehr, and Christian Majenz, [The Measure-and-Reprogram
  Technique 2.0: Multi-Round Fiat-Shamir and More](https://eprint.iacr.org/2020/282).
- Alex B. Grilo, Kathrin Hoevelmanns, Andreas Huelsing, and Christian Majenz,
  [Tight Adaptive Reprogramming in the
  QROM](https://eprint.iacr.org/2020/1361). Its entropy/query bound needs an
  exact programmed-point distribution that this PCS has not supplied.
- Alexander R. Block, Albert Garreta, Pratyush Mishra, and Michal
  Nitulescu, [On Soundness Notions for Interactive Oracle
  Proofs](https://eprint.iacr.org/2023/1256).
- Mihir Bellare, Russell Impagliazzo, and Moni Naor, [Does Parallel Repetition
  Lower the Error in Computationally Sound
  Protocols?](https://www.wisdom.weizmann.ac.il/~naor/PAPERS/bin.pdf).
- Alessandro Chiesa, Ziyi Guan, and Burcu Yildiz, [On Parallel Repetition of
  PCPs](https://eprint.iacr.org/2023/1714).

The measure-and-reprogram and IOP-soundness papers identify the kind of
round-by-round and QROM compiler theorem needed. The repetition papers are
guardrails against inferring hardness amplification from repetition syntax
alone. None is cited as a theorem already instantiated by Hegemon.

## Validation

From the repository root, run:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-pq128-proof-size/e256-parallel-product/parallel_product.py \
      --check --report

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-pq128-proof-size/e256-parallel-product/test_parallel_product.py \
      -v

The first command must print `E256_PARALLEL_PRODUCT_CHECK_PASS`. The second
currently runs 22 dependency-free tests. Neither command allocates a codeword,
invokes Cargo, or writes a proof artifact.
