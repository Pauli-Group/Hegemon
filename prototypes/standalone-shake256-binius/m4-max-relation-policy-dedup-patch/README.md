# Maximum-M4 policy-opening deduplication

Status: applied source optimization. It targets the one-hot mux source at SHA-256
`5f8f12b418a9e67aa3ee977ae51fba55e773f7b4ee8ed23f26375ab13e9cf976`
and the live patched source is
`f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b`.
The patch SHA-256 is
`c8f2b088f170b6cc4238f1a9ff0593e06b0ed2535e56d7fc8698b8685629f7c9`.

The old relation separately rebuilds and validates current and next policy
structure. The refactor constructs one raw selected opening
`S = init ? next : current`, derives its numeric threshold, signer count, and
six prefix slot predicates once, and shares them across the policy hash,
structure checks, final threshold, and approval membership. Current and next
approval state remain distinct and are both checked.

This is exact on every accepted mode because the unchanged relation supplies
the following premises:

- Single forces current, next, and all signer tags to zero.
- Init forces current to zero and selects next.
- Approval equates current/next policy root, intent, threshold, and signer
  count, while selecting current.
- Lock and Final force next to zero and select current.

The two approval-state checks can therefore be unconditional against
`S.signer_count`: the inactive lane is canonical zero, and both active lanes
have the selected signer count. Unconditional approved-bit boolean checks and
addition carry checks are retained. Tag uniqueness needs only the later slot's
activity because active signer slots form a prefix.

Pinned CSE/DCE/fusion accounting predicts:

```text
nonlinear constraints in changed slice       419 -> 258  (-161)
hidden words in changed slice                 333 -> 210  (-123)
one-hot stack hidden-word upper            60,911 -> 60,788
active B128 symbol upper                               30,394
guaranteed n15 random-tail lower                        2,374
full 1,984-symbol margin                                  390
conditional 1,060-symbol margin                          1,314
```

These are source-static compiler predictions, not compiled statistics. The
checker pins the active scalar/action/composed relation boundary and the
upstream builder, gate, CSE, DCE, fusion, and byte-swap sources; reverses and
reapplies the patch only in a unique temporary copy; checks both source hashes;
and runs 131,862 deterministic relation and invariant checks.

Run from the repository root:

```text
PYTHONDONTWRITEBYTECODE=1 python3 \
  prototypes/standalone-shake256-binius/m4-max-relation-policy-dedup-patch/check_policy_dedup_patch.py \
  --pretty
```

No Cargo command, circuit build, prover, or encoded-oracle allocation was run.
At packaging, free disk was about 23.01 GiB, below the 28 GiB heavy-run gate.
The patch is not a formal proof, measured proof-byte improvement, strict
PQ128/QROM result, or frontier point. Typechecking, exact compiled statistics,
scalar/M4 differential vectors, and a proof-size measurement remain mandatory
after the disk gate opens.
