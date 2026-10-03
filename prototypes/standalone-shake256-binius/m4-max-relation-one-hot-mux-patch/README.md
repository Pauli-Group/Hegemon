# Maximum-M4 one-hot SHAKE mux rewrite

Status: applied source optimization. The patch is based on maximum-production
M4 source SHA-256
`56301203b5d6d8cd99b1941778fe95887c65cc92957a73ae0413a8565b1f6b9b`
and produces stage hash
`5f8f12b418a9e67aa3ee977ae51fba55e773f7b4ee8ed23f26375ab13e9cf976`.
The following policy-dedup patch makes the current live source
`f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b`.
No Cargo command, circuit build, prover, or encoded-oracle allocation was run.

The two authorization SHAKE slots currently select padded blocks by folding an
explicit candidate for every one of the five auth modes. The circuit already
rejects `mode > 4`, so the five equality flags form an exact one-hot partition
on every accepted row. The patch uses the all-zero dummy frame as the default,
combines Approval and Final where both select the current accumulator, and
keeps only mutually exclusive nondefault overrides. It orders the short
value-lock frame first so identical zero/default words fold before either
181-byte accumulator frame changes the running selection. It also replaces the
four-way `non_single` union with the complement of the exact `mode == 0` test.

For accepted modes the selected padded words are byte-identical:

| Mode | Slot A | Slot B |
|---:|---|---|
| 0 Single | dummy | dummy |
| 1 Init | next accumulator | dummy |
| 2 Approval | current accumulator | next accumulator |
| 3 Lock | value lock | dummy |
| 4 Final | current accumulator | value lock |

The source-static, pinned-compiler accounting is:

```text
attempted Select calls                    272 -> 170
Select gates after identical-arm folding 148 -> 105
immediate nonlinear gate cut                      47
new linear BNOT output                              1
net emitted-output cut                             46
CSE-aware nonlinear constraint cut                 46
conservative hidden-word upper          60,957 -> 60,911
active B128 symbol upper                            30,456
guaranteed n15 tail lower                            2,312
full 1,984-symbol margin                               328
```

The checker first reverses the later policy patch, then reverses and reapplies
this patch only in a unique temporary copy. It verifies every stage hash, pins
the scalar/action/composed boundary and the upstream builder, Select/BOR/BXOR,
CSE/DCE/fusion, and Keccak sources, exhausts all five accepted modes, and runs
5,120 deterministic random absorption-word comparisons.

Run it from the repository root:

```text
PYTHONDONTWRITEBYTECODE=1 python3 \
  prototypes/standalone-shake256-binius/m4-max-relation-one-hot-mux-patch/check_one_hot_mux_patch.py \
  --pretty
```

This is not a compiled constraint count, measured proof-byte reduction,
complete-ZK result, strict PQ128/QROM result, or frontier point. Typecheck,
compiled statistics, scalar/M4 differential vectors, and exact proof bytes
remain mandatory after the disk admission gate opens.
