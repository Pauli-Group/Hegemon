# Strict mixed-field PCS screen

This directory freezes the first exact byte and theorem screen for a strict
standalone Hegemon PCS at relation size `2^15`. It is deliberately a
fail-closed lower-bound model, not a proof-system implementation or frontier
candidate.

The executable charges canonical SHAKE256-512 Merkle multiproofs, B128 leaf
values, true E384 or paired E256 wire values, and the published TensorSwitch
first-level field-message floor. It also records the missing security gates:
mixed-field extraction, characteristic-two ZK ring switching, parallel RBR
extraction for two E256 repetitions, complete ZK, and composed QROM security.

Run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 strict_mixed_pcs_screen.py --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_strict_mixed_pcs_screen.py
```

The corrected one-symbol-leaf screen puts the rate-`1/8` TensorSwitch first level at
`146,656` raw bytes. Exhaustive power-of-two leaf packing improves the exact
lower bound: four B128 symbols per leaf minimizes the worst-case wire at
`136,496` bytes and reduces the tree from roughly 160 MiB to 64 MiB. That is
still 12,428 bytes over the `124,068` raw cap before recursion, masking, salts, or
ZK, and a ZK compiler must hide all four revealed symbols per queried group.
Charging Diamond/BCS's required 32-byte salt for every opened leaf raises this
first-level floor to `140,560` bytes and the stored tree to about 80 MiB.
Lower rates reduce wire only by increasing the encoded tree to hundreds of MiB
or GiB, and they still fail the theorem gate. E256 x 2 is retained only as the closest research seam:
degree two matches the power-of-two ring-switch requirement, but the required
parallel extraction and ZK theorems do not yet exist. With the same four-symbol
leaf packing and a single strict shared proximity schedule, its screened first
level is `114,304` bytes at rate `1/16` and `97,216` bytes at rate `1/32`.
Per-opened-leaf BCS salts raise them to `117,088` and `99,328` bytes, leaving
`6,980` and `24,740` bytes respectively for every later round, ZK message,
and frame; they are architecture budgets, not proof
sizes or security evidence.

The older 56-byte SHAKE256-448 rows were a profile error: that width belongs to
semantic relation digests, while proof commitments and Fiat--Shamir use
SHAKE256-512. They are not strict results and are no longer emitted by this
screen.
