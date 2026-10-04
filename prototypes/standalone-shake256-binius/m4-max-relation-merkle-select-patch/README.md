# Maximum-M4 Merkle selector rewrite

Status: applied source-static optimization. The live full-production M4 source
hash is
`f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b`.
No Cargo build, circuit compile, prover, or proof measurement was run.

For each of the two depth-32 paths and seven digest words, the former circuit
expanded one position bit into an all-zero/all-one mask, formed a masked XOR
delta, and XORed that delta into both children. The applied form uses the same
MSB condition directly:

```text
left  = select(direction_msb, sibling, current)
right = current XOR sibling XOR left
```

The identity is exact for every 64-bit child word. `CircuitBuilder::select`
reads only the condition's MSB, which is exactly the bit that the former
arithmetic shift expanded. The second equation returns the unselected member
of the pair. It does not assume SHAKE collision resistance or trust a derived
host value.

The frozen patch applies to the prior live hash
`6a37ca5d2f2eb826c77c645b9dd7ab1f86ac2522acea86b9099b4ff24956988e`
and is followed by the one-hot and policy-dedup patches in the live source. The
checker reverses those later patches before reversing this one, pins all four
patches, the scalar/action/composed semantic boundary, and the upstream select,
shift, XOR, AND, CSE, and fusion implementations. It runs 52,608 deterministic
equivalence/permutation checks.

The conservative attempted-output accounting falls by 512 words:

```text
hidden-word upper        61,469 -> 60,957
active B128 upper                  30,479
guaranteed n15 tail                 2,289
margin over 1,060                    1,229
margin over 1,984                      305
```

This remains a syntactic upper, not compiled evidence. The selector rewrite is
not an existing CSE identity, but fusion and DCE can still change the realized
delta. Typecheck, compiled statistics, scalar/M4 differential execution,
complete ZK, strict PQ128/QROM, and exact proof bytes remain mandatory.

Run the allocation-free checker from the repository root:

```text
PYTHONDONTWRITEBYTECODE=1 python3 \
  prototypes/standalone-shake256-binius/m4-max-relation-merkle-select-patch/check_merkle_select_patch.py \
  --pretty
```
