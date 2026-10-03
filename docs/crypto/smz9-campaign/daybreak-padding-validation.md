# Daybreak validation: HGV8RP03 final-block sponge padding

Date: 2026-09-07
Scope: historical local defensive validation against the superseded pre-repair HGV8RP03 program;
no proof generation, network execution, or production-authority claim.

## Historical artifact status

Every counterexample value, digest, command, and acceptance count below applies to the
852,305-byte pre-repair artifact with SHA-512
`8477896dc765c3776fefc93bb74fb0c7668a677abdc60697b0c216bc9b4363e46a8b7cadc557dba4a1e4ccdfe572e5b2833879dd465079b12b6044a51a5612c3`.
That artifact formerly occupied the canonical path
`testdata/formal_core_vectors/poseidon2_v8_relation_program.bin`; it is preserved here as
historical defect evidence and does not describe the current successor relation.

## Historical assessment

The suspected padding mismatch is **validated at the raw pinned-relation boundary**.
`bind_sponge` treats both an in-range private `None` source and an out-of-range source as an
unbound rate lane on every non-first block. For the 18-word output-note sponge, call 75 is the
third and final block: lanes 0 and 1 absorb words 16 and 17, while lanes 2 through 7 are
out-of-range padding lanes. The exact typed sponge leaves those lanes unchanged from call 74,
but HGV8RP03 emits no chaining equation for them.

A one-active-output, zero-value synthetic fixture demonstrates the mismatch without changing
the decoded typed note. Changing only call 75 initial lane 2 from the honest chained value
`7108444980566443614` to `7108444980566443615`, then recomputing the call trace, the public note
commitment, and the dependent action-intent calls 79 through 93, satisfies every raw predicate in
the pinned 852,305-byte program. The public commitment changes from

```text
[1304616816402909845, 5271022208387270245, 4627469860910654867,
 16524964466526191584, 10221701269769215826, 1009918371105773459,
 5208962243992354420]
```

to

```text
[17751802988045145084, 12180955044989797322, 15912287762348533326,
 7613337792310322050, 10620598151151873051, 16686142365350090278,
 6197469576421591197]
```

The extracted witness still decodes exactly as one active output with value `0`, native asset
`0`, zero recipient/authorization/rho/randomness words, native balance selector true, no inputs,
and fee `0`. A nonzero synthetic ciphertext commitment `[1,2,3,4,5,6]` makes the public output
slot structurally active; no ciphertext bytes or native carrier admission are exercised.

The normal verifier-owned adapter does **not** accept this as an honest typed lowering. After
all raw CSR and nonlinear checks succeed, `verify_packed_witness` returns
`NonCanonicalTypedLowering { index: 29899 }`. Therefore this is a concrete raw-relation
counterexample and a typed-semantic completeness/refinement failure, not an accepted honest
compiler output.

## Validation rubric

- [x] Cached encoder bytes equal the pinned relation artifact byte for byte.
- [x] The fixture has one active native output and a valid ordinary typed note commitment.
- [x] The mutation preserves the decoded 721-word typed witness.
- [x] An independent artifact interpreter accepts all raw CSR and nonlinear predicates.
- [x] The honest typed-lowering guard rejects the mutated assignment.

## Exact predicates accepted by the superseded artifact

The independent interpreter parsed
`testdata/formal_core_vectors/poseidon2_v8_relation_program.bin` directly and evaluated:

- 120 canonical public words and 43,904 canonical packed witness words;
- all 20,569 encoded CSR attempts: zero failures;
- all 830 encoded nonlinear roots in each of 64 packed lanes, 53,120 evaluations: zero failures.

Thus the raw pinned program accepts the assignment under its encoded CSR and nonlinear
identities. The higher-level adapter subsequently rejects only at canonical typed-lowering
comparison.

The false extracted semantic property is:

```text
For an 18-word sponge, final-block out-of-range rate lane 2 is unchanged:
initial_state(call 75, lane 2) = final_state(call 74, lane 2).
```

The counterexample has `7108444980566443615 != 7108444980566443614` while all raw encoded
predicates remain zero. The same source condition applies to final-block lanes 2 through 7; this
probe changes only lane 2.

## Reproduction

Scratch artifacts are under `/private/tmp/daybreak-padding-validation.7yzfO5` (3.6 MiB):
`probe.rs`, `check_artifact.py`, `public.bin`, and `mutated.bin`. The probe links the pre-existing
cached transaction library; it performs no Cargo build.

```sh
rustc --edition=2021 /private/tmp/daybreak-padding-validation.7yzfO5/probe.rs \
  --extern transaction_circuit=target/debug/deps/libtransaction_circuit-ba878d439cf61b67.rlib \
  -L dependency=target/debug/deps \
  -o /private/tmp/daybreak-padding-validation.7yzfO5/probe
/private/tmp/daybreak-padding-validation.7yzfO5/probe
python3 /private/tmp/daybreak-padding-validation.7yzfO5/check_artifact.py
```

SHA-512 evidence:

```text
8477896dc765c3776fefc93bb74fb0c7668a677abdc60697b0c216bc9b4363e46a8b7cadc557dba4a1e4ccdfe572e5b2833879dd465079b12b6044a51a5612c3  poseidon2_v8_relation_program.bin
ca63a4d991faa7b50e4e3d9178642ca73b80153bf0e9a3a044770dd86d00a718fa82d9f0058d391ba6711404d7eba5abbd5a8b7930ce2eaf4495d43dfa602666  public.bin
9be39d6330f4412584e263c89a05ca57268b53a674ea1d928786444803d960688944f791aa4920625790159d49a663efc852b0475f64036711c63109498060af  mutated.bin
e21b5dcdb8771f4ad0c8f9c84a3158c3c8803dab43689e7c0bc041b3069a3edc8768912bcbee33187db111d8317e1a2b747827960d1e53f432d76786e191b4fc  probe.rs
90675474a2141175154ac0298b190c22639a43eefeb5cc1d051025e04c82b021f2046737c853ae53072a58fdd0fd6df44e53e82efbd6fbc7a2542c3c12e0563c  check_artifact.py
```

## Repair disposition

The current successor program is 853,429 bytes with SHA-512
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.
It adds 36 canonical padding constraints: eight first-block singleton-zero equations and 28
later-block chaining equations. The raw output-note tail-lane mutation used by this historical
counterexample is now rejected by the relation regression rather than surviving until canonical
typed relowering. This repair and its regenerated identity grant no production authority;
production remains fail-closed.

## Historical boundaries and remaining proof gap

This historical validation does not construct or verify an SMZ9 proof, pass the contextual inline-ciphertext
carrier checks, show inflation, establish attacker reachability through an activated route, or
demonstrate a production exploit. The pre-repair HGV8RP03 artifact was unselected and
nonauthorizing. It shows that its raw relation acceptance did not imply the exact typed sponge
semantics then specified in Lean; the separate honest-lowering comparison was material to
rejection.
