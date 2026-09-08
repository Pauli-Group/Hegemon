# SMZ9 Rust source-refinement obligations

## Verdict and scope

The bounded source audit found **no concrete mismatch on the canonical accepted domain** between the inspected Rust public admission, packed evaluator, and typed source projection and their Lean counterparts. This is a source-review result, not a universal Rust execution proof. **The universal Rust refinement remains unproved.**

In particular, a theorem about `hgv8rp03ProgramComponents.AcceptsPacked` is not automatically a theorem about an invocation of the Rust verifier. A handwritten Lean function, an alias to `AcceptsPacked`, a source digest, matching vectors, or a record containing the desired semantic conclusion does not establish source extraction or execution refinement.

This document records the remaining implementation-ready obligations. It does not change Rust, run Lean or builds, claim proof-byte extraction, establish cryptographic security, or authorize a production route. The audit covered the source seams below, not every compiler transformation, platform, panic path, or caller in the repository.

The important separations are:

- Public admission depends only on the exact public words and the source-owned hash computation; it does not need a packed witness.
- Packed evaluator refinement concerns an arbitrary canonical 43,904-word assignment and all 64 nonlinear lanes, not just an honestly generated witness or lane zero.
- Typed decoder correspondence concerns the actual source projection, parser, and validation branches. Its total Lean projection deliberately has values on inputs that Rust rejects.
- Accepted proof bytes producing the required full assignment or polynomial evidence is a separate extraction/soundness obligation. `verify_packed_witness` and its relowering check do not provide that implication.

## Source snapshot and anchors

Reviewed on 2026-09-07 in the working tree whose `HEAD` was `4a0acb9be94ff15441855cbb9ea7051ca104998a`. This is not a claim that the reviewed working tree equals that commit; use the file hashes below to identify the actual snapshot. Line numbers refer to those bytes and must be refreshed if a source changes.

| Short name | Source and principal anchors |
| --- | --- |
| `frontend` | `circuits/transaction/src/smallwood_poseidon2_v8_frontend.rs`: source factory 190–217; candidate verification 1006–1051; relation/input matching 1116–1136; input admission 1151–1185 |
| `types` | `circuits/transaction/src/smallwood_poseidon2_v8_types.rs`: scalar helpers 213–282; public encoder/parser 286–450; action intent 479–496; public validation 506–623; typed parser 938–976; stable parser 1098–1177; witness validation 1403–1457 |
| `semantics` | `circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs`: numeric/symbolic arithmetic 147–171; CSR provenance 981–996; nonlinear interpreter call 1842–1858; specialization 2750–2827; typed decoding 3414–3911; relowering 3914–3927; packed evaluator 4120–4185; proof adapter evaluation 4251–4275 |
| `ir` | `circuits/transaction/src/smallwood_poseidon2_v8_ir.rs`: arena lifecycle 324–352; field operations 430–462; node/root interpretation 465–527 |
| `field` | `circuits/hegemon-field/src/lib.rs`: raw/canonical representation 80–130; reduction/multiplication 149–156; equality 192–195; addition 230–242; multiplication 264–276 |
| `poseidon` | `circuits/transaction-core/src/poseidon2_width16.rs`: 166 diagonal/round constants 44–248; layers/permutation 250–384; sponge 421–483 |
| `Program` | `formal/lean/Hegemon/Transaction/Poseidon2V8RelationProgram.lean`: expression canonicality 146–171; interpreter 305–385; packed acceptance 394–421 |
| `Spec` | `formal/lean/Hegemon/Transaction/Poseidon2V8SemanticSpecification.lean`: public encoding 202–220; asset/compatibility/slot predicates 269–362; sponge/action intent 392–472; `CanonicalPublicStatement` 1027–1054 |
| `Projection` | `formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticDecoder.lean`: packed reads, sponge source, note/selectors/position 29–58; inputs/outputs 60–79; modes/accumulators 82–108; stable/typed projection 110–124 |

SHA-256 observations, made with `shasum -a 256` and without rewriting inputs:

```text
1d5abc358b91e4985d292e8f8a185ff0dd7cb41de6c5085e3e276df3b57126f6  circuits/transaction/src/smallwood_poseidon2_v8_frontend.rs
fd1add668d9c1cb9413211b06fb0dfec3e281b7e9336ab46dddf4a31af32b95f  circuits/transaction/src/smallwood_poseidon2_v8_types.rs
608786dc9232c22612da6ce4e13bab4fdfe354be2065cdc08227a9ceff618454  circuits/transaction/src/smallwood_poseidon2_v8_ir.rs
873d95d94af7b2ff60b665f9f55ea8508a07334a8a3cdee2877fb79c0752ffcc  circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs
6058cb6f76eae3f5e6ab89405da433e0c28aef09dfc4f38d62c36d6d20cd7d1c  circuits/hegemon-field/src/lib.rs
7f298af6a9268d232b5723823d136c1cd68a5f702a25fad8316edcc3b8ff4daa  circuits/transaction-core/src/poseidon2_width16.rs
a4c9714d6a8d21b0ffe1e1539d838917fb505708f2c0fde4f30fb222ba0151a9  formal/lean/Hegemon/Transaction/Poseidon2V8RelationProgram.lean
71276753755e85cd38e21eead46b2066eaa2df02d0a02afa56b0d1b680fbc6b7  formal/lean/Hegemon/Transaction/Poseidon2V8SemanticSpecification.lean
ef2c59274b9a2eb2ab3522425214e92b4be0fd7ec138c6d111671303cd734786  formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticDecoder.lean
92a1a681ee35f8c7b8e24ddcf23319f7b7d3c97e79a26d2d944b19c290aff7e9  formal/lean/Hegemon/Transaction/Poseidon2Width16Kernel.lean
b8829047b09ba678ef62a358cb721d41855127152c69dee12d70f77a043eda4f  formal/lean/Hegemon/Transaction/Poseidon2V8PublicDecoder.lean
a8de8ec5a2b18de9c681eb66361e553949b2c35318625ac1ea028dc1359f2774  formal/lean/Hegemon/Transaction/Poseidon2V8DecoderRefinement.lean
5e3aaaada02dcdf143afc87ee7aaaad30b7d179b408ad6b8fc1ff21389f08b58  circuits/transaction-core/src/stablecoin_poseidon2_v8.rs
3f1ec13a129bdd3bba8d0e07d3198ff1e8c6fa4b2ecec5e517743427264a20e4  circuits/transaction-core/src/constants.rs
b68db4ee36d93bc4af209e8c26da92be7bc691d93bdc5bf3273df3e535d9ab47  protocol/versioning/src/lib.rs
```

These hashes identify reviewed files; equality of hashes is not a substitute for an operational correspondence theorem.

## Required theorem boundary

The signatures below are specifications for future theorems, **not existing declarations or proved results**. `Exec(f, args) = Ok(result)` must denote a verified operational semantics or source-extracted model of the actual pinned Rust entry point. `liftWords` is lossless `u64`-to-`Nat` conversion; `liftPublic` and `liftWitness` map arrays to lists, booleans to 0/1, matching enums to matching constructors, and `Felt` values to canonical residues. The stable part of `liftWitness` uses the exact 94-word typed serializer.

Before crediting any theorem, produce the source-to-model correctness artifact for the relevant Rust functions, including called field operations, fixed arrays, mutable vectors, indexing, casts, loops, and thread-local/initialization behavior. A reviewed handwritten model may be useful scaffolding, but naming it `Rust...` or defining it as a Lean predicate does not discharge this requirement. Source-level refinement also does not silently verify the Rust compiler or a deployed binary.

The three principal conclusions must have the following strength:

```text
PUBLIC:
  Exec(try_from_public_words, words) = Ok(rustStatement)
    implies encodePublicStatement(liftPublic rustStatement) = liftWords words
        and CanonicalPublicStatement exactV8SemanticPrimitives
              (liftPublic rustStatement).

PACKED:
  Exec(from_public_statement, rustStatement) = Ok(adapter)
  and Exec(adapter.verify_packed_witness, packed) = Ok(())
    implies hgv8rp03ProgramComponents.AcceptsPacked
              (liftWords adapter.public_values) (liftWords packed).

TYPED-CORRESPONDENCE:
  Exec(decode_smallwood_poseidon2_v8_packed_witness,
       (rustStatement, packed)) = Ok(rustWitness)
    implies liftWitness rustWitness =
              projectTypedWitness (liftPublic rustStatement) (liftWords packed).
```

The source-owned adapter provenance in `PACKED` is important: do not quantify over an arbitrary caller-provided CSR table. The `PUBLIC` conclusion cannot be supplied as a caller premise. Conversely, typed-decoder **success from accepted packed equations** requires proving every parser/validator guard from the independently proved semantic endpoint; it cannot assume Rust decoder success or canonical honest lowering.

After `PUBLIC`, the public frontend corollary is:

```text
Exec(verify_smallwood_poseidon2_v8_candidate, (input, proofBytes)) = Ok(())
  implies there exists statement,
      encodePublicStatement statement = liftWords input.public_values
    and CanonicalPublicStatement exactV8SemanticPrimitives statement
    and liftWords input.relation_balance_binding = exactV8ActionIntent statement.
```

This corollary intentionally does **not** assert existence of an accepted packed witness. That further implication needs the actual proof-verifier/extractor bridge.

## A. Arbitrary packed evaluator

### A1. Pin the executable program, not only its identity string

Relate the actual `OnceLock`-initialized nonlinear and CSR programs (`semantics:1842–1858`, `2741–2744`) to the exact generated Lean components, including node order, root order, every original attempted row, term coordinates, coefficient roots, targets, and family bookkeeping. The source-owned digest check and private `ProgramSpecializedCsr` constructor are useful provenance, not a proof of this full identity.

Prove the finite canonicality facts used by the interpreter: constants below the field modulus; public indices below 120; nonlinear witness rows below 686; all expression references strictly backward; root indices in range; bit indices below 64; CSR coefficient/target roots in range; and **all original CSR witness indices below 43,904, including indices whose coefficients later vanish or cancel**. Otherwise Rust may drop a term whose Lean `Option` lookup would fail. Existing Lean program-canonicality theorems apply to the Lean components; the source identity theorem must connect them to Rust.

### A2. Field and expression induction

For `p = 18446744069414584321`, prove the canonical-representative correspondence of `ir:430–462` with `Program.fieldAdd`, `fieldSub`, `fieldMul`, and `fieldInverse`.

- Rust constant/public/witness nodes return raw words (`ir:473–479`); Lean normalizes them (`Program:314–318`). The canonicality invariant is necessary to equate these operations, not optional cleanup.
- Addition and multiplication use `u128` intermediates. Canonical operands make the mathematical sum and product fit; subtraction's two branches equal `(left + p - right) mod p` and do not underflow.
- Inverse returns zero on zero. For nonzero input, prove the square-and-multiply loop equals exponentiation by `p - 2`, followed by reduction. Do not change its zero convention to a partial field inverse.
- Induct over the growing expression-value vector. Show every intermediate is canonical and each Rust append equals the corresponding Lean append; preserve every constructor, including `SelectEqual` and `Bit`.
- Under `bit < 64`, establish `(value >> bit) & 1 = (value / 2^bit) mod 2`. Backward-reference bounds justify Rust's direct indexing, where Lean instead uses `Option` reads.
- Relate root collection and its ordered zero checks to `ExpressionProgram.EvaluatesTo`/`Accepts`; a multiset or count agreement is insufficient.

### A3. Specialized CSR to every original attempted equation

`semantics:2750–2827` interprets the public-only expression program once, combines duplicate witness indices in a `BTreeMap` by modular addition, removes zero coefficients, sorts by index, drops empty zero-target rows, and materializes an empty nonzero-target row using `tail_source_index(120)` with coefficient one.

Prove, in order:

1. Public expression evaluation agrees with Lean and never reads witness rows.
2. Combining duplicates, deleting zero coefficients, and reordering preserve the field sum of every original attempted row. Address Lean's recursive right fold versus Rust's left-fold accumulator explicitly.
3. Finalized CSR offsets, indices, coefficients, and targets have exact bounds and canonicality; conversions to `u32` cannot fail or truncate on the pinned program.
4. A dropped empty zero-target row satisfies the original equation.
5. The fallback cell is independently zero under accepted finalized rows. `semantics:2382–2385` emits `stable.source_padding` for source slots 120–127. The Lean source-acceptance development identifies the corresponding zero equation at attempt 19,298, family 39, packed coordinate 41,528. Transport that fact through the source-program/specialization correspondence; do not assume fallback zero or original acceptance while proving it.
6. Therefore an emitted empty nonzero-target row cannot occur in an accepted assignment, and every original attempted equation follows from accepted finalized rows.

For the actual accumulation `acc + coefficient * witness` at `semantics:4142–4145`, each loop invariant has `acc < p`, `coefficient < p`, and `witness < p`. Thus the unreduced intermediate is at most `p(p - 1) < 2^128`; machine arithmetic agrees with the unbounded natural expression.

The numeric/symbolic wrappers at `semantics:147–171` consult thread-local arena state. Model the normal construction/interpretation lifecycle: `ir:324–352` rejects nested construction and removes the arena on completion. Establish that numeric specialization/decoding runs without an active symbolic arena. This is a required state invariant, not a concrete reentrancy bug established by this audit.

### A4. Complete lane coverage and the distinct proof-adapter seam

`verify_packed_witness` checks length/canonicality (`semantics:4124–4134`), finalized CSR (`4137–4151`), then all 64 lane views (`4153–4182`). Show `row * 64 + lane` equals Lean's `packedWitnessLaneRows` at every one of the 686 rows, is in bounds, and covers every required lane. Public canonicality comes from the source-owned constructor/public admission, not the packed witness check alone.

Its final typed decode/relowering (`4183–4185`) is an additional rejection condition. It need not be used to prove the forward evaluator implication `Ok -> AcceptsPacked`.

By contrast, the proof adapter's `compute_constraints_u64` (`4251–4275`) receives one row-scalar view, rejects auxiliary words and wrong shapes, computes residuals, and copies them into `out`. It does not receive or verify a full packed assignment. Prove this callback's exact interpreter correspondence separately. Neither callback success nor `verify_packed_witness` success supplies a proof-byte-to-full-codeword extraction theorem.

## B. Public parser and admission

### B1. Encode/decode equality without assuming canonical semantics

`types:357–450` checks exactly 120 canonical field words, parses booleans, validates the three-valued stable direction, checks `u32` conversions at public coordinates 60, 84, and 85, copies fixed slices, and validates the reconstructed statement.

First prove small representation lemmas: successful `parse_bool` is inverted by `u64::from`; direction parsing is inverted by `direction_word`; successful checked casts preserve the input value; fixed slice copies have the specified length and contents; and canonical input words survive `Felt::from_u64` followed by `as_canonical_u64`. The last fact follows from `field:115–130`; `from_u64` itself stores a raw `u64` rather than reducing it.

Then prove `encodePublicStatement (liftPublic s) = words` directly from `types:286–354` and `Spec:202–220`. Rust arrays establish the exact 2/2/7/6/4/3 field lengths. No semantic conclusion or `CanonicalPublicStatement` premise is needed for this layout proof.

The existing `Poseidon2V8PublicDecoder.decode_encode_of_exact_shape` (`formal/lean/Hegemon/Transaction/Poseidon2V8PublicDecoder.lean:135–157`) can then establish successful Lean layout decoding using those lengths. Its `decode_encode_of_canonical` theorem at 225–230 instead assumes the desired public predicate and must not be used to hide the missing admission proof. The Lean layout decoder at 39–79 intentionally checks only total length and stable direction; Rust's successful parser is much stronger than that bare decoder.

### B2. Discharge each structural validator family

The guards at `types:506–623` provide the following exact correspondence:

| Rust successful guard | Required Lean fact |
| --- | --- |
| Canonical 120 words, fixed arrays, parsed booleans | All flag/digest lengths, Boolean flags, canonical digest words, and canonical exact public encoding |
| Circuit/suite comparisons 509–514 | Version 8 and crypto suite 7 |
| Fee/value-balance checks 515–527 | Fee `< 2^61`; value-balance sign and magnitude both zero |
| Activity branches 530–547 | Inactive nullifiers zero; active nullifiers nonzero; inactive output commitments and ciphertext commitments both zero; active versions both nonzero |
| Duplicate check 548–550 | Distinct nullifiers when both inputs are active |
| Three-step asset loop 565–584 | Native asset first, canonical values, strictly ordered real assets, and an all-padding suffix |
| Compatibility checks 586–623 | Every disabled/mint/burn `CanonicalCompatibility` conjunct |
| Parent-height check 552–554 | Parent height `< 2^63` |
| Enabled action-intent check 555–559 | Stored action intent equals the independently specified action hash, after primitive refinement below |

Relevant boundary values agree: `MAX_IN_CIRCUIT_VALUE = 2^61 - 1` (`transaction-core/src/constants.rs:40`); stable value/scalar maxima are `2^56 - 1` and `2^63 - 1` (`transaction-core/src/stablecoin_poseidon2_v8.rs:16–20`); circuit/suite are 8/7 (`protocol/versioning/src/lib.rs:315`, `325`). The reserved balance padding is `u64::MAX mod p = 4294967294`, **not** `p - 1` (`constants.rs:20–22`, `Spec:45–53`). Pairwise ordering follows from the successful previous-real-asset loop plus the padded-suffix invariant, not from comparing the sentinel to all real assets.

Disabled compatibility is exactly zero and the stable object equals `disabled_at_context(parent_height, before_root)` (`types:591–601`; `stablecoin_poseidon2_v8.rs:246–255`). This keeps `beforeRoot = afterRoot`, permits the supplied bounded parent height/current root, and zeroes the remaining disabled data. Enabled compatibility requires matching asset/policy/magnitude/sign, non-native/nonpadding asset, magnitude `< 2^56`, exactly one public asset occurrence, all three reserved six-word commitments zero, and zero issuer authorization for burn. Checked `u32` parsing supplies the asset/policy bounds.

Enabled public after-counters are only field-canonical at this public-admission layer in **both** Rust and Lean. Do not infer the stronger stable transition range or lifecycle properties from public parsing alone; those belong to the private relation/transition proof.

### B3. Actual Goldilocks/Poseidon2 action hash

Prove that the canonical-residue interpretation of the actual `Goldilocks` implementation preserves zero, one, construction, equality, addition, multiplication, and assignment operations. Its raw representation accepts all `u64` values, while equality and arithmetic use canonical residues (`field:80–84`, `192–195`). One subtraction in `as_canonical_u64` suffices because every `u64` is below `2p`; successful public parsing additionally starts with words already below `p`.

Lift these lemmas through the exact S-box multiplication chain, `P4` chunk sums, strided `M4`, internal diagonal layer, external/internal rounds, and 31-step schedule (`poseidon:250–384`; `Poseidon2Width16Kernel.lean:157–236`). Bind the 16 diagonal and 150 round constants by an exact ordered-data certificate, not merely the parameter-set identifier or digest.

For action intent specifically, prove the exact 120-word projection: zero half-open ranges `4..18`, `47..54`, `87..94`, and `113..120`, preserving every other serialized word (`types:479–485`, `Spec:464–469`). The action domain is `0x4854_5838_494e_5400`; input length is 120. Discharge the Rust canonical-domain and maximum-input guards. The generic Lean sponge is total on longer inputs whereas Rust rejects inputs above 120; this is a necessary theorem-domain restriction, not an accepted-action mismatch.

Relate the Rust sponge loop to the Lean fold: 15 full rate-eight blocks; initial capacity lanes 8 = domain, 9 = 120, 10 = mode marker, and 15 = suite marker; add one only to capacity lane 11 before the final permutation; return lanes 0–6. There is no extra final permutation and no rate-lane padding marker. Any existing Lean full-rate composition helper may be reused only after the actual Rust permutation and loop correspondence have been established.

### B4. Frontend control-flow corollary

The public candidate function uses the source-owned factory (`frontend:1043–1051`), validates the input before construction (`1030–1038`), and reconstructs the relation from the same public words (`206–213`). `validate_verifier_input` successfully parses the statement at 1160–1167, recomputes action intent at 1168–1172, compares all seven binding limbs at 1173–1176, and equates enabled public intent with that binding at 1178–1184. Relation matching at 1120–1135 separately equates relation digest, public values, and binding with the leaf-owned input.

Transport these successful branches through the operational model to derive the `PUBLIC` and frontend conclusions above. No private witness or relowering premise belongs in this proof. The `SourceVerifierCanonicalReloweringOpening` record in `Poseidon2V8SemanticAdequacy.lean:296–311` already contains `canonicalPublic`; projecting that field at 317–323 is not this Rust public-admission theorem.

## C. Typed source decoder, parser, and validator

### C1. All 721 source words and branch operations

The actual decoder builds `252 + 252 + 23 + 23 + 77 + 94 = 721` words (`types:912–935`; `semantics:3796–3911`). Prove correspondence of each operation and its source coordinate, not just the count of descriptors:

- Sponge source words: block zero copies the initial rate lane; later blocks subtract the preceding final rate lane in the field (`semantics:3414–3423`; `Projection:31–37`). Establish all indices are in the 43,904-word input rectangle; Lean default reads must never stand in for Rust out-of-bounds access.
- Note permutation: hash order is value, asset, recipient, rho, randomness, authorization; typed order moves authorization before rho/randomness (`semantics:3775–3785`; `types:646–663`; `Projection:39–45`). Notes are decoded unconditionally, including inactive notes. Only the input spend key is activity-selected to zero at this stage (`3818–3823`). Prove inactive note zeroing from accepted equations, not by changing the decoder.
- Position: Rust checks 32 Boolean directions then combines `direction << bit` by bitwise OR (`3825–3834`); Lean sums `2^bit * direction` (`Projection:57–58`). Prove equality using Boolean, disjoint-bit, and shift-bound facts. Canonical field words alone do not suffice.
- Merkle siblings: 448 limbs use the same direction bits to choose right operand when direction is zero, left otherwise (`3836–3842`). Reuse the exact note call/depth schedule.
- Selectors: Rust's first matching nonpadding asset (`3426–3439`) equals Lean `findIdx?` and four selector bits (`Projection:47–52`), including inactive and no-match branches. Successful public asset validation/accepted note membership can then rule out invalid active no-match cases.
- Authorization: Rust accepts only `[1,0,0]`, `[0,1,0]`, or `[0,0,1]` (`3855–3869`). Lean's fallback maps malformed triples to single-key (`Projection:82–88`). Prove one-hotness before equating the selected modes. Current accumulator uses call 98; next uses call 101 only in approval mode, otherwise 23 zeros; signer tags use all 6 × 5 raw words (`3870–3881`).
- Stable words: 55 config words from calls 106–110, four before counters from call 113 lanes 7–10, 28 sibling limbs from calls `115 + 2*level`, and seven issuer-secret words from call 123 (`3884–3905`; `Projection:110–118`). For levels 0–3 prove Rust's successive bits of `asset_id & 15` equal Lean `(assetId / 2^level) mod 2`.

The source descriptor function at `semantics:3541–3770` and `Poseidon2V8DecoderRefinement.lean:150–197` are useful finite coverage material. Coverage, operation counts, a branch-space list, or the definition `reloweringComparedPackedWords := 43904` alone does not prove that the Rust decoder executes those operations or succeeds. Several existing finite descriptor results use `native_decide`; do not silently reclassify them as a new standard-axiom universal Rust proof.

### C2. Typed parser roundtrip and guard discharge

Prove the cursor operations, slice bounds, exact advancement, and exhaustion (`types:1000–1035`), then the fixed typed parser/serializer roundtrip (`938–976`). This includes input/output flags and selectors, six slot booleans per accumulator, and the three authorization mode words—not just field canonicality.

The stable parser (`1098–1177`) adds checked `u32` conversions for asset, policy version, collateral ratio, oracle price numerator/denominator, and collateral asset; checked `u8` collateral decimals; Boolean active/retirement/attestation fields; canonical Felt conversions; and absent retirement requiring a zero retirement value. Its typed serializer (`1038–1095`) must preserve those successful representations exactly. Prove these guards from the accepted semantic/range facts when establishing decoder success; do not infer them from 94 canonical field words alone.

Then connect the actual `validate_against_statement` branches (`1403–1457`) to their semantic obligations: activity agreement; fully zero inactive objects; active note bounds/nonpadding asset; nonzero/shared active spend keys; position bound; canonical siblings; selectors; authorization mode/accumulator/signer shape; and signed integer per-asset conservation. Prove machine checked-add/sub behavior agrees with the integer balance equations under the established bounds. Successful parsing is not itself a proof of note/nullifier/Merkle hash links or the stable state transition; this validator does not replace those separate semantic families.

For the forward `TYPED-CORRESPONDENCE` theorem, Rust success supplies its branch guards and successful parser roundtrip. For the converse accepted-program-to-Rust-decoder-success theorem, derive those guards from the unchanged independent semantic predicates and coordinate lemmas, then replay the actual source model. Keep the two directions distinct.

### C3. Relowering is an extra source check, not extraction

`semantics:3914–3927` decodes, rebuilds, and compares with `zip`. Prove both lengths, not just the comparison loop: the original input was checked as 43,904 words; `build_smallwood_poseidon2_v8_assignment` allocates exactly 686 rows of 64 words at 2990 and flattens them at 3396. With both lengths proved, no mismatch means equality of the complete arrays.

This can establish an additional property of a successful local source witness check. It does not prove that a proof accepted by the production SMZ9 verifier exposes such a witness, and it must not substitute for arbitrary `AcceptsPacked`-to-semantics reasoning. No completeness claim that every satisfying packed assignment equals honest lowering was established in this audit.

## Reproducible 166-constant observation

The audit performed the following read-only literal comparison from the repository root. It extracts only the diagonal and three ordered round-constant sections, not arbitrary hexadecimal values elsewhere in the files. It creates no artifact and runs no compiler or proof checker.

```sh
perl -0777 -e '
  my ($rfile, $lfile) = @ARGV;
  open my $rf, "<", $rfile or die $!;
  my $r = <$rf>;
  open my $lf, "<", $lfile or die $!;
  my $l = <$lf>;
  my ($rd) = $r =~ /pub const POSEIDON2_WIDTH16_INTERNAL_MATRIX_DIAG:.*?=\s*\[(.*?)\];/s;
  my ($rc) = $r =~ /pub const POSEIDON2_WIDTH16_ROUND_CONSTANTS:.*?Poseidon2Width16RoundConstants\s*\{(.*?)\n\s*\};/s;
  my ($ld) = $l =~ /def internalMatrixDiagonal.*?\n(.*?)\n\s*def externalRoundConstantsInitial/s;
  my ($lc) = $l =~ /def externalRoundConstantsInitial.*?\n(.*?)\n\s*theorem/s;
  die "section extraction failed\n"
    unless defined($rd) && defined($rc) && defined($ld) && defined($lc);
  my @r = map { lc } (($rd =~ /(0x[0-9a-f]+)/gi), ($rc =~ /(0x[0-9a-f]+)/gi));
  my @l = map { lc } (($ld =~ /(0x[0-9a-f]+)/gi), ($lc =~ /(0x[0-9a-f]+)/gi));
  print "Rust constants: ", scalar(@r), "; Lean constants: ", scalar(@l), "\n";
  die "count mismatch\n" unless @r == @l;
  my @bad = grep { $r[$_] ne $l[$_] } 0..$#r;
  print "Ordered literal mismatches: ", scalar(@bad), "\n";
  for my $i (@bad) { print "$i $r[$i] $l[$i]\n"; }
' circuits/transaction-core/src/poseidon2_width16.rs \
  formal/lean/Hegemon/Transaction/Poseidon2Width16Kernel.lean
```

Observed output:

```text
Rust constants: 166; Lean constants: 166
Ordered literal mismatches: 0
```

The 166 entries are 16 diagonal values plus `4*16 + 22 + 4*16 = 150` round constants. This command is an observation, not a fail-closed gate: promote it only with explicit expected counts, mismatch failure, checked section parsing, and a source-to-model data certificate. The observation says nothing by itself about arithmetic correctness, loop order, machine execution, or cryptographic security.

## Completion criteria and remaining authority

The next implementation should retain separate reviewable artifacts for source/model identity, the expression interpreter, CSR normalization including fallback zero, all-lane packing, Goldilocks/Poseidon2 execution, public admission, and all typed decoding operations/guards. Prove the stated implications over arbitrary inputs in their declared domains; do not add their final conclusions as assumptions. Audit the actual theorem dependency boundary and preserve the existing independent semantic definitions.

Evidence to retain includes exact source/program pins; coordinate/constant certificates; range and machine-overflow lemmas; the operational-model correspondence; universal theorem statements and axiom reports; and negative checks for malformed references, noncanonical words, canceled/out-of-range CSR terms, wrong packing lanes, nonboolean directions, invalid one-hot modes, wrong public slices, and mismatched sponge framing. Run checks only under the coordinator's separately allocated resources; none were run for this document task.

At handoff this document records **no concrete accepted-domain mismatch found and no universal Rust proof completed**. Existing Lean source-equation and semantic results remain valuable but conditional on their stated premises. Proof-byte extraction, verifier chronology, polynomial/codeword binding, cryptographic assumptions, the unchanged self-contained carrier lifecycle, and production authorization remain independently required.
