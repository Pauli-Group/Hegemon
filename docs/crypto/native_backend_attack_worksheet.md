# Native Backend Attack Worksheet

This worksheet is the concrete attack ledger for the active native backend family. Each line names the break class, the assumption or claim it targets, how the repo should exercise it, and what would count as a real failure.

## Active Target

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v4"`
- `spec_digest = 08eae1920eaf6e3cc1a8f9a149885221aed8172a5d33ae21a264d239b4b2cf88`

## Break Classes

### 1. Mixed-manifest or mixed-spec acceptance

- Targeted claim:
  - `serialization.canonical_native_artifact_bytes`
- What to exercise:
  - mutate `parameter_fingerprint`
  - mutate `spec_digest`
  - mix artifacts from distinct manifest labels
- Break condition:
  - verifier accepts an artifact whose manifest-owned identity does not match the active backend params

### 2. Transcript aliasing

- Targeted claims:
  - `random_oracle.blake3_fiat_shamir`
  - `fs.quint_goldilocks_negacyclic_fold_challenges`
- What to exercise:
  - distinct fold inputs producing identical transcript bytes
  - domain-separation collisions across leaf/fold/opening subtranscripts
  - width/length ambiguities in encoded transcript material
- Break condition:
  - two distinct proof states derive the same challenge stream under accepted encodings

### 3. Opening-seed canonicality failures

- Targeted claim:
  - `commitment.deterministic_public_witness_reconstruction`
- What to exercise:
  - mutate serialized STARK public inputs without changing the public tx view
  - mutate the public tx view without changing serialized STARK public inputs
  - mutate commitment rows or commitment digest while preserving the rest of the artifact
- Break condition:
  - verifier accepts an artifact whose deterministic public-witness reconstruction does not match the committed rows or digest

### 4. Commitment opening mismatch acceptance

- Targeted claim:
  - `commitment.bounded_message_random_matrix_union_bound`
- What to exercise:
  - wrong witness reconstruction, same digest
  - wrong rows, same digest
  - mixed params with same shape
- Break condition:
  - verifier accepts a commitment that does not reconstruct the committed witness under the configured params

### 5. Fold-row forgery

- Targeted claims:
  - `fs.quint_goldilocks_negacyclic_fold_challenges`
  - `commitment.bounded_message_random_matrix_union_bound`
- What to exercise:
  - mutated parent rows
  - swapped left/right child commitments
  - mutated fold challenge vector
  - invalid negacyclic mix rows
- Break condition:
  - verifier accepts a fold proof whose parent rows are not the challenge-mixed children

### 6. Overclaim acceptance

- Targeted claim:
  - repository claim discipline itself
- What to exercise:
  - parameter sets with `claimed_security_bits > soundness_floor_bits`
  - unsupported commitment labels
  - unsupported challenge schedules
- Break condition:
  - setup succeeds even though the code-derived floor is below the requested claim

### 7. Parser and length-bound failures

- Targeted claim:
  - `serialization.canonical_native_artifact_bytes`
- What to exercise:
  - truncated artifacts
  - oversized artifacts
  - malformed vector lengths
  - mixed version/spec/length fields
- Break condition:
  - parser panics, allocates absurdly, or accepts malformed bytes

### 8. Timing leakage on secret-bearing prover paths

- Targeted claim:
  - constant-time/canonicality discipline, once added
- What to exercise:
  - witness-dependent prover inputs
  - deterministic public-witness commitment generation
  - branch-heavy edge cases
- Break condition:
  - timing harness shows gross, stable separation driven by secret-dependent data on the claimed constant-time paths

### 9. Cross-verifier disagreement

- Targeted claim:
  - the package as a whole
- What to exercise:
  - fixed valid vectors
  - fixed invalid vectors
  - cross-check production verifier versus reference verifier
- Break condition:
  - the two verifiers disagree on any accepted or rejected vector

## Current Status

Current repository status:

- mixed-spec rejection: covered by fixed invalid vectors and both verifiers
- transcript aliasing: covered by transcript-domain and relation-id regression tests plus fuzz smoke, still awaiting outside review
- opening canonicality: covered by fixed invalid vectors and direct backend regressions
- commitment opening mismatch: covered by backend regressions and cross-verifier review vectors
- fold-row forgery: covered by fixed invalid vectors and backend regressions
- overclaim rejection: covered in code and backend regressions
- parser/fuzz coverage: local smoke complete and CI job added in `.github/workflows/ci.yml`
- timing harness: built and passing
- cross-verifier agreement: built and passing on the fixed bundle

That status is why the active review state remains `candidate_under_review`.

## Immediate Next Checks

The next concrete work is no longer package construction. It is outside review:

1. external cryptanalysis against the packaged claims,
2. public break-it submissions against the packaged bundle,
3. and any follow-up claim/parameter changes forced by those findings.

Until that review closes cleanly, the current 128-bit claim remains a serious package under review rather than a settled result.
