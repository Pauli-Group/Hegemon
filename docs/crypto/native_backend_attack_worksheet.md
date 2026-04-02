# Native Backend Attack Worksheet

This worksheet is the concrete attack ledger for the active native backend family. Each line names the break class, the assumption or claim it targets, how the repo should exercise it, and what would count as a real failure.

## Active Target

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v8"`
- `spec_digest = c441d06521bf6e604fda75378aea05e341ad3f4a8769d74a9cca4e3ff582eb23`

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
  - `fs.quint_goldilocks_profile_fold_challenges`
- What to exercise:
  - distinct fold inputs producing identical transcript bytes
  - domain-separation collisions across leaf and fold subtranscripts
  - width or length ambiguities in encoded transcript material
- Break condition:
  - two distinct proof states derive the same challenge stream under accepted encodings

### 3. Public-witness reconstruction mismatch

- Targeted claim:
  - `commitment.deterministic_public_witness_reconstruction`
- What to exercise:
  - mutate serialized STARK public inputs without changing the public tx view
  - mutate the public tx view without changing serialized STARK public inputs
  - mutate commitment rows or commitment digest while preserving the rest of the artifact
- Break condition:
  - verifier accepts an artifact whose deterministic public-witness reconstruction does not match the committed rows or digest

### 4. BK-MSIS reduction mismatch

- Targeted claim:
  - `commitment.bounded_kernel_module_sis_exact_reduction`
- What to exercise:
  - construct accepted live messages at the bound edges
  - try to produce commitment collisions whose difference vector falls outside the claimed bounds
  - try to produce accepted artifacts whose verifier reconstruction does not stay inside the claimed bounded message class
- Break condition:
  - an accepted collision exists that does not map to the exact bounded-kernel problem stated in the reduction note

### 5. Fold-row forgery

- Targeted claims:
  - `fs.quint_goldilocks_negacyclic_fold_challenges`
  - `commitment.bounded_kernel_module_sis_exact_reduction`
- What to exercise:
  - mutated parent rows
  - swapped left or right child commitments
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
  - mixed version, spec, or length fields
- Break condition:
  - parser panics, allocates absurdly, or accepts malformed bytes

### 8. Timing leakage on secret-bearing prover paths

- Targeted claim:
  - constant-time and canonicality discipline, once added
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
- public-witness reconstruction: covered by fixed invalid vectors and direct backend regressions
- BK-MSIS reduction boundary: now explicitly documented and tied to the active claim, with an in-repo Euclidean SIS estimate for the exact active instance, still awaiting independent review of that concretization and estimator
- fold-row forgery: covered by fixed invalid vectors and backend regressions
- overclaim rejection: covered in code and backend regressions
- parser and fuzz coverage: local smoke complete and CI job added in `.github/workflows/ci.yml`
- timing harness: built and passing
- cross-verifier agreement: built and passing on the fixed bundle

That status is why the active review state remains `candidate_under_review`.

## Immediate Next Checks

The next concrete work is outside review:

1. external cryptanalysis against the packaged BK-MSIS reduction and the exact coefficient-space Euclidean SIS estimate used for the live binding floor,
2. public break-it submissions against the packaged bundle,
3. any follow-up claim or parameter changes forced by those findings.

Until that review closes cleanly, the current 128-bit claim remains a serious package under review rather than a settled result.
