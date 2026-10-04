import SmzaRp05PhysicalAcceptedReplayLite
import HegemonCrypto.CmsOracleDatabaseBridge

/-! # Identity of an already-known verifier readout

Replaying the same finite answer trace against a standard-oracle state in
which every answer is already known leaves that state unchanged.  The
physical-run corollary is pointwise and uses one ambient finite key type; it
does not identify a checkpoint selector with a selector after an arbitrary
suffix.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentVerifierReplay

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output Phase Work Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

/-- If all answers in a retained trace are already known, replaying its
coordinate projectors changes no standard-oracle state. -/
theorem retainedTrace_eq_self_of_claims_known
    (inputs : List Key) (answers : ReadAnswers Output inputs)
    (state : State Key Output Phase Work)
    (known : ∀ claim, claim ∈ branchClaims inputs answers →
      KnownAt claim.1 claim.2 state) :
    retainedTrace inputs answers state = state := by
  induction inputs generalizing state with
  | nil => rfl
  | cons input inputs ih =>
      rcases answers with ⟨answer, answers⟩
      have headKnown : KnownAt input answer state :=
        known (input, answer) (by simp [branchClaims])
      have tailKnown : ∀ claim, claim ∈ branchClaims inputs answers →
          KnownAt claim.1 claim.2 state := by
        intro claim member
        exact known claim (by simp [branchClaims, member])
      simp only [retainedTrace]
      rw [headKnown]
      exact ih answers state tailKnown

/-- A physical verifier replay whose exact branch answers are already known
in the pre-replay standard view has the same final standard view.  Callers
must establish `known` in this same `Key` universe and for this exact answer
trace; this theorem supplies no cross-program key or register embedding. -/
theorem physicalRun_standard_view_eq_self_on_known_branch
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : State Key Output Phase Work)
    (known : ∀ claim,
      claim ∈ branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch) →
      KnownAt claim.1 claim.2 (globalDecompress state)) :
    globalDecompress (physicalRun encode decode program branch state) =
      globalDecompress state := by
  rw [global_decompress_physical_run_eq_retainedTrace]
  apply retainedTrace_eq_self_of_claims_known
  intro claim member
  exact known claim member

/-- Because global decompression is involutive, the preceding equality also
gives equality of the compressed physical branch state itself. -/
theorem physicalRun_eq_self_on_known_branch
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : State Key Output Phase Work)
    (known : ∀ claim,
      claim ∈ branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch) →
      KnownAt claim.1 claim.2 (globalDecompress state)) :
    physicalRun encode decode program branch state = state := by
  calc
    physicalRun encode decode program branch state =
        globalDecompress (globalDecompress
          (physicalRun encode decode program branch state)) :=
      (global_decompress_involutive _).symm
    _ = globalDecompress (globalDecompress state) :=
      congrArg globalDecompress
        (physicalRun_standard_view_eq_self_on_known_branch
          encode decode program branch state known)
    _ = state := global_decompress_involutive _

/-- Replaying a finite prefix branch after any intervening read-only suffix
does not change the branch state. The first execution makes all of its exact
answer cells known; suffix projectors preserve those facts, and the final
replay is therefore pointwise identity. All three executions use the same
ambient key universe and read semantics. -/
theorem physicalRun_prefix_suffix_prefix_idempotent
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (firstProgram : Program Result)
    (firstBranch : Branches decode firstProgram)
    (suffix : Program Result) (suffixBranch : Branches decode suffix)
    (state : State Key Output Phase Work) :
    physicalRun encode decode firstProgram firstBranch
        (physicalRun encode decode suffix suffixBranch
          (physicalRun encode decode firstProgram firstBranch state)) =
      physicalRun encode decode suffix suffixBranch
        (physicalRun encode decode firstProgram firstBranch state) := by
  let afterPrefix := physicalRun encode decode firstProgram firstBranch state
  have prefixClaimsKnown : ∀ claim,
      claim ∈ branchClaims (branchKeys encode decode firstProgram firstBranch)
        (branchAnswers encode decode firstProgram firstBranch) →
      KnownAt claim.1 claim.2 (globalDecompress afterPrefix) := by
    intro claim member
    rw [show afterPrefix =
      physicalRun encode decode firstProgram firstBranch state from rfl]
    rw [global_decompress_physical_run_eq_retainedTrace]
    exact branch_claim_known_at_repeated
      (branchKeys encode decode firstProgram firstBranch)
      (branchAnswers encode decode firstProgram firstBranch)
      (globalDecompress state) claim member
  have prefixClaimsStillKnown : ∀ claim,
      claim ∈ branchClaims (branchKeys encode decode firstProgram firstBranch)
        (branchAnswers encode decode firstProgram firstBranch) →
      KnownAt claim.1 claim.2
        (globalDecompress
          (physicalRun encode decode suffix suffixBranch afterPrefix)) := by
    intro claim member
    rw [global_decompress_physical_run_eq_retainedTrace]
    exact retained_trace_preserves_known
      (branchKeys encode decode suffix suffixBranch)
      (branchAnswers encode decode suffix suffixBranch)
      (globalDecompress afterPrefix) claim.1 claim.2
      (prefixClaimsKnown claim member)
  exact physicalRun_eq_self_on_known_branch encode decode firstProgram firstBranch
    (physicalRun encode decode suffix suffixBranch afterPrefix)
    prefixClaimsStillKnown

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentVerifierReplay
