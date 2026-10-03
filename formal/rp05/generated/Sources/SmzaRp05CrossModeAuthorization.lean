import SmzaRp05ConcreteBindingInputs
import HegemonCrypto.SmallWoodV8Smz9TypedScheduleKernel

/-!
# The actual single-key / accumulator authorization boundary

The source binds the seven call-0 inputs to five global-key words followed by
two zero words. Calls 107/108 instead compress the policy key and accumulator
digest. An equal seven-word output is a collision of two distinct *width-16
permutation frames*, not a collision of two call-107 preimages. The separation
is in lane 14, independently of the key or accumulator values.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule

set_option maxRecDepth 10000
set_option maxHeartbeats 600000

/-- `SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN` in the live hash schedule. -/
def currentSingleKeyDomain : Nat := 0x4853_4b41_5632_0001

/-- Exact seven source words of the call-0 transaction PRF. -/
def currentSingleKeyWords (key : Fin 5 → Nat) : List Nat :=
  List.ofFn key ++ [0, 0]

theorem current_single_key_words_length (key : Fin 5 → Nat) :
    (currentSingleKeyWords key).length = 7 := by
  simp [currentSingleKeyWords]

/-- One and only one source sponge block precedes call-0 permutation. -/
def currentSingleCall0Frame (key : Fin 5 → Nat) : List Nat :=
  spongePreparedWords currentSingleKeyDomain (currentSingleKeyWords key) 1
    poseidon2V8InitialState 0

/-- Actual complete initial frame for calls 107/108, with the fixed domain in
lane 14 and the suite marker in lane 15. -/
def currentAccumulatorAuthorizationFrame
    (policyKey accumulatorDigest : Digest) : List Nat :=
  (List.range Poseidon2Width16Kernel.width).map fun lane =>
    if lane < digestWords then policyKey.getD lane 0
    else if lane < 2 * digestWords then
      accumulatorDigest.getD (lane - digestWords) 0
    else if lane = 2 * digestWords then currentAuthorizationBindingDomain
    else poseidon2V8SuiteMarker

/-- The call-0 PRF is the first seven output lanes of this actual frame. -/
theorem current_single_call0_frame_digest (key : Fin 5 → Nat) :
    poseidon2V8Sponge currentSingleKeyDomain (currentSingleKeyWords key) =
      (Poseidon2Width16Kernel.permutation
        (currentSingleCall0Frame key)).take digestWords := by
  unfold poseidon2V8Sponge
  simp [current_single_key_words_length, Poseidon2Width16Kernel.rate,
    poseidon2V8AbsorbBlock, currentSingleCall0Frame,
    spongePreparedWords]

/-- The call-107/108 binding digest is the first seven output lanes of its
distinct compression frame. -/
theorem current_accumulator_authorization_frame_digest
    (policyKey accumulatorDigest : Digest) :
    poseidon2V8Compress14 currentAuthorizationBindingDomain
        policyKey accumulatorDigest =
      (Poseidon2Width16Kernel.permutation
        (currentAccumulatorAuthorizationFrame policyKey accumulatorDigest)).take
          digestWords := rfl

theorem current_single_call0_frame_lane14 (key : Fin 5 → Nat) :
    (currentSingleCall0Frame key).getD 14 0 = 0 := by
  simp [currentSingleCall0Frame, spongePreparedWords,
    poseidon2V8SeedFirstBlock, poseidon2V8InitialState,
    currentSingleKeyWords, Poseidon2Width16Kernel.rate,
    Poseidon2Width16Kernel.width, List.range_succ]

theorem current_accumulator_authorization_frame_lane14
    (policyKey accumulatorDigest : Digest) :
    (currentAccumulatorAuthorizationFrame policyKey accumulatorDigest).getD 14 0 =
      currentAuthorizationBindingDomain := by
  simp [currentAccumulatorAuthorizationFrame, currentAuthorizationBindingDomain,
    Poseidon2Width16Kernel.width, digestWords]

/-- Distinctness is unconditional: no primitive binding game or pairwise
preimage-inequality hypothesis is used. -/
theorem current_cross_mode_frames_distinct
    (key : Fin 5 → Nat) (policyKey accumulatorDigest : Digest) :
    currentSingleCall0Frame key ≠
      currentAccumulatorAuthorizationFrame policyKey accumulatorDigest := by
  intro equal
  have lane := congrArg (fun frame : List Nat => frame.getD 14 0) equal
  rw [current_single_call0_frame_lane14,
    current_accumulator_authorization_frame_lane14] at lane
  have domainNonzero : currentAuthorizationBindingDomain ≠ 0 := by
    decide
  exact domainNonzero lane.symm

/-- Effective permutation coordinates, removing aliases of natural-number
representatives modulo the field modulus. -/
def currentEffectivePermutationFrame (frame : List Nat) : Fin 16 → Nat :=
  fun lane => frame.getD lane.val 0 % fieldModulus

theorem current_cross_mode_effective_frames_distinct
    (key : Fin 5 → Nat) (policyKey accumulatorDigest : Digest) :
    currentEffectivePermutationFrame (currentSingleCall0Frame key) ≠
      currentEffectivePermutationFrame
        (currentAccumulatorAuthorizationFrame policyKey accumulatorDigest) := by
  intro equal
  have lane := congrFun equal (⟨14, by decide⟩ : Fin 16)
  change (currentSingleCall0Frame key).getD 14 0 % fieldModulus =
    (currentAccumulatorAuthorizationFrame policyKey accumulatorDigest).getD
      14 0 % fieldModulus at lane
  rw [current_single_call0_frame_lane14,
    current_accumulator_authorization_frame_lane14] at lane
  norm_num [currentAuthorizationBindingDomain, fieldModulus] at lane

/-- The exact cross-mode primitive event required at an empty-note origin.
Unlike `emptyAuthorizationBreak`, this compares two different source-live
frames of the same width-16 permutation. -/
structure CurrentCrossModeAuthorizationCollision where
  key : Fin 5 → Nat
  policyKey : Digest
  accumulatorDigest : Digest
  differentFrames : currentSingleCall0Frame key ≠
    currentAccumulatorAuthorizationFrame policyKey accumulatorDigest
  differentEffectiveFrames :
    currentEffectivePermutationFrame (currentSingleCall0Frame key) ≠
      currentEffectivePermutationFrame
        (currentAccumulatorAuthorizationFrame policyKey accumulatorDigest)
  sameProjectedPermutationOutput :
    (Poseidon2Width16Kernel.permutation (currentSingleCall0Frame key)).take
      digestWords =
    (Poseidon2Width16Kernel.permutation
      (currentAccumulatorAuthorizationFrame policyKey accumulatorDigest)).take
        digestWords

/-- Origin-boundary recipe: source readback supplies the call-0 and call-107
identities, while equality of the note's seven-word identity supplies the
common output. Frame inequality is derived from lane 14. -/
def crossModeCollisionOfIdentity
    (key : Fin 5 → Nat) (policyKey accumulatorDigest : Digest)
    (singleIdentity accumulatorIdentity : Digest)
    (singleReadback : singleIdentity =
      poseidon2V8Sponge currentSingleKeyDomain (currentSingleKeyWords key))
    (accumulatorReadback : accumulatorIdentity =
      poseidon2V8Compress14 currentAuthorizationBindingDomain
        policyKey accumulatorDigest)
    (sameIdentity : singleIdentity = accumulatorIdentity) :
    CurrentCrossModeAuthorizationCollision := by
  refine ⟨key, policyKey, accumulatorDigest,
    current_cross_mode_frames_distinct key policyKey accumulatorDigest,
    current_cross_mode_effective_frames_distinct key policyKey accumulatorDigest, ?_⟩
  calc
    (Poseidon2Width16Kernel.permutation
        (currentSingleCall0Frame key)).take digestWords =
        poseidon2V8Sponge currentSingleKeyDomain (currentSingleKeyWords key) :=
      (current_single_call0_frame_digest key).symm
    _ = singleIdentity := singleReadback.symm
    _ = accumulatorIdentity := sameIdentity
    _ = poseidon2V8Compress14 currentAuthorizationBindingDomain
          policyKey accumulatorDigest := accumulatorReadback
    _ = (Poseidon2Width16Kernel.permutation
          (currentAccumulatorAuthorizationFrame policyKey accumulatorDigest)).take
            digestWords :=
      current_accumulator_authorization_frame_digest policyKey accumulatorDigest

end HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry
