import SmzaRp05CrossModeAuthorization

/-!
# Source-live RP05 authorization identity domains

The RP05 transaction PRF at call 0 hashes five key digits followed by two
zero words.  Calls 107 and 108 compress a policy key and an accumulator or
value-lock digest.  A domain label attached to one compress14 preimage cannot
turn it into the call-0 sponge; this tagged input preserves the actual source
operation.  No statement here asserts equality between the two operations.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05LiveAuthorizationIdentity

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry

set_option autoImplicit false

inductive LiveAuthorizationInput where
  | singleKey (key : Fin 5 → Nat)
  | accumulator (policyKey accumulatorDigest : Digest)

def LiveAuthorizationInput.digest : LiveAuthorizationInput → Digest
  | .singleKey key =>
      poseidon2V8Sponge currentSingleKeyDomain (currentSingleKeyWords key)
  | .accumulator policyKey accumulatorDigest =>
      poseidon2V8Compress14 currentAuthorizationBindingDomain
        policyKey accumulatorDigest

/-- The fixed nonzero five-digit key used by the known empty opening. -/
def knownEmptyKey : Fin 5 → Nat :=
  fun limb => if limb.val = 0 then 1 else 0

theorem known_empty_key_words :
    currentSingleKeyWords knownEmptyKey = [1, 0, 0, 0, 0, 0, 0] := by
  decide

/-- This equality is definitional after the source input map.  It is not an
assumed cross-mode hash equality. -/
theorem known_empty_single_identity :
    LiveAuthorizationInput.digest (.singleKey knownEmptyKey) =
      currentKnownEmptyIdentity := by
  simp [LiveAuthorizationInput.digest, known_empty_key_words,
    currentKnownEmptyIdentity, currentSingleKeyDomain]

/-- The accumulator branch is exactly the current call-107/108 evaluator. -/
theorem accumulator_identity (policyKey accumulatorDigest : Digest) :
    LiveAuthorizationInput.digest (.accumulator policyKey accumulatorDigest) =
      currentBindingDigest (.authorization
        { domain := .accumulator, policyKey, accumulatorDigest }) := rfl

/-- The registry's call-0 constructor agrees with the source-live evaluator;
the old `.authorization ⟨.singleKey, ..., ...⟩` payload does not. -/
theorem registry_single_key_identity (key : Fin 5 → Nat) :
    currentBindingDigest (.singleKeyAuthorization key) =
      LiveAuthorizationInput.digest (.singleKey key) := rfl

/-- When an accumulator identity equals the known empty SingleKey identity,
the exact witness is a cross-mode projected-permutation collision.  The
distinct frames are proved in `SmzaRp05CrossModeAuthorization`; this is not a
same-function `CurrentPrimitiveCollision`. -/
def known_empty_cross_mode_collision (policyKey accumulatorDigest : Digest)
    (sameDigest :
      currentBindingDigest (.singleKeyAuthorization currentKnownEmptyKey) =
        currentBindingDigest (.authorization
          { domain := .accumulator, policyKey, accumulatorDigest })) :
    CurrentCrossModeAuthorizationCollision := by
  apply crossModeCollisionOfIdentity currentKnownEmptyKey policyKey
    accumulatorDigest
    (currentBindingDigest (.singleKeyAuthorization currentKnownEmptyKey))
    (currentBindingDigest (.authorization
      { domain := .accumulator, policyKey, accumulatorDigest }))
  · rfl
  · rfl
  · exact sameDigest

end HegemonCrypto.SmallWood.SmzaRp05LiveAuthorizationIdentity
