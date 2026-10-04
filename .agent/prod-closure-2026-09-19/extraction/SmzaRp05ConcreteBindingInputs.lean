import SmzaRp05ThresholdRegistry

/-!
# Effective RP05 binding inputs

`CurrentBindingPreimage` includes registry metadata. A primitive collision
requires different *absorbed inputs*, not merely different tagged records.
Moreover, the call-107/108 authorization evaluator is source-live only for
the accumulator domain. The single-key identity has a separate PRF route;
this file deliberately does not assign it the call-107/108 evaluator.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

/-- The permutation absorbs field elements. Natural-number representatives
differing by a modulus are not different primitive inputs. -/
def currentCanonicalBindingWords (words : List Nat) : List Nat :=
  words.map (fun word => word % fieldModulus)

/-- Canonical seven-word lane projection of a compression operand. -/
def currentCompressOperand (words : Digest) : List Nat :=
  (List.range 7).map (fun limb => words.getD limb 0 % fieldModulus)

/-- Domain and complete effective input words for the primitive in question.
The family tag distinguishes sponge from compression and their uses. -/
structure CurrentEffectiveBindingInput where
  family : BindingFamily
  domain : Nat
  words : List Nat
deriving DecidableEq

def currentEffectiveBindingInput : CurrentBindingPreimage →
    CurrentEffectiveBindingInput
  | .note p =>
      ⟨.note, poseidon2V8NoteDomain,
        currentCanonicalBindingWords (exactV8NoteWords p.opening)⟩
  | .merkle p =>
      ⟨.merkle, poseidon2V8MerkleDomain,
        currentCompressOperand p.left ++ currentCompressOperand p.right⟩
  | .authorization p =>
      ⟨.authorization, currentAuthorizationBindingDomain,
        currentCompressOperand p.policyKey ++
          currentCompressOperand p.accumulatorDigest⟩
  | .singleKeyAuthorization key =>
      ⟨.authorization, currentSourceSingleKeyDomain,
        currentCanonicalBindingWords (currentSourceSingleKeyWords key)⟩
  | .accumulator p =>
      ⟨.accumulator, poseidon2V8AccumulatorDomain,
        currentCanonicalBindingWords (List.ofFn p)⟩
  | .policy p =>
      ⟨.policy, poseidon2V8PolicyDomain,
        currentCanonicalBindingWords (List.ofFn p)⟩
  | .intent p =>
      ⟨.intent, currentIntentBindingDomain,
        currentCanonicalBindingWords (List.ofFn p)⟩

/-- Input-note source positions 14..17 are the first four authorization
identity words; positions 10..12 are the remaining three. In
`exactV8NoteWords` these are respectively `authorizationKey[0..4]` and
`randomness[0..3]`, after value, asset, recipient, and rho. Field reduction
matches the permutation's absorbed elements. -/
def currentNoteIdentityFromOpening (opening : V8NoteOpening) : Digest :=
  let words := currentCanonicalBindingWords (exactV8NoteWords opening)
  (words.drop 14).take 4 ++ (words.drop 10).take 3

/-- Exact source shape and the CSR copy from the auth-input vector into
the note's 18 absorbed words. -/
structure CurrentNoteSourceValid (preimage : CurrentNotePreimage) : Prop where
  recipientWidth : preimage.opening.recipientKey.length = 4
  rhoWidth : preimage.opening.rho.length = 4
  randomnessWidth : preimage.opening.randomness.length = 4
  authorizationWidth : preimage.opening.authorizationKey.length = 4
  identityBound :
    preimage.authorizationIdentity =
      currentNoteIdentityFromOpening preimage.opening

/-- The old two-digest authorization payload is source-live only for
calls 107/108. The separate SingleKey constructor is source-live for call 0.
Source-valid notes obey the actual 18-word shape and auth-vector copies. -/
def currentBindingSourceValid : CurrentBindingPreimage → Prop
  | .note p => CurrentNoteSourceValid p
  | .authorization p => p.domain = .accumulator
  | .singleKeyAuthorization _ => True
  | _ => True

/-- Equal effective note hash inputs force equal seven-word identities once
the source copy and widths have been established. -/
theorem source_valid_note_effective_input_identity
    (left right : CurrentNotePreimage)
    (leftValid : CurrentNoteSourceValid left)
    (rightValid : CurrentNoteSourceValid right)
    (sameInput : currentEffectiveBindingInput (.note left) =
      currentEffectiveBindingInput (.note right)) :
    left.authorizationIdentity = right.authorizationIdentity := by
  have wordsEq :
      currentCanonicalBindingWords (exactV8NoteWords left.opening) =
        currentCanonicalBindingWords (exactV8NoteWords right.opening) := by
    exact congrArg CurrentEffectiveBindingInput.words sameInput
  calc
    left.authorizationIdentity = currentNoteIdentityFromOpening left.opening :=
      leftValid.identityBound
    _ = currentNoteIdentityFromOpening right.opening := by
      unfold currentNoteIdentityFromOpening
      exact congrArg
        (fun words : List Nat => (words.drop 14).take 4 ++
          (words.drop 10).take 3) wordsEq
    _ = right.authorizationIdentity := rightValid.identityBound.symm

/-- This rules out treating the single-key identity as a call-107 collision. -/
theorem single_key_not_current_authorization_source
    (policyKey accumulatorDigest : Digest) :
    ¬ currentBindingSourceValid
      (.authorization ⟨.singleKey, policyKey, accumulatorDigest⟩) := by
  simp [currentBindingSourceValid]

/-- Different stored note identities do not change the note hash input. -/
theorem note_identity_is_not_effective_input
    (opening : V8NoteOpening) (left right : Digest) :
    currentEffectiveBindingInput (.note ⟨opening, left⟩) =
      currentEffectiveBindingInput (.note ⟨opening, right⟩) := rfl

/-- Nor does the metadata domain tag change the modeled call-107 frame.
Only the accumulator-tagged side is source-valid for that evaluator. -/
theorem authorization_domain_is_not_effective_input
    (policyKey accumulatorDigest : Digest) :
    currentEffectiveBindingInput
        (.authorization ⟨.singleKey, policyKey, accumulatorDigest⟩) =
      currentEffectiveBindingInput
        (.authorization ⟨.accumulator, policyKey, accumulatorDigest⟩) := rfl

/-- The source-live call-0 input and call-107/108 input are in distinct
domains. An equal seven-word result belongs to the cross-mode frame event. -/
theorem single_key_accumulator_primitive_domains_differ
    (key : Fin 5 → Nat) (policyKey accumulatorDigest : Digest) :
    (currentEffectiveBindingInput (.singleKeyAuthorization key)).domain ≠
    (currentEffectiveBindingInput (.authorization
        ⟨.accumulator, policyKey, accumulatorDigest⟩)).domain := by
  change currentSourceSingleKeyDomain ≠ currentAuthorizationBindingDomain
  decide

/-- A collision claim for the actual input to one source-live evaluator. -/
structure CurrentPrimitiveCollision where
  left : CurrentBindingPreimage
  right : CurrentBindingPreimage
  leftSourceValid : currentBindingSourceValid left
  rightSourceValid : currentBindingSourceValid right
  sameFamily : currentBindingFamily left = currentBindingFamily right
  /-- A call-0/call-107 equal output is charged through the distinct-frame
  cross-mode reduction, not as a same-primitive collision. -/
  sameDomain : (currentEffectiveBindingInput left).domain =
    (currentEffectiveBindingInput right).domain
  differentEffectiveInput :
    currentEffectiveBindingInput left ≠ currentEffectiveBindingInput right
  sameDigest : currentBindingDigest left = currentBindingDigest right

/-- Forgetting the stronger evidence recovers the old tagged break; the
converse is not supplied because metadata-only differences are insufficient. -/
def CurrentPrimitiveCollision.toBindingBreak
    (collision : CurrentPrimitiveCollision) : BindingBreak currentBindingModel :=
  bindingBreakOfDistinct collision.left collision.right collision.sameFamily
    (by
      intro equal
      exact collision.differentEffectiveInput
        (congrArg currentEffectiveBindingInput equal))
    collision.sameDigest

end HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry
