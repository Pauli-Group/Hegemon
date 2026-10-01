import SmzaRp05AccumulatorHashBridge
import HegemonCrypto.SmallWoodV8Smz9SemanticDecoder

/-!
# Live RP05 nullifier-key source binding

RP05 hashes twelve words over calls 36--37 or 73--74: five selected
nullifier-key words, two zero pads, a 32-bit position, and four note-rho
words.  This file establishes the accepted nonlinear selection of the five
key words.  It does not import the obsolete six-word, one-call RP03
nullifier theorem, nor postulate the missing RP05 two-call CSR digest edge.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierBinding

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open SmzaRp05TypedRelation

set_option autoImplicit false
open scoped Classical

/-- Exact live RP05 rows from `AUTH_ROW_START = 92`. -/
def inputNullifierKeyRow (input : Fin 2) : Nat := 97 + input.val
def globalNullifierKeyRow : Nat := 227
def policyNullifierKeyRow : Nat := 228

/-- Exact live two-call nullifier schedule, not the old call36/72 schedule. -/
def nullifierFirstCall (input : Fin 2) : Nat := if input.val = 0 then 36 else 73
def nullifierLastCall (input : Fin 2) : Nat := nullifierFirstCall input + 1
def inputNoteFirstCall (input : Fin 2) : Nat := if input.val = 0 then 1 else 38

/-- Twelve live source words, in the exact RP05 CSR order.  The note-rho
words are decoded from the current note-call schedule, including input1's
call38 rather than the obsolete call37. -/
def nullifierPreimage (packed : List Nat) (input : Fin 2) : List Nat :=
  (List.range 5).map (fun limb =>
    packed.getD ((inputNullifierKeyRow input) * 64 + limb) 0) ++
  [0, 0, projectPosition packed input.val] ++
  (List.range 4).map (fun limb =>
    spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))

@[simp] theorem nullifier_preimage_length (packed : List Nat) (input : Fin 2) :
    (nullifierPreimage packed input).length = 12 := by
  simp [nullifierPreimage]

/-- Live RP05 `SMALLWOOD_POSEIDON2_V8_NULLIFIER_DOMAIN`; semantic domain 2
belongs to an older hash schedule and is not the accepted call-36/73 frame. -/
def currentNullifierDomain : Nat := 0x484e_554c_5632_0001

def liveNullifierDigest (packed : List Nat) (input : Fin 2) : Digest :=
  poseidon2V8Sponge currentNullifierDomain
    (nullifierPreimage packed input)

/-- A full-seven-word collision of the exact two-call, twelve-word primitive;
this is not a prefix collision in call107/108 and not the old scalar hash. -/
structure FullNullifierCollision where
  left : List Nat
  right : List Nat
  leftLength : left.length = 12
  rightLength : right.length = 12
  different : left ≠ right
  sameDigest :
    poseidon2V8Sponge currentNullifierDomain left =
      poseidon2V8Sponge currentNullifierDomain right

/-- Data-valued, decidable equality-or-collision result for two concrete
twelve-word inputs. The collision payload is tied to these exact inputs. -/
inductive FullNullifierComparison (left right : List Nat) : Type where
  | equal (same : left = right) : FullNullifierComparison left right
  | collision (pair : FullNullifierCollision)
      (leftExact : pair.left = left) (rightExact : pair.right = right) :
      FullNullifierComparison left right

def equal_live_nullifier_or_full_collision
    (leftPacked rightPacked : List Nat) (input : Fin 2)
    (sameDigest : liveNullifierDigest leftPacked input =
      liveNullifierDigest rightPacked input) :
    FullNullifierComparison (nullifierPreimage leftPacked input)
      (nullifierPreimage rightPacked input) := by
  if same : nullifierPreimage leftPacked input =
      nullifierPreimage rightPacked input then
    exact .equal same
  else
    exact .collision {
      left := nullifierPreimage leftPacked input
      right := nullifierPreimage rightPacked input
      leftLength := nullifier_preimage_length leftPacked input
      rightLength := nullifier_preimage_length rightPacked input
      different := same
      sameDigest := sameDigest
    } rfl rfl

/-- The current nonlinear root selects global or policy key according to
mode and input slot.  In Final mode both inputs use the policy key; the
value-lock/current-accumulator distinction belongs to their *note identity*,
not to this nullifier-key selector. -/
def nullifierKeyMuxTerm (input : Fin 2) : SourceTerm :=
  let global := trow globalNullifierKeyRow
  let policy := trow policyNullifierKeyRow
  let selected := if input.val = 0 then
    tadd (tmul (trow singleRow) global)
      (tmul policy (tadd (trow approvalRow) (trow finalRow)))
    else
    tadd (tmul (trow finalRow) policy)
      (tmul global (tadd (trow singleRow) (trow approvalRow)))
  tsub (trow (inputNullifierKeyRow input)) selected

/-- Finite source artifact: only current nonlinear root membership and
syntax-directed DAG realizations, with no semantic or digest equality field. -/
structure CurrentNullifierMuxCertificate
    (components : RelationProgramComponents) where
  canonical : components.nonlinearExecutable.Canonical true
  rootFor : Fin 2 → Nat
  member : ∀ input, rootFor input ∈ components.nonlinearExecutable.roots
  realizes : ∀ input, Realizes components.nonlinearExecutable.expressions
    (rootFor input) (nullifierKeyMuxTerm input)

theorem accepted_nullifier_key_mux
    {components : RelationProgramComponents}
    (certificate : CurrentNullifierMuxCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 5) :
    (nullifierKeyMuxTerm input).eval
      (fun index => (publicWords.getD index 0 : Goldilocks))
      (fun row =>
        ((packedWitnessLaneRows packed limb.val).getD row 0 : Goldilocks)) = 0 := by
  have laneBound : limb.val < packingFactor := by
    simpa [packingFactor] using (show limb.val < 64 by omega)
  have laneAccepted := accepted_packed_program_checks_every_nonlinear_lane
    accepted laneBound
  obtain ⟨values, evaluated, rootZero⟩ :=
    acceptance_makes_each_named_root_zero laneAccepted
      (certificate.member input)
  have rootBound := certificate.canonical.2 _ (certificate.member input)
  have refined := fieldAt_refines_source components.nonlinearExecutable
    publicWords (packedWitnessLaneRows packed limb.val) values
    certificate.canonical evaluated (certificate.rootFor input) rootBound
  have valueZero : values.getD (certificate.rootFor input) 0 = 0 := by
    simp [List.getD_eq_getElem?_getD, rootZero]
  rw [fieldAt_of_realizes (certificate.realizes input)] at refined
  rw [valueZero] at refined
  exact refined

/-- Both active Final input nullifiers use the five-word policy key.  This
statement is in the field because the current selector roots are field
equations; canonical packed-word bounds can be applied by consumers. -/
theorem accepted_final_nullifier_key_word
    {components : RelationProgramComponents}
    (certificate : CurrentNullifierMuxCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 5)
    (finalSelected :
      ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) = 1)
    (singleUnselected :
      ((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) = 0)
    (approvalUnselected :
      ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) = 0) :
    ((packedWitnessLaneRows packed limb.val).getD
        (inputNullifierKeyRow input) 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD
        policyNullifierKeyRow 0 : Goldilocks) := by
  have equation := accepted_nullifier_key_mux certificate accepted input limb
  rcases input with ⟨inputValue, inputBound⟩
  interval_cases inputValue
  · change ((packedWitnessLaneRows packed limb.val).getD 97 0 : Goldilocks) -
      (((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) *
          ((packedWitnessLaneRows packed limb.val).getD globalNullifierKeyRow 0 : Goldilocks) +
        ((packedWitnessLaneRows packed limb.val).getD policyNullifierKeyRow 0 : Goldilocks) *
          (((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) +
            ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks))) = 0 at equation
    change ((packedWitnessLaneRows packed limb.val).getD 97 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD policyNullifierKeyRow 0 : Goldilocks)
    rw [singleUnselected, approvalUnselected, finalSelected] at equation
    linear_combination equation
  · change ((packedWitnessLaneRows packed limb.val).getD 98 0 : Goldilocks) -
      (((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) *
          ((packedWitnessLaneRows packed limb.val).getD policyNullifierKeyRow 0 : Goldilocks) +
        ((packedWitnessLaneRows packed limb.val).getD globalNullifierKeyRow 0 : Goldilocks) *
          (((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) +
            ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks))) = 0 at equation
    change ((packedWitnessLaneRows packed limb.val).getD 98 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD policyNullifierKeyRow 0 : Goldilocks)
    rw [singleUnselected, approvalUnselected, finalSelected] at equation
    linear_combination equation

/-- Approval input0 uses the policy key; its ordinary signer input1 uses the
global key.  This mode split is part of the actual accepted RP05 selector. -/
theorem accepted_approval_nullifier_key_word
    {components : RelationProgramComponents}
    (certificate : CurrentNullifierMuxCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 5)
    (approvalSelected :
      ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) = 1)
    (singleUnselected :
      ((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) = 0)
    (finalUnselected :
      ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) = 0) :
    ((packedWitnessLaneRows packed limb.val).getD
        (inputNullifierKeyRow input) 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD
        (if input.val = 0 then policyNullifierKeyRow else globalNullifierKeyRow) 0 :
        Goldilocks) := by
  have equation := accepted_nullifier_key_mux certificate accepted input limb
  rcases input with ⟨inputValue, inputBound⟩
  interval_cases inputValue
  · change ((packedWitnessLaneRows packed limb.val).getD 97 0 : Goldilocks) -
      (((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) *
          ((packedWitnessLaneRows packed limb.val).getD globalNullifierKeyRow 0 : Goldilocks) +
        ((packedWitnessLaneRows packed limb.val).getD policyNullifierKeyRow 0 : Goldilocks) *
          (((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) +
            ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks))) = 0 at equation
    change ((packedWitnessLaneRows packed limb.val).getD 97 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD policyNullifierKeyRow 0 : Goldilocks)
    rw [singleUnselected, approvalSelected, finalUnselected] at equation
    linear_combination equation
  · change ((packedWitnessLaneRows packed limb.val).getD 98 0 : Goldilocks) -
      (((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) *
          ((packedWitnessLaneRows packed limb.val).getD policyNullifierKeyRow 0 : Goldilocks) +
        ((packedWitnessLaneRows packed limb.val).getD globalNullifierKeyRow 0 : Goldilocks) *
          (((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) +
            ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks))) = 0 at equation
    change ((packedWitnessLaneRows packed limb.val).getD 98 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD globalNullifierKeyRow 0 : Goldilocks)
    rw [singleUnselected, approvalSelected, finalUnselected] at equation
    linear_combination equation

/-- Ordinary single-key spends use the global five-word key in either input. -/
theorem accepted_single_nullifier_key_word
    {components : RelationProgramComponents}
    (certificate : CurrentNullifierMuxCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 5)
    (singleSelected :
      ((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) = 1)
    (approvalUnselected :
      ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) = 0)
    (finalUnselected :
      ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) = 0) :
    ((packedWitnessLaneRows packed limb.val).getD
        (inputNullifierKeyRow input) 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD
        globalNullifierKeyRow 0 : Goldilocks) := by
  have equation := accepted_nullifier_key_mux certificate accepted input limb
  rcases input with ⟨inputValue, inputBound⟩
  interval_cases inputValue
  · change ((packedWitnessLaneRows packed limb.val).getD 97 0 : Goldilocks) -
      (((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) *
          ((packedWitnessLaneRows packed limb.val).getD globalNullifierKeyRow 0 : Goldilocks) +
        ((packedWitnessLaneRows packed limb.val).getD policyNullifierKeyRow 0 : Goldilocks) *
          (((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) +
            ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks))) = 0 at equation
    change ((packedWitnessLaneRows packed limb.val).getD 97 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD globalNullifierKeyRow 0 : Goldilocks)
    rw [singleSelected, approvalUnselected, finalUnselected] at equation
    linear_combination equation
  · change ((packedWitnessLaneRows packed limb.val).getD 98 0 : Goldilocks) -
      (((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) *
          ((packedWitnessLaneRows packed limb.val).getD policyNullifierKeyRow 0 : Goldilocks) +
        ((packedWitnessLaneRows packed limb.val).getD globalNullifierKeyRow 0 : Goldilocks) *
          (((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) +
            ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks))) = 0 at equation
    change ((packedWitnessLaneRows packed limb.val).getD 98 0 : Goldilocks) =
      ((packedWitnessLaneRows packed limb.val).getD globalNullifierKeyRow 0 : Goldilocks)
    rw [singleSelected, approvalUnselected, finalUnselected] at equation
    linear_combination equation

end HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
