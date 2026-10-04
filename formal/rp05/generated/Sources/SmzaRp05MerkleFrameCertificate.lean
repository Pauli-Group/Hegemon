import SmzaRp05CurrentMerklePublic
import SmzaRp05AccumulatorHashBridge

/-!
# Finite current RP05 Merkle frame certificate (source-only)

Every field below is finite program syntax: exact attempt identity and
membership, CSR node realization, or a named nonlinear root realization.
There is no field asserting a witness-wide Merkle equality.  The source
fixture checker in `relation/rp05_merkle_frame_audit.py` independently verifies
the 64-call CSR geometry; a Lean instance for the parsed generated component
file remains to be checked.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05MerkleFrameCertificate

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex inputDirectionRow rawIndex)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05CurrentMerklePublic
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation

set_option autoImplicit false

def callAt (step : Nat) : Nat :=
  if step < 32 then 4 + step else 41 + (step - 32)

def previousCall (step : Nat) : Nat :=
  if step % 32 = 0 then (if step < 32 then 3 else 40)
  else callAt (step - 1)

def inlineIndex (step limb component : Nat) : Nat :=
  let slot := step * 7 + limb
  (252 + 4 * (slot / 64) + component) * 64 + slot % 64

def directionIndex (step : Nat) : Nat :=
  rawIndex (inputDirectionRow (step / 32) (step % 32))

def initialGlobal (step lane : Nat) : Nat := 15873 + 16 * step + lane
def currentGlobal (step limb : Nat) : Nat := 16897 + 7 * step + limb
def directionGlobal (step limb : Nat) : Nat := 17345 + 7 * step + limb

abbrev InitialCell := Fin 64 × Fin 16
abbrev CopyCell := Fin 64 × Fin 7

def initialTerms (cell : InitialCell) : List (Nat × Nat) :=
  let step := cell.1.val
  let lane := cell.2.val
  [(hashInitialIndex (callAt step) lane, 1)] ++
    if lane < 14 then
      [(inlineIndex step (lane % 7) (if lane < 7 then 1 else 2), 160)]
    else []

def initialTarget (cell : InitialCell) : Nat :=
  if cell.2.val < 14 then 0 else if cell.2.val = 14 then 130 else 541

def currentTerms (cell : CopyCell) : List (Nat × Nat) :=
  [(inlineIndex cell.1.val cell.2.val 0, 1),
    (hashFinalIndex (previousCall cell.1.val) cell.2.val, 160)]

def directionTerms (cell : CopyCell) : List (Nat × Nat) :=
  [(inlineIndex cell.1.val cell.2.val 3, 1),
    (directionIndex cell.1.val, 160)]

/-- Exact current CSR family16/17/18 frames. `attemptIdentity` includes the
parsed global index, family and local index, so a stray structurally similar
attempt from another family cannot satisfy the certificate. -/
structure FrameCertificate (components : RelationProgramComponents) where
  canonical : ({ expressions := components.csrExpressions, roots := [] } :
    ExpressionProgram).Canonical true
  zero : Realizes components.csrExpressions 0 (.constant 0)
  one : Realizes components.csrExpressions 1 (.constant 1)
  negative : Realizes components.csrExpressions 160
    (.sub (.constant 0) (.constant 1))
  domain : Realizes components.csrExpressions 130 (.constant 4)
  suite : Realizes components.csrExpressions 541
    (.constant poseidon2V8SuiteMarker)
  initial : InitialCell → CsrExecutableAttempt
  initialMember : ∀ cell, initial cell ∈ components.csrAttempts
  initialIdentity : ∀ cell,
    (initial cell).globalIndex = initialGlobal cell.1.val cell.2.val ∧
      (initial cell).family = 16 ∧
      (initial cell).localIndex = 16 * cell.1.val + cell.2.val ∧
      (initial cell).emission = 0
  initialExact : ∀ cell,
    (initial cell).terms = initialTerms cell ∧
      (initial cell).targetRoot = initialTarget cell
  current : CopyCell → CsrExecutableAttempt
  currentMember : ∀ cell, current cell ∈ components.csrAttempts
  currentIdentity : ∀ cell,
    (current cell).globalIndex = currentGlobal cell.1.val cell.2.val ∧
      (current cell).family = 17 ∧
      (current cell).localIndex = 7 * cell.1.val + cell.2.val ∧
      (current cell).emission = 0
  currentExact : ∀ cell,
    (current cell).terms = currentTerms cell ∧
      (current cell).targetRoot = 0
  direction : CopyCell → CsrExecutableAttempt
  directionMember : ∀ cell, direction cell ∈ components.csrAttempts
  directionIdentity : ∀ cell,
    (direction cell).globalIndex = directionGlobal cell.1.val cell.2.val ∧
      (direction cell).family = 18 ∧
      (direction cell).localIndex = 7 * cell.1.val + cell.2.val ∧
      (direction cell).emission = 0
  directionExact : ∀ cell,
    (direction cell).terms = directionTerms cell ∧
      (direction cell).targetRoot = 0

/-- Seven packed groups cover 64*7 oriented digest limbs. Each nonlinear
root is a single finite expression of four actual inline witness rows. -/
structure OrientationCertificate (components : RelationProgramComponents) where
  canonical : components.nonlinearExecutable.Canonical true
  root : Fin 7 → Nat
  member : ∀ group, root group ∈ components.nonlinearExecutable.roots
  realizes : ∀ group,
    Realizes components.nonlinearExecutable.expressions (root group)
      (.sub (.witness (252 + 4 * group.val))
        (.add (.witness (253 + 4 * group.val))
          (.mul (.witness (255 + 4 * group.val))
            (.sub (.witness (254 + 4 * group.val))
              (.witness (253 + 4 * group.val))))))

/-- One exact current-program two-term copy, derived from the checked CSR
attempt and its finite coefficient nodes. -/
private theorem accepted_copy
    {components : RelationProgramComponents}
    (certificate : FrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (attempt : CsrExecutableAttempt)
    (member : attempt ∈ components.csrAttempts)
    (left right : Nat)
    (terms : attempt.terms = [(left, 1), (right, 160)])
    (target : attempt.targetRoot = 0) :
    packed.getD left 0 = packed.getD right 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have one : (values.getD 1 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated certificate.one
  have negative : (values.getD 160 0 : Goldilocks) = -1 := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated certificate.negative
  have zero : (values.getD 0 0 : Goldilocks) = 0 := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated certificate.zero
  have equation := accepted_csr_attempt_field_equality (attempts attempt member)
  rw [terms, target] at equation
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, one, negative, zero, one_mul, neg_one_mul, add_zero] at equation
  apply canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 left)
    (packed_word_canonical accepted.2.1 right)
  simp only [packedWord]
  linear_combination equation

theorem accepted_current_copy
    {components : RelationProgramComponents}
    (certificate : FrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (cell : CopyCell) :
    packed.getD (inlineIndex cell.1.val cell.2.val 0) 0 =
      packed.getD
        (hashFinalIndex (previousCall cell.1.val) cell.2.val) 0 := by
  exact accepted_copy certificate accepted (certificate.current cell)
    (certificate.currentMember cell) _ _
    (certificate.currentExact cell).1 (certificate.currentExact cell).2

theorem accepted_direction_copy
    {components : RelationProgramComponents}
    (certificate : FrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (cell : CopyCell) :
    packed.getD (inlineIndex cell.1.val cell.2.val 3) 0 =
      packed.getD (directionIndex cell.1.val) 0 := by
  exact accepted_copy certificate accepted (certificate.direction cell)
    (certificate.directionMember cell) _ _
    (certificate.directionExact cell).1 (certificate.directionExact cell).2

/-- The exact family16 CSR attempts bind all sixteen words of each Merkle
compression initial state: seven left, seven right, domain, suite marker. -/
theorem accepted_initial_word
    {components : RelationProgramComponents}
    (certificate : FrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (cell : InitialCell) :
    packed.getD (hashInitialIndex (callAt cell.1.val) cell.2.val) 0 =
      if cell.2.val < 14 then
        packed.getD
          (inlineIndex cell.1.val (cell.2.val % 7)
            (if cell.2.val < 7 then 1 else 2)) 0
      else if cell.2.val = 14 then poseidon2V8MerkleDomain
      else poseidon2V8SuiteMarker := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have one : (values.getD 1 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated certificate.one
  have negative : (values.getD 160 0 : Goldilocks) = -1 := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated certificate.negative
  have zero : (values.getD 0 0 : Goldilocks) = 0 := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated certificate.zero
  have domain : (values.getD 130 0 : Goldilocks) =
      (poseidon2V8MerkleDomain : Goldilocks) := by
    simpa [SourceTerm.eval, poseidon2V8MerkleDomain] using
      csr_node_value certificate.canonical evaluated certificate.domain
  have suite : (values.getD 541 0 : Goldilocks) =
      (poseidon2V8SuiteMarker : Goldilocks) := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated certificate.suite
  have oneOption : ((values[1]?.getD 0 : Nat) : Goldilocks) = 1 := by
    simpa only [List.getD_eq_getElem?_getD] using one
  have negativeOption : ((values[160]?.getD 0 : Nat) : Goldilocks) = -1 := by
    simpa only [List.getD_eq_getElem?_getD] using negative
  have zeroOption : ((values[0]?.getD 0 : Nat) : Goldilocks) = 0 := by
    simpa only [List.getD_eq_getElem?_getD] using zero
  have domainOption : ((values[130]?.getD 0 : Nat) : Goldilocks) =
      (poseidon2V8MerkleDomain : Goldilocks) := by
    simpa only [List.getD_eq_getElem?_getD] using domain
  have suiteOption : ((values[541]?.getD 0 : Nat) : Goldilocks) =
      (poseidon2V8SuiteMarker : Goldilocks) := by
    simpa only [List.getD_eq_getElem?_getD] using suite
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (certificate.initialMember cell))
  rw [(certificate.initialExact cell).1,
    (certificate.initialExact cell).2] at equation
  by_cases payload : cell.2.val < 14
  · have castEq :
        (packed.getD (hashInitialIndex (callAt cell.1.val) cell.2.val) 0 :
            Goldilocks) =
      (packed.getD
          (inlineIndex cell.1.val (cell.2.val % 7)
              (if cell.2.val < 7 then 1 else 2)) 0 : Goldilocks) := by
      simp [initialTerms, initialTarget, payload, csrFieldSum,
        oneOption, negativeOption, zeroOption] at equation
      have optionCopy :
          ((packed[hashInitialIndex (callAt cell.1.val) cell.2.val]?.getD 0 : Nat) : Goldilocks) =
            ((packed[inlineIndex cell.1.val (cell.2.val % 7)
              (if cell.2.val < 7 then 1 else 2)]?.getD 0 : Nat) : Goldilocks) := by
        linear_combination equation
      simpa only [List.getD_eq_getElem?_getD] using optionCopy
    rw [if_pos payload]
    exact canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 _)
      (packed_word_canonical accepted.2.1 _) castEq
  · by_cases domainLane : cell.2.val = 14
    · have castEq :
      (packed.getD (hashInitialIndex (callAt cell.1.val) cell.2.val) 0 :
          Goldilocks) = (poseidon2V8MerkleDomain : Goldilocks) := by
        simp [initialTerms, initialTarget, domainLane,
          csrFieldSum, oneOption, domainOption] at equation
        simpa only [domainLane, List.getD_eq_getElem?_getD] using equation
      rw [if_neg payload, if_pos domainLane]
      exact canonical_nat_cast_injective
        (packed_word_canonical accepted.2.1 _) (by decide) castEq
    · have castEq :
      (packed.getD (hashInitialIndex (callAt cell.1.val) cell.2.val) 0 :
          Goldilocks) = (poseidon2V8SuiteMarker : Goldilocks) := by
        simp [initialTerms, initialTarget, payload, domainLane,
          csrFieldSum, oneOption, suiteOption] at equation
        simpa only [List.getD_eq_getElem?_getD] using equation
      rw [if_neg payload, if_neg domainLane]
      exact canonical_nat_cast_injective
        (packed_word_canonical accepted.2.1 _) (by decide) castEq

end HegemonCrypto.SmallWood.SmzaRp05MerkleFrameCertificate
