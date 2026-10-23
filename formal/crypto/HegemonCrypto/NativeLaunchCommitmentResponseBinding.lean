import HegemonCrypto.NativeLaunchCommitmentReadback

/-! Exact restoration/serialization correspondence, not accepted execution.
The engine checks a final PIOP digest; it has no direct prior coefficient guard.
Historical raw-input binding, collision exclusions, authenticated chronology,
source geometry/refinement, simulation and release authority remain external. -/
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchCommitmentResponseBinding
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Word)
open NativeLaunchRelationModelStatement
open NativeLaunchCommitmentReadback
open SmallWood
open SmallWood.NativeLaunchRelationModelResponse
open SmallWood.SmzaRp05ExecutablePcsClosureAlgebra (coefficientPolynomial coefficient_polynomial_coeff)
open SmallWood.V8Smz9McaRecovery (BoundedResponse)
open SmallWood.V8Smz9RawCounterCompiler (typedWordPayload)
noncomputable section

/-- Fixed-width row partition; no polynomial or correctness flag is supplied. -/
def splitRows {α : Type*} : Nat → Nat → List α → List (List α)
  | 0, _, _ => []
  | n+1, width, fields => fields.take width :: splitRows n width (fields.drop width)

theorem split_rows_roundtrip {α : Type*} {width : Nat} (rows : List (Fin width → α)) :
    splitRows rows.length width (rows.flatMap List.ofFn) = rows.map List.ofFn := by
  induction rows with
  | nil => rfl
  | cons row rows ih =>
    simp only [List.length_cons, List.flatMap_cons, splitRows, List.map_cons]
    have size : (List.ofFn row).length = width := List.length_ofFn
    have takeRow : (List.ofFn row ++ rows.flatMap List.ofFn).take (List.ofFn row).length =
        List.ofFn row := List.take_left
    have dropRow : (List.ofFn row ++ rows.flatMap List.ofFn).drop (List.ofFn row).length =
        rows.flatMap List.ofFn := List.drop_left
    rw [size] at takeRow dropRow
    rw [takeRow, dropRow, ih]

theorem commitment_rows_recovered {branch : Branch} (c : Commitment branch) :
    splitRows 5 (degree branch + 1) (coefficientList c) =
      List.ofFn (fun row => List.ofFn (c.coefficients row)) := by
  have result := split_rows_roundtrip (List.ofFn c.coefficients)
  simpa only [List.length_ofFn, List.map_ofFn, coefficientList, Function.comp_def] using result

def canonicalField (value : Goldilocks) : FieldWord := ⟨value.val, value.val_lt⟩
def interpretField (value : FieldWord) : Goldilocks := (value.val : Goldilocks)

theorem canonical_field_roundtrip (value : Goldilocks) :
    interpretField (canonicalField value) = value := by
  exact ZMod.natCast_zmod_val value

def restoredCommitment {branch : Branch} {Position : Type*}
    (root : Fin 8 → Word) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix) :
    Commitment branch where
  root := root
  statement := statement
  coefficients := fun row index => canonicalField
    ((restoredWords point wire matrix row)[index.val]'(by
      rw [restored_words_length]; exact index.isLt))

/-- Interpret exactly the five consecutive complete decoded rows. -/
def decodedResponse (branch : Branch) (fields : List FieldWord) :
    BoundedResponse Goldilocks (Fin 5) (degree branch) := fun row =>
  (Polynomial.degreeLTEquiv Goldilocks (degree branch + 1)).symm (fun index =>
    interpretField (((splitRows 5 (degree branch + 1) fields).getD row.val []).getD index.val 0))

theorem decoded_commitment_coefficients {branch : Branch} (c : Commitment branch)
    (row : Fin 5) (index : Fin (degree branch + 1)) :
    (Polynomial.degreeLTEquiv Goldilocks (degree branch + 1))
      (decodedResponse branch (coefficientList c) row) index =
      interpretField (c.coefficients row index) := by
  simp only [decodedResponse, LinearEquiv.apply_symm_apply, commitment_rows_recovered,
    List.getD_eq_getElem?_getD, List.getElem?_ofFn, dif_pos row.isLt,
    dif_pos index.isLt, Option.getD_some]

/-- All coefficient positions, hence the full bounded polynomials, agree with
actual restoration. No response-equality premise is used. -/
theorem constructed_response_is_calculated {branch : Branch} {Position : Type*}
    (root : Fin 8 → Word) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix) :
    decodedResponse branch (coefficientList (restoredCommitment root statement point wire matrix)) =
      calculatedResponse point wire matrix := by
  funext row
  apply (Polynomial.degreeLTEquiv Goldilocks (degree branch + 1)).injective
  funext index
  rw [decoded_commitment_coefficients]
  change interpretField (canonicalField _) =
    (coefficientPolynomial (restoredWords point wire matrix row)).coeff index.val
  rw [canonical_field_roundtrip, coefficient_polynomial_coeff]
  have bound : index.val < (restoredWords point wire matrix row).length := by
    rw [restored_words_length]; exact index.isLt
  simp [List.getD_eq_getElem?_getD, bound]

structure DecodedCommitment (branch : Branch) where
  root : List Byte
  statement : List Byte
  response : BoundedResponse Goldilocks (Fin 5) (degree branch)

def decodeFppResponse (branch : Branch) (raw : List Byte) : Option (DecodedCommitment branch) := do
  let (root, coefficients, statement) ← parseCommitment branch raw
  some ⟨root, statement, decodedResponse branch coefficients⟩

/-- Unconditional literal decoder/constructor identity preserving the complete
root and statement, with the response computed from the actual restored rows. -/
theorem decode_restored_commitment {branch : Branch} {Position : Type*}
    (root : Fin 8 → Word) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix) :
    decodeFppResponse branch (frame (restoredCommitment root statement point wire matrix)) =
      some ⟨typedWordPayload (List.ofFn root), statementBytes statement,
        calculatedResponse point wire matrix⟩ := by
  simp only [decodeFppResponse, complete_readback]
  change some (DecodedCommitment.mk _ _
    (decodedResponse branch (coefficientList (restoredCommitment root statement point wire matrix)))) = _
  rw [constructed_response_is_calculated]
  rfl

/-- Raw address equality is explicit. This is not derived from acceptance,
output-hash equality or a prequery record assumption. -/
theorem raw_key_equality_binds_response {branch : Branch} {Position : Type*}
    (root : Fin 8 → Word) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix)
    (prior : List Byte)
    (sameKey : prior = frame (restoredCommitment root statement point wire matrix)) :
    decodeFppResponse branch prior =
      some ⟨typedWordPayload (List.ofFn root), statementBytes statement,
        calculatedResponse point wire matrix⟩ := by
  rw [sameKey]
  exact decode_restored_commitment root statement point wire matrix

/-- Full parsed coefficient-list equality also suffices; no desired polynomial
equality or supplied correctness Boolean is consumed. -/
theorem complete_coefficients_bind_response {branch : Branch} {Position : Type*}
    (root : Fin 8 → Word) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix)
    (fields : List FieldWord)
    (sameFields : fields = coefficientList (restoredCommitment root statement point wire matrix)) :
    decodedResponse branch fields = calculatedResponse point wire matrix := by
  rw [sameFields]
  exact constructed_response_is_calculated root statement point wire matrix
end
end HegemonCrypto.NativeLaunchCommitmentResponseBinding
