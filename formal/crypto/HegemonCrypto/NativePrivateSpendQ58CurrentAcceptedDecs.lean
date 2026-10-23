import SmzaRp05ExecutablePcsClosureMcaAlgebra
import HegemonCrypto.NativePrivateSpendQ58CurrentGeometry

/-!
# Current SMZD verifier restoration: five rows, 58 queried positions

SOURCE-ONLY DRAFT. The source interpreter follows the retained PR205 trust
contract. Only the opened-count parameter changes; the original interpolation
and emitted-coefficient proofs are reused. The current native instance fixes
58 samples, 140 data rows and 13115 high coefficients. Arbitrary adversarial
rows/masks/highs are allowed. These theorems derive equations and degree from
the successful verifier computation. They do not prove the prequery committed
table extraction or complete accepted-invalid soundness.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedDecs

open Polynomial
open SmzaRp05DecsResponseProjection
open SmzaRp05ExecutablePcsClosureAlgebra
open SmzaRp05ExecutablePcsClosureDecsChecks (sourceEvaluation)
open SmzaRp05ExecutablePcsClosureMcaAlgebra (dec_evaluation_success_equation)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open scoped BigOperators

set_option autoImplicit false
noncomputable section

private theorem mapM_success_getD {α β : Type}
    (xs : List α) (f : α → Option β) (values : List β)
    (sourceFallback : α) (valueFallback : β)
    (success : xs.mapM f = some values) :
    values.length = xs.length ∧
      ∀ index, index < xs.length →
        f (xs.getD index sourceFallback) = some (values.getD index valueFallback) := by
  induction xs generalizing values with
  | nil =>
      simp at success
      subst values
      simp
  | cons x rest ih =>
      cases hx : f x with
      | none => simp [List.mapM_cons, hx] at success
      | some value =>
          cases hrest : rest.mapM f with
          | none => simp [List.mapM_cons, hx, hrest] at success
          | some tail =>
              simp [List.mapM_cons, hx, hrest] at success
              subst values
              obtain ⟨length_eq, entry_eq⟩ := ih tail hrest
              constructor
              · simp [length_eq]
              · intro index hindex
                cases index with
                | zero => simpa using hx
                | succ index =>
                    have htail : index < rest.length := by simpa using hindex
                    simpa using entry_eq index htail

private theorem getD_injective_on_range (points : FieldRow) (distinct : points.Nodup) :
    Set.InjOn (fun i => points.getD i 0) (Finset.range points.length) := by
  intro i hi j hj equal
  exact (List.getD_inj (Finset.mem_range.mp hi) (Finset.mem_range.mp hj) distinct).mp equal

def restoreAt (openedCount : Nat) (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (polynomialIndex : Nat) : Option FieldRow := do
  let values ← (List.range openedCount).mapM (sourceEvaluation fields lvcsRows gamma polynomialIndex)
  polyRestoreResponse (decodeFieldRow evalPoints) values
    (decodeFieldRow (fields.highCoeffs.getD polynomialIndex []))

/-- The retained source restoration with only the opened-count boundary made
explicit. Its dimensions and point distinctness are successful verifier-stage
checks; there is no witness-satisfaction or response-agreement certificate. -/
def restoreResponses (openedCount : Nat) (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) : Option (List FieldRow) := do
  if fields.highCoeffs.length ≠ 5 ∨ fields.maskingEvals.length ≠ openedCount ∨
      evalPoints.length ≠ openedCount ∨ gamma.length ≠ 5 ∨ lvcsRows.length ≠ openedCount ∨
      fields.maskingEvals.any (fun row => decide (row.length ≠ 5)) ∨
      gamma.any (fun row => decide (row.length ≠ rowCount)) ∨
      lvcsRows.any (fun row => decide (row.length ≠ rowCount)) ∨
      fields.highCoeffs.any (fun row => decide (row.length ≠ highCount))
    then none else pure ()
  let points := decodeFieldRow evalPoints
  if points.length ≠ openedCount then none else pure ()
  if !decide points.Nodup then none else pure ()
  (List.range 5).mapM (restoreAt openedCount fields lvcsRows gamma evalPoints)

/-- All mapM branches and the distinctness premise come from the native
success equation itself. No response-polynomial success is supplied. -/
theorem restore_response_exposes_branches
    (openedCount : Nat) (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (polynomials : List FieldRow)
    (success : restoreResponses openedCount fields lvcsRows gamma evalPoints
      rowCount highCount = some polynomials) :
    (decodeFieldRow evalPoints).length = openedCount ∧
    (decodeFieldRow evalPoints).Nodup ∧ polynomials.length = 5 ∧
      ∀ polynomialIndex, polynomialIndex < 5 →
        restoreAt openedCount fields lvcsRows gamma evalPoints polynomialIndex =
          some (polynomials.getD polynomialIndex []) := by
  let shapeFailure := fields.highCoeffs.length ≠ 5 ∨ fields.maskingEvals.length ≠ openedCount ∨
    evalPoints.length ≠ openedCount ∨ gamma.length ≠ 5 ∨ lvcsRows.length ≠ openedCount ∨
    fields.maskingEvals.any (fun row => decide (row.length ≠ 5)) ∨
    gamma.any (fun row => decide (row.length ≠ rowCount)) ∨
    lvcsRows.any (fun row => decide (row.length ≠ rowCount)) ∨
    fields.highCoeffs.any (fun row => decide (row.length ≠ highCount))
  have shape : ¬ shapeFailure := by
    have expanded := success
    simp [restoreResponses] at expanded
    have ⟨highLength, maskingLength, pointLength, gammaLength, lvcsLength,
      maskingRows, gammaRows, lvcsRowsGood, highRows⟩ := expanded.1
    intro failed
    rcases failed with bad | failed
    · exact bad highLength
    rcases failed with bad | failed
    · exact bad maskingLength
    rcases failed with bad | failed
    · exact bad pointLength
    rcases failed with bad | failed
    · exact bad gammaLength
    rcases failed with bad | failed
    · exact bad lvcsLength
    rcases failed with bad | failed
    · obtain ⟨row, member, rowBad⟩ := List.any_eq_true.mp bad
      exact (of_decide_eq_true rowBad) (maskingRows row member)
    rcases failed with bad | failed
    · obtain ⟨row, member, rowBad⟩ := List.any_eq_true.mp bad
      exact (of_decide_eq_true rowBad) (gammaRows row member)
    rcases failed with bad | failed
    · obtain ⟨row, member, rowBad⟩ := List.any_eq_true.mp bad
      exact (of_decide_eq_true rowBad) (lvcsRowsGood row member)
    · obtain ⟨row, member, rowBad⟩ := List.any_eq_true.mp failed
      exact (of_decide_eq_true rowBad) (highRows row member)
  have length : (decodeFieldRow evalPoints).length = openedCount := by
    by_contra failed
    have rejected : restoreResponses openedCount fields lvcsRows gamma evalPoints
        rowCount highCount = none := by
      simp [restoreResponses, failed]
    rw [rejected] at success
    cases success
  have distinct : (decodeFieldRow evalPoints).Nodup := by
    by_contra failed
    simp [restoreResponses, length, failed] at success
  have mapped : (List.range 5).mapM
      (restoreAt openedCount fields lvcsRows gamma evalPoints) = some polynomials := by
    have expanded := success
    unfold restoreResponses at expanded
    simp only [shapeFailure, shape, length, distinct, decide_true,
      if_false] at expanded
    simpa using expanded
  obtain ⟨count, each⟩ := mapM_success_getD (List.range 5)
    (restoreAt openedCount fields lvcsRows gamma evalPoints) polynomials 0 [] mapped
  refine ⟨length, distinct, by simpa using count, ?_⟩
  intro polynomialIndex bound
  simpa [bound] using each polynomialIndex (by simpa using bound)

/-- Shape premises used by downstream source algebra are consequences of the
exact restoration-success branch, not extra verifier guards. -/
theorem restore_response_shape_facts
    (openedCount : Nat) (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (polynomials : List FieldRow)
    (success : restoreResponses openedCount fields lvcsRows gamma evalPoints
      rowCount highCount = some polynomials) :
    fields.highCoeffs.length = 5 ∧ fields.maskingEvals.length = openedCount ∧
    evalPoints.length = openedCount ∧ gamma.length = 5 ∧ lvcsRows.length = openedCount ∧
    (∀ row, row ∈ fields.maskingEvals → row.length = 5) ∧
    (∀ row, row ∈ gamma → row.length = rowCount) ∧
    (∀ row, row ∈ lvcsRows → row.length = rowCount) ∧
    (∀ row, row ∈ fields.highCoeffs → row.length = highCount) := by
  have expanded := success
  simp [restoreResponses] at expanded
  rcases expanded.1 with ⟨highLength, maskingLength, pointLength, gammaLength,
    lvcsLength, maskingRows, gammaRows, lvcsRowsGood, highRows⟩
  exact ⟨highLength, maskingLength, pointLength, gammaLength, lvcsLength,
    maskingRows, gammaRows, lvcsRowsGood, highRows⟩

/-- Exact five-by-openedCount native equations, obtained from one ordinary successful
DECS restoration. The left side is the original `decEvaluation` computation;
the right side evaluates precisely the source-emitted coefficient row. -/
theorem restore_success_has_five_source_checks
    (openedCount : Nat) (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (polynomials : List FieldRow)
    (success : restoreResponses openedCount fields lvcsRows gamma evalPoints
      rowCount highCount = some polynomials) :
    polynomials.length = 5 ∧
      ∀ polynomialIndex, polynomialIndex < 5 →
        ∀ evaluationIndex, evaluationIndex < openedCount →
          sourceEvaluation fields lvcsRows gamma polynomialIndex evaluationIndex =
            some ((coefficientPolynomial (polynomials.getD polynomialIndex [])).eval
              ((decodeFieldRow evalPoints).getD evaluationIndex 0)) := by
  obtain ⟨pointsLength, pointsDistinct, count, branches⟩ :=
    restore_response_exposes_branches openedCount fields lvcsRows gamma evalPoints
      rowCount highCount polynomials success
  refine ⟨count, ?_⟩
  intro polynomialIndex polynomialBound evaluationIndex evaluationBound
  have branch := branches polynomialIndex polynomialBound
  unfold restoreAt at branch
  cases valuesEq : (List.range openedCount).mapM
      (sourceEvaluation fields lvcsRows gamma polynomialIndex) with
  | none => simp [valuesEq] at branch
  | some values =>
      simp only [valuesEq] at branch
      obtain ⟨_valuesLength, valuesAt⟩ := mapM_success_getD (List.range openedCount)
        (sourceEvaluation fields lvcsRows gamma polynomialIndex) values 0 0 valuesEq
      have evaluation := successful_restore_evaluation (decodeFieldRow evalPoints)
        values (decodeFieldRow (fields.highCoeffs.getD polynomialIndex []))
        (polynomials.getD polynomialIndex []) branch
        (getD_injective_on_range _ pointsDistinct) evaluationIndex
        (by omega)
      rw [evaluation]
      simpa [evaluationBound] using valuesAt evaluationIndex (by simpa using evaluationBound)


/-- Current SMZD/COMPFF01 configuration, derived from 26210 source rows and
26230 unstacked rows: ceil(26230/2)=13115 LVCS columns; q=58. -/
def currentRestore (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord) :
    Option (List FieldRow) :=
  restoreResponses 58 fields rows gamma points 140 13115

/-- Current literal response lengths match the already checked current count
geometry. No old q38/degree405 or pre-COMPFF degree13169 type is reinterpreted. -/
theorem current_geometry_is_checked :
    NativePrivateSpendQ58CurrentGeometry.headColumns = 13115 ∧
    NativePrivateSpendQ58CurrentGeometry.decodedCoordinates = 13173 ∧
    NativePrivateSpendQ58CurrentGeometry.degree = 13172 :=
  NativePrivateSpendQ58CurrentGeometry.exact_geometry.2

/-- The actual verifier emits 5 coefficient vectors of length 58+13115.
Their high portions are the adversary's unchanged proof-carried coefficients. -/
theorem current_restore_emits_five_13173_rows
    (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord)
    (polynomials : List FieldRow)
    (success : currentRestore fields rows gamma points = some polynomials) :
    polynomials.length = 5 ∧
      ∀ k, k < 5 → (polynomials.getD k []).length = 13173 := by
  obtain ⟨pointLength, _pointNodup, count, branches⟩ :=
    restore_response_exposes_branches 58 fields rows gamma points 140 13115
      polynomials success
  have shapes := restore_response_shape_facts 58 fields rows gamma points
    140 13115 polynomials success
  refine ⟨count, ?_⟩
  intro k kBound
  have branch := branches k kBound
  unfold restoreAt at branch
  cases valuesBuilt : (List.range 58).mapM
      (sourceEvaluation fields rows gamma k) with
  | none => simp [valuesBuilt] at branch
  | some values =>
      simp only [valuesBuilt] at branch
      have highIndexBound : k < fields.highCoeffs.length := by
        rw [shapes.1]
        exact kBound
      have highMember : fields.highCoeffs.getD k [] ∈ fields.highCoeffs := by
        rw [List.getD_eq_getElem fields.highCoeffs [] highIndexBound]
        exact List.getElem_mem highIndexBound
      have highLength :
          (decodeFieldRow (fields.highCoeffs.getD k [])).length = 13115 := by
        simpa [decodeFieldRow] using shapes.2.2.2.2.2.2.2.2
          (fields.highCoeffs.getD k []) highMember
      have emitted := successful_restore_emits_expression
        (decodeFieldRow points) values
        (decodeFieldRow (fields.highCoeffs.getD k []))
        (polynomials.getD k []) branch
      rw [emitted.2]
      simp only [List.length_map, List.length_range]
      rw [pointLength, highLength]

/-- Degree bound is derived from the emitted coefficient list, rather than
requiring a well-formed `BoundedResponse` input. Zero is permitted. -/
theorem current_restore_degree_le_13172
    (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord)
    (polynomials : List FieldRow)
    (success : currentRestore fields rows gamma points = some polynomials) :
    ∀ k, k < 5 →
      (coefficientPolynomial (polynomials.getD k [])).natDegree ≤ 13172 := by
  have lengths := current_restore_emits_five_13173_rows fields rows gamma
    points polynomials success
  intro k kBound
  apply Polynomial.natDegree_le_iff_coeff_eq_zero.mpr
  intro degree above
  rw [coefficient_polynomial_coeff]
  have outside : ¬ degree < (polynomials.getD k []).length := by
    rw [lengths.2 k kBound]
    omega
  rw [List.getD_eq_getElem?_getD,
    List.getElem?_eq_none (Nat.le_of_not_gt outside)]
  rfl

private theorem masking_map_getD (rows : List (List FieldWord))
    (i k : Nat) :
    ((rows.map fun row =>
      ((row.getD k ⟨0, by decide⟩).val : Goldilocks)).getD i 0) =
      ((rows.getD i []).getD k ⟨0, by decide⟩).val := by
  induction rows generalizing i with
  | nil => cases i <;> rfl
  | cons head tail ih =>
      cases i with
      | zero => rfl
      | succ i => exact ih i

/-- Current 5-by-58 equations over the calculated LVCS rows and transmitted
masking cells. This is proved for every successful adversarial restoration;
no packed-witness validity, source-table agreement or collision exclusion is
an input. Rows/gamma/masks are the decoded outputs of the same verifier stage. -/
def CurrentOpenedEquations (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord)
    (polynomials : List FieldRow) : Prop :=
  ∀ k, k < 5 → ∀ i, i < 58 →
    (coefficientPolynomial (polynomials.getD k [])).eval
      ((decodeFieldRow points).getD i 0) =
      ((fields.maskingEvals.getD i []).getD k ⟨0, by decide⟩).val +
        ∑ column : Fin 140,
          (decodeFieldRow (gamma.getD k [])).getD column.val 0 *
          (decodeFieldRow (rows.getD i [])).getD column.val 0

theorem current_restore_opened_equations
    (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord)
    (polynomials : List FieldRow)
    (success : currentRestore fields rows gamma points = some polynomials) :
    CurrentOpenedEquations fields rows gamma points polynomials := by
  have checks := restore_success_has_five_source_checks 58 fields rows gamma
    points 140 13115 polynomials success
  have shapes := restore_response_shape_facts 58 fields rows gamma points
    140 13115 polynomials success
  intro k kBound i iBound
  have gammaIndexBound : k < gamma.length := by
    rw [shapes.2.2.2.1]
    exact kBound
  have gammaMember : gamma.getD k [] ∈ gamma := by
    rw [List.getD_eq_getElem gamma [] gammaIndexBound]
    exact List.getElem_mem gammaIndexBound
  have gammaLength : (decodeFieldRow (gamma.getD k [])).length = 140 := by
    simpa [decodeFieldRow] using shapes.2.2.2.2.2.2.1
      (gamma.getD k []) gammaMember
  have sourceCheck := checks.2 k kBound i iBound
  change decEvaluation (decodeFieldRow (rows.getD i []))
    (decodeFieldRow (gamma.getD k []))
    ((fields.maskingEvals.map fun row =>
      ((row.getD k ⟨0, by decide⟩).val : Goldilocks)).getD i 0) =
      some ((coefficientPolynomial (polynomials.getD k [])).eval
        ((decodeFieldRow points).getD i 0)) at sourceCheck
  have equation := dec_evaluation_success_equation
    (decodeFieldRow (rows.getD i [])) (decodeFieldRow (gamma.getD k []))
    ((fields.maskingEvals.map fun row =>
      ((row.getD k ⟨0, by decide⟩).val : Goldilocks)).getD i 0)
    ((coefficientPolynomial (polynomials.getD k [])).eval
      ((decodeFieldRow points).getD i 0)) sourceCheck
  rw [masking_map_getD, gammaLength] at equation
  have sumEq :
      (∑ column : Fin 140,
        (decodeFieldRow (gamma.getD k [])).getD column.val 0 *
        (decodeFieldRow (rows.getD i [])).getD column.val 0) =
      ∑ index ∈ Finset.range 140,
        (decodeFieldRow (gamma.getD k [])).getD index 0 *
        (decodeFieldRow (rows.getD i [])).getD index 0 := by
    rw [← Fin.sum_univ_eq_sum_range]
  change (coefficientPolynomial (polynomials.getD k [])).eval
      ((decodeFieldRow points).getD i 0) =
      ((fields.maskingEvals.getD i []).getD k ⟨0, by decide⟩).val + _
  rw [sumEq]
  exact equation

/-- Same raw transcript suffix the verifier feeds to hash_fpp/hash_piop:
8 digest-prefix words followed by all 5*13173 restored coefficient words.
The prefix is the already calculated root-domain hash, not a response input. -/
def currentTranscript (hashMtWords : List Nat) (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord) :
    Option (List Nat) := do
  let polynomials ← currentRestore fields rows gamma points
  pure (hashMtWords ++ polynomials.flatten.map (fun value => value.val))

/-- A successful physical-transcript construction supplies the internally
computed responses, their degrees and every opened DECS equation. The output
coefficient rows are existentially derived, never supplied as advice. -/
theorem current_transcript_derives_opened_checks
    (hashMtWords : List Nat) (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord)
    (transcriptWords : List Nat)
    (success : currentTranscript hashMtWords fields rows gamma points =
      some transcriptWords) :
    ∃ polynomials : List FieldRow,
      currentRestore fields rows gamma points = some polynomials ∧
      transcriptWords = hashMtWords ++ polynomials.flatten.map (fun value => value.val) ∧
      polynomials.length = 5 ∧
      (∀ k, k < 5 → (polynomials.getD k []).length = 13173) ∧
      (∀ k, k < 5 →
        (coefficientPolynomial (polynomials.getD k [])).natDegree ≤ 13172) ∧
      CurrentOpenedEquations fields rows gamma points polynomials := by
  unfold currentTranscript at success
  cases restored : currentRestore fields rows gamma points with
  | none => simp [restored] at success
  | some polynomials =>
      simp [restored] at success
      have lengths := current_restore_emits_five_13173_rows fields rows gamma
        points polynomials restored
      exact ⟨polynomials, rfl,
        by simpa only [List.map_flatten] using success.symm, lengths.1, lengths.2,
        current_restore_degree_le_13172 fields rows gamma points polynomials restored,
        current_restore_opened_equations fields rows gamma points polynomials restored⟩

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedDecs
