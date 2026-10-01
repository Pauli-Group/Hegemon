import SmzaRp05ExecutablePcsClosureAlgebra

/-!
# Five source DECS evaluations from successful list restoration

This theorem removes the per-polynomial success premises: the original
`restoredResponsePolynomials` computation supplies every mapM result, the
point distinctness check, and each actual returned coefficient row. It proves
the source five-by-38 evaluation equations. Matching these source rows to
canonical authenticated leaf cells and to the role-decoded response remains
a separate serialization/readback step.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureDecsChecks

open SmzaRp05DecsResponseProjection
open SmzaRp05ExecutablePcsClosureAlgebra
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawDigest)

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

def sourceEvaluation (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (polynomialIndex evaluationIndex : Nat) :
    Option Goldilocks :=
  let gammaRow := decodeFieldRow (gamma.getD polynomialIndex [])
  let maskingRow := fields.maskingEvals.map fun row =>
    (row.getD polynomialIndex ⟨0, by decide⟩).val
  let row := decodeFieldRow (lvcsRows.getD evaluationIndex [])
  decEvaluation row gammaRow (maskingRow.getD evaluationIndex 0)

def sourceRestore (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (polynomialIndex : Nat) : Option FieldRow := do
  let values ← (List.range 38).mapM (sourceEvaluation fields lvcsRows gamma polynomialIndex)
  polyRestoreResponse (decodeFieldRow evalPoints) values
    (decodeFieldRow (fields.highCoeffs.getD polynomialIndex []))

/-- All mapM branches and the distinctness premise come from the native
success equation itself. No response-polynomial success is supplied. -/
theorem restored_response_exposes_branches
    (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (polynomials : List FieldRow)
    (success : restoredResponsePolynomials fields lvcsRows gamma evalPoints
      rowCount highCount = some polynomials) :
    (decodeFieldRow evalPoints).length = 38 ∧
    (decodeFieldRow evalPoints).Nodup ∧ polynomials.length = 5 ∧
      ∀ polynomialIndex, polynomialIndex < 5 →
        sourceRestore fields lvcsRows gamma evalPoints polynomialIndex =
          some (polynomials.getD polynomialIndex []) := by
  let shapeFailure := fields.highCoeffs.length ≠ 5 ∨ fields.maskingEvals.length ≠ 38 ∨
    evalPoints.length ≠ 38 ∨ gamma.length ≠ 5 ∨ lvcsRows.length ≠ 38 ∨
    fields.maskingEvals.any (fun row => decide (row.length ≠ 5)) ∨
    gamma.any (fun row => decide (row.length ≠ rowCount)) ∨
    lvcsRows.any (fun row => decide (row.length ≠ rowCount)) ∨
    fields.highCoeffs.any (fun row => decide (row.length ≠ highCount))
  have shape : ¬ shapeFailure := by
    have expanded := success
    simp [restoredResponsePolynomials] at expanded
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
  have length : (decodeFieldRow evalPoints).length = 38 := by
    by_contra failed
    have rejected : restoredResponsePolynomials fields lvcsRows gamma evalPoints
        rowCount highCount = none := by
      simp [restoredResponsePolynomials, failed]
    rw [rejected] at success
    cases success
  have distinct : (decodeFieldRow evalPoints).Nodup := by
    by_contra failed
    simp [restoredResponsePolynomials, length, failed] at success
  have mapped : (List.range 5).mapM
      (sourceRestore fields lvcsRows gamma evalPoints) = some polynomials := by
    have expanded := success
    unfold restoredResponsePolynomials at expanded
    simp only [shapeFailure, shape, length, distinct, decide_true,
      if_false] at expanded
    exact expanded
  obtain ⟨count, each⟩ := mapM_success_getD (List.range 5)
    (sourceRestore fields lvcsRows gamma evalPoints) polynomials 0 [] mapped
  refine ⟨length, distinct, by simpa using count, ?_⟩
  intro polynomialIndex bound
  simpa [bound] using each polynomialIndex (by simpa using bound)

/-- Shape premises used by downstream source algebra are consequences of the
exact restoration-success branch, not extra verifier guards. -/
theorem restored_response_shape_facts
    (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (polynomials : List FieldRow)
    (success : restoredResponsePolynomials fields lvcsRows gamma evalPoints
      rowCount highCount = some polynomials) :
    fields.highCoeffs.length = 5 ∧ fields.maskingEvals.length = 38 ∧
    evalPoints.length = 38 ∧ gamma.length = 5 ∧ lvcsRows.length = 38 ∧
    (∀ row, row ∈ fields.maskingEvals → row.length = 5) ∧
    (∀ row, row ∈ gamma → row.length = rowCount) ∧
    (∀ row, row ∈ lvcsRows → row.length = rowCount) ∧
    (∀ row, row ∈ fields.highCoeffs → row.length = highCount) := by
  have expanded := success
  simp [restoredResponsePolynomials] at expanded
  rcases expanded.1 with ⟨highLength, maskingLength, pointLength, gammaLength,
    lvcsLength, maskingRows, gammaRows, lvcsRowsGood, highRows⟩
  exact ⟨highLength, maskingLength, pointLength, gammaLength, lvcsLength,
    maskingRows, gammaRows, lvcsRowsGood, highRows⟩

/-- Exact five-by-38 native equations, obtained from one ordinary successful
DECS restoration. The left side is the original `decEvaluation` computation;
the right side evaluates precisely the source-emitted coefficient row. -/
theorem successful_response_has_five_source_checks
    (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (polynomials : List FieldRow)
    (success : restoredResponsePolynomials fields lvcsRows gamma evalPoints
      rowCount highCount = some polynomials) :
    polynomials.length = 5 ∧
      ∀ polynomialIndex, polynomialIndex < 5 →
        ∀ evaluationIndex, evaluationIndex < 38 →
          sourceEvaluation fields lvcsRows gamma polynomialIndex evaluationIndex =
            some ((coefficientPolynomial (polynomials.getD polynomialIndex [])).eval
              ((decodeFieldRow evalPoints).getD evaluationIndex 0)) := by
  obtain ⟨pointsLength, pointsDistinct, count, branches⟩ :=
    restored_response_exposes_branches fields lvcsRows gamma evalPoints
      rowCount highCount polynomials success
  refine ⟨count, ?_⟩
  intro polynomialIndex polynomialBound evaluationIndex evaluationBound
  have branch := branches polynomialIndex polynomialBound
  unfold sourceRestore at branch
  cases valuesEq : (List.range 38).mapM
      (sourceEvaluation fields lvcsRows gamma polynomialIndex) with
  | none => simp [valuesEq] at branch
  | some values =>
      simp only [valuesEq] at branch
      obtain ⟨_valuesLength, valuesAt⟩ := mapM_success_getD (List.range 38)
        (sourceEvaluation fields lvcsRows gamma polynomialIndex) values 0 0 valuesEq
      have evaluation := successful_restore_evaluation (decodeFieldRow evalPoints)
        values (decodeFieldRow (fields.highCoeffs.getD polynomialIndex []))
        (polynomials.getD polynomialIndex []) branch
        (getD_injective_on_range _ pointsDistinct) evaluationIndex
        (by omega)
      rw [evaluation]
      simpa [evaluationBound] using valuesAt evaluationIndex (by simpa using evaluationBound)

/-- Successful construction of the actual hash-fpp query entails successful
DECS restoration; the polynomial rows are internal outputs of that same
program construction, not additional verifier inputs. -/
theorem successful_hash_fpp_program_has_restoration
    (hashMt : RawDigest) (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (statementBinding : List Nat)
    (program : Program RawDigest)
    (success : hashFppProgram hashMt fields lvcsRows gamma evalPoints
      rowCount highCount statementBinding = some program) :
    ∃ polynomials,
      restoredResponsePolynomials fields lvcsRows gamma evalPoints
        rowCount highCount = some polynomials := by
  unfold hashFppProgram responseTranscriptWords at success
  cases restored : restoredResponsePolynomials fields lvcsRows gamma evalPoints
      rowCount highCount with
  | none => simp [restored] at success
  | some polynomials => exact ⟨polynomials, rfl⟩

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureDecsChecks
