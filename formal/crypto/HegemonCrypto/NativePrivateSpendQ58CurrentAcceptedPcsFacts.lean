import HegemonCrypto.NativePrivateSpendQ58CurrentExecutableVerifier
import SmzaRp05CurrentTwelveCalculated

/-! Derived current PCS facts. Every stage output and success equation follows
from ONE ordinary PCS execution. The native residual computation is not
replaced by an assumed twelve-check certificate. No physical prior-table or
accepted-invalid mass assertion is made by this component. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedPcsFacts

open NativePrivateSpendQ58CurrentExecutableVerifier
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutableChallengeStage (FieldWord returnedWords pendingFailure digestWords)
open SmzaRp05PcsWireProjection (DecodedPcsFields fieldWordsToGoldilocks)
open SmzaRp05LvcsWireProjection
open SmzaRp05ExecutablePcsClosureLvcsAlgebra
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false

/-- The existential values are native intermediate outputs, extracted after
acceptance rather than supplied as mathematical acceptance premises. -/
def PcsFacts (ns : CM.Namespace) (pending : Bool) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) (oracle : Oracle)
    (output : PcsOutput) : Prop :=
  ∃ openingDigest sampledPending sampled,
    SmzaRp05PcsWireProjection.reconstructedHeadsAll decoded.pcs
      (List.ofFn (points opening)) decoded.rowScalars 64 widths deltas 2 13115 =
        some output.heads ∧
    oracle (decsInput wire.hPiop output.heads
      (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)) = openingDigest ∧
    (queryProgram pending openingDigest).eval oracle = some (output.indexes, sampledPending) ∧
    SmzaRp05DecsPointProjection.fieldPoints 13173 output.indexes = some output.decsPoints ∧
    reconstructRowsFromPcsFields decoded.pcs (List.ofFn (points opening)) output.decsPoints
      decoded.rowScalars 64 widths deltas 2 13115 140 58 = some output.rows ∧
    makeMerkleInput wire.salt ns.binding sampledPending output.indexes output.rows
      decoded.decs.maskingEvals wire.tapes wire.paths = some output.input ∧
    (CM.merkleProgram ns output.input).eval oracle = some output.root ∧
    (fieldXof .decsMatrix 700 output.root).eval oracle = some sampled ∧
    gammaRows (returnedWords 700 sampled) = output.gamma ∧
    AD.currentRestore decoded.decs
      (output.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord) =
        some output.polynomials ∧
    (RR.sourceHashProgram (digestWords output.root) decoded.decs
      (output.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord)
      (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val)).eval oracle =
        some output.hashFpp ∧
    pendingFailure sampledPending sampled = output.pending

theorem pcs_execution_has_actual_facts (ns : CM.Namespace) (pending : Bool) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    PcsFacts ns pending wire decoded opening oracle output := by
  cases headEq : SmzaRp05PcsWireProjection.reconstructedHeadsAll decoded.pcs
      (List.ofFn (points opening)) decoded.rowScalars 64 widths deltas 2 13115 with
  | none => simp only [pcsProgram, headEq, Program.eval] at executed; cases executed
  | some heads =>
      by_cases bad : heads.length ≠ 12 ∨ decoded.pcs.rcombiTails.length ≠ 12 ∨
          heads.any (fun row => decide (row.length ≠ 13115)) ∨
          decoded.pcs.rcombiTails.any (fun row => decide (row.length ≠ 58))
      · simp only [pcsProgram, headEq, if_pos bad, Program.eval] at executed
        cases executed
      · simp only [pcsProgram, headEq, if_neg bad] at executed
        obtain ⟨openingDigest, _hashExecuted, afterHash⟩ :=
          SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
            (ask (decsInput wire.hPiop heads
              (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks))) _ output executed
        obtain ⟨query, _queryExecuted, afterQuery⟩ :=
          SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
            (queryProgram pending openingDigest) _ output afterHash
        rcases query with ⟨indexes, sampledPending⟩
        cases pointEq : SmzaRp05DecsPointProjection.fieldPoints 13173 indexes with
        | none => simp only [pointEq, Program.eval] at afterQuery; cases afterQuery
        | some decsPoints =>
          simp only [pointEq] at afterQuery
          cases rowEq : SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields decoded.pcs
              (List.ofFn (points opening)) decsPoints decoded.rowScalars 64 widths deltas
              2 13115 140 58 with
          | none => simp only [rowEq, Program.eval] at afterQuery; cases afterQuery
          | some rows =>
            simp only [rowEq] at afterQuery
            cases inputEq : makeMerkleInput wire.salt ns.binding sampledPending indexes rows
                decoded.decs.maskingEvals wire.tapes wire.paths with
            | none => simp only [inputEq, Program.eval] at afterQuery; cases afterQuery
            | some input =>
              simp only [inputEq] at afterQuery
              obtain ⟨root, _rootExecuted, afterRoot⟩ :=
                SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
                  (CM.merkleProgram ns input) _ output afterQuery
              obtain ⟨sampled, _gammaExecuted, afterGamma⟩ :=
                SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
                  (fieldXof .decsMatrix 700 root) _ output afterRoot
              let gamma := gammaRows (returnedWords 700 sampled)
              let pointWords := decsPoints.map SmzaRp05ExecutableRestore.toWord
              let rowWords := rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord
              change
                (match AD.currentRestore decoded.decs rowWords gamma pointWords with
                 | none => (.done none : Program PcsOutput)
                 | some polynomials =>
                     (RR.sourceHashProgram (digestWords root) decoded.decs
                       rowWords gamma pointWords
                       (List.ofFn fun i : Fin 77 =>
                         V8SmzaOracleParser.wordAt ns.binding i.val)).bind fun hashFpp =>
                       .done (some ⟨heads, indexes, decsPoints, rows, input, root,
                         gamma, polynomials, hashFpp,
                         pendingFailure sampledPending sampled⟩)).eval oracle =
                  some output at afterGamma
              generalize restoreEq :
                AD.currentRestore decoded.decs rowWords gamma pointWords =
                  restored at afterGamma
              cases restored with
              | none =>
                change (none : Option PcsOutput) = some output at afterGamma
                cases afterGamma
              | some polynomials =>
                obtain ⟨hashFpp, _fppExecuted, returned⟩ :=
                  SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
                    (RR.sourceHashProgram (digestWords root) decoded.decs rowWords gamma pointWords
                      (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val))
                    _ output afterGamma
                have same :
                    (⟨heads, indexes, decsPoints, rows, input, root, gamma, polynomials,
                      hashFpp, pendingFailure sampledPending sampled⟩ : PcsOutput) = output :=
                  Option.some.inj returned
                rw [← same]
                refine ⟨openingDigest, sampledPending, sampled, headEq, ?_,
                  _queryExecuted, pointEq, rowEq, inputEq, _rootExecuted,
                  _gammaExecuted, rfl, restoreEq, _fppExecuted, rfl⟩
                apply Option.some.inj
                simpa only [ask, Program.eval] using _hashExecuted


/-- Current 13115 heads and58 tails, reusing the unchanged generic split/merge algebra. -/
theorem reconstruct_rows_current_full_dot
    (fields : DecodedPcsFields) (points decsPoints : List F)
    (pointCount : points.length = 6) (rowScalars : List (List FieldWord))
    (widths deltas : List Nat) (rows : FMatrix)
    (success : reconstructRowsFromPcsFields fields points decsPoints rowScalars
      64 widths deltas 2 13115 140 58 = some rows) :
    ∃ heads inverse,
      reconstructAllHeads fields points rowScalars 64 widths deltas 2 13115 = some heads ∧
      gaussInverse 12
        (splitCoefficientMatrix pivotColumns (pcsBuildCoefficients points 2 64 140)).1 =
          some inverse ∧
      rows.length = decsPoints.length ∧
      ∀ j, j < decsPoints.length → ∀ k, k < 12 →
        dot ((pcsBuildCoefficients points 2 64 140).getD k []) (rows.getD j []) =
          evaluateConsecutive
            (rotateLeft ((heads.getD k []) ++
              ((fields.rcombiTails.map fieldWordsToGoldilocks).getD k [])) 13115)
            (decsPoints.getD j 0) := by
  cases headsBuilt : reconstructAllHeads fields points rowScalars 64 widths deltas 2 13115 with
  | none => simp [reconstructRowsFromPcsFields, pointCount, headsBuilt] at success
  | some heads =>
      have kernel : rowsKernel 140 13115 58 pivotColumns
          (pcsBuildCoefficients points 2 64 140) heads
          (fields.rcombiTails.map fieldWordsToGoldilocks)
          (fields.subsetEvals.map fieldWordsToGoldilocks) decsPoints = some rows := by
        have expanded := success
        simp only [reconstructRowsFromPcsFields, pointCount, headsBuilt] at expanded
        change rowsKernel 140 13115 58 pivotColumns
          (pcsBuildCoefficients points 2 64 140) heads
          (fields.rcombiTails.map fieldWordsToGoldilocks)
          (fields.subsetEvals.map fieldWordsToGoldilocks) decsPoints = some rows at expanded
        exact expanded
      obtain ⟨inverse, inverseBuilt, rowCount, entries⟩ :=
        rows_kernel_success_entries 140 13115 58 pivotColumns
          (pcsBuildCoefficients points 2 64 140) heads
          (fields.rcombiTails.map fieldWordsToGoldilocks)
          (fields.subsetEvals.map fieldWordsToGoldilocks) decsPoints rows kernel
      have pivotCount : pivotColumns.length = 12 := by decide
      refine ⟨heads, inverse, rfl, ?_, rowCount, ?_⟩
      · simpa only [pivotCount] using inverseBuilt
      · intro j within
        apply reconstruct_one_full_dot 13115 58 (pcsBuildCoefficients points 2 64 140)
          inverse heads (fields.rcombiTails.map fieldWordsToGoldilocks)
          ((fields.subsetEvals.map fieldWordsToGoldilocks).getD j [])
          (decsPoints.getD j 0) (rows.getD j [])
          (pcs_coefficients_shape points pointCount).1
          (pcs_coefficients_shape points pointCount).2
        simpa only [pivotCount] using entries j within


theorem reconstructed_rows_current_twelve_block_equations
    (fields : DecodedPcsFields) (points decsPoints : List F)
    (pointCount : points.length = 6) (rowScalars : List (List FieldWord))
    (widths deltas : List Nat) (rows : FMatrix)
    (success : reconstructRowsFromPcsFields fields points decsPoints rowScalars
      64 widths deltas 2 13115 140 58 = some rows) :
    ∃ heads,
      reconstructAllHeads fields points rowScalars 64 widths deltas 2 13115 = some heads ∧
      rows.length = decsPoints.length ∧
      ∀ j, j < decsPoints.length → ∀ opening : Fin 6, ∀ block : Fin 2,
        evaluateConsecutive
          (rotateLeft ((heads.getD (2 * opening.val + block.val) []) ++
            ((fields.rcombiTails.map fieldWordsToGoldilocks).getD
              (2 * opening.val + block.val) [])) 13115) (decsPoints.getD j 0) =
        ∑ coefficient : Fin 70, (points.getD opening.val 0) ^ coefficient.val *
          (rows.getD j []).getD (70 * block.val + coefficient.val) 0 := by
  obtain ⟨heads, inverse, headsBuilt, _, rowCount, equations⟩ :=
    reconstruct_rows_current_full_dot fields points decsPoints pointCount
      rowScalars widths deltas rows success
  refine ⟨heads, headsBuilt, rowCount, ?_⟩
  intro j within opening block
  have rowBound : 2 * opening.val + block.val < 12 := by
    have := opening.isLt; have := block.isLt; omega
  rw [← equations j within _ rowBound]
  exact native_dot_block points pointCount opening block (rows.getD j [])

/-- The heads used in the accepted DECS challenge are the same calculated
heads used by successful LVCS reconstruction. Exact height guards, not a
caller-provided equality, establish this agreement. -/
theorem pcs_execution_heads_are_lvcs_heads (ns : CM.Namespace) (pending : Bool) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    reconstructAllHeads decoded.pcs (List.ofFn (points opening)) decoded.rowScalars
      64 widths deltas 2 13115 = some output.heads := by
  obtain ⟨_, _, _, headEq, _⟩ := pcs_execution_has_actual_facts
    ns pending wire decoded opening oracle output executed
  have heights : decoded.rowScalars.length = (List.ofFn (points opening)).length ∧
      decoded.pcs.partialEvals.length = (List.ofFn (points opening)).length := by
    have pass : ¬ (decoded.rowScalars.length ≠ (List.ofFn (points opening)).length ∨
        decoded.pcs.partialEvals.length ≠ (List.ofFn (points opening)).length) := by
      intro bad
      simp only [SmzaRp05PcsWireProjection.reconstructedHeadsAll,
        if_pos bad] at headEq
      cases headEq
    exact ⟨by omega, by omega⟩
  rw [SmzaRp05CurrentTwelveCalculated.reconstructed_head_aggregators_agree
    decoded.pcs (List.ofFn (points opening)) decoded.rowScalars 64 widths deltas
    2 13115 heights.1 heights.2]
  exact headEq

/-- Acceptance derives all twelve equations on the same actual58 rows.
Every row, head, point and scalar is connected to the accepted PCS result. -/
theorem pcs_execution_has_twelve_actual_equations (ns : CM.Namespace) (pending : Bool)
    (wire : Wire) (decoded : DecodedFields) (opening : Opening) (oracle : Oracle)
    (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    output.rows.length = output.decsPoints.length ∧
      ∀ j, j < output.decsPoints.length → ∀ coordinate : Fin 6, ∀ block : Fin 2,
        evaluateConsecutive
          (rotateLeft ((output.heads.getD (2 * coordinate.val + block.val) []) ++
            ((decoded.pcs.rcombiTails.map fieldWordsToGoldilocks).getD
              (2 * coordinate.val + block.val) [])) 13115) (output.decsPoints.getD j 0) =
        ∑ coefficient : Fin 70, (points opening coordinate) ^ coefficient.val *
          (output.rows.getD j []).getD (70 * block.val + coefficient.val) 0 := by
  obtain ⟨_, _, _, _, _, _, _, rowEq, _⟩ := pcs_execution_has_actual_facts
    ns pending wire decoded opening oracle output executed
  obtain ⟨heads, headsEq, rowCount, equations⟩ :=
    reconstructed_rows_current_twelve_block_equations decoded.pcs
      (List.ofFn (points opening)) output.decsPoints (by simp) decoded.rowScalars
      widths deltas output.rows rowEq
  have headsSame : heads = output.heads := Option.some.inj
    (headsEq.symm.trans (pcs_execution_heads_are_lvcs_heads
      ns pending wire decoded opening oracle output executed))
  subst heads
  refine ⟨rowCount, ?_⟩
  intro j within coordinate block
  have pointLookup :
      (List.ofFn (points opening)).getD coordinate.val 0 = points opening coordinate := by
    rw [List.getD_eq_getElem (List.ofFn (points opening)) 0 (by
      simpa only [List.length_ofFn] using coordinate.isLt)]
    simp only [List.getElem_ofFn]
  have actualEquation := equations j within coordinate block
  rw [pointLookup] at actualEquation
  exact actualEquation

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedPcsFacts
