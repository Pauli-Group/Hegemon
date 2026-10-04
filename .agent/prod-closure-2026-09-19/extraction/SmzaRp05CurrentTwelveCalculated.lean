import SmzaRp05ExecutablePcsClosureLvcsAlgebraInterpolation
import SmzaRp05AcceptedGlobalQueryReadback
import SmzaRp05ExecutablePcsClosureLeafCodec
import SmzaRp05ExecutablePcsClosureMcaPositionBinding
import SmzaRp05ExecutablePcsClosureMcaAlgebra

/-!
# Current calculated twelve LVCS query polynomials

For each opening/block, the claim polynomial is defined from the same
`PcsStages.heads` and `wire.pcs.rcombiTails` used to form the DECS-opening
input.  It is the Lagrange interpolant on exactly 406 nodes, with the source
368-position rotation.  No legacy `ClaimedPolynomials` or gate conclusion is
assumed.  This is a source-calculated predicate, not a Rust-refinement result.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentTwelveCalculated

open Polynomial
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosure (widths deltas)
open SmzaRp05ExecutablePcsClosureLvcsAlgebra
open SmzaRp05ExecutablePcsClosureMcaAlgebra (normalized_data_goldilocks)
open SmzaRp05LvcsWireProjection
open SmzaRp05PcsWireProjection
open SmzaRp05GlobalOpeningReadback
open SmzaRp05FilteredDecoderInstability (RawRecords)
open HegemonCrypto.SmallWood.V8Smz9OracleExtraction (wordToGoldilocks)
open SmzaRp05PcsMerklePayload
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05Q38CurrentRebinding (smz9EvaluationPoint)
open V8Smz9PiopSoundness (Opening)
open SmzaRp05DecsPointProjection (fieldPoint fieldPoints)
open scoped BigOperators

set_option autoImplicit false

abbrev F := Goldilocks
abbrev QueryIndex := Fin 406

/-- The actual transcript path passes opening evaluation points as this
fixed-arity `List.ofFn`; its length is six by construction. -/
theorem generated_opening_points_length (opening : Opening) :
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points opening j).length = 6 := by
  simp

/-- The exact current source vector for one opening/block. -/
def currentQueryValues (heads tails : List (List F))
    (opening : Fin 6) (block : Fin 2) : List F :=
  rotateLeft
    ((heads.getD (2 * opening.val + block.val) []) ++
      (tails.getD (2 * opening.val + block.val) [])) 368

/-- Exact tail projection carried by the current PCS-stage record. -/
def currentStageTails (wire : SmzaRp05PcsWireProjection.DecodedMiddleWire) :
    List (List F) := wire.pcs.rcombiTails.map fieldWordsToGoldilocks

/-- Fixed-size current claimed polynomial. The type enforces 406 interpolation
nodes; `CurrentQueryVectorWellFormed` below separately excludes default-padded
malformed source vectors. -/
noncomputable def currentQueryPolynomial (heads tails : List (List F))
    (opening : Fin 6) (block : Fin 2) : F[X] :=
  Lagrange.interpolate (Finset.univ : Finset QueryIndex)
    (fun index => (index.val : F))
    (fun index => (currentQueryValues heads tails opening block).getD index.val 0)

/-- The polynomial selected from the actual returned `PcsStages.heads` and
the same proof's `wire.pcs.rcombiTails`. -/
noncomputable def currentPcsStagePolynomial {ns : SmzaRp05LeafNamespace.Namespace}
    {pending : Bool} {hPiop : V8SmzaOracleParser.RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List F} {salt binding : List HegemonCrypto.CanonicalBytes.Byte}
    {statementBinding : List Nat} {tapes : List (List HegemonCrypto.CanonicalBytes.Byte)}
    {paths : List (List V8SmzaOracleParser.RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : V8SmzaOracleParser.RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (opening : Fin 6) (block : Fin 2) : F[X] :=
  currentQueryPolynomial stages.heads (currentStageTails wire) opening block

/-- Strict opening-input shape: every queried pair is one 368-head plus one
38-tail vector, without relying on `getD` padding. -/
def CurrentQueryVectorWellFormed (heads tails : List (List F)) : Prop :=
  heads.length = 12 ∧ tails.length = 12 ∧
    (∀ row, row < 12 → (heads.getD row []).length = 368) ∧
    (∀ row, row < 12 → (tails.getD row []).length = 38)

private theorem map_getD_default {α β : Type} (values : List α) (f : α → β)
    (index : Nat) (fallback : α) :
    (values.map f).getD index (f fallback) = f (values.getD index fallback) := by
  induction values generalizing index with
  | nil => cases index <;> rfl
  | cons head tail ih =>
      cases index with
      | zero => rfl
      | succ index => exact ih index

private theorem openingRowsWords_success_shape
    (count cols tailCount : Nat) (heads : List (List F))
    (tails : List (List FieldWord)) (words : List Nat)
    (success : SmzaRp05PcsWireProjection.openingRowsWords count cols tailCount
      heads tails = some words) :
    heads.length = count ∧ tails.length = count ∧
      (∀ row, row < count → (heads.getD row []).length = cols) ∧
      (∀ row, row < count → (tails.getD row []).length = tailCount) := by
  induction count generalizing heads tails words with
  | zero =>
      cases heads <;> cases tails <;>
        simp_all [SmzaRp05PcsWireProjection.openingRowsWords]
  | succ count ih =>
      cases heads with
      | nil => simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
      | cons head heads =>
          cases tails with
          | nil => simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
          | cons tail tails =>
              simp only [SmzaRp05PcsWireProjection.openingRowsWords] at success
              split at success
              · simp at success
              · rename_i shape
                cases restEq : SmzaRp05PcsWireProjection.openingRowsWords
                    count cols tailCount heads tails with
                | none => simp [restEq] at success
                | some rest =>
                    obtain ⟨headCount, tailCountEq, headShape, tailShape⟩ :=
                      ih heads tails rest restEq
                    have shapeFacts : head.length = cols ∧ tail.length = tailCount := by
                      simp only [not_or] at shape
                      exact ⟨by omega, by omega⟩
                    have headLength := shapeFacts.1
                    have tailLength := shapeFacts.2
                    refine ⟨?_, ?_, ?_, ?_⟩
                    · simp [headCount]
                    · simp [tailCountEq]
                    · intro row within
                      cases row with
                      | zero => simpa using headLength
                      | succ row =>
                          have within' : row < count := by omega
                          simpa using headShape row within'
                    · intro row within
                      cases row with
                      | zero => simpa using tailLength
                      | succ row =>
                          have within' : row < count := by omega
                          simpa using tailShape row within'

/-- Successful 12-row DECS-opening framing is the source's checked shape
guard: exactly twelve 368-word heads and twelve 38-word tails. -/
theorem opening_input_success_has_query_vector_shape
    (hPiop : V8SmzaOracleParser.RawDigest) (heads : List (List F))
    (tails : List (List FieldWord)) (input : V8SmzaOracleParser.RawInput)
    (success : SmzaRp05PcsWireProjection.decsOpeningInput hPiop 12 368 38
      heads tails = some input) :
    CurrentQueryVectorWellFormed heads (tails.map fieldWordsToGoldilocks) := by
  unfold SmzaRp05PcsWireProjection.decsOpeningInput
    SmzaRp05PcsWireProjection.decsOpeningWords at success
  cases rows : SmzaRp05PcsWireProjection.openingRowsWords 12 368 38 heads tails with
  | none => simp [rows] at success
  | some words =>
      have shape := openingRowsWords_success_shape 12 368 38 heads tails words rows
      have mappedCount : (tails.map fieldWordsToGoldilocks).length = tails.length := by
        simp
      refine ⟨shape.1, mappedCount.trans shape.2.1, shape.2.2.1, ?_⟩
      intro row within
      have sourceShape := shape.2.2.2 row within
      have mappedGet := map_getD_default tails fieldWordsToGoldilocks row []
      have mappedGet' :
          (tails.map fieldWordsToGoldilocks).getD row [] =
            fieldWordsToGoldilocks (tails.getD row []) := by
        simpa [fieldWordsToGoldilocks] using mappedGet
      have mappedRow :
          ((tails.map fieldWordsToGoldilocks).getD row []).length =
            (tails.getD row []).length := by
        rw [mappedGet']
        simp [fieldWordsToGoldilocks]
      exact mappedRow.trans sourceShape

/-- The 368+38 vector lengths are extracted from the actual successful field
of `PcsStages`; they are not independent inputs to the calculated claim. -/
theorem pcs_stages_query_vector_well_formed
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool}
    {hPiop : V8SmzaOracleParser.RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List F} {salt binding : List HegemonCrypto.CanonicalBytes.Byte}
    {statementBinding : List Nat} {tapes : List (List HegemonCrypto.CanonicalBytes.Byte)}
    {paths : List (List V8SmzaOracleParser.RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : V8SmzaOracleParser.RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending) :
    CurrentQueryVectorWellFormed stages.heads (currentStageTails wire) := by
  exact opening_input_success_has_query_vector_shape hPiop stages.heads
    wire.pcs.rcombiTails stages.openingInput stages.openingBuilt

/-- Shape facts used by authenticated decoding are exactly the success guards
of the same `makeMerkleInput` value retained in `PcsStages`. -/
private theorem successful_merkle_input_current_dimensions
    (salt binding : List HegemonCrypto.CanonicalBytes.Byte) (pending : Bool)
    (indexes : List Nat) (rows : List (List F))
    (masks : SmzaRp05PcsWireProjection.FieldMatrix)
    (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (paths : List (List V8SmzaOracleParser.RawDigest))
    (input : SmzaRp05ExecutableMerkleVerifier.Input)
    (built : SmzaRp05PcsMerklePayload.makeMerkleInput salt binding pending
      indexes rows masks tapes paths = some input) :
    salt.length = 32 ∧ tapes.length = 38 ∧ rows.length = 38 ∧
      (∀ j, j < 38 → (tapes.getD j []).length = 64) ∧
      (∀ j, j < 38 → (rows.getD j []).length = 140) := by
  unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
  split at built
  · simp at built
  · rename_i good
    have saltGood : salt.length = 32 := by
      by_contra bad
      exact good (Or.inl bad)
    have rowCount : rows.length = 38 := by
      by_contra bad
      exact good (Or.inr (Or.inr (Or.inr (Or.inl bad))))
    have tapeCount : tapes.length = 38 := by
      by_contra bad
      exact good (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl bad))))))
    refine ⟨saltGood, tapeCount, rowCount, ?_, ?_⟩
    · intro index within
      have member : tapes.getD index [] ∈ tapes := by
        rw [List.getD_eq_getElem tapes [] (by rw [tapeCount]; exact within)]
        exact List.getElem_mem (by rw [tapeCount]; exact within)
      by_contra bad
      have anyBad : tapes.any (fun tape => decide (tape.length ≠ 64)) = true :=
        List.any_eq_true.mpr ⟨tapes.getD index [], member, decide_eq_true bad⟩
      exact good (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
        (Or.inr (Or.inr (Or.inr (Or.inr anyBad)))))))))
    · intro index within
      have member : rows.getD index [] ∈ rows := by
        rw [List.getD_eq_getElem rows [] (by rw [rowCount]; exact within)]
        exact List.getElem_mem (by rw [rowCount]; exact within)
      by_contra bad
      have anyBad : rows.any (fun row => decide (row.length ≠ 140)) = true :=
        List.any_eq_true.mpr ⟨rows.getD index [], member, decide_eq_true bad⟩
      exact good (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
        (Or.inl anyBad))))))))

/-- The fixed query-program result has 38 indexes; successful field-point
construction therefore gives one DECS evaluation point per sampled leaf. -/
private theorem pcs_stages_sample_point_count
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool}
    {hPiop : V8SmzaOracleParser.RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List F} {salt binding : List HegemonCrypto.CanonicalBytes.Byte}
    {statementBinding : List Nat} {tapes : List (List HegemonCrypto.CanonicalBytes.Byte)}
    {paths : List (List V8SmzaOracleParser.RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : V8SmzaOracleParser.RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending) :
    stages.decsPoints.length = 38 := by
  have queryExact := SmzaRp05ExecutablePcsClosureSampling.query_program_exact
    pending stages.openingDigest oracle
  have querySuccess : SmzaRp05ExecutablePcsClosure.queryResult pending
      (SmzaRp05ExecutableChallengeStage.scan oracle 50 []
        (SmzaRp05ExecutableChallengeStage.counterKeys
          SmallWoodTranscript.decsFixedSamplingDomain 50 stages.openingDigest)) =
      some (stages.indexes, stages.sampledPending) := by
    rw [← queryExact]
    exact stages.queryExecuted
  have indexCount : stages.indexes.length = 38 := by
    unfold SmzaRp05ExecutablePcsClosure.queryResult at querySuccess
    dsimp only at querySuccess
    split at querySuccess
    · rename_i lengthGuard
      have eq := Option.some.inj querySuccess
      have indexesEq := congrArg Prod.fst eq
      have indexesLength := congrArg List.length indexesEq
      exact indexesLength.symm.trans lengthGuard
    · cases querySuccess
  have pointsSuccess : fieldPoints 406 stages.indexes = some stages.decsPoints :=
    stages.pointsBuilt
  simp only [fieldPoints] at pointsSuccess
  obtain ⟨pointLength, _pointAt⟩ :=
    SmzaRp05ExecutablePcsClosureLvcsAlgebra.mapM_success_entry
      stages.indexes (fieldPoint 406) stages.decsPoints 0 0 pointsSuccess
  exact pointLength.trans indexCount
  

private theorem append_forIn_eq_mapM_flatten {α β : Type}
    (xs : List α) (initial : List β) (f : α → Option (List β)) :
    (forIn xs initial (fun x acc => do
      let value ← f x
      pure (.yield (acc ++ value)))) =
      (xs.mapM f).map (fun values => initial ++ values.flatten) := by
  induction xs generalizing initial with
  | nil => simp
  | cons x rest ih =>
      rw [List.forIn_cons, List.mapM_cons]
      cases hx : f x with
      | none => simp
      | some value =>
          simp
          simpa [Option.map_eq_bind, List.flatten_cons, List.append_assoc] using
            ih (initial ++ value)

private theorem reconstructed_heads_success_heights
    (fields : SmzaRp05PcsWireProjection.DecodedPcsFields)
    (evalPoints : List F) (rowScalars : List (List FieldWord))
    (packingFactor : Nat) (widths deltas : List Nat) (beta lvcsCols : Nat)
    (heads : List (List F))
    (success : SmzaRp05PcsWireProjection.reconstructedHeadsAll fields evalPoints
      rowScalars packingFactor widths deltas beta lvcsCols = some heads) :
    rowScalars.length = evalPoints.length ∧
      fields.partialEvals.length = evalPoints.length := by
  have guardFalse : ¬ (rowScalars.length ≠ evalPoints.length ∨
      fields.partialEvals.length ≠ evalPoints.length) := by
    intro bad
    simp [SmzaRp05PcsWireProjection.reconstructedHeadsAll, bad] at success
  exact ⟨by omega, by omega⟩

/-- The PCS opening-hash head aggregator and LVCS row-reconstruction head
aggregator agree whenever the former's exact input-height guards pass. -/
theorem reconstructed_head_aggregators_agree
    (fields : SmzaRp05PcsWireProjection.DecodedPcsFields)
    (evalPoints : List F) (rowScalars : List (List FieldWord))
    (packingFactor : Nat) (widths deltas : List Nat) (beta lvcsCols : Nat)
    (scalarHeight : rowScalars.length = evalPoints.length)
    (partialHeight : fields.partialEvals.length = evalPoints.length) :
    SmzaRp05LvcsWireProjection.reconstructAllHeads fields evalPoints rowScalars
        packingFactor widths deltas beta lvcsCols =
      SmzaRp05PcsWireProjection.reconstructedHeadsAll fields evalPoints rowScalars
        packingFactor widths deltas beta lvcsCols := by
  unfold SmzaRp05LvcsWireProjection.reconstructAllHeads
    SmzaRp05PcsWireProjection.reconstructedHeadsAll
  have heightsPass : ¬ (rowScalars.length ≠ evalPoints.length ∨
      fields.partialEvals.length ≠ evalPoints.length) := by omega
  simp only [if_neg heightsPass]
  simpa [Option.map_eq_bind, Function.comp_def, List.nil_append] using
    append_forIn_eq_mapM_flatten (List.range evalPoints.length) []
    (fun index => SmzaRp05PcsWireProjection.reconstructedHeadsForRow fields
      evalPoints rowScalars index packingFactor widths deltas beta lvcsCols)

/-- The source's successful head guard plus the block equations yields native
sampled equations using exactly `PcsStages.heads` and its proof tails. -/
theorem pcs_stages_native_twelve_equations
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool}
    {hPiop : V8SmzaOracleParser.RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List F} {salt binding : List HegemonCrypto.CanonicalBytes.Byte}
    {statementBinding : List Nat} {tapes : List (List HegemonCrypto.CanonicalBytes.Byte)}
    {paths : List (List V8SmzaOracleParser.RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : V8SmzaOracleParser.RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) :
    (∀ (j : Nat), j < stages.decsPoints.length →
      ∀ (opening : Fin 6) (block : Fin 2),
      evaluateConsecutive
        (currentQueryValues stages.heads (currentStageTails wire) opening block)
        (stages.decsPoints.getD j 0) =
      (∑ coefficient : Fin 70, points.getD opening.val 0 ^ coefficient.val *
        (stages.rows.getD j []).getD (70 * block.val + coefficient.val) 0)) := by
  obtain ⟨rowHeads, rowHeadsBuilt, rowCount, equations⟩ :=
    reconstructed_rows_twelve_block_equations wire.pcs points stages.decsPoints
      pointCount wire.rowScalars widths deltas stages.rows stages.rowsBuilt
  have heights := reconstructed_heads_success_heights wire.pcs points wire.rowScalars
    64 widths deltas 2 368 stages.heads stages.headsBuilt
  have sameHeads := reconstructed_head_aggregators_agree wire.pcs points
    wire.rowScalars 64 widths deltas 2 368 heights.1 heights.2
  have headEq : rowHeads = stages.heads := by
    have outputEq := Option.some.inj
      (rowHeadsBuilt.symm.trans (sameHeads.trans stages.headsBuilt))
    exact outputEq
  intro j within opening block
  simpa [currentQueryValues, currentStageTails, headEq] using equations j within opening block

/-- Current twelve sampled equations against the actual reconstructed stage
rows. -/
def CurrentTwelveCalculatedChecks (heads tails : List (List F))
    (points : Fin 6 → F) (samplePoints : List F) (rows : List (List F)) : Prop :=
  CurrentQueryVectorWellFormed heads tails ∧
    ∀ (opening : Fin 6) (block : Fin 2) (j : Nat), j < samplePoints.length →
      (currentQueryPolynomial heads tails opening block).eval
          (samplePoints.getD j 0) =
        ∑ coefficient : Fin 70,
          points opening ^ coefficient.val *
            (rows.getD j []).getD (70 * block.val + coefficient.val) 0

theorem current_query_values_length
    (heads tails : List (List F))
    (wellFormed : CurrentQueryVectorWellFormed heads tails)
    (opening : Fin 6) (block : Fin 2) :
    (currentQueryValues heads tails opening block).length = 406 := by
  have rowBound : 2 * opening.val + block.val < 12 := by
    have ho := opening.isLt
    have hb := block.isLt
    omega
  have headLength := wellFormed.2.2.1 (2 * opening.val + block.val) rowBound
  have tailLength := wellFormed.2.2.2 (2 * opening.val + block.val) rowBound
  have sourceLength :
    ((heads.getD (2 * opening.val + block.val) []) ++
        (tails.getD (2 * opening.val + block.val) [])).length = 406 := by
    rw [List.length_append, headLength, tailLength]
  unfold currentQueryValues rotateLeft
  rw [sourceLength, Nat.mod_eq_of_lt (by decide : 368 < 406)]
  simp only [List.length_append, List.length_drop, List.length_take]
  omega

/-- Every fixed current polynomial has degree at most 405. -/
theorem current_query_polynomial_degree (heads tails : List (List F))
    (opening : Fin 6) (block : Fin 2) :
    (currentQueryPolynomial heads tails opening block).natDegree ≤ 405 := by
  apply natDegree_le_of_degree_le
  have nodesInjective : Function.Injective
      (fun index : QueryIndex => (index.val : F)) := by
    change Function.Injective (fun index : Fin 406 => (index.val : Goldilocks))
    exact HegemonCrypto.SmallWood.SmzaRp04TracePrefixes.consecutive_point_injective
  have bounded := Lagrange.degree_interpolate_le
    (fun index : QueryIndex =>
      (currentQueryValues heads tails opening block).getD index.val 0)
    nodesInjective.injOn (s := (Finset.univ : Finset QueryIndex))
  simpa [currentQueryPolynomial, Finset.card_univ, Fintype.card_fin] using bounded

/-- If the source vector is exactly 406 values, its finite-list evaluator is
the polynomial just defined above. -/
theorem evaluate_current_query_polynomial
    (heads tails : List (List F)) (opening : Fin 6) (block : Fin 2)
    (point : F)
    (wellFormed : CurrentQueryVectorWellFormed heads tails) :
    evaluateConsecutive (currentQueryValues heads tails opening block) point =
      (currentQueryPolynomial heads tails opening block).eval point := by
  have valuesLength : (currentQueryValues heads tails opening block).length = 406 := by
    exact current_query_values_length heads tails wellFormed opening block
  have canonical :
      List.ofFn (fun index : QueryIndex =>
        (currentQueryValues heads tails opening block).getD index.val 0) =
        currentQueryValues heads tails opening block := by
    apply List.ext_getElem
    · simp only [List.length_ofFn, valuesLength]
    · intro index leftBound rightBound
      simp only [List.getElem_ofFn]
      rw [← List.getD_eq_getElem
        (currentQueryValues heads tails opening block) 0 rightBound]
  have interp := evaluate_consecutive_ofFn 406
    (fun index : QueryIndex =>
      (currentQueryValues heads tails opening block).getD index.val 0) point
  rw [canonical] at interp
  simpa [currentQueryPolynomial] using interp

/-- Algebraic transfer from the checked source row equations to the calculated
current twelve-check predicate. `nativeEquation` is the output shape proved by
`reconstructed_rows_twelve_block_equations`; the length guard prevents
default-padding from standing in for a malformed 368+38 vector. -/
theorem current_checks_of_native_row_equations
    (heads tails : List (List F)) (points : Fin 6 → F)
    (samplePoints : List F) (rows : List (List F))
    (wellFormed : CurrentQueryVectorWellFormed heads tails)
    (nativeEquation : ∀ (j : Nat), j < samplePoints.length →
      ∀ opening : Fin 6, ∀ block : Fin 2,
        evaluateConsecutive
          (rotateLeft
            ((heads.getD (2 * opening.val + block.val) []) ++
              (tails.getD (2 * opening.val + block.val) [])) 368)
          (samplePoints.getD j 0) =
        ∑ coefficient : Fin 70,
          points opening ^ coefficient.val *
            (rows.getD j []).getD (70 * block.val + coefficient.val) 0) :
    CurrentTwelveCalculatedChecks heads tails points samplePoints rows := by
  refine ⟨wellFormed, ?_⟩
  intro opening block j within
  exact (evaluate_current_query_polynomial heads tails opening block
    (samplePoints.getD j 0) wellFormed).symm.trans
      (nativeEquation j within opening block)

/-- The checked native row equations directly instantiate the calculated
predicate for a successful current PCS stage; source dimensions are obtained
from its strict DECS-opening input guard. -/
theorem current_checks_of_pcs_stages
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool}
    {hPiop : V8SmzaOracleParser.RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List F} {salt binding : List HegemonCrypto.CanonicalBytes.Byte}
    {statementBinding : List Nat} {tapes : List (List HegemonCrypto.CanonicalBytes.Byte)}
    {paths : List (List V8SmzaOracleParser.RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : V8SmzaOracleParser.RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) :
    CurrentTwelveCalculatedChecks stages.heads (currentStageTails wire)
      (fun opening => points.getD opening.val 0) stages.decsPoints stages.rows := by
  have wellFormed := pcs_stages_query_vector_well_formed stages
  apply current_checks_of_native_row_equations stages.heads
    (currentStageTails wire) (fun opening => points.getD opening.val 0)
    stages.decsPoints stages.rows wellFormed
  intro j within opening block
  exact pcs_stages_native_twelve_equations stages pointCount j within opening block

/-- Authenticated form of the current check: decoded values are obtained from
the exact normalized bytes calculated from the same reconstructed rows. -/
def CurrentTwelveAuthenticatedChecks {ns : SmzaRp05LeafNamespace.Namespace}
    {records : RawRecords}
    {root : V8SmzaOracleParser.RawDigest}
    {query : SmzaQ38McaSourceBinding.Query}
    (claims : GlobalQueryReadback ns records root query)
    (positions : Fin 38 → SmzaQ38McaSourceBinding.Position)
    (heads tails : List (List F)) (points : Fin 6 → F) : Prop :=
  CurrentQueryVectorWellFormed heads tails ∧
    ∀ (opening : Fin 6) (block : Fin 2) (j : Fin 38),
      positions j ∈ query.val →
        (currentQueryPolynomial heads tails opening block).eval
            (smz9EvaluationPoint (positions j)) =
          ∑ coefficient : Fin 70,
              points opening ^ coefficient.val *
              wordToGoldilocks (decodedOracle claims (positions j)
                ⟨70 * block.val + coefficient.val, by
                  have hb := block.isLt
                  have hc := coefficient.isLt
                  unfold HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsRowCount
                    HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsEta
                  omega⟩)

/-- Accepted leaf readback transfers the calculated stage-row equations to
the actual q38 sampled row words, while preserving the original proof bytes. -/
theorem authenticated_checks_of_calculated
    {ns : SmzaRp05LeafNamespace.Namespace}
    {records : RawRecords}
    {root : V8SmzaOracleParser.RawDigest}
    {query : SmzaQ38McaSourceBinding.Query}
    (claims : GlobalQueryReadback ns records root query)
    (positions : Fin 38 → SmzaQ38McaSourceBinding.Position)
    (heads tails : List (List F)) (points : Fin 6 → F)
    (samplePoints : List F) (rows : List (List F))
    (salt : List HegemonCrypto.CanonicalBytes.Byte)
    (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (indexes : List Nat) (masks : List (List FieldWord))
    (checks : CurrentTwelveCalculatedChecks heads tails points samplePoints rows)
    (pointBinding : ∀ j : Fin 38,
      samplePoints.getD j.val 0 = smz9EvaluationPoint (positions j))
    (leafReadback : ∀ j : Fin 38,
      (claims.leaf (positions j)).bytes = normalizedLeafPayload salt
        (tapes.getD j.val []) (indexes.getD j.val 0)
        (rows.getD j.val []) (masks.getD j.val []))
    (saltLength : salt.length = 32)
    (tapeLength : ∀ j : Fin 38, (tapes.getD j.val []).length = 64)
    (rowLength : ∀ j : Fin 38, (rows.getD j.val []).length = 140)
    (sampleBound : ∀ j : Fin 38, j.val < samplePoints.length) :
    CurrentTwelveAuthenticatedChecks claims positions heads tails points := by
  refine ⟨checks.1, ?_⟩
  intro opening block j member
  rw [← pointBinding j, checks.2 opening block j.val (sampleBound j)]
  apply Finset.sum_congr rfl
  intro coefficient _
  let column := 70 * block.val + coefficient.val
  have columnBound : column < 140 := by
    have hb := block.isLt
    have hc := coefficient.isLt
    dsimp [column]
    omega
  have decodedColumnBound : column <
      HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsRowCount +
        HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsEta := by
    have hb := block.isLt
    have hc := coefficient.isLt
    unfold HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsRowCount
      HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsEta
    dsimp [column]
    omega
  have decoded : wordToGoldilocks (decodedOracle claims (positions j)
      ⟨column, decodedColumnBound⟩) = (rows.getD j.val []).getD column 0 := by
    rw [SmzaRp05GlobalOpeningReadback.decodedOracle, leafReadback j]
    rw [if_pos columnBound]
    exact normalized_data_goldilocks
        salt (tapes.getD j.val []) (indexes.getD j.val 0)
        (rows.getD j.val []) (masks.getD j.val []) saltLength (tapeLength j)
        column (by rw [rowLength j]; exact columnBound)
  rw [decoded]

/-- The current stage checks hold on any readback of that same stage's
actual leaf payloads and sampled evaluation points. This lets the MCA and
LVCS joins retain one shared query/readback witness, without identifying two
independently chosen existential witnesses. -/
theorem pcs_stages_authenticated_checks_on_readback
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool}
    {hPiop : V8SmzaOracleParser.RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List F} {salt binding : List HegemonCrypto.CanonicalBytes.Byte}
    {statementBinding : List Nat} {tapes : List (List HegemonCrypto.CanonicalBytes.Byte)}
    {paths : List (List V8SmzaOracleParser.RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : V8SmzaOracleParser.RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6)
    {measured : RawRecords} {query : SmzaQ38McaSourceBinding.Query}
    (claims : GlobalQueryReadback ns measured stages.post.root query)
    (positions : Fin 38 → SmzaQ38McaSourceBinding.Position)
    (pointBinding : ∀ j : Fin 38,
      stages.decsPoints.getD j.val 0 = smz9EvaluationPoint (positions j))
    (leafPayloads : ∀ j : Fin 38,
      (claims.leaf (positions j)).bytes = normalizedLeafPayload salt
        (tapes.getD j.val []) (stages.indexes.getD j.val 0)
        (stages.rows.getD j.val []) (decs.maskingEvals.getD j.val [])) :
    CurrentTwelveAuthenticatedChecks claims positions stages.heads
      (currentStageTails wire) (fun opening => points.getD opening.val 0) := by
  have dimensions := successful_merkle_input_current_dimensions salt binding
    stages.sampledPending stages.indexes stages.rows decs.maskingEvals tapes paths
    stages.merkleInput stages.inputBuilt
  have sampleCount := pcs_stages_sample_point_count stages
  have sampleBound : ∀ j : Fin 38, j.val < stages.decsPoints.length := by
    intro j
    rw [sampleCount]
    exact j.isLt
  exact authenticated_checks_of_calculated claims positions stages.heads
    (currentStageTails wire) (fun opening => points.getD opening.val 0)
    stages.decsPoints stages.rows salt tapes stages.indexes decs.maskingEvals
    (current_checks_of_pcs_stages stages pointCount) pointBinding leafPayloads
    dimensions.1 (fun j => dimensions.2.2.2.1 j.val j.isLt)
    (fun j => dimensions.2.2.2.2 j.val j.isLt) sampleBound

/-- Accepted same-run global readback supplies the exact positions and leaf
bytes for the current calculated checks. The remaining length facts are the
literal successful `makeMerkleInput` shape guards, exposed here rather than
replaced by a guessed payload. -/
theorem accepted_pcs_stages_authenticated_checks
    (ns : SmzaRp05LeafNamespace.Namespace) (pending : Bool)
    (hPiop : V8SmzaOracleParser.RawDigest)
    (wire : SmzaRp05PcsWireProjection.DecodedMiddleWire)
    (decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (points : List F) (salt binding : List HegemonCrypto.CanonicalBytes.Byte)
    (statementBinding : List Nat) (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (paths : List (List V8SmzaOracleParser.RawDigest))
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (hashFpp : V8SmzaOracleParser.RawDigest) (finalPending : Bool)
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) (clean : finalPending = false)
    (measured : RawRecords)
    (retained : ∀ stage raw digest,
      (raw, digest) ∈
        (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle stages.merkleInput).2 →
      (SmzaRp05FilteredDecoderInstability.globalOnlineNext ns stage raw).isSome →
      (raw, digest) ∈ measured)
    :
    ∃ positions : Fin 38 → SmzaQ38McaSourceBinding.Position,
      ∃ query : SmzaQ38McaSourceBinding.Query,
        ∃ claims : GlobalQueryReadback ns measured stages.post.root query,
          StrictMono positions ∧ query.val = Finset.univ.image positions ∧
          CurrentTwelveAuthenticatedChecks claims positions stages.heads
            (currentStageTails wire)
            (fun opening => points.getD opening.val 0) := by
  obtain ⟨positions, query, claims, _coordinates, ordered, image,
      _inputs, _bytes, coordinateIndexes, leafPayloads⟩ :=
    SmzaRp05AcceptedGlobalQueryReadback.accepted_pcs_stages_global_query_readback
      ns pending hPiop wire decs points salt binding statementBinding tapes paths oracle
      hashFpp finalPending stages clean measured retained
  have pointBinding :=
    SmzaRp05ExecutablePcsClosureMcaPositionBinding.pcs_stages_position_binding
      ns pending hPiop wire decs points salt binding statementBinding tapes paths oracle
      hashFpp finalPending stages positions coordinateIndexes
  have calculated := current_checks_of_pcs_stages stages pointCount
  have dimensions := successful_merkle_input_current_dimensions salt binding
    stages.sampledPending stages.indexes stages.rows decs.maskingEvals tapes paths
    stages.merkleInput stages.inputBuilt
  have sampleCount := pcs_stages_sample_point_count stages
  have sampleBound : ∀ j : Fin 38, j.val < stages.decsPoints.length := by
    intro j
    rw [sampleCount]
    exact j.isLt
  have authenticated := authenticated_checks_of_calculated claims positions
    stages.heads (currentStageTails wire)
    (fun opening => points.getD opening.val 0) stages.decsPoints stages.rows salt tapes
    stages.indexes decs.maskingEvals calculated pointBinding leafPayloads
    dimensions.1
    (fun j => dimensions.2.2.2.1 j.val j.isLt)
    (fun j => dimensions.2.2.2.2 j.val j.isLt) sampleBound
  refine ⟨positions, query, claims, ordered, image, ?_⟩
  exact authenticated

/-- Same-run specialization of the accepted authenticated-check theorem to
the actual `transcriptProgram` PCS argument. In particular, the generic list
length premise is discharged by the source's `List.ofFn` over `Fin 6`, and
PCS cleanliness is extracted from the final transcript's pending guard. -/
theorem execution_stages_authenticated_checks
    (ns : SmzaRp05LeafNamespace.Namespace)
    (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List HegemonCrypto.CanonicalBytes.Byte)
    (statementBinding : List Nat) (nonce : Fin (2 ^ 32))
    (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement
      pending binding statementBinding nonce wire oracle transcript)
    (cleanTranscript : transcript.pendingXofFailure = false)
    (measured : RawRecords)
    (retained : ∀ input stage raw digest,
      (raw, digest) ∈
        (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle input).2 →
      (SmzaRp05FilteredDecoderInstability.globalOnlineNext ns stage raw).isSome →
      (raw, digest) ∈ measured) :
    ∃ stages : PcsStages ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 =>
          V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt binding statementBinding wire.tapes wire.paths oracle
        execution.hashFpp execution.pcsPending,
      ∃ positions : Fin 38 → SmzaQ38McaSourceBinding.Position,
        ∃ query : SmzaQ38McaSourceBinding.Query,
          ∃ claims : GlobalQueryReadback ns measured stages.post.root query,
            StrictMono positions ∧ query.val = Finset.univ.image positions ∧
              CurrentTwelveAuthenticatedChecks claims positions stages.heads
                (currentStageTails
                  (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop))
                (fun opening =>
                  (List.ofFn fun j : Fin 6 =>
                    V8Smz9PiopReconstruction.points execution.opening j).getD
                      opening.val 0) := by
  let stagePoints : List F := List.ofFn fun j : Fin 6 =>
    V8Smz9PiopReconstruction.points execution.opening j
  have pointsLength : stagePoints.length = 6 := by
    exact generated_opening_points_length execution.opening
  have pcsClean :=
    SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
      ns dsl statement pending binding statementBinding nonce wire oracle transcript
      execution cleanTranscript
  obtain ⟨stages⟩ :=
    @SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages
      ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs stagePoints wire.salt binding statementBinding wire.tapes wire.paths
      oracle execution.hashFpp execution.pcsPending execution.pcsExecuted
  have accepted := accepted_pcs_stages_authenticated_checks ns execution.openingPending
    wire.hPiop (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs stagePoints wire.salt binding statementBinding wire.tapes wire.paths
    oracle execution.hashFpp execution.pcsPending stages pointsLength pcsClean.1 measured
    (fun stage raw digest recorded online =>
      retained stages.merkleInput stage raw digest recorded online)
  rcases accepted with ⟨positions, query, claims, ordered, image, checks⟩
  exact ⟨stages, positions, query, claims, ordered, image, checks⟩

end HegemonCrypto.SmallWood.SmzaRp05CurrentTwelveCalculated
