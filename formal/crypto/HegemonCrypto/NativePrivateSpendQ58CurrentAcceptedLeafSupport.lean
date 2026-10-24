import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedPcsFacts
import HegemonCrypto.NativePrivateSpendQ58CurrentRecovery
import SmzaRp05ExecutablePcsClosureMcaAlgebra

/-! Same-execution current58 leaf cells and prior response support. The input
rows, masks, gamma and points are outputs of the existing PCS computation.
An arbitrary prior record relation is read by the current parser/extractor;
absent paths, absent response preimages and collisions remain explicit arms.
No whole-view binding, sampled scalar agreement or decoder success is a premise.
This finite inclusion does not assign a physical probability to those arms. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedLeafSupport

open HegemonCrypto.CanonicalBytes (Byte)
open NativePrivateSpendQ58CurrentExecutableVerifier
open NativePrivateSpendQ58CurrentAcceptedPcsFacts
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableChallengeStage (FieldWord digestWords pendingFailure)
open SmzaRp05DecsResponseProjection (decodeFieldRow)
open SmzaRp05ExecutablePcsClosureAlgebra (coefficientPolynomial)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree RecordedPath readPath)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9McaDecoder (responseSupport)
open V8Smz9McaRecovery (mem_agreement mixed_word_eq_sum)
open scoped Classical BigOperators

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (makeMerkleInput)
end E
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace Input acceptedResult encodeLeaf accepted_shape_valid shapeValid accepted_prior_readback_or_missing_path_or_collision)
end M
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext rawPayload raw_payload_frame)
end F
namespace A
export NativePrivateSpendQ58CurrentAcceptedDecs (current_restore_opened_equations)
end A
namespace R
export NativePrivateSpendQ58CurrentRetainedResponseReadback (sourceHashProgram priorResponse priorResponseRule current_source_response_binds_prior_or_bad_event)
end R
namespace D
export SmzaRp05DecsPointProjection (fieldPoint)
end D
namespace C
export SmzaRp05ExecutablePcsClosureMcaAlgebra (normalized_data_goldilocks normalized_mask_goldilocks)
end C

abbrev Position := SmzaQ38McaSourceBinding.Position
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev Coefficients := Fin 140 → Fin 5 → Goldilocks

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

def currentPoint (position : Position) : Goldilocks :=
  (D.fieldPoint 13173 position.val).getD 0

/-- Total field readback from one current root, retaining its original raw
leaf input. The616-byte public binding is removed only after current parsing. -/
def priorLegacy (prior : RawRecords) (root : RawDigest) (position : Position) : List Byte :=
  ((readPath (0 :: SmzaRp05FilteredReadback.indexPath position 23)
    (extract F.rawNext prior 25 .root root)).bind fun raw =>
      (F.rawPayload raw).map fun payload => payload.bytes.drop 616).getD []

def priorData (prior : RawRecords) (root : RawDigest) : Nat → Position → Goldilocks :=
  fun column position => if column < 140 then
    V8Smz9OracleExtraction.wordToGoldilocks
      (SmzaRp05TracePrefixes.fieldWordAt (priorLegacy prior root position) (14 + column))
  else 0

def priorMasks (prior : RawRecords) (root : RawDigest) : Fin 5 → Position → Goldilocks :=
  fun row position => V8Smz9OracleExtraction.wordToGoldilocks
    (SmzaRp05TracePrefixes.fieldWordAt (priorLegacy prior root position) (155 + row.val))

def actualCoefficients (gamma : List (List FieldWord)) : Coefficients :=
  fun column row => (decodeFieldRow (gamma.getD row.val [])).getD column.val 0

private theorem decoded_toWord (values : List Goldilocks) :
    decodeFieldRow (values.map SmzaRp05ExecutableRestore.toWord) = values := by
  induction values with
  | nil => rfl
  | cons value rest ih =>
      change ((SmzaRp05ExecutableRestore.toWord value).val : Goldilocks) ::
        decodeFieldRow (rest.map SmzaRp05ExecutableRestore.toWord) = value :: rest
      rw [ih]
      congr 1
      simp [SmzaRp05ExecutableRestore.toWord]

private theorem map_getD_default {α β : Type} (values : List α) (f : α → β)
    (index : Nat) (fallback : α) :
    (values.map f).getD index (f fallback) = f (values.getD index fallback) := by
  induction values generalizing index with
  | nil => cases index <;> rfl
  | cons head tail ih =>
      cases index with
      | zero => rfl
      | succ index => exact ih index

private theorem row_at_shape {α : Type} (rows : List (List α))
    (count width : Nat) (rowCount : rows.length = count)
    (shape : ¬ rows.any (fun row => decide (row.length ≠ width)))
    (index : Nat) (within : index < count) : (rows.getD index []).length = width := by
  have bound : index < rows.length := by rw [rowCount]; exact within
  have member : rows.getD index [] ∈ rows := by
    rw [List.getD_eq_getElem rows [] bound]
    exact List.getElem_mem bound
  by_contra wrong
  exact shape (List.any_eq_true.mpr ⟨rows.getD index [], member, decide_eq_true wrong⟩)

/-- Every input equality and dimension below follows from makeMerkleInput's
existing failure guard. The theorem adds no new acceptance test. -/
theorem merkle_input_actual_fields
    (salt binding : List Byte) (pending : Bool) (indexes : List Nat)
    (rows : List (List Goldilocks)) (masks : List (List FieldWord))
    (tapes : List (List Byte)) (paths : List (List RawDigest)) (input : M.Input)
    (built : E.makeMerkleInput salt binding pending indexes rows masks tapes paths = some input) :
    salt.length = 32 ∧ binding.length = 616 ∧ indexes.length = 58 ∧
    rows.length = 58 ∧ masks.length = 58 ∧ tapes.length = 58 ∧
    (∀ j : Fin 58, (rows.getD j.val []).length = 140) ∧
    (∀ j : Fin 58, (masks.getD j.val []).length = 5) ∧
    (∀ j : Fin 58, (tapes.getD j.val []).length = 64) ∧
    input.salt = salt ∧ input.binding = binding ∧
    input.pendingXofFailure = pending ∧
    (∀ j, input.indices j = indexes.getD j.val 0) ∧
    (∀ j, input.payloads j = SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
      (tapes.getD j.val []) (indexes.getD j.val 0) (rows.getD j.val []) (masks.getD j.val [])) := by
  unfold E.makeMerkleInput at built
  split at built
  · simp at built
  · rename_i good
    simp only [not_or, not_not] at good
    have fields := Option.some.inj built
    subst input
    refine ⟨good.1, good.2.1, good.2.2.1, good.2.2.2.1,
      good.2.2.2.2.1, good.2.2.2.2.2.1, ?_, ?_, ?_, rfl, rfl, rfl,
      fun _ => rfl, fun _ => rfl⟩
    · intro j
      exact row_at_shape rows 58 140 good.2.2.2.1
        good.2.2.2.2.2.2.2.1 j.val j.isLt
    · intro j
      exact row_at_shape masks 58 5 good.2.2.2.2.1
        good.2.2.2.2.2.2.2.2.1 j.val j.isLt
    · intro j
      exact row_at_shape tapes 58 64 good.2.2.2.2.2.1
        good.2.2.2.2.2.2.2.2.2 j.val j.isLt

theorem pcs_clean_merkle_accepted (ns : M.Namespace) (pending : Bool) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (clean : output.pending = false) :
    M.acceptedResult ns oracle output.input = some output.root := by
  obtain ⟨_, sampledPending, sampled, _, _, _, _, _, inputEq, merkleEq,
    _, _, _, _, pendingEq⟩ := pcs_execution_has_actual_facts
      ns pending wire decoded opening oracle output executed
  have sampledClean : sampledPending = false :=
    (SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words sampledPending sampled
      (pendingEq.trans clean)).1
  have fields := merkle_input_actual_fields wire.salt ns.binding sampledPending
    output.indexes output.rows decoded.decs.maskingEvals wire.tapes wire.paths output.input inputEq
  have inputClean : output.input.pendingXofFailure = false :=
    fields.2.2.2.2.2.2.2.2.2.2.2.1.trans sampledClean
  simpa only [M.acceptedResult, inputClean, Bool.false_eq_true, if_false] using merkleEq

private theorem prior_legacy_at_leaf (prior : RawRecords) (root : RawDigest)
    (position : Position) (binding legacy : List Byte)
    (bindingLength : binding.length = 616) (legacyLength : legacy.length = 1280)
    (readback : readPath (0 :: SmzaRp05FilteredReadback.indexPath position 23)
      (extract F.rawNext prior 25 .root root) = some (M.encodeLeaf binding legacy)) :
    priorLegacy prior root position = legacy := by
  have payloadLength : (binding ++ legacy).length = 1896 := by
    rw [List.length_append, bindingLength, legacyLength]
  have parsed := F.raw_payload_frame .leaf 237 (binding ++ legacy)
    (by decide) (by omega) payloadLength
  have drop : (binding ++ legacy).drop 616 = legacy := by
    simpa only [bindingLength] using List.drop_left (l₁ := binding) (l₂ := legacy)
  simp only [priorLegacy, readback, Option.bind_some, M.encodeLeaf, parsed,
    Option.map_some, Option.getD_some, drop]

/-- Both the actual data row and all five mask values are read from the same
current leaf. No independently supplied table-cell equality enters. -/
theorem prior_tables_match_actual_rows (ns : M.Namespace) (pending : Bool) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (prior : RawRecords)
    (coordinates : Fin 58 → Position)
    (readbacks : ∀ j, readPath (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (extract F.rawNext prior 25 .root output.root) =
        some (M.encodeLeaf output.input.binding (output.input.payloads j))) :
    (∀ j (column : Fin 140), priorData prior output.root column.val (coordinates j) =
      (output.rows.getD j.val []).getD column.val 0) ∧
    (∀ j (row : Fin 5), priorMasks prior output.root row (coordinates j) =
      ((decoded.decs.maskingEvals.getD j.val []).getD row.val ⟨0, by decide⟩).val) := by
  obtain ⟨_, sampledPending, _, _, _, _, _, _, inputEq, _⟩ :=
    pcs_execution_has_actual_facts ns pending wire decoded opening oracle output executed
  have fields := merkle_input_actual_fields wire.salt ns.binding sampledPending
    output.indexes output.rows decoded.decs.maskingEvals wire.tapes wire.paths output.input inputEq
  have saltLength := fields.1
  have bindingLength : output.input.binding.length = 616 := by
    rw [fields.2.2.2.2.2.2.2.2.2.2.1]
    exact fields.2.1
  have rowShape := fields.2.2.2.2.2.2.1
  have maskShape := fields.2.2.2.2.2.2.2.1
  have tapeShape := fields.2.2.2.2.2.2.2.2.1
  have payloadEq := fields.2.2.2.2.2.2.2.2.2.2.2.2.2
  have legacyRead : ∀ j, priorLegacy prior output.root (coordinates j) = output.input.payloads j := by
    intro j
    apply prior_legacy_at_leaf prior output.root (coordinates j) _ _ bindingLength
    · rw [payloadEq j]
      exact SmzaRp05PcsMerklePayload.normalized_payload_length wire.salt
        (wire.tapes.getD j.val []) (output.indexes.getD j.val 0)
        (output.rows.getD j.val []) (decoded.decs.maskingEvals.getD j.val [])
        saltLength (tapeShape j) (rowShape j) (maskShape j)
    · exact readbacks j
  constructor
  · intro j column
    rw [priorData, if_pos column.isLt, legacyRead j, payloadEq j]
    exact C.normalized_data_goldilocks wire.salt (wire.tapes.getD j.val [])
      (output.indexes.getD j.val 0) (output.rows.getD j.val [])
      (decoded.decs.maskingEvals.getD j.val []) saltLength (tapeShape j)
      column.val (by rw [rowShape j]; exact column.isLt)
  · intro j row
    rw [priorMasks, legacyRead j, payloadEq j]
    exact C.normalized_mask_goldilocks wire.salt (wire.tapes.getD j.val [])
      (output.indexes.getD j.val 0) (output.rows.getD j.val [])
      (decoded.decs.maskingEvals.getD j.val []) saltLength (tapeShape j)
      (rowShape j) row.val (by rw [maskShape j]; exact row.isLt)

/-- The source's deterministic coset point getter, not historical shift388. -/
theorem pcs_points_match_actual_indices (ns : M.Namespace) (pending : Bool) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (coordinates : Fin 58 → Position)
    (indicesEq : ∀ j, (coordinates j).val = output.indexes.getD j.val 0) :
    ∀ j, output.decsPoints.getD j.val 0 = currentPoint (coordinates j) := by
  obtain ⟨_, sampledPending, _, _, _, _, pointsEq, _, inputEq, _⟩ :=
    pcs_execution_has_actual_facts ns pending wire decoded opening oracle output executed
  have fields := merkle_input_actual_fields wire.salt ns.binding sampledPending
    output.indexes output.rows decoded.decs.maskingEvals wire.tapes wire.paths output.input inputEq
  obtain ⟨_, pointAt⟩ := SmzaRp05ExecutablePcsClosureLvcsAlgebra.mapM_success_entry
    output.indexes (D.fieldPoint 13173) output.decsPoints 0 0 pointsEq
  intro j
  have entry := pointAt j.val (by rw [fields.2.2.1]; exact j.isLt)
  rw [← indicesEq j] at entry
  simp only [currentPoint, entry, Option.getD_some]

/-- Native restoration derives the five equations over the exact prior-read
tables. The hypotheses are execution plus the explicit extractor good arm. -/
theorem actual_response_equations_on_prior_tables
    (ns : M.Namespace) (pending : Bool) (wire : Wire) (decoded : DecodedFields)
    (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (prior : RawRecords)
    (coordinates : Fin 58 → Position)
    (indicesEq : ∀ j, (coordinates j).val = output.indexes.getD j.val 0)
    (readbacks : ∀ j, readPath (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (extract F.rawNext prior 25 .root output.root) =
        some (M.encodeLeaf output.input.binding (output.input.payloads j))) :
    ∀ j (row : Fin 5),
      (coefficientPolynomial (output.polynomials.getD row.val [])).eval
        (currentPoint (coordinates j)) =
      priorMasks prior output.root row (coordinates j) +
        ∑ column : Fin 140, actualCoefficients output.gamma column row *
          priorData prior output.root column.val (coordinates j) := by
  have tables := prior_tables_match_actual_rows ns pending wire decoded opening oracle
    output executed prior coordinates readbacks
  have pointAt := pcs_points_match_actual_indices ns pending wire decoded opening oracle
    output executed coordinates indicesEq
  have restored := pcs_execution_has_restoration ns pending wire decoded opening oracle output executed
  have native := A.current_restore_opened_equations decoded.decs
    (output.rows.map fun values => values.map SmzaRp05ExecutableRestore.toWord)
    output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord)
    output.polynomials restored
  intro j row
  have equation := native row.val row.isLt j.val j.isLt
  rw [decoded_toWord, pointAt j] at equation
  have decodedRow : decodeFieldRow
      ((output.rows.map fun values => values.map SmzaRp05ExecutableRestore.toWord).getD j.val []) =
        output.rows.getD j.val [] := by
    rw [show ([] : List FieldWord) = ([] : List Goldilocks).map
      SmzaRp05ExecutableRestore.toWord from rfl, map_getD_default, decoded_toWord]
  rw [decodedRow] at equation
  rw [tables.2 j row]
  simp_rw [tables.1 j]
  exact equation

/-- The query is obtained from the ordinary sorted58-index guard. -/
theorem actual_coordinates_injective (ns : M.Namespace) (oracle : Oracle)
    (input : M.Input) (root : RawDigest)
    (accepted : M.acceptedResult ns oracle input = some root)
    (coordinates : Fin 58 → Position)
    (indicesEq : ∀ j, (coordinates j).val = input.indices j) :
    Function.Injective coordinates := by
  have shape := M.accepted_shape_valid ns oracle input root accepted
  simp only [M.shapeValid, Bool.and_eq_true, decide_eq_true_eq] at shape
  have ordered := shape.2.2.2.1
  intro left right same
  apply Fin.ext
  by_contra different
  have valuesSame := congrArg (@Fin.val 8388608) same
  rcases lt_or_gt_of_ne different with before | after
  · have less := ordered left right before
    rw [← indicesEq left, ← indicesEq right] at less
    omega
  · have less := ordered right left after
    rw [← indicesEq left, ← indicesEq right] at less
    omega

/-- Exactly the four outcomes produced by the literal current parser and
response readback. The first three arms and missing paths are not discarded. -/
def PriorSupportOutcome (ns : M.Namespace) (decoded : DecodedFields)
    (oracle : Oracle) (output : PcsOutput) (prior : RawRecords) : Prop :=
    (¬ ∃ raw, (raw, output.hashFpp) ∈ prior) ∨
    (¬ RecordsCollisionFree (prior ∪
      ((R.sourceHashProgram (digestWords output.root) decoded.decs
        (output.rows.map fun values => values.map SmzaRp05ExecutableRestore.toWord)
        output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord)
        (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val)).record oracle).2.toFinset)) ∨
    (¬ RecordsCollisionFree prior) ∨
    ∃ coordinates : Fin 58 → Position,
      Function.Injective coordinates ∧
      (∀ j, (coordinates j).val = output.indexes.getD j.val 0) ∧
      ((∃ j, ¬ RecordedPath F.rawNext prior .root output.root
        (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (M.encodeLeaf output.input.binding (output.input.payloads j))) ∨
       (Finset.univ.image coordinates ⊆ responseSupport currentPoint 13172
         (priorData prior output.root) (priorMasks prior output.root)
         (R.priorResponseRule prior output.hashFpp) (actualCoefficients output.gamma)))

section PriorSupportProof

attribute [local irreducible] V8Smz9McaRecovery.agreement V8Smz9McaRecovery.mixedWord

/-- The actual response is read from the fixed prior record selector. Absent
preimages/collisions/missing paths are retained, never assumed away. -/
theorem pcs_execution_has_prior_support_or_named_bad_arm
    (ns : M.Namespace) (pending : Bool) (wire : Wire) (decoded : DecodedFields)
    (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (clean : output.pending = false) (prior : RawRecords) :
    PriorSupportOutcome ns decoded oracle output prior := by
  unfold PriorSupportOutcome
  obtain ⟨_, sampledPending, _, _, _, _, _, _, inputEq, _, _, _, outputRestore,
    responseExecuted, _⟩ := pcs_execution_has_actual_facts
      ns pending wire decoded opening oracle output executed
  have response := R.current_source_response_binds_prior_or_bad_event oracle prior output.hashFpp
    (digestWords output.root) decoded.decs
    (output.rows.map fun values => values.map SmzaRp05ExecutableRestore.toWord)
    output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord)
    (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val)
    (by simp [digestWords]) (by simp) responseExecuted
  rcases response with absent | collision | goodResponse
  · exact Or.inl absent
  · exact Or.inr (Or.inl collision)
  · rcases goodResponse with ⟨polynomials, restored, _, _, _, _, responseEq⟩
    have polynomialEq : polynomials = output.polynomials :=
      Option.some.inj (restored.symm.trans outputRestore)
    subst polynomials
    have accepted := pcs_clean_merkle_accepted ns pending wire decoded opening oracle output executed clean
    have tree := M.accepted_prior_readback_or_missing_path_or_collision
      ns oracle output.input output.root prior accepted
    rcases tree with collision | ⟨coordinates, indicesEq, paths⟩
    · exact Or.inr (Or.inr (Or.inl collision))
    · have fields := merkle_input_actual_fields wire.salt ns.binding sampledPending
        output.indexes output.rows decoded.decs.maskingEvals wire.tapes wire.paths output.input inputEq
      have actualIndices : ∀ j, (coordinates j).val = output.indexes.getD j.val 0 :=
        fun j => (indicesEq j).trans (fields.2.2.2.2.2.2.2.2.2.2.2.2.1 j)
      have injective := actual_coordinates_injective ns oracle output.input output.root
        accepted coordinates indicesEq
      refine Or.inr (Or.inr (Or.inr ⟨coordinates, injective, actualIndices, ?_⟩))
      rcases paths with missing | readbacks
      · exact Or.inl missing
      · apply Or.inr
        have equations := actual_response_equations_on_prior_tables ns pending wire decoded
          opening oracle output executed prior coordinates actualIndices readbacks
        intro position member
        obtain ⟨j, _, rfl⟩ := Finset.mem_image.mp member
        apply (mem_agreement currentPoint
          (V8Smz9McaRecovery.mixedWord (priorData prior output.root) (priorMasks prior output.root)
            (V8Smz9McaRecovery.extendCoefficients (actualCoefficients output.gamma)) 140)
          (V8Smz9McaRecovery.responsePolynomials
            (R.priorResponse prior output.hashFpp)) (coordinates j)).mpr
        intro row
        have responseAt :
            (V8Smz9McaRecovery.responsePolynomials
              (R.priorResponse prior output.hashFpp) row).eval (currentPoint (coordinates j)) =
            (coefficientPolynomial (output.polynomials.getD row.val [])).eval
              (currentPoint (coordinates j)) :=
          congrArg (fun polynomial : Polynomial Goldilocks =>
            polynomial.eval (currentPoint (coordinates j))) (responseEq row)
        have summed :
            (∑ column : Fin 140, actualCoefficients output.gamma column row *
              priorData prior output.root column.val (coordinates j)) =
            ∑ column ∈ Finset.range 140,
              V8Smz9McaRecovery.extendCoefficients (actualCoefficients output.gamma) column row *
                priorData prior output.root column (coordinates j) := by
          rw [← Fin.sum_univ_eq_sum_range]
          apply Finset.sum_congr rfl
          intro column _
          simp only [V8Smz9McaRecovery.extendCoefficients, dif_pos column.isLt]
        have mixtureAt :
            V8Smz9McaRecovery.mixedWord (priorData prior output.root) (priorMasks prior output.root)
              (V8Smz9McaRecovery.extendCoefficients (actualCoefficients output.gamma))
              140 row (coordinates j) =
            priorMasks prior output.root row (coordinates j) +
              ∑ column : Fin 140, actualCoefficients output.gamma column row *
                priorData prior output.root column.val (coordinates j) :=
          (mixed_word_eq_sum (priorData prior output.root) (priorMasks prior output.root)
            (V8Smz9McaRecovery.extendCoefficients (actualCoefficients output.gamma))
            140 row (coordinates j)).trans
              (congrArg (fun value : Goldilocks =>
                priorMasks prior output.root row (coordinates j) + value) summed.symm)
        exact responseAt.trans ((equations j row).trans mixtureAt.symm)

end PriorSupportProof

/-- Clean PCS state is propagated backwards through the actual matrix-XOF
execution and actual reconstructed transcript. It is not an acceptance premise. -/
theorem stages_pcs_pending_false
    (ns : M.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire)
    (oracle : Oracle) (transcript : Transcript)
    (stages : ExecutionStages ns relation pending nonce wire oracle transcript)
    (clean : transcript.pending = false) :
    stages.pcs.pending = false := by
  have finalClean : stages.finalPending = false := by
    have same := congrArg Transcript.pending stages.reconstructed
    simpa only [reconstruct] using same.trans clean
  have executed := stages.matrixExecuted
  unfold matrixProgram at executed
  obtain ⟨sampled, _, finished⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (NativePrivateSpendQ58CurrentExecutableVerifier.fieldXof .piopMatrix 6722970 stages.pcs.hashFpp)
      _ (stages.matrix, stages.finalPending) executed
  change some
    (SmzaRp05PiopMatrixStage.matrixFromWords 1344594
      (SmzaRp05ExecutableChallengeStage.returnedWords 6722970 sampled),
      pendingFailure stages.pcs.pending sampled) =
    some (stages.matrix, stages.finalPending) at finished
  have pendingEq :
      pendingFailure stages.pcs.pending sampled = stages.finalPending :=
    congrArg Prod.snd (Option.some.inj finished)
  exact (SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words
    stages.pcs.pending sampled (pendingEq.trans finalClean)).1

/-- Every stage and the final hash record below comes from one accepting
ordinary current execution. Prior availability is not assumed: its missing
response/path and collision outcomes remain in PriorSupportOutcome. -/
theorem accepted_current_execution_has_prior_support_or_named_bad_arm
    (ns : M.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire)
    (oracle : Oracle) (prior : RawRecords)
    (accepted : (verifierProgram ns relation pending nonce wire).eval oracle = some ()) :
    ∃ transcript, ∃ stages : ExecutionStages ns relation pending nonce wire oracle transcript,
      transcript.pending = false ∧ oracle (finalInput transcript) = wire.hPiop ∧
      (finalInput transcript, wire.hPiop) ∈
        ((verifierProgram ns relation pending nonce wire).record oracle).2 ∧
      PriorSupportOutcome ns stages.decoded oracle stages.pcs prior := by
  obtain ⟨transcript, ⟨stages⟩, clean, digestEq, recorded⟩ :=
    accepted_execution_has_stages ns relation pending nonce wire oracle accepted
  have pcsClean := stages_pcs_pending_false ns relation pending nonce wire oracle
    transcript stages clean
  refine ⟨transcript, stages, clean, digestEq, recorded, ?_⟩
  exact pcs_execution_has_prior_support_or_named_bad_arm ns stages.openingPending
    wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted pcsClean prior

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedLeafSupport
