import HegemonCrypto.NativePrivateSpendQ58CurrentSourceCandidate
import HegemonCrypto.NativePrivateSpendQ58CurrentPrequeryEvents
import SmzaDynamicOracleExecution
import SmzaRp04RawMcaSampling
private def g3_mdm01_progress (phase : String) : IO Unit := do -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
  match ← IO.getEnv "HEGEMON_G3_MATRIX_PROGRESS_PATH" with -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
  | some path => IO.FS.withFile (System.FilePath.mk path) IO.FS.Mode.append (fun handle => do handle.putStrLn phase; handle.flush) -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
  | none => pure () -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
elab "g3_mdm01_entry " phase:str : command => -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
  Lean.Elab.Command.liftIO (g3_mdm01_progress phase.getString) -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
elab "g3_mdm01_returned " id:ident : command => do -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
  let names ← Lean.Elab.Command.liftCoreM (Lean.Elab.realizeGlobalConstWithInfos id) -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
  let env ← Lean.getEnv -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
  for name in names do -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
    match env.toKernelEnv.find? name with -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
    | some (.thmInfo _) => Lean.Elab.Command.liftIO (g3_mdm01_progress ("PHASE MDM01_RETURNED " ++ id.getId.toString)) -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
    | some (.defnInfo _) => Lean.Elab.Command.liftIO (g3_mdm01_progress ("PHASE MDM01_RETURNED " ++ id.getId.toString)) -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
    | _ => Lean.throwError "MDM01 returned command did not find a definition or theorem" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

elab "g3_mdm02_step " label:str " => " tac:tactic : tactic => do -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS02
  (liftM (g3_mdm01_progress ("PHASE MDM02_" ++ label.getString ++ "_ENTRY")) : Lean.Elab.Tactic.TacticM Unit) -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS02
  Lean.Elab.Tactic.evalTactic tac -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS02
  (liftM (g3_mdm01_progress ("PHASE MDM02_" ++ label.getString ++ "_END")) : Lean.Elab.Tactic.TacticM Unit) -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS02
/-! Concrete current13172/360448 DECS-matrix event on one initialized full
vector-oracle execution. The pure capped700-field decoder is reused; neither
the old405/65536 event nor its loss is used. Per-label density comes from the
current universal matrix count, and insertion loss from current raw frames.
The empty initial database has actual zero DynamicBad projection, so no
incoming event mass is silently dropped. This is one role, not all G3.
SOURCE ONLY; kernel and current accepted-event inclusion remain pending. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixDynamicMass
open Polynomial
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsLifting HegemonCrypto.CmsFinitePhaseSystem
open V8Smz9CoherentVectorMerkle V8Smz9CappedRawSampler
open V8Smz9CoherentMerkleInstrument V8Smz9RawCounterCompiler
open V8Smz9RuntimeFieldLayout V8Smz9McaRecovery V8Smz9McaDecoder
open NativeHtlcUniversalMatrix
open SmzaDynamicDatabaseSoundness SmzaDynamicOracleExecution
open SmzaRp04RawRoleSampling
open SmzaRp04RawMcaSampling (rawDecsMatrixOutput actualDecsMatrixOutput decsMatrixFieldEquiv)
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport (currentPoint)
end L
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (RawInput Trace)
end F
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (parseCurrentStageQuery)
end C
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (SourceLabel labelData labelMasks)
end S
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel current_tracked_label_changes)
end P

abbrev Position := Fin 8388608
abbrev Coefficients := NativePrivateSpendQ58CurrentRecovery.Coefficients Goldilocks

g3_mdm01_entry "PHASE MDM01_ENTRY matrixLoss" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
def matrixLoss : Rat := (140 * 16445033384594 : Rat) / Fintype.card (Fin 5 → Goldilocks)
g3_mdm01_returned matrixLoss -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

g3_mdm01_entry "PHASE MDM01_ENTRY matrixBad" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
def matrixBad (data : Nat → Position → Goldilocks) (masks : Fin 5 → Position → Goldilocks)
    (coefficients : Coefficients) : Prop :=
  BadMatrix L.currentPoint 13172 360448 data masks coefficients
g3_mdm01_returned matrixBad -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

g3_mdm01_entry "PHASE MDM01_ENTRY current_matrix_output_density" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
/-- All later degree13172 responses are included in this exceptional event.
The current line-count theorem is applied, not supplied by the caller. -/
theorem current_matrix_output_density
    (injective : Function.Injective L.currentPoint)
    (data : Nat → Position → Goldilocks) (masks : Fin 5 → Position → Goldilocks) :
    outputEventProbability (matrixBad data masks) ≤ matrixLoss := by
  let point : Position → Goldilocks := L.currentPoint
  have pointInjective : Function.Injective point := injective
  have pointEvent : matrixBad data masks = BadMatrix point 13172 360448 data masks := by
    unfold matrixBad
    rfl
  have currentCount :=
    NativePrivateSpendQ58CurrentOrdinaryRecovery.current_matrix_event_card
      point pointInjective data masks
  g3_mdm02_step "DENSITY_BODY" => with_reducible
    g3_mdm02_step "DENSITY_SAME" =>
      have same : Finset.univ.filter (matrixBad data masks) =
          badMatrices point 13172 360448 data masks 140 := by
        ext coefficients
        simp only [pointEvent, badMatrices, Finset.mem_filter, Finset.mem_univ, true_and]
    g3_mdm02_step "DENSITY_COUNT" =>
      have count : (Finset.univ.filter (matrixBad data masks)).card *
          Fintype.card (Fin 5 → Goldilocks) ≤
          Fintype.card Coefficients * (140 * 16445033384594) := by
        rw [same]
        exact currentCount
    g3_mdm02_step "DENSITY_FINAL" =>
      with_reducible
        simpa only [matrixLoss, Nat.cast_mul, Nat.cast_ofNat] using
          (SmzaRp04McaRoleCells.output_density_of_card_bound
            (B := Fin 5 → Goldilocks) (matrixBad data masks) (140 * 16445033384594) count)
g3_mdm01_returned current_matrix_output_density -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

g3_mdm01_entry "PHASE MDM01_ENTRY current_raw_matrix_bad_and_success" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
/-- Success-and-bad on capped uniform raw blocks; rejected and exhausted
sampler outputs remain in the original denominator. -/
theorem current_raw_matrix_bad_and_success
    (injective : Function.Injective L.currentPoint)
    (data : Nat → Position → Goldilocks) (masks : Fin 5 → Position → Goldilocks) :
    outputEventProbability (fun raw : Fin (digestCallCap 700) → RawByteBlock =>
      ∃ coefficients, rawDecsMatrixOutput raw = some coefficients ∧
        matrixBad data masks coefficients) ≤ matrixLoss := by
  let bad := Finset.univ.filter (matrixBad data masks)
  have sampled := raw_field_then_partial_decoder_bad_le (digestCallCap 700) 700
    (totalEquivDecoder decsMatrixFieldEquiv)
    (total_equiv_decoder_fibers_equal decsMatrixFieldEquiv) bad
  have event : (fun raw : Fin (digestCallCap 700) → RawByteBlock =>
      ∃ coefficients, rawDecsMatrixOutput raw = some coefficients ∧ coefficients ∈ bad) =
      (fun raw => ∃ coefficients, rawDecsMatrixOutput raw = some coefficients ∧
        matrixBad data masks coefficients) := by
    funext raw
    simp only [bad, Finset.mem_filter, Finset.mem_univ, true_and]
  change outputEventProbability (fun raw : Fin (digestCallCap 700) → RawByteBlock =>
    ∃ coefficients, rawDecsMatrixOutput raw = some coefficients ∧ coefficients ∈ bad) ≤
    V8Smz9RobustQueryMismatch.FiniteEvents.probability bad at sampled
  rw [event] at sampled
  apply sampled.trans
  calc
    _ = outputEventProbability (fun coefficients => coefficients ∈ bad) :=
      (SmzaRp04RoleBadCells.output_event_probability_membership bad).symm
    _ = outputEventProbability (matrixBad data masks) := by
      apply congrArg outputEventProbability
      funext coefficients
      apply propext
      simp only [bad, Finset.mem_filter, Finset.mem_univ, true_and]
    _ ≤ matrixLoss := current_matrix_output_density injective data masks
g3_mdm01_returned current_raw_matrix_bad_and_success -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

g3_mdm01_entry "PHASE MDM01_ENTRY current_vector_matrix_bad_and_success" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
theorem current_vector_matrix_bad_and_success
    {Counter : Type} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap 700) ↪ Counter)
    (injective : Function.Injective L.currentPoint)
    (data : Nat → Position → Goldilocks) (masks : Fin 5 → Position → Goldilocks) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ coefficients, actualDecsMatrixOutput select vector = some coefficients ∧
        matrixBad data masks coefficients) ≤ matrixLoss := by
  have selected := selected_raw_blocks_event_probability select
    (fun raw : Fin (digestCallCap 700) → RawByteBlock =>
      ∃ coefficients, rawDecsMatrixOutput raw = some coefficients ∧
        matrixBad data masks coefficients)
  exact selected.trans_le (current_raw_matrix_bad_and_success injective data masks)
g3_mdm01_returned current_vector_matrix_bad_and_success -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

g3_mdm01_entry "PHASE MDM01_ENTRY traceLabel" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
def traceLabel (trace : F.Trace) : S.SourceLabel := ⟨trace, none, []⟩
g3_mdm01_returned traceLabel -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

variable {Key Counter Workspace : Type}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]

g3_mdm01_entry "PHASE MDM01_ENTRY vectorBad" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
/-- Only a current DECS-matrix base vector is a selected bad claim. Parser
failure and every other challenge role give false, not an old-profile event. -/
def vectorBad (keyBytes : Key → F.RawInput) (select : Fin (digestCallCap 700) ↪ Counter)
    (trace : F.Trace) (key : Key) (vector : VectorOutput Counter) : Prop :=
  (∃ query, C.parseCurrentStageQuery (keyBytes key) = some query ∧
    query.role = .decsMatrix ∧ query.counter = 0) ∧
  ∃ coefficients, actualDecsMatrixOutput select vector = some coefficients ∧
    matrixBad (S.labelData (traceLabel trace)) (S.labelMasks (traceLabel trace)) coefficients
g3_mdm01_returned vectorBad -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

g3_mdm01_entry "PHASE MDM01_ENTRY output_event_probability_mono" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
private theorem output_event_probability_mono {Output : Type} [Fintype Output]
    (left right : Output → Prop) (included : ∀ output, left output → right output) :
    outputEventProbability left ≤ outputEventProbability right := by
  classical
  have subset : Finset.univ.filter left ⊆ Finset.univ.filter right := by
    intro output member
    exact Finset.mem_filter.mpr
      ⟨Finset.mem_univ _, included output (Finset.mem_filter.mp member).2⟩
  unfold outputEventProbability
  apply div_le_div_of_nonneg_right
  · exact_mod_cast Finset.card_le_card subset
  · exact Nat.cast_nonneg _
g3_mdm01_returned output_event_probability_mono -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

g3_mdm01_entry "PHASE MDM01_ENTRY current_vector_bad_per_label" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
omit [Fintype Key] [DecidableEq Key] in
theorem current_vector_bad_per_label
    (keyBytes : Key → F.RawInput) (select : Fin (digestCallCap 700) ↪ Counter)
    (injective : Function.Injective L.currentPoint) (trace : F.Trace) (key : Key) :
    outputEventProbability (vectorBad keyBytes select trace key) ≤ matrixLoss := by
  g3_mdm02_step "PER_LABEL_BODY" => with_reducible
    g3_mdm02_step "PER_LABEL_MONO" =>
      have dominated : outputEventProbability (vectorBad keyBytes select trace key) ≤
          outputEventProbability (fun vector : VectorOutput Counter =>
            ∃ coefficients, actualDecsMatrixOutput select vector = some coefficients ∧
              matrixBad (S.labelData (traceLabel trace))
                (S.labelMasks (traceLabel trace)) coefficients) :=
        output_event_probability_mono (vectorBad keyBytes select trace key)
          (fun vector : VectorOutput Counter =>
            ∃ coefficients, actualDecsMatrixOutput select vector = some coefficients ∧
              matrixBad (S.labelData (traceLabel trace))
                (S.labelMasks (traceLabel trace)) coefficients)
          (by
            intro vector member
            unfold vectorBad at member
            exact member.2)
    g3_mdm02_step "PER_LABEL_FINAL" =>
      exact dominated.trans (current_vector_matrix_bad_and_success select injective
        (S.labelData (traceLabel trace)) (S.labelMasks (traceLabel trace)))
g3_mdm01_returned current_vector_bad_per_label -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

g3_mdm01_entry "PHASE MDM01_ENTRY current_matrix_dynamic_instability" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
/-- Literal current source traces, including a queried key not yet in the
database, derive both entry and exit losses. No probability callback occurs. -/
theorem current_matrix_dynamic_instability
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (select : Fin (digestCallCap 700) ↪ Counter)
    (injective : Function.Injective L.currentPoint) (cap : Nat) :
    InstabilityBound (DynamicBad (P.currentLabel keyBytes counter 25)
      (vectorBad keyBytes select)) cap (((3 * cap : Rat) / (2^512 : Rat)) + matrixLoss) := by
  exact dynamic_bad_instability (P.currentLabel keyBytes counter 25)
    (vectorBad keyBytes select) cap matrixLoss ((3 * cap : Rat) / (2^512 : Rat))
    (by
      unfold matrixLoss
      exact div_nonneg (by norm_num) (Nat.cast_nonneg _))
    (by positivity) (current_vector_bad_per_label keyBytes select injective)
    (P.current_tracked_label_changes keyBytes counter 25 cap)
g3_mdm01_returned current_matrix_dynamic_instability -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

variable [Fintype Workspace] [DecidableEq Workspace]

g3_mdm01_entry "PHASE MDM01_ENTRY current_matrix_dynamic_initialized_zero" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
/-- The incoming event mass at the empty initialized database is actually
zero. This statement concerns this same DynamicBad, not a post-hoc cut event. -/
theorem current_matrix_dynamic_initialized_zero
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (select : Fin (digestCallCap 700) ↪ Counter) (cap : Nat)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ) :
    project (DynamicBad (P.currentLabel keyBytes counter 25) (vectorBad keyBytes select)) cap
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) = 0 :=
  initialized_dynamic_bad_zero (P.currentLabel keyBytes counter 25)
    (vectorBad keyBytes select) cap registers
g3_mdm01_returned current_matrix_dynamic_initialized_zero -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

g3_mdm01_entry "PHASE MDM01_ENTRY current_matrix_dynamic_database_mass" -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01
/-- Same initialized physical CMS execution; no uniform-challenge experiment
or supplied incoming projection is substituted for its terminal database. -/
theorem current_matrix_dynamic_database_mass
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (select : Fin (digestCallCap 700) ↪ Counter)
    (injective : Function.Injective L.currentPoint)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
      (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :
    normSquared (project
      (DynamicBad (P.currentLabel keyBytes counter 25) (vectorBad keyBytes select)) steps.length
      (rawRun vectorPhaseSystem steps.length
        (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) ≤
      databaseLoss steps.length
        ((((3 * steps.length : Rat) / (2^512 : Rat)) + matrixLoss : Rat) : ℝ) := by
  have capacity : (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction).length ≤
      steps.length := by simp
  have result := implemented_raw_database_game_le_database_loss vectorPhaseSystem
    (DynamicBad (P.currentLabel keyBytes counter 25) (vectorBad keyBytes select)) steps.length
    (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
    (current_matrix_dynamic_instability keyBytes counter select injective steps.length).toReal
    capacity (partial_random_oracle_empty_bounded registers) normalized
    (current_matrix_dynamic_initialized_zero keyBytes counter select steps.length registers)
  simpa only [List.length_map] using result
g3_mdm01_returned current_matrix_dynamic_database_mass -- G3_MATRIX_DYNAMIC_MASS_BUILD_PROGRESS01

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixDynamicMass
