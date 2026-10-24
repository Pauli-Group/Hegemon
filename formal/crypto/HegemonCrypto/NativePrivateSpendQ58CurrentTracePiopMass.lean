import HegemonCrypto.NativePrivateSpendQ58CurrentRawPiopDensity
import HegemonCrypto.NativePrivateSpendQ58CurrentGammaFiber
import HegemonCrypto.NativePrivateSpendQ58CurrentPiopRecordJoin
import HegemonCrypto.NativePrivateSpendQ58CurrentMatrixDynamicMass

/-! Current parsed-trace PIOP events on one fixed other-role table.
The FPP/PIOP inputs are read from the parsed extraction trace, not from the
unfiltered any-preimage selector. Current other-role gamma and matrix are
computed from the literal fixed table. Thus a label is fixed before its raw
selected challenge, including failed samplers. The derived physical suffix
bound retains the actual incoming event mass. This file does not assert that
every accepted physical branch already supplies the required trace/claim
readback; that same-execution inclusion remains a separate obligation.
SOURCE ONLY; no compiler or gate qualification. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentTracePiopMass
open Polynomial V8Smz9PiopSoundness
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open V8Smz9CoherentVectorMerkle V8Smz9CappedRawSampler
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument
open SmzaRp04RawRoleSampling SmzaDynamicDatabaseSoundness
open SmzaDynamicOracleExecution
open SmzaChallengeStageTargets (Role)
open V8Smz9RawCounterCompiler (digestCallCap)
open SmzaRp05RoleReadTotality (StandardOn)
open SmzaRecordedTracePath (readPath)
open SmzaRp05ExecutableMerkleVerifier (Program)
open scoped Classical
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (RawInput RawDigest Trace rawPayload)
end F
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (SourceLabel calculatedCandidate)
end S
namespace G
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps fixedGamma)
end G
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier
  (FixedTable parseCurrentStageQuery fixedVectorAtNonce)
end C
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (candidate)
end D
namespace Q
export NativePrivateSpendQ58CurrentPiopEvents
  (currentMatrixEvent currentOpeningEvent conservativeCurrentDenominator)
end Q
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel current_tracked_label_changes)
end P
namespace R
export NativePrivateSpendQ58CurrentRawPiopDensity
  (rawCurrentOpeningOutput vector_current_piop_matrix_success_and_bad_le
   vector_current_piop_opening_success_and_bad_le)
end R
namespace A
export SmzaRp05AdaptivePhysicalReadBound
  (ReadsAtMost ReadsWithinKeys adaptiveReadMass adaptive_read_role_mass_le)
end A
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

def child (trace : F.Trace) (index : Nat) : F.Trace :=
  match trace with
  | .missing => .missing
  | .budget => .budget
  | .record _ children => children.getD index .missing

def traceInput (trace : F.Trace) : F.RawInput := (readPath [] trace).getD []

def childDigest (trace : F.Trace) : F.RawDigest :=
  V8SmzaOracleParser.digestAt
    (((F.rawPayload (traceInput trace)).map V8SmzaOracleParser.Payload.bytes).getD []) 0

variable {Key Counter Work : Type}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]

/-- Actual current fixed-table lookup; missing cells remain none. Source
hashes have no successful current challenge parser and are not frozen here. -/
def fppLabel (selected : Role) (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) selected G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest) (fppTrace : F.Trace) : S.SourceLabel :=
  { rootTrace := child fppTrace 0
    responseInput := readPath [] fppTrace
    gamma := (G.fixedGamma selected keyBytes fixed decode (childDigest fppTrace)).getD [] }

def matrixLoss : Rat := ((1 : Rat) / Fintype.card Goldilocks)^5
def openingLoss : Rat := (V8Smz9QromAccounting.fallingProduct 552 6 : Rat) /
  Q.conservativeCurrentDenominator

private def optionEvent {Value Output : Type}
    (value : Option Value) (event : Value → Output → Prop) : Output → Prop :=
  match value with
  | none => fun _ => False
  | some source => event source

private def twoOptionEvent {Left Right Output : Type}
    (left : Option Left) (right : Option Right)
    (event : Left → Right → Output → Prop) : Output → Prop :=
  match left, right with
  | some source, some matrix => event source matrix
  | _, _ => fun _ => False

def matrixBad (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) Role.piopMatrix G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (select : Fin (digestCallCap (5 * 1344594)) ↪ Counter)
    (trace : F.Trace) (key : Key) : VectorOutput Counter → Prop :=
  optionEvent (S.calculatedCandidate (fppLabel .piopMatrix keyBytes fixed decode trace))
    (fun source vector =>
    (∃ query, C.parseCurrentStageQuery (keyBytes key) = some query ∧
      query.role = .piopMatrix ∧ query.counter = 0) ∧
    ¬ PiopExtraction.FullySatisfied (D.candidate relation source).system ∧
    ∃ matrix, rawPiopMatrixOutput 1344594 (selectedRawBlocks select vector) = some matrix ∧
      matrix ∈ Q.currentMatrixEvent (D.candidate relation source))

/-- The PIOP matrix for opening analysis is read only from the fixed
OTHER-role table and decoded by the current capped6722970-field sampler. -/
def fixedMatrix (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) Role.piopOpening G.currentRoleCaps keyBytes)
    (select : Fin (digestCallCap (5 * 1344594)) ↪ Counter) (target : F.RawDigest) :
    Option (Matrix 1344594) :=
  (C.fixedVectorAtNonce .piopOpening G.currentRoleCaps keyBytes fixed
    .piopMatrix target 0).bind fun vector =>
      rawPiopMatrixOutput 1344594 (selectedRawBlocks select vector)

def openingBad (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) Role.piopOpening G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (selectMatrix : Fin (digestCallCap (5 * 1344594)) ↪ Counter)
    (selectOpening : Fin (digestCallCap 6) ↪ Counter)
    (trace : F.Trace) (key : Key) : VectorOutput Counter → Prop :=
  twoOptionEvent
    (S.calculatedCandidate (fppLabel .piopOpening keyBytes fixed decode (child trace 0)))
    (fixedMatrix keyBytes fixed selectMatrix (childDigest trace))
    (fun source matrix vector =>
    (∃ query, C.parseCurrentStageQuery (keyBytes key) = some query ∧
      query.role = .piopOpening ∧ query.nonce < 16 ∧ query.counter = 0) ∧
    ¬ PiopExtraction.AffineBatchAccepts (D.candidate relation source).system
      (maskSum (D.candidate relation source)) matrix ∧
    ∃ opening, R.rawCurrentOpeningOutput (selectedRawBlocks selectOpening vector) = some opening ∧
      opening ∈ Q.currentOpeningEvent (D.candidate relation source) matrix
        (NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (traceInput trace)))

private theorem probability_mono {Output : Type} [Fintype Output]
    (left right : Output → Prop) (included : ∀ output, left output → right output) :
    outputEventProbability left ≤ outputEventProbability right := by
  unfold outputEventProbability
  apply div_le_div_of_nonneg_right
  · exact_mod_cast Finset.card_le_card (show Finset.univ.filter left ⊆
        Finset.univ.filter right from fun output member =>
          Finset.mem_filter.mpr ⟨Finset.mem_univ _, included output (Finset.mem_filter.mp member).2⟩)
  · exact Nat.cast_nonneg _

private theorem probability_empty_le {Output : Type} [Fintype Output]
    (event : Output → Prop) (loss : Rat)
    (empty : ∀ output, event output → False) (nonnegative : 0 ≤ loss) :
    outputEventProbability event ≤ loss := by
  have emptyEvent : event = (fun _ => False) := by
    funext output
    exact propext ⟨empty output, False.elim⟩
  simpa [emptyEvent, outputEventProbability] using nonnegative

private theorem matrixLoss_nonnegative : 0 ≤ matrixLoss := by
  unfold matrixLoss
  exact pow_nonneg (div_nonneg zero_le_one (Nat.cast_nonneg _)) _

private theorem openingLoss_nonnegative : 0 ≤ openingLoss := by
  unfold openingLoss
  exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)

private theorem option_none_or_some {Value : Type} (value : Option Value) :
    value = none ∨ ∃ source, value = some source := by
  cases value with
  | none => exact Or.inl rfl
  | some source => exact Or.inr ⟨source, rfl⟩

private theorem probability_option_event_le {Value Output : Type} [Fintype Output]
    (value : Option Value) (event : Value → Output → Prop) (loss : Rat)
    (nonnegative : 0 ≤ loss) (bound : ∀ source, outputEventProbability (event source) ≤ loss) :
    outputEventProbability (optionEvent value event) ≤ loss := by
  cases value with
  | none => exact probability_empty_le _ loss (fun _ absent => absent) nonnegative
  | some source => exact bound source

private theorem probability_two_option_event_le {Left Right Output : Type} [Fintype Output]
    (left : Option Left) (right : Option Right) (event : Left → Right → Output → Prop)
    (loss : Rat) (nonnegative : 0 ≤ loss)
    (bound : ∀ source matrix, outputEventProbability (event source matrix) ≤ loss) :
    outputEventProbability (twoOptionEvent left right event) ≤ loss := by
  cases left with
  | none =>
      cases right with
      | none => exact probability_empty_le _ loss (fun _ absent => absent) nonnegative
      | some matrix => exact probability_empty_le _ loss (fun _ absent => absent) nonnegative
  | some source =>
      cases right with
      | none => exact probability_empty_le _ loss (fun _ absent => absent) nonnegative
      | some matrix => exact bound source matrix

private theorem probability_selected_guarded_le {Output : Type} [Fintype Output]
    (selector guard : Prop) (event : Output → Prop) (loss : Rat) (nonnegative : 0 ≤ loss)
    (bound : guard → outputEventProbability event ≤ loss) :
    outputEventProbability (fun output => selector ∧ guard ∧ event output) ≤ loss := by
  by_cases inside : guard
  · exact (probability_mono _ event (fun _ selected => selected.2.2)).trans (bound inside)
  · exact probability_empty_le _ loss
      (fun _ selected => inside selected.2.1) nonnegative

omit [Fintype Key] [DecidableEq Key] in
theorem current_trace_matrix_per_label
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) Role.piopMatrix G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (select : Fin (digestCallCap (5 * 1344594)) ↪ Counter) (trace : F.Trace) (key : Key) :
    outputEventProbability (matrixBad relation keyBytes fixed decode select trace key) ≤ matrixLoss := by
  delta matrixBad
  with_reducible
    exact probability_option_event_le
      (S.calculatedCandidate (fppLabel .piopMatrix keyBytes fixed decode trace))
      (fun source vector =>
        (∃ query, C.parseCurrentStageQuery (keyBytes key) = some query ∧
          query.role = .piopMatrix ∧ query.counter = 0) ∧
        ¬ PiopExtraction.FullySatisfied (D.candidate relation source).system ∧
        ∃ matrix, rawPiopMatrixOutput 1344594 (selectedRawBlocks select vector) = some matrix ∧
          matrix ∈ Q.currentMatrixEvent (D.candidate relation source))
      matrixLoss matrixLoss_nonnegative
      (fun source => probability_selected_guarded_le _ _ _ matrixLoss matrixLoss_nonnegative
        (fun invalid => by
          delta matrixLoss
          with_reducible
            exact (R.vector_current_piop_matrix_success_and_bad_le select
                (D.candidate relation source) invalid)))


omit [Fintype Key] [DecidableEq Key] in
theorem current_trace_opening_per_label
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) Role.piopOpening G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (selectMatrix : Fin (digestCallCap (5 * 1344594)) ↪ Counter)
    (selectOpening : Fin (digestCallCap 6) ↪ Counter) (trace : F.Trace) (key : Key) :
    outputEventProbability
      (openingBad relation keyBytes fixed decode selectMatrix selectOpening trace key) ≤ openingLoss := by
  delta openingBad
  with_reducible
    exact probability_two_option_event_le
      (S.calculatedCandidate (fppLabel .piopOpening keyBytes fixed decode (child trace 0)))
      (fixedMatrix keyBytes fixed selectMatrix (childDigest trace))
      (fun source matrix vector =>
        (∃ query, C.parseCurrentStageQuery (keyBytes key) = some query ∧
          query.role = .piopOpening ∧ query.nonce < 16 ∧ query.counter = 0) ∧
        ¬ PiopExtraction.AffineBatchAccepts (D.candidate relation source).system
          (maskSum (D.candidate relation source)) matrix ∧
        ∃ opening, R.rawCurrentOpeningOutput (selectedRawBlocks selectOpening vector) = some opening ∧
          opening ∈ Q.currentOpeningEvent (D.candidate relation source) matrix
            (NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (traceInput trace)))
      openingLoss openingLoss_nonnegative
      (fun source matrix => probability_selected_guarded_le _ _ _ openingLoss openingLoss_nonnegative
        (fun failure => by
          delta openingLoss
          with_reducible
            exact (R.vector_current_piop_opening_success_and_bad_le selectOpening
                (D.candidate relation source) matrix
                (NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (traceInput trace)) failure)))


theorem current_trace_matrix_instability
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (fixed : C.FixedTable (Counter := Counter) Role.piopMatrix G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (select : Fin (digestCallCap (5 * 1344594)) ↪ Counter) (cap : Nat) :
    InstabilityBound (DynamicBad (P.currentLabel keyBytes counter 26)
      (matrixBad relation keyBytes fixed decode select)) cap
      (((3 * cap : Rat)/(2^512 : Rat)) + matrixLoss) :=
  dynamic_bad_instability _ _ cap matrixLoss ((3 * cap : Rat)/(2^512 : Rat))
    matrixLoss_nonnegative (by positivity)
    (current_trace_matrix_per_label relation keyBytes fixed decode select)
    (P.current_tracked_label_changes keyBytes counter 26 cap)

theorem current_trace_opening_instability
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (fixed : C.FixedTable (Counter := Counter) Role.piopOpening G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (selectMatrix : Fin (digestCallCap (5 * 1344594)) ↪ Counter)
    (selectOpening : Fin (digestCallCap 6) ↪ Counter) (cap : Nat) :
    InstabilityBound (DynamicBad (P.currentLabel keyBytes counter 27)
      (openingBad relation keyBytes fixed decode selectMatrix selectOpening)) cap
      (((3 * cap : Rat)/(2^512 : Rat)) + openingLoss) :=
  dynamic_bad_instability _ _ cap openingLoss ((3 * cap : Rat)/(2^512 : Rat))
    openingLoss_nonnegative (by positivity)
    (current_trace_opening_per_label relation keyBytes fixed decode selectMatrix selectOpening)
    (P.current_tracked_label_changes keyBytes counter 27 cap)

variable [Fintype Work] [DecidableEq Work]

/-- Same current event has zero mass at actual empty initialization. This
does not declare its mass zero at a later producer-end or role cut. -/
theorem current_trace_matrix_initialized_zero
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (fixed : C.FixedTable (Counter := Counter) Role.piopMatrix G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (select : Fin (digestCallCap (5 * 1344594)) ↪ Counter) (cap : Nat)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter) (Workspace := Work) → ℂ) :
    project (DynamicBad (P.currentLabel keyBytes counter 26)
      (matrixBad relation keyBytes fixed decode select)) cap
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) = 0 :=
  initialized_dynamic_bad_zero _ _ cap registers

theorem current_trace_opening_initialized_zero
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (fixed : C.FixedTable (Counter := Counter) Role.piopOpening G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (selectMatrix : Fin (digestCallCap (5 * 1344594)) ↪ Counter)
    (selectOpening : Fin (digestCallCap 6) ↪ Counter) (cap : Nat)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter) (Workspace := Work) → ℂ) :
    project (DynamicBad (P.currentLabel keyBytes counter 27)
      (openingBad relation keyBytes fixed decode selectMatrix selectOpening)) cap
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) = 0 :=
  initialized_dynamic_bad_zero _ _ cap registers

/-- Unnormalised conditional mass of this current event on the actual
adaptive physical suffix. Its incoming mass is displayed, not postulated
zero at a late role cut. The two-sided instability is derived above. -/
theorem current_trace_matrix_physical_suffix_mass {Result : Type}
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (fixed : C.FixedTable (Counter := Counter) Role.piopMatrix G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (select : Fin (digestCallCap (5 * 1344594)) ↪ Counter)
    (depth : Nat) (encode : F.RawInput → Key) (program : Program Result)
    (readBound : A.ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : A.ReadsWithinKeys encode decode keys program)
    (support cap : Nat)
    (state : SmzaRp05VectorReadCharge.VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState support state) (total : StandardOn keys state)
    (within : support + depth ≤ cap) :
    let event := DynamicBad (P.currentLabel keyBytes counter 26)
      (matrixBad relation keyBytes fixed decode select)
    A.adaptiveReadMass encode decode (fun _ => event) program state ≤
      (stateNorm (workspaceEventProjection (fun _ => event) state) +
        (depth : ℝ) * Real.sqrt (6 *
          ((((3 * cap : Rat)/(2^512 : Rat)) + matrixLoss : Rat) : ℝ)) * stateNorm state)^2 := by
  apply A.adaptive_read_role_mass_le depth encode decode program readBound keys keysWithin
    support cap state bounded total within _ _ (by
      exact_mod_cast (show (0 : Rat) ≤ ((3 * cap : Rat)/(2^512 : Rat)) + matrixLoss from
        add_nonneg (div_nonneg (by positivity) (by positivity)) matrixLoss_nonnegative))
  intro _
  exact (current_trace_matrix_instability relation keyBytes counter fixed decode select cap).toReal

theorem current_trace_opening_physical_suffix_mass {Result : Type}
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (fixed : C.FixedTable (Counter := Counter) Role.piopOpening G.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (selectMatrix : Fin (digestCallCap (5 * 1344594)) ↪ Counter)
    (selectOpening : Fin (digestCallCap 6) ↪ Counter)
    (depth : Nat) (encode : F.RawInput → Key) (program : Program Result)
    (readBound : A.ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : A.ReadsWithinKeys encode decode keys program)
    (support cap : Nat)
    (state : SmzaRp05VectorReadCharge.VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState support state) (total : StandardOn keys state)
    (within : support + depth ≤ cap) :
    let event := DynamicBad (P.currentLabel keyBytes counter 27)
      (openingBad relation keyBytes fixed decode selectMatrix selectOpening)
    A.adaptiveReadMass encode decode (fun _ => event) program state ≤
      (stateNorm (workspaceEventProjection (fun _ => event) state) +
        (depth : ℝ) * Real.sqrt (6 *
          ((((3 * cap : Rat)/(2^512 : Rat)) + openingLoss : Rat) : ℝ)) * stateNorm state)^2 := by
  apply A.adaptive_read_role_mass_le depth encode decode program readBound keys keysWithin
    support cap state bounded total within _ _ (by
      exact_mod_cast (show (0 : Rat) ≤ ((3 * cap : Rat)/(2^512 : Rat)) + openingLoss from
        add_nonneg (div_nonneg (by positivity) (by positivity)) openingLoss_nonnegative))
  intro _
  exact (current_trace_opening_instability relation keyBytes counter fixed decode
    selectMatrix selectOpening cap).toReal

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentTracePiopMass

