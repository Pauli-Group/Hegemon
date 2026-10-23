import HegemonCrypto.NativePrivateSpendQ58CurrentOrdinaryRecovery
import HegemonCrypto.NativePrivateSpendQ58CurrentRoleClassifier
import SmzaRp05AdaptivePhysicalReadBound
import SmzaRp05PhysicalAcceptedReplayLite

/-! Literal current pre-query trace events and their conditional physical
suffix mass. Late or missing-at-cut source material is never declared fixed.
A source trace changes only at an actual suffix insertion, charged to the
current challenge target or an existing current-frame child digest.
The physical inequality retains its genuine initial event mass; no assertion
that a producer-end prefix precedes every earlier adversarial role query is
introduced. This is a source proposal, not G3 qualification. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPrequeryEvents

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open V8Smz9CoherentVectorMerkle V8Smz9CoherentMerkleGeometry
open V8Smz9CoherentMerkleInstrument V8SmzaOnlineParser
open SmzaRp05FilteredDecoderInstability
open SmzaDynamicDatabaseSoundness
open SmzaRecordedTracePath
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaChallengeStageTargets (Role StageQuery)
open NativePrivateSpendQ58CurrentExecutableVerifier
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope
  (RawInput RawDigest Stage Trace rawNext rawPayload payloadNext rawChildren
    payload_next_child raw_children_arity)
end F
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (parseCurrentStageQuery)
end C
namespace O
export NativePrivateSpendQ58CurrentOrdinaryRecovery
  (Position PriorBad producerPrior actualView actualSample
    accepted_producer_verifier_has_actual_prefix_and_current_recovery_event)
end O
namespace P
export SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult rawLog basisOracle physicalRun accepted_branch_record_eq_physical_rawLog)
end P
namespace A
export SmzaRp05AdaptivePhysicalReadBound
  (ReadsAtMost ReadsWithinKeys adaptiveReadMass adaptive_read_role_mass_le)
end A

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
local instance : DecidableEq F.RawInput :=
  (inferInstance : LinearOrder F.RawInput).toDecidableEq

/-- The exact source dependency of each literal challenge-role key. -/
def queryStage : Role → F.Stage
  | .decsMatrix => .root
  | .piopMatrix => .fpp
  | .piopOpening => .piop
  | .decsSample => .decs

def queryTarget (input : F.RawInput) : F.Stage × F.RawDigest :=
  match C.parseCurrentStageQuery input with
  | some query => (queryStage query.role, query.target)
  | none => (.tree 0, fun _ => 0)

def sourceTrace (fuel : Nat) (records : RawRecords) (input : F.RawInput) : F.Trace :=
  extract F.rawNext records fuel (queryTarget input).1 (queryTarget input).2

/-- Child inclusion is derived from the current parser, not the old profile. -/
theorem current_raw_next_child
    (stage : F.Stage) (input : F.RawInput) (edges : List (F.Stage × F.RawDigest))
    (decoded : F.rawNext stage input = some edges)
    (edge : F.Stage × F.RawDigest) (member : edge ∈ edges) :
    edge.2 ∈ F.rawChildren input := by
  cases payload : F.rawPayload input with
  | none => simp [F.rawNext, payload] at decoded
  | some parsed =>
      have next : F.payloadNext stage parsed = some edges := by
        simpa [F.rawNext, payload] using decoded
      simpa only [F.rawChildren, payload] using
        F.payload_next_child stage parsed edges next edge member

/-- Each frontier is the literal finite set of the recorded list prefix. -/
def rawFrontier (log : List (F.RawInput × F.RawDigest)) (cut : Nat) : RawRecords :=
  (log.take cut).toFinset

theorem frontier_zero (log : List (F.RawInput × F.RawDigest)) :
    rawFrontier log 0 = ∅ := rfl

theorem frontier_end (log : List (F.RawInput × F.RawDigest)) :
    rawFrontier log log.length = log.toFinset := by simp [rawFrontier]

theorem frontier_succ (log : List (F.RawInput × F.RawDigest)) (cut : Nat)
    (within : cut < log.length) :
    rawFrontier log (cut + 1) =
      insert (log[cut]) (rawFrontier log cut) := by
  induction log generalizing cut with
  | nil => simp at within
  | cons call rest ih =>
      cases cut with
      | zero => simp [rawFrontier]
      | succ cut =>
          have next := ih cut (by simpa using within)
          simp only [rawFrontier, List.take_succ_cons, List.toFinset_cons,
            List.getElem_cons_succ] at next ⊢
          rw [next, Finset.insert_comm]

/-- A changed end trace has a concrete first-changing suffix insertion.
Neither endpoint is supplied as an accepted coverage certificate. -/
theorem suffix_difference_has_insertion
    (log : List (F.RawInput × F.RawDigest)) (input : F.RawInput)
    (fuel cut finish : Nat) (ordered : cut ≤ finish) (endBound : finish ≤ log.length)
    (different : sourceTrace fuel (rawFrontier log finish) input ≠
      sourceTrace fuel (rawFrontier log cut) input) :
    ∃ step, cut ≤ step ∧ step < finish ∧
      sourceTrace fuel (rawFrontier log (step + 1)) input ≠
        sourceTrace fuel (rawFrontier log step) input := by
  induction finish generalizing cut with
  | zero =>
      have zero : cut = 0 := by omega
      subst cut
      exact (different rfl).elim
  | succ finish ih =>
      by_cases prior : cut ≤ finish
      · by_cases lastChanged :
            sourceTrace fuel (rawFrontier log (finish + 1)) input ≠
              sourceTrace fuel (rawFrontier log finish) input
        · exact ⟨finish, prior, Nat.lt_succ_self _, lastChanged⟩
        · have oldDifferent : sourceTrace fuel (rawFrontier log finish) input ≠
              sourceTrace fuel (rawFrontier log cut) input := by
            intro same
            exact different ((not_ne_iff.mp lastChanged).trans same)
          obtain ⟨step, lower, upper, change⟩ := ih cut prior (by omega) oldDifferent
          exact ⟨step, lower, upper.trans (Nat.lt_succ_self _), change⟩
      · have same : cut = finish + 1 := by omega
        subst cut
        exact (different rfl).elim

/-- The selected late insertion must hit the actual current key's source
target or a child already named by a current raw frame at that prefix. -/
theorem late_source_insertion_hits_target_or_child
    (log : List (F.RawInput × F.RawDigest)) (input : F.RawInput)
    (fuel cut finish : Nat) (ordered : cut ≤ finish) (endBound : finish ≤ log.length)
    (different : sourceTrace fuel (rawFrontier log finish) input ≠
      sourceTrace fuel (rawFrontier log cut) input) :
    ∃ step, cut ≤ step ∧ step < finish ∧
      (log.getD step ([], fun _ => 0)).2 ∈
        ({(queryTarget input).2} : Finset F.RawDigest) ∪
          databaseChildren F.rawChildren (rawFrontier log step) := by
  obtain ⟨step, lower, upper, change⟩ :=
    suffix_difference_has_insertion log input fuel cut finish ordered endBound different
  have within : step < log.length := upper.trans_le endBound
  rw [frontier_succ log step within] at change
  have charged := changed_extraction_implies_target_or_child F.rawNext F.rawChildren
    current_raw_next_child (rawFrontier log step) (log[step]).1 (log[step]).2
    fuel [queryTarget input] (by simpa [sourceTrace, extractTargets] using change)
  refine ⟨step, lower, upper, ?_⟩
  rw [List.getD_eq_getElem log ([], fun _ => 0) within]
  simpa [targetDigests] using charged

/-- Missing-at-cut/present-at-finish source path is one literal late event,
with its insertion witness. It is not assumed absent. -/
theorem missing_at_cut_present_at_finish_is_late
    (log : List (F.RawInput × F.RawDigest)) (input : F.RawInput)
    (fuel cut finish : Nat) (ordered : cut ≤ finish) (endBound : finish ≤ log.length)
    (path : List Nat) (raw : F.RawInput)
    (missing : readPath path (sourceTrace fuel (rawFrontier log cut) input) = none)
    (present : readPath path (sourceTrace fuel (rawFrontier log finish) input) = some raw) :
    ∃ step, cut ≤ step ∧ step < finish ∧
      (log.getD step ([], fun _ => 0)).2 ∈
        ({(queryTarget input).2} : Finset F.RawDigest) ∪
          databaseChildren F.rawChildren (rawFrontier log step) := by
  apply late_source_insertion_hits_target_or_child log input fuel cut finish ordered endBound
  intro equal
  rw [equal, missing] at present
  cases present

variable {Key Counter Work Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]

def currentLabel (keyBytes : Key → F.RawInput) (counter : Counter) (fuel : Nat)
    (database : Database Key (VectorOutput Counter)) (input : Key) : F.Trace :=
  sourceTrace fuel (rawRecords keyBytes (vectorOutputBytes counter) database) (keyBytes input)

/-- Current role parsing plus actual current-frame source extraction has the
same finite target/child loss as the unchanged generic compiler. Parser=None
source keys remain live and can trigger this event. -/
theorem current_tracked_label_changes
    (keyBytes : Key → F.RawInput) (counter : Counter) (fuel cap : Nat)
    (database : Database Key (VectorOutput Counter)) (bounded : size database < cap)
    (queried : Key) :
    stepProbability (TrackedLabelChange (currentLabel keyBytes counter fuel)
      database queried) database queried ≤ (3 * cap : Rat) / (2^512 : Rat) := by
  let indices := trackedInputs database queried
  let keep : Key → F.RawInput → Prop := fun _ _ => True
  let target : Key → F.Stage × F.RawDigest := fun key => queryTarget (keyBytes key)
  apply NativePrivateSpendQ58EnvelopeInstability.filtered_family_step_change_bound
    F.rawChildren F.raw_children_arity F.rawNext current_raw_next_child
    keyBytes counter keep target fuel indices cap
    (tracked_inputs_length_le database queried cap bounded) database bounded queried
  intro output changed sameFamily
  obtain ⟨input, tracked, different⟩ := changed
  apply different
  have equal := filtered_family_eq_at F.rawNext keep target fuel
    (rawRecords keyBytes (vectorOutputBytes counter) (query database queried output))
    (rawRecords keyBytes (vectorOutputBytes counter) database) indices sameFamily input
    (tracked_inputs_mem database queried input tracked)
  simpa [currentLabel, sourceTrace, keep, target, restrictedRecords] using equal

/-- One observed current challenge target and the actual trace at its cut.
Deviation includes late response, Merkle and PIOP preimages uniformly. -/
def TraceDeviation (keyBytes : Key → F.RawInput) (counter : Counter)
    (fuel : Nat) (input : Key) (reference : F.Trace)
    (database : Database Key (VectorOutput Counter)) : Prop :=
  currentLabel keyBytes counter fuel database input ≠ reference

/-- This exact trace deviation has a derived two-sided instability bound.
No caller-supplied density, label-change or acceptance inclusion is used. -/
theorem trace_deviation_instability
    (keyBytes : Key → F.RawInput) (counter : Counter) (fuel : Nat)
    (input : Key) (reference : F.Trace) (cap : Nat) :
    InstabilityBound (TraceDeviation keyBytes counter fuel input reference)
      cap ((3 * cap : Rat) / (2^512 : Rat)) := by
  have changedBound : ∀ database : Database Key (VectorOutput Counter),
      size database < cap → ∀ queried,
      ∀ event : Property Key (VectorOutput Counter),
      (∀ output, event (query database queried output) →
        currentLabel keyBytes counter fuel (query database queried output) input ≠
          currentLabel keyBytes counter fuel database input) →
      stepProbability event database queried ≤ (3 * cap : Rat) / (2^512 : Rat) := by
    intro database bounded queried event changed
    let keep : Unit → F.RawInput → Prop := fun _ _ => True
    let target : Unit → F.Stage × F.RawDigest := fun _ => queryTarget (keyBytes input)
    apply NativePrivateSpendQ58EnvelopeInstability.filtered_family_step_change_bound
      F.rawChildren F.raw_children_arity F.rawNext current_raw_next_child
      keyBytes counter keep target fuel [()] cap (by simp; omega)
      database bounded queried event
    intro output inside equal
    have traceEqual := filtered_family_eq_at F.rawNext keep target fuel
      (rawRecords keyBytes (vectorOutputBytes counter) (query database queried output))
      (rawRecords keyBytes (vectorOutputBytes counter) database) [()] equal () (by simp)
    exact changed output inside (by
      simpa [currentLabel, sourceTrace, keep, target, restrictedRecords] using traceEqual)
  constructor
  · refine ⟨by positivity, ?_⟩
    intro database outside bounded queried
    apply changedBound database bounded queried _
    intro output deviated same
    exact deviated (same.trans (not_ne_iff.mp outside))
  · refine ⟨by positivity, ?_⟩
    intro database deviated bounded queried
    apply changedBound database bounded queried _
    intro output returned same
    apply deviated
    exact same.symm.trans (not_ne_iff.mp returned)

variable [Fintype Work] [DecidableEq Work]

/-- Conditional unnormalised mass on the SAME adaptive physical read tree.
The inequality displays the real incoming deviation mass, rather than
fabricating a zero initial event from a producer-end prefix. Every numerical
instability term is derived from current source grammar above. -/
theorem current_trace_deviation_physical_suffix_mass
    (depth : Nat) (encode : F.RawInput → Key)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (program : Program Result) (readBound : A.ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : A.ReadsWithinKeys encode decode keys program)
    (support cap : Nat)
    (state : SmzaRp05VectorReadCharge.VectorCmsState
      (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState support state) (total : HegemonCrypto.SmallWood.SmzaRp05RoleReadTotality.StandardOn keys state)
    (within : support + depth ≤ cap)
    (keyBytes : Key → F.RawInput) (counter : Counter) (fuel : Nat)
    (observedKey : Work → Key) (cutTrace : Work → F.Trace) :
    A.adaptiveReadMass encode decode
      (fun workspace => TraceDeviation keyBytes counter fuel
        (observedKey workspace) (cutTrace workspace)) program state ≤
      (stateNorm (workspaceEventProjection
        (fun workspace => TraceDeviation keyBytes counter fuel
          (observedKey workspace) (cutTrace workspace)) state) +
        (depth : ℝ) * Real.sqrt
          (6 * (((3 * cap : Rat) / (2^512 : Rat)) : ℝ)) * stateNorm state)^2 := by
  apply A.adaptive_read_role_mass_le depth encode decode program readBound keys keysWithin
    support cap state bounded total within _ _ (by positivity)
  intro workspace
  simpa only [Rat.cast_div] using
    (trace_deviation_instability keyBytes counter fuel
      (observedKey workspace) (cutTrace workspace) cap).toReal

/-- A nonzero accepted physical branch yields the very same ordinary current
wire, producer prefix and recovery event. No prior certificate is a premise. -/
theorem accepted_physical_current_execution_has_prefix_and_recovery_event
    {Phase Output : Type} [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    (encode : F.RawInput → Key) (decode : F.RawInput → Output → F.RawDigest)
    (producer : Program Wire) (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32))
    (branch : P.Branches decode (producer.bind (verifierProgram ns relation pending nonce)))
    (state : State Key Output Phase Work) (basis : Basis Key Output Phase Work)
    (fallback : F.RawDigest)
    (nonzero : globalDecompress
      (P.physicalRun encode decode (producer.bind (verifierProgram ns relation pending nonce))
        branch state) basis ≠ 0)
    (accepted : P.branchResult decode
      (producer.bind (verifierProgram ns relation pending nonce)) branch = some ()) :
    let oracle := P.basisOracle encode decode basis fallback
    ∃ wire, producer.eval oracle = some wire ∧
      P.rawLog decode (producer.bind (verifierProgram ns relation pending nonce)) branch =
        (producer.record oracle).2 ++
          ((verifierProgram ns relation pending nonce wire).record oracle).2 ∧
      ∃ transcript, ∃ stages : ExecutionStages ns relation pending nonce wire oracle transcript,
        transcript.pending = false ∧ oracle (finalInput transcript) = wire.hPiop ∧
        (O.PriorBad ns stages.decoded oracle stages.pcs (O.producerPrior producer oracle) ∨
         NativePrivateSpendQ58CurrentRecovery.WholeResponseRecovered
           NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint
           (O.actualView (O.producerPrior producer oracle) stages.pcs) ∨
         NativeHtlcUniversalMatrix.BadMatrix
           NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint 13172 360448
           (O.actualView (O.producerPrior producer oracle) stages.pcs).data
           (O.actualView (O.producerPrior producer oracle) stages.pcs).masks
           (O.actualView (O.producerPrior producer oracle) stages.pcs).coefficients ∨
         ∃ coordinates : Fin 58 → O.Position, ∃ distinct : Function.Injective coordinates,
           (∀ j, (coordinates j).val = stages.pcs.indexes.getD j.val 0) ∧
           (NativePrivateSpendQ58CurrentRecovery.support
             NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint
             (O.actualView (O.producerPrior producer oracle) stages.pcs)).card < 360448 ∧
           (O.actualSample coordinates distinct).val ⊆
             NativePrivateSpendQ58CurrentRecovery.support
               NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint
               (O.actualView (O.producerPrior producer oracle) stages.pcs)) := by
  let oracle := P.basisOracle encode decode basis fallback
  have replay := P.accepted_branch_record_eq_physical_rawLog encode decode
    (producer.bind (verifierProgram ns relation pending nonce)) branch state basis
    fallback nonzero accepted
  have ordinary : (producer.bind (verifierProgram ns relation pending nonce)).eval oracle =
      some () := by
    exact (Program.record_result oracle _).symm.trans (congrArg Prod.fst replay)
  obtain ⟨wire, produced, sourcePrefix, transcript, stages, clean, digestEq, event⟩ :=
    O.accepted_producer_verifier_has_actual_prefix_and_current_recovery_event
      producer ns relation pending nonce oracle ordinary
  refine ⟨wire, produced, ?_, transcript, stages, clean, digestEq, event⟩
  exact (congrArg Prod.snd replay).symm.trans sourcePrefix

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPrequeryEvents
