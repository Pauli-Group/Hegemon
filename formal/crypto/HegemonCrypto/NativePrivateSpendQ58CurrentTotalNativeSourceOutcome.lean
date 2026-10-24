import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalFinalSecurity
import HegemonCrypto.NativePrivateSpendQ58CurrentNativeOperationData

/-! Actual canonical G3 recovery for the source-owned native operation data
constructor. Erasure is pure and preserves the original adaptive program,
raw proof producers, public namespaces, rejection behavior and lifetime Q.
No arbitrary satisfying assignment is substituted for the actual decoder. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentTotalNativeSourceOutcome
open scoped Classical BigOperators
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult rawLog)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open V8Smz9CoherentVectorMerkle (VectorOutput)
namespace GS
export NativePrivateSpendQ58CurrentGlobalSourceSupport
  (NativeStageInput nativeStage nativeConstructor AllActualSourceWitnesses)
end GS
namespace H
export NativePrivateSpendQ58CurrentGlobalRawLogTransport
  (Stage adaptiveHistoryProgram actualTerminalProducer actualTerminalRoot historyProgram)
end H
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter decode)
end G
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay (claimOracle fullClaims)
end Q
namespace CC
export NativePrivateSpendQ58CurrentCanonicalSourceClassifier (root sourceOracle records SourceWitness)
end CC
namespace GC
export NativePrivateSpendQ58CurrentGlobalSourceClassification (observerSourceView)
end GC
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded decodedValues)
end D
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire Transcript ExecutionStages)
end E
namespace RG
export NativePrivateSpendQ58CurrentRecoveryGeometry (RecoveryGeometry)
end RG
namespace S
export NativePrivateSpendQ58CurrentGlobalSourceSelector (canonical missingSource)
end S
namespace Current
export NativePrivateSpendQ58CurrentPublicOpening (Values Satisfies)
end Current
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- Pure erasure of ordinary operation/append metadata; no extra oracle read. -/
def eraseConstructor {Input : Type} (input : Input → GS.NativeStageInput)
    (constructor : Program (List Input)) : Program (List GS.NativeStageInput) :=
  constructor.bind fun inputs => .done (some (inputs.map input))

/-- The SAME producer, same physical records and calculated decoder source. -/
def CalculatedPacked (producer : Program E.Wire)
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce : Fin (2^32))
    (branch : Branches G.decode (CC.root producer ns relation nonce))
    (view : NativePrivateSpendQ58CurrentSourceSelectorTransport.SourceView (CC.root producer ns relation nonce))
    (packed : Current.Values) : Prop :=
  let oracle := CC.sourceOracle producer ns relation nonce branch view
  ∃ wire, producer.eval oracle=some wire ∧
    ∃ transcript, ∃ stages : E.ExecutionStages ns relation false nonce wire oracle transcript,
      transcript.pending=false ∧
      ∃ geometry : RG.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs
          (CC.records producer ns relation nonce view), packed=D.decodedValues geometry.source

theorem source_witness_derives_calculated_packed
    (producer : Program E.Wire) (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce : Fin (2^32))
    (branch : Branches G.decode (NativePrivateSpendQ58CurrentCanonicalSourceClassifier.root producer ns relation nonce))
    (view : NativePrivateSpendQ58CurrentSourceSelectorTransport.SourceView
      (NativePrivateSpendQ58CurrentCanonicalSourceClassifier.root producer ns relation nonce))
    (witness : CC.SourceWitness producer ns relation nonce branch view) :
    ∃ packed, Current.Satisfies relation packed ∧
      CalculatedPacked producer ns relation nonce branch view packed := by
  obtain ⟨wire,produced,transcript,stages,clean,geometry,_identities,_claims,valid⟩ := witness
  exact ⟨D.decodedValues geometry.source,valid,wire,produced,transcript,stages,clean,geometry,rfl⟩

variable {Input : Type} (input : Input → GS.NativeStageInput)
    (template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate)
    (constructor : Program (List Input))
local notation "Ctor" => GS.nativeConstructor template (eraseConstructor input constructor)
local notation "Global" => H.adaptiveHistoryProgram Ctor
local notation "V" => VectorOutput G.Counter

/-- Actual source-good execution supplies the returned operation data and a
SAME calculated satisfying assignment for EVERY actually constructed stage.
The raw input constructor is replayed on the canonical original source DB;
neither its result nor any selected stage/validity certificate is an input. -/
theorem actual_source_good_derives_recovered_operation_inputs
    (branch : Branches G.decode Global) (database : Database (G.Key Global) V)
    (good : ¬S.missingSource template (eraseConstructor input constructor) branch
      (SmzaRp05ConditionedExecution.xView
        (NativePrivateSpendQ58CurrentSourceSelectorTransport.sourceKeys Global) database)) :
    let full := S.canonical template (eraseConstructor input constructor) branch
      (SmzaRp05ConditionedExecution.xView
        (NativePrivateSpendQ58CurrentSourceSelectorTransport.sourceKeys Global) database)
    let oracle := Q.claimOracle Global full (fun _ => 0)
    ∃ (inputs : List Input) (stages : List H.Stage)
      (constructed : (Ctor).eval oracle=some stages),
      constructor.eval oracle=some inputs ∧
      stages=inputs.map (fun value => GS.nativeStage template (input value)) ∧
      (H.historyProgram stages).eval oracle=some () ∧
      ∀ i : Fin stages.length,
        ∃ observer : Branches G.decode (H.actualTerminalRoot Ctor stages i),
          branchResult G.decode (H.actualTerminalRoot Ctor stages i) observer=some () ∧
          (rawLog G.decode (H.actualTerminalRoot Ctor stages i) observer).toFinset=
            (rawLog G.decode Global branch).toFinset ∧
          ClaimsDatabaseEvent (Q.fullClaims (H.actualTerminalRoot Ctor stages i) observer)
            (fun key => full (NativePrivateSpendQ58CurrentGlobalRawLogTransport.actualTerminalKeys
              Ctor oracle stages constructed i key)) ∧
          ∃ packed, Current.Satisfies stages[i.val].relation packed ∧
            CalculatedPacked (H.actualTerminalProducer Ctor stages i)
              stages[i.val].ns stages[i.val].relation stages[i.val].nonce observer
              (GC.observerSourceView Ctor oracle stages constructed i full) packed := by
  dsimp only
  let full := S.canonical template (eraseConstructor input constructor) branch
    (SmzaRp05ConditionedExecution.xView
      (NativePrivateSpendQ58CurrentSourceSelectorTransport.sourceKeys Global) database)
  let oracle := Q.claimOracle Global full (fun _ => 0)
  have witnesses : GS.AllActualSourceWitnesses Ctor branch full := not_not.mp good
  obtain ⟨stages,constructed,accepted,recovered⟩ := witnesses
  obtain ⟨erased,eraseResult,mappedStages⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (eraseConstructor input constructor)
      (fun values => Program.done (some (values.map (GS.nativeStage template)))) stages constructed
  have stagesEq : erased.map (GS.nativeStage template)=stages := Option.some.inj mappedStages
  obtain ⟨inputs,inputResult,mappedInput⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle constructor
      (fun values => Program.done (some (values.map input))) erased eraseResult
  have erasedEq : inputs.map input=erased := Option.some.inj mappedInput
  refine ⟨inputs,stages,constructed,inputResult,?_,accepted,?_⟩
  · rw [←stagesEq,←erasedEq,List.map_map]
    rfl
  · intro i
    obtain ⟨observer,success,logEq,claims,witness⟩ := recovered i
    obtain ⟨packed,valid,calculated⟩ := source_witness_derives_calculated_packed
      (H.actualTerminalProducer Ctor stages i) stages[i.val].ns stages[i.val].relation
      stages[i.val].nonce observer _ witness
    exact ⟨observer,success,logEq,claims,packed,valid,calculated⟩

namespace GD
export NativePrivateSpendQ58CurrentNativeOperationData
  (EnrichedStageInput OperationData SnapshotData nativeStages nativeConstructor stagePrefix
   appendOutputs append_native_trace append_outputs_raw_trace snapshot nativePublic
   append_rewards_native_trace)
end GD
namespace CG
export HegemonCrypto.NativePrivateSpendCurrentG1CanonicalGameAdapter
  (SourceOutcome SourceOutcome.unauthorized sourceGameEvent source_game_coverage)
end CG
open HegemonCrypto.NativePrivateSpendCurrentChronologicalApprovalHistory
open HegemonCrypto.NativePrivateSpendCurrentNativeHistoryJoin
open HegemonCrypto.NativePrivateSpendCurrentProtocolHistory
open HegemonCrypto.NativePrivateSpendCurrentFinalHistory
open HegemonCrypto.NativePrivateSpendLocalSemantics
open HegemonCrypto.NativeLaunchConstraintAdapterBridge

namespace Collector
local instance collectorPrimeFact : Fact (Nat.Prime HegemonCrypto.NativePrivateSpendLocalSemantics.modulus) :=
  ⟨HegemonCrypto.SmallWood.goldilocks_prime⟩
/-- This internal value is created only by the actual G3 recovery below.
Its ordinary data remain the original enriched input; its packed assignment
and satisfying proof come from the SAME actual calculated geometry. -/
structure RecoveredOperation (template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate) where
  input : GD.EnrichedStageInput template
  packed : Current.Values
  valid : Current.Satisfies (GS.nativeStage template input.input).relation packed

def selectedFinal {template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate}
    (operation : RecoveredOperation template) : Prop :=
  HegemonCrypto.NativePrivateSpendArithmeticTopology.natural (HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics.sourceAssignment operation.packed) (operation.input.data.routes.modes 2)=1

/-- Ordinary snapshot data at the exact prefix reconstructed by append order.
There is no NativeSourceTrace, selected mode or desired authorization field.
This is the explicit finite F1 append/table/root interpretation; positions and
all source/Final validity are derived by the collector, not supplied by F1. -/
inductive RawChronology (template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate) :
    List (RecoveredOperation template) → List Produced → Type
  | nil (outputs : List Produced) : RawChronology template [] outputs
  | cons (head : RecoveredOperation template) (tail : List (RecoveredOperation template))
      (outputs : List Produced)
      (raw : GD.SnapshotData head.input.data head.packed
        (GD.stagePrefix head.input outputs).length (GD.stagePrefix head.input outputs))
      (later : RawChronology template tail
        (GD.appendOutputs head.input head.packed head.valid outputs)) :
      RawChronology template (head::tail) outputs

def atStage {template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate}
    (operation : RecoveredOperation template) (outputs : List Produced)
    (before : NativeSourceTrace outputs)
    (raw : GD.SnapshotData operation.input.data operation.packed
      (GD.stagePrefix operation.input outputs).length (GD.stagePrefix operation.input outputs)) :
    Option CG.SourceOutcome :=
  if selected : selectedFinal operation then
    some { outputs := GD.stagePrefix operation.input outputs
           trace := GD.append_rewards_native_trace operation.input.rewardsBefore outputs before
           final := NativePrivateSpendQ58CurrentNativeOperationData.final operation.input.data
             operation.packed (GD.stagePrefix operation.input outputs).length
           valid := NativePrivateSpendQ58CurrentNativeOperationData.final_valid_of_mode2
             operation.input.data operation.packed _ operation.valid (by
               simpa (config := { instances := true }) only [selectedFinal] using! selected)
           snapshot := GD.snapshot raw
             (HegemonCrypto.NativePrivateSpendCurrentNativeHistoryJoin.native_trace_raw_append
               (GD.append_rewards_native_trace operation.input.rewardsBefore outputs before)) }
  else none

/-- Every actual selected Final is retained, including a healthy Final before
or after a bad one. Emitted slots and rewards are scanned in native order. -/
def collect {template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate}
    {operations : List (RecoveredOperation template)} {outputs : List Produced}
    (raw : RawChronology template operations outputs) (before : NativeSourceTrace outputs) :
    List CG.SourceOutcome :=
  match raw with
  | .nil _ => []
  | .cons head tail outputs snapshot later =>
      (atStage head outputs before snapshot).toList ++
        collect later (GD.append_native_trace head.input head.packed head.valid outputs before snapshot)

theorem collect_empty_iff {template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate}
    {operations : List (RecoveredOperation template)} {outputs : List Produced}
    (raw : RawChronology template operations outputs) (before : NativeSourceTrace outputs) :
    collect raw before=[] ↔ ∀ operation∈operations,¬selectedFinal operation := by
  induction raw with
  | nil outputs => simp [collect]
  | cons head tail outputs snapshot later ih =>
      by_cases selected : selectedFinal head
      · simp [collect,atStage,selected]
      · simp [collect,atStage,selected,ih]

/-- The first bad Final is an internal mathematical readout, as in the G1
canonical game adapter. No private-DB conditioning is an adversary gate and
no efficiency/extractor claim is made. None means there is no selected Final. -/
def firstBad (outcomes : List CG.SourceOutcome) : Option CG.SourceOutcome :=
  if bad : ∃ outcome∈outcomes,outcome.unauthorized then
    some (Classical.choose bad)
  else outcomes.head?

theorem first_bad_covers_all (outcomes : List CG.SourceOutcome)
    (bad : ∃ outcome∈outcomes,outcome.unauthorized) :
    ∃ outcome, firstBad outcomes=some outcome ∧ outcome∈outcomes ∧ outcome.unauthorized := by
  exact ⟨Classical.choose bad,dif_pos bad,(Classical.choose_spec bad).1,(Classical.choose_spec bad).2⟩

theorem first_bad_none_iff (outcomes : List CG.SourceOutcome) : firstBad outcomes=none ↔ outcomes=[] := by
  unfold firstBad
  split
  · constructor
    · intro impossible;cases impossible
    · intro empty
      obtain ⟨outcome,member,_⟩ := ‹∃ outcome∈outcomes,outcome.unauthorized›
      simp [empty] at member
  · cases outcomes <;> simp

theorem complete_readout_none_iff_no_final
    {template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate}
    {operations : List (RecoveredOperation template)} {outputs : List Produced}
    (raw : RawChronology template operations outputs) (before : NativeSourceTrace outputs) :
    firstBad (collect raw before)=none ↔ ∀ operation∈operations,¬selectedFinal operation :=
  (first_bad_none_iff _).trans (collect_empty_iff raw before)

theorem every_unauthorized_final_has_current_game
    {template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate}
    {operations : List (RecoveredOperation template)} {outputs : List Produced}
    (raw : RawChronology template operations outputs) (before : NativeSourceTrace outputs)
    (bad : ∃ outcome∈collect raw before,outcome.unauthorized) :
    ∃ kind : Fin 7,∃ outcome,firstBad (collect raw before)=some outcome ∧ CG.sourceGameEvent kind outcome := by
  obtain ⟨outcome,read,_member,bad⟩ := first_bad_covers_all _ bad
  obtain ⟨kind,game⟩ := CG.source_game_coverage outcome bad
  exact ⟨kind,outcome,read,game⟩

variable (template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate)
    (rawConstructor : Program (List (GD.EnrichedStageInput template)))
local notation "CtorData" => GD.nativeConstructor template rawConstructor
local notation "GlobalData" => H.adaptiveHistoryProgram CtorData
local notation "VData" => VectorOutput G.Counter
local notation "sourceView" => SmzaRp05ConditionedExecution.xView
  (NativePrivateSpendQ58CurrentSourceSelectorTransport.sourceKeys GlobalData)
local notation "fullData" => S.canonical template
  (NativePrivateSpendQ58CurrentNativeOperationData.eraseConstructor template rawConstructor)

structure StageRecovery (branch : Branches G.decode GlobalData)
    (database : Database (G.Key GlobalData) VData) (stages : List H.Stage)
    (constructed : (CtorData).eval (Q.claimOracle GlobalData (fullData branch (sourceView database)) (fun _=>0))=some stages)
    (i : Fin stages.length) where
  observer : Branches G.decode (H.actualTerminalRoot CtorData stages i)
  accepted : branchResult G.decode (H.actualTerminalRoot CtorData stages i) observer=some ()
  log : (rawLog G.decode (H.actualTerminalRoot CtorData stages i) observer).toFinset=
    (rawLog G.decode GlobalData branch).toFinset
  claims : ClaimsDatabaseEvent (Q.fullClaims (H.actualTerminalRoot CtorData stages i) observer)
    (fun key => fullData branch (sourceView database)
      (NativePrivateSpendQ58CurrentGlobalRawLogTransport.actualTerminalKeys CtorData
        (Q.claimOracle GlobalData (fullData branch (sourceView database)) (fun _=>0)) stages constructed i key))
  packed : Current.Values
  valid : Current.Satisfies stages[i.val].relation packed
  calculated : CalculatedPacked (H.actualTerminalProducer CtorData stages i)
    stages[i.val].ns stages[i.val].relation stages[i.val].nonce observer
    (GC.observerSourceView CtorData
      (Q.claimOracle GlobalData (fullData branch (sourceView database)) (fun _=>0))
      stages constructed i (fullData branch (sourceView database))) packed

structure ActualRecovery (branch : Branches G.decode GlobalData)
    (database : Database (G.Key GlobalData) VData) where
  inputs : List (GD.EnrichedStageInput template)
  stages : List H.Stage
  constructed : (CtorData).eval (Q.claimOracle GlobalData (fullData branch (sourceView database)) (fun _=>0))=some stages
  produced : rawConstructor.eval (Q.claimOracle GlobalData (fullData branch (sourceView database)) (fun _=>0))=some inputs
  stageMap : stages=GD.nativeStages template inputs
  history : (H.historyProgram stages).eval
    (Q.claimOracle GlobalData (fullData branch (sourceView database)) (fun _=>0))=some ()
  «at» : (i : Fin stages.length) → StageRecovery template rawConstructor branch database stages constructed i

/-- Canonical recovery is source owned and choice is confined to its proved
actual decoded assignments. Neither inputs nor packed validity are premises. -/
def actualRecovery (branch : Branches G.decode GlobalData)
    (database : Database (G.Key GlobalData) VData)
    (good : ¬S.missingSource template
      (NativePrivateSpendQ58CurrentNativeOperationData.eraseConstructor template rawConstructor)
      branch (sourceView database)) : ActualRecovery template rawConstructor branch database :=
  Classical.choice (by
    obtain ⟨inputs,stages,constructed,produced,stageMap,history,recovered⟩ :=
      actual_source_good_derives_recovered_operation_inputs
        HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentNativeOperationData.EnrichedStageInput.input template rawConstructor branch database good
    refine ⟨{
      inputs := inputs
      stages := stages
      constructed := constructed
      produced := produced
      stageMap := stageMap
      history := history
      «at» := ?_ }⟩
    intro i
    apply Classical.choice
    obtain ⟨observer,accepted,log,claims,packed,valid,calculated⟩ := recovered i
    exact ⟨{
      observer := observer
      accepted := accepted
      log := log
      claims := claims
      packed := packed
      valid := valid
      calculated := calculated }⟩)

def ActualRecovery.operationAt {branch : Branches G.decode GlobalData}
    {database : Database (G.Key GlobalData) VData}
    (recovery : ActualRecovery template rawConstructor branch database) (i : Fin recovery.inputs.length) :
    RecoveredOperation template :=
  let j : Fin recovery.stages.length :=
    ⟨i.val, Nat.lt_of_lt_of_eq i.isLt
      ((congrArg List.length recovery.stageMap).trans (List.length_map _)).symm⟩
  { input:=recovery.inputs[i.val],packed:=(recovery.«at» j).packed,
    valid:=by simpa only [recovery.stageMap,GD.nativeStages,List.getElem_map] using (recovery.«at» j).valid }

def ActualRecovery.operations {branch : Branches G.decode GlobalData}
    {database : Database (G.Key GlobalData) VData}
    (recovery : ActualRecovery template rawConstructor branch database) : List (RecoveredOperation template) :=
  List.ofFn (recovery.operationAt template rawConstructor)

theorem actual_recovery_operations_keep_original_inputs
    {branch : Branches G.decode GlobalData} {database : Database (G.Key GlobalData) VData}
    (recovery : ActualRecovery template rawConstructor branch database) :
    (recovery.operations template rawConstructor).map RecoveredOperation.input=recovery.inputs := by
  rw [ActualRecovery.operations,List.map_ofFn]
  exact List.ofFn_getElem

/-- Original fullClaims give read-by-read equality between the physical
branch and canonical source completion. Restrict to the constructor's reads;
the actual original operation input list is therefore the SAME list. The
unclaimed complement must be charged on the original Born state below. -/
theorem actual_recovery_inputs_equal_original_claimed_constructor
    {branch : Branches G.decode GlobalData} {database : Database (G.Key GlobalData) VData}
    (claims : ClaimsDatabaseEvent (Q.fullClaims GlobalData branch) database)
    (recovery : ActualRecovery template rawConstructor branch database) :
    rawConstructor.eval (Q.claimOracle GlobalData database (fun _=>0))=some recovery.inputs := by
  let full := fullData branch (sourceView database)
  have sources : NativePrivateSpendQ58CurrentSourceCompletion.SourceClaims GlobalData branch
      (sourceView database) := by
    intro key value member source
    exact claims (key,value) member
  have fullClaims := NativePrivateSpendQ58CurrentSourceCompletion.complete_source_claims
    GlobalData branch (sourceView database) 0 sources
    (NativePrivateSpendQ58CurrentSourceCompletion.consistent_of_claims GlobalData branch database claims)
  have agrees := NativePrivateSpendQ58CurrentSourceCompletion.full_claims_agree_on_reads
    GlobalData branch full database fullClaims claims (fun _=>0) (fun _=>0)
  let oracle := Q.claimOracle GlobalData full (fun _=>0)
  have nativeCtor := NativePrivateSpendQ58CurrentNativeOperationData.native_constructor_erasure template rawConstructor
  have rawSubset : ∀ input,(input,oracle input)∈(rawConstructor.record oracle).2 →
      (input,oracle input)∈((GlobalData).record oracle).2 := by
    intro input member
    apply Program.bind_log_left oracle CtorData H.historyProgram recovery.stages recovery.constructed
    rw [nativeCtor]
    exact Program.bind_log_left oracle rawConstructor _ recovery.inputs recovery.produced member
  have equality := SmzaRp05CurrentBranchOracleAgreement.eval_eq_of_agrees_on_left_reads
    rawConstructor oracle (Q.claimOracle GlobalData database (fun _=>0))
      (fun input member => agrees input (rawSubset input member))
  exact equality.symm.trans recovery.produced

/-- This finite F1 interface supplies only ordinary snapshot/table/root data
at the actual constructed prefix. Recovered inputs/assignments, validity,
selected modes, trace and all-Final completeness are absent from its fields. -/
structure RawNativeData where
  chronology : ∀ (branch : Branches G.decode GlobalData)
    (database : Database (G.Key GlobalData) VData)
    (good : ¬S.missingSource template
      (NativePrivateSpendQ58CurrentNativeOperationData.eraseConstructor template rawConstructor)
      branch (sourceView database)),
    RawChronology template ((actualRecovery template rawConstructor branch database good).operations
      template rawConstructor) []

def actualFinals (raw : RawNativeData template rawConstructor)
    (branch : Branches G.decode GlobalData) (database : Database (G.Key GlobalData) VData)
    (good : ¬S.missingSource template
      (NativePrivateSpendQ58CurrentNativeOperationData.eraseConstructor template rawConstructor)
      branch (sourceView database)) : List CG.SourceOutcome :=
  collect (raw.chronology branch database good) NativeSourceTrace.empty

def actualReadout (raw : RawNativeData template rawConstructor)
    (branch : Branches G.decode GlobalData) (database : Database (G.Key GlobalData) VData)
    (good : ¬S.missingSource template
      (NativePrivateSpendQ58CurrentNativeOperationData.eraseConstructor template rawConstructor)
      branch (sourceView database)) : Option CG.SourceOutcome :=
  firstBad (actualFinals template rawConstructor raw branch database good)

theorem actual_readout_none_iff_no_actual_selected_final
    (raw : RawNativeData template rawConstructor)
    (branch : Branches G.decode GlobalData) (database : Database (G.Key GlobalData) VData)
    (good : ¬S.missingSource template
      (NativePrivateSpendQ58CurrentNativeOperationData.eraseConstructor template rawConstructor)
      branch (sourceView database)) :
    actualReadout template rawConstructor raw branch database good=none ↔
      ∀ operation∈(actualRecovery template rawConstructor branch database good).operations template rawConstructor,
        ¬selectedFinal operation :=
  complete_readout_none_iff_no_final (raw.chronology branch database good) NativeSourceTrace.empty

theorem every_actual_unauthorized_final_is_covered
    (raw : RawNativeData template rawConstructor)
    (branch : Branches G.decode GlobalData) (database : Database (G.Key GlobalData) VData)
    (good : ¬S.missingSource template
      (NativePrivateSpendQ58CurrentNativeOperationData.eraseConstructor template rawConstructor)
      branch (sourceView database))
    (bad : ∃ outcome∈actualFinals template rawConstructor raw branch database good,outcome.unauthorized) :
    ∃ kind : Fin 7,∃ outcome,
      actualReadout template rawConstructor raw branch database good=some outcome ∧ CG.sourceGameEvent kind outcome :=
  every_unauthorized_final_has_current_game (raw.chronology branch database good) NativeSourceTrace.empty bad

namespace FS
export NativePrivateSpendQ58CurrentGlobalFinalSecurity
  (nativeMass sourceGood initialized_global_missing_source_mass_below_129)
end FS
namespace M
export NativePrivateSpendQ58CurrentGlobalInitializedSourceMass
  (initial reached terminal missingSourceMass full_count)
end M
namespace O
export SmzaRp05OrdinarySoundnessExecution
  (OrdinaryPrefix compileOrdinary compileOrdinary_certified ordinaryRun_eq_compiled emptyAuthorizationContexts)
end O
namespace R
export NativePrivateSpendQ58CurrentFiberMassTransport (Active)
end R
namespace U
export SmzaRoleDomainConditioning (finiteNormSquared eventProjection same_execution_event_union_bound)
end U
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsQuerySequence
open SmzaChallengeStageTargets (Role)
open SmzaRp05AdaptivePhysicalReadBound (ReadsAtMost physicalBranchesFintype)

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
local notation "InputCtor" => NativePrivateSpendQ58CurrentNativeOperationData.eraseConstructor template rawConstructor
local notation "WorkData" => SmzaRp05CurrentAdaptiveExecution.Work (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "BasisData" => Basis (G.Key GlobalData) VData VData WorkData
local notation "RegistersData" => RegisterBasis (Input:=G.Key GlobalData) (Phase:=VData) (Workspace:=WorkData) → ℂ
local notation "MetadataData" => SmzaRp05CurrentAdaptiveExecution.Context (Key:=G.Key GlobalData) (Counter:=G.Counter) (BaseWork:=BaseWork)

/-- The defined collector is complete over ALL selected actual Finals. Full
claims identify its canonical constructor inputs with the literal physical
branch. The complementary unclaimed event is charged separately below. -/
def actualUnauthorized (raw : RawNativeData template rawConstructor)
    (branch : Branches G.decode GlobalData) (basis : BasisData) : Prop :=
  ClaimsDatabaseEvent (Q.fullClaims GlobalData branch) basis.database ∧
  ∃ good : ¬S.missingSource template InputCtor branch (sourceView basis.database),
    ∃ outcome∈actualFinals template rawConstructor raw branch basis.database good,outcome.unauthorized

def actualGame (raw : RawNativeData template rawConstructor) (kind : Fin 7)
    (branch : Branches G.decode GlobalData) (basis : BasisData) : Prop :=
  ClaimsDatabaseEvent (Q.fullClaims GlobalData branch) basis.database ∧
  ∃ good : ¬S.missingSource template InputCtor branch (sourceView basis.database),
    ∃ outcome,actualReadout template rawConstructor raw branch basis.database good=some outcome ∧
      CG.sourceGameEvent kind outcome

omit [Fintype BaseWork] [DecidableEq BaseWork] in
theorem actual_unauthorized_coverage (raw : RawNativeData template rawConstructor)
    (branch : Branches G.decode GlobalData) (basis : BasisData)
    (bad : actualUnauthorized template rawConstructor raw branch basis) :
    ∃ kind : Fin 7,actualGame template rawConstructor raw kind branch basis := by
  obtain ⟨claims,good,bad⟩ := bad
  obtain ⟨kind,outcome,read,game⟩ := every_actual_unauthorized_final_is_covered
    template rawConstructor raw branch basis.database good bad
  exact ⟨kind,claims,good,outcome,read,game⟩

/-- SAME original terminal amplitudes, with the source-good mask only. No
observer physicalRun, extra query history, invocation union or free carrier. -/
theorem actual_unauthorized_mass_le_current_seven_games
    (raw : RawNativeData template rawConstructor) {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key GlobalData) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : RegistersData) :
    FS.nativeMass template InputCtor «prefix» registers (actualUnauthorized template rawConstructor raw) ≤
      ∑ kind : Fin 7,FS.nativeMass template InputCtor «prefix» registers (actualGame template rawConstructor raw kind) := by
  letI := physicalBranchesFintype G.decode GlobalData
  unfold FS.nativeMass
  calc
    _ ≤ ∑ branch : Branches G.decode GlobalData,∑ kind : Fin 7,
        U.finiteNormSquared (U.eventProjection (actualGame template rawConstructor raw kind branch)
          (FS.sourceGood template InputCtor «prefix» registers branch)) := by
      apply Finset.sum_le_sum
      intro branch _
      have mono : U.finiteNormSquared
          (U.eventProjection (actualUnauthorized template rawConstructor raw branch)
            (FS.sourceGood template InputCtor «prefix» registers branch)) ≤
          U.finiteNormSquared
            (U.eventProjection (fun basis => ∃ kind,actualGame template rawConstructor raw kind branch basis)
              (FS.sourceGood template InputCtor «prefix» registers branch)) := by
        unfold U.finiteNormSquared U.eventProjection
        apply Finset.sum_le_sum
        intro basis _
        by_cases bad : actualUnauthorized template rawConstructor raw branch basis
        · simp only [if_pos bad,if_pos (actual_unauthorized_coverage template rawConstructor raw branch basis bad)]
          exact le_rfl
        · simp only [if_neg bad,Complex.normSq_zero]
          exact Complex.normSq_nonneg _
      exact mono.trans (U.same_execution_event_union_bound
        (fun kind basis => actualGame template rawConstructor raw kind branch basis)
        (FS.sourceGood template InputCtor «prefix» registers branch))
    _ = _ := Finset.sum_comm

/-- Unclaimed raw branch records are charged on the unselected original
terminal Born state, once. They are never identified with canonical source
completion and never turned into a caller supplied readout-completeness law. -/
def unclaimedMass {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key GlobalData) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : RegistersData) : ℝ :=
  letI := physicalBranchesFintype G.decode GlobalData
  ∑ branch : Branches G.decode GlobalData,
    normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims GlobalData branch)
      (M.terminal template InputCtor «prefix» registers branch))

theorem original_raw_claim_debt_le
    (metadata : MetadataData) {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key GlobalData) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : RegistersData) (normalized : Subnormalized (M.initial template InputCtor registers))
    (count : Nat) (reads : ReadsAtMost G.decode count GlobalData) (support : finish+count≤q) :
    unclaimedMass template rawConstructor «prefix» registers ≤ 2*(q:ℝ)/Fintype.card VData := by
  letI := physicalBranchesFintype G.decode GlobalData
  have each (branch : Branches G.decode GlobalData) :
      normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims GlobalData branch)
        (M.terminal template InputCtor «prefix» registers branch)) ≤
      (2*(q:ℝ)/Fintype.card VData)*normSquared (M.terminal template InputCtor «prefix» registers branch) := by
    have debt : normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims GlobalData branch)
        (M.terminal template InputCtor «prefix» registers branch)) ≤
        (((2*(Q.fullClaims GlobalData branch).toFinset.card:Nat):ℝ)/Fintype.card VData)*
          normSquared (M.terminal template InputCtor «prefix» registers branch) := by
      apply SmzaRp05CurrentKnownClaimsFailureMass.global_known_claims_failure_mass_le
      intro claim member
      exact SmzaRp05CurrentPhysicalBranchClaimReadback.physical_branch_claim_known_at_standard
        (NativePrivateSpendQ58CurrentConstructorGrouping.encode GlobalData) G.decode GlobalData branch
        (M.reached template InputCtor «prefix» registers) claim member
    have fullCount : (Q.fullClaims GlobalData branch).toFinset.card≤q :=
      (List.toFinset_card_le _).trans ((M.full_count template InputCtor branch count reads).trans (by omega))
    apply debt.trans
    apply mul_le_mul_of_nonneg_right _ (by
      unfold normSquared;exact Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _))
    apply div_le_div_of_nonneg_right _ (by positivity)
    exact_mod_cast Nat.mul_le_mul_left 2 fullCount
  have total : SmzaRp05RoleReadTotality.StandardOn (Finset.univ:Finset (G.Key GlobalData)).toList
      (M.reached template InputCtor «prefix» registers) := by
    intro key _
    exact SmzaRp05OrdinarySoundnessStandardTotal.initialized_ordinary_run_standard_total «prefix» registers key
  have conserved := SmzaRp05CurrentPhysicalNonchallengeClaims.physical_branch_mass_eq_initial_of_reads_within
    (NativePrivateSpendQ58CurrentConstructorGrouping.encode GlobalData) G.decode GlobalData
    (M.reached template InputCtor «prefix» registers)
    (Finset.univ:Finset (G.Key GlobalData)).toList
    (NativePrivateSpendQ58CurrentAcceptedSourceInitialized128.reads_univ
      (NativePrivateSpendQ58CurrentConstructorGrouping.encode GlobalData) GlobalData) total
  let ctx : MetadataData := {metadata with authorizedOf:=fun _=>∅}
  have certified : SmzaRp05ConditionedExecution.CertifiedFor
      (NativePrivateSpendQ58CurrentRoleEventPhysicalMass.contexts GlobalData ctx) (O.compileOrdinary «prefix») := by
    have contextsEq : O.emptyAuthorizationContexts
        (NativePrivateSpendQ58CurrentRoleEventPhysicalMass.contexts GlobalData metadata) =
        NativePrivateSpendQ58CurrentRoleEventPhysicalMass.contexts GlobalData ctx := by
      funext role
      rfl
    exact Eq.mp
      (congrArg (fun contexts : SmzaChallengeStageTargets.Role → MetadataData =>
        SmzaRp05ConditionedExecution.CertifiedFor contexts (O.compileOrdinary «prefix»)) contextsEq)
      (O.compileOrdinary_certified
        (NativePrivateSpendQ58CurrentRoleEventPhysicalMass.contexts GlobalData metadata) «prefix»)
  have prefixNorm : normSquared (M.reached template InputCtor «prefix» registers)≤1 := by
    simpa (config := { instances := true }) only
      [Subnormalized,M.reached,M.initial,O.ordinaryRun_eq_compiled,
        NativePrivateSpendQ58CurrentNativeOperationData.nativeConstructor] using!
      SmzaRp05ConditionedExecution.CertifiedFor.common_run_subnormalized certified .decsSample normalized
  unfold unclaimedMass
  have sum := Finset.sum_le_sum (s := (Finset.univ : Finset (Branches G.decode GlobalData)))
    (fun branch _=>each branch)
  have terminalConserved :
      (∑ branch : Branches G.decode GlobalData,
        normSquared (M.terminal template InputCtor «prefix» registers branch)) =
      normSquared (M.reached template InputCtor «prefix» registers) := by
    simpa (config := { instances := true }) only
      [M.terminal,NativePrivateSpendQ58CurrentNativeOperationData.nativeConstructor] using! conserved
  rw [←Finset.mul_sum,terminalConserved] at sum
  exact sum.trans (mul_le_of_le_one_right (by positivity) prefixNorm)

/-- Explicit complete native authorization contract. EVERY selected Final
from the SAME recovered operation stream is represented. Source validity,
Final validity, valid chronological outputs and absence-of-Final None are
DERIVED. F1 supplies only the finite immutable ordinary operation and snapshot
interpretation. The seven CURRENT typed games retain all seven actual domains
and target widths; 88Q³/2^512 is used only in the current proof oracle bound.
Their aggregate remaining budget includes the raw claim debt explicitly.
All terms refer to the SAME initialized original Global Born execution/Q.
There is no M union, second physical observer run or efficient PoK assertion. -/
theorem initialized_complete_native_final_failure_mass_below_128
    (raw : RawNativeData template rawConstructor)
    (metadata : MetadataData)
    (dummy : (role : Role)→R.Active role (NativePrivateSpendQ58CurrentConstructorGrouping.keyBytes GlobalData))
    {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key GlobalData) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : RegistersData) (normalized : Subnormalized (M.initial template InputCtor registers))
    (count : Nat) (reads : ReadsAtMost G.decode count GlobalData)
    (support : finish+count≤q) (queriesBound : queries+count≤q) (lifetime : q≤3*2^64)
    (advantages : Fin 7→ℝ)
    (games : ∀ kind : Fin 7,FS.nativeMass template InputCtor «prefix» registers
      (actualGame template rawConstructor raw kind)≤advantages kind)
    (remaining : (∑ kind : Fin 7,advantages kind)+2*(q:ℝ)/Fintype.card VData≤(2:ℝ)^(-129:ℤ)) :
    M.missingSourceMass template InputCtor «prefix» registers +
      unclaimedMass template rawConstructor «prefix» registers +
      FS.nativeMass template InputCtor «prefix» registers (actualUnauthorized template rawConstructor raw) <
      (2:ℝ)^(-128:ℤ) := by
  have source := FS.initialized_global_missing_source_mass_below_129 template InputCtor metadata dummy
    «prefix» registers normalized count reads support queriesBound lifetime
  have claims := original_raw_claim_debt_le template rawConstructor metadata «prefix» registers normalized count reads support
  have primitive := (actual_unauthorized_mass_le_current_seven_games template rawConstructor raw «prefix» registers).trans
    (Finset.sum_le_sum (fun kind _=>games kind))
  have exactBudget : (2:ℝ)^(-129:ℤ)+(2:ℝ)^(-129:ℤ)=(2:ℝ)^(-128:ℤ) := by norm_num
  have parts : unclaimedMass template rawConstructor «prefix» registers +
      FS.nativeMass template InputCtor «prefix» registers (actualUnauthorized template rawConstructor raw) ≤
      (∑ kind : Fin 7,advantages kind)+2*(q:ℝ)/Fintype.card VData := by
    calc
      _ ≤ 2*(q:ℝ)/Fintype.card VData + (∑ kind : Fin 7,advantages kind) :=
        add_le_add claims primitive
      _ = _ := add_comm _ _
  calc
    _ = M.missingSourceMass template InputCtor «prefix» registers +
        (unclaimedMass template rawConstructor «prefix» registers +
          FS.nativeMass template InputCtor «prefix» registers (actualUnauthorized template rawConstructor raw)) :=
      add_assoc _ _ _
    _ < (2:ℝ)^(-129:ℤ)+(2:ℝ)^(-129:ℤ) :=
      add_lt_add_of_lt_of_le source (parts.trans remaining)
    _ = _ := exactBudget

/-- One failure event on the literal original terminal carrier: missing SAME
source witness, unclaimed raw records, or ANY unauthorized selected Final.
No optional/readout carrier can hide a selected Final. -/
def completeFailure (raw : RawNativeData template rawConstructor)
    (branch : Branches G.decode GlobalData) (basis : BasisData) : Prop :=
  S.missingSource template InputCtor branch (sourceView basis.database) ∨
    ¬ClaimsDatabaseEvent (Q.fullClaims GlobalData branch) basis.database ∨
    actualUnauthorized template rawConstructor raw branch basis

def completeFailureMass (raw : RawNativeData template rawConstructor) {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key GlobalData) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : RegistersData) : ℝ :=
  letI := physicalBranchesFintype G.decode GlobalData
  ∑ branch : Branches G.decode GlobalData,if branchResult G.decode GlobalData branch=some () then
    U.finiteNormSquared (U.eventProjection (completeFailure template rawConstructor raw branch)
      (M.terminal template InputCtor «prefix» registers branch)) else 0

theorem complete_failure_mass_le_parts
    (raw : RawNativeData template rawConstructor) {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key GlobalData) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : RegistersData) :
    completeFailureMass template rawConstructor raw «prefix» registers ≤
      M.missingSourceMass template InputCtor «prefix» registers + unclaimedMass template rawConstructor «prefix» registers +
        FS.nativeMass template InputCtor «prefix» registers (actualUnauthorized template rawConstructor raw) := by
  letI := physicalBranchesFintype G.decode GlobalData
  have each (branch : Branches G.decode GlobalData) :
      (if branchResult G.decode GlobalData branch=some () then
        U.finiteNormSquared (U.eventProjection (completeFailure template rawConstructor raw branch)
          (M.terminal template InputCtor «prefix» registers branch)) else 0) ≤
      (if branchResult G.decode GlobalData branch=some () then
        normSquared (NativePrivateSpendQ58CurrentGlobalInitializedSourceMass.failure template InputCtor branch
          (M.terminal template InputCtor «prefix» registers branch)) else 0) +
      normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims GlobalData branch)
        (M.terminal template InputCtor «prefix» registers branch)) +
      U.finiteNormSquared (U.eventProjection (actualUnauthorized template rawConstructor raw branch)
        (FS.sourceGood template InputCtor «prefix» registers branch)) := by
    by_cases accepted : branchResult G.decode GlobalData branch=some ()
    · rw [if_pos accepted,if_pos accepted]
      have pointwise (basis : BasisData) :
          Complex.normSq (U.eventProjection (completeFailure template rawConstructor raw branch)
            (M.terminal template InputCtor «prefix» registers branch) basis) ≤
          Complex.normSq (NativePrivateSpendQ58CurrentGlobalInitializedSourceMass.failure template InputCtor branch
            (M.terminal template InputCtor «prefix» registers branch) basis) +
          Complex.normSq (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims GlobalData branch)
            (M.terminal template InputCtor «prefix» registers branch) basis) +
          Complex.normSq (U.eventProjection (actualUnauthorized template rawConstructor raw branch)
            (FS.sourceGood template InputCtor «prefix» registers branch) basis) := by
        have acceptedCurrent := accepted
        dsimp (config := { instances := true }) only
          [NativePrivateSpendQ58CurrentNativeOperationData.nativeConstructor] at acceptedCurrent
        dsimp (config := { instances := true }) only
          [U.eventProjection,completeFailure,
            NativePrivateSpendQ58CurrentGlobalInitializedSourceMass.failure,
            NativePrivateSpendQ58CurrentSourceSelectorTransport.sourceProjection,
            SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection,
            HegemonCrypto.CmsAdaptiveClaimBridge.workspaceEventProjection,
            HegemonCrypto.CmsOracleDatabaseBridge.databaseEventProjection,
            SmzaRp05PartialReadout.claimFailureProjection,FS.sourceGood,
            NativePrivateSpendQ58CurrentNativeOperationData.nativeConstructor]
        rw [if_pos acceptedCurrent]
        dsimp (config := { instances := true }) only
          [HegemonCrypto.CmsAdaptiveClaimBridge.workspaceEventProjection]
        by_cases missing : S.missingSource template InputCtor branch (sourceView basis.database) <;>
          by_cases claims : ClaimsDatabaseEvent (Q.fullClaims GlobalData branch) basis.database <;>
          by_cases bad : actualUnauthorized template rawConstructor raw branch basis
        all_goals
          dsimp (config := { instances := true }) only
            [NativePrivateSpendQ58CurrentNativeOperationData.nativeConstructor] at missing claims
          simp [missing,claims,bad] <;>
            nlinarith [Complex.normSq_nonneg (M.terminal template InputCtor «prefix» registers branch basis)]
      have summed := Finset.sum_le_sum (s := (Finset.univ : Finset BasisData))
        (fun basis _ => pointwise basis)
      simpa (config := { instances := true }) only
        [U.finiteNormSquared,normSquared,Finset.sum_add_distrib] using! summed
    · rw [if_neg accepted,if_neg accepted]
      apply add_nonneg
      · exact add_nonneg (by norm_num) (by unfold normSquared;exact Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _))
      · unfold U.finiteNormSquared
        exact Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _)
  have summed := Finset.sum_le_sum (s := (Finset.univ : Finset (Branches G.decode GlobalData)))
    (fun branch _ => each branch)
  simpa (config := { instances := true }) only
    [completeFailureMass,M.missingSourceMass,unclaimedMass,FS.nativeMass,
      NativePrivateSpendQ58CurrentNativeOperationData.nativeConstructor,Finset.sum_add_distrib] using! summed

/-- The closed SAME-original-Born128 endpoint, under seven explicitly named
CURRENT primitive advantages and the retained finite F1 ordinary data binding.
Raw input/assignment/history/Final completeness and derived validity are not
caller security assumptions. No threshold reduction or observer/Q/M change. -/
theorem initialized_actual_native_global_failure_below_128
    (raw : RawNativeData template rawConstructor)
    (metadata : MetadataData)
    (dummy : (role : Role)→R.Active role (NativePrivateSpendQ58CurrentConstructorGrouping.keyBytes GlobalData))
    {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key GlobalData) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : RegistersData) (normalized : Subnormalized (M.initial template InputCtor registers))
    (count : Nat) (reads : ReadsAtMost G.decode count GlobalData)
    (support : finish+count≤q) (queriesBound : queries+count≤q) (lifetime : q≤3*2^64)
    (advantages : Fin 7→ℝ)
    (games : ∀ kind : Fin 7,FS.nativeMass template InputCtor «prefix» registers
      (actualGame template rawConstructor raw kind)≤advantages kind)
    (remaining : (∑ kind : Fin 7,advantages kind)+2*(q:ℝ)/Fintype.card VData≤(2:ℝ)^(-129:ℤ)) :
    completeFailureMass template rawConstructor raw «prefix» registers < (2:ℝ)^(-128:ℤ) :=
  (complete_failure_mass_le_parts template rawConstructor raw «prefix» registers).trans_lt
    (initialized_complete_native_final_failure_mass_below_128 template rawConstructor raw metadata dummy
      «prefix» registers normalized count reads support queriesBound lifetime advantages games remaining)

end Collector
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentTotalNativeSourceOutcome
