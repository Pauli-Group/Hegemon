import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalSourceSupport
import HegemonCrypto.NativePrivateSpendQ58CurrentSameSourceSemanticJoin
import HegemonCrypto.NativePrivateSpendCurrentG1CanonicalGameAdapter
import Mathlib.Data.List.Infix

/-! Finite ordinary native operation data, before recovering an assignment.
The enriched constructor erases to the unchanged current stage constructor.
It adds no oracle query, witness validity, native-valid trace, authorization,
failure inclusion, total readout, lifetime budget, or cryptographic game.
Existing F1 interprets the original finite graph/CSR/locators and literal
append/table/root metadata. This source does not prove a Rust factory theorem.
Output flags are the original statement's emitted-slot data, not values and
not a field inferred from the current public77. Both NOTE commitments remain
in the current relation. The consumer must retain the SAME constructed input
and the actual recovered geometry; it may not supply detached valid values.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentNativeOperationData
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches)
open HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics
open HegemonCrypto.NativePrivateSpendCurrentApprovalTransition
open HegemonCrypto.NativePrivateSpendCurrentFinalHistory
open HegemonCrypto.NativePrivateSpendCurrentChronologicalApprovalHistory
open HegemonCrypto.NativePrivateSpendCurrentNativeHistoryJoin
open HegemonCrypto.NativePrivateSpendCurrentAppendReadback
open HegemonCrypto.NativePrivateSpendCurrentOutputOrigin
open HegemonCrypto.NativePrivateSpendCurrentSourceCallContract
open HegemonCrypto.NativePrivateSpendCurrentRoleTransport
open HegemonCrypto.NativePrivateSpendCurrentProtocolHistory
open HegemonCrypto.NativePrivateSpendRoleBridge
open HegemonCrypto.NativePrivateSpendPackedLowering
open HegemonCrypto.NativePrivateSpendCsrCertificate
open HegemonCrypto.NativePrivateSpendArithmeticTopology
open HegemonCrypto.NativePrivateSpendSelectedNullifier
open HegemonCrypto.NativePrivateSpendMerkleContinuation
open HegemonCrypto.NativeLaunchConstraintAdapterBridge
open HegemonCrypto.NativePrivateSpendLocalSemantics
namespace GS
export NativePrivateSpendQ58CurrentGlobalSourceSupport
  (NativeStageInput nativeStage nativeConstructor)
end GS
namespace CS
export NativePrivateSpendQ58CurrentCausalSourceJoin (SourceTemplate)
end CS
namespace H
export NativePrivateSpendQ58CurrentGlobalRawLogTransport (Stage)
end H
namespace SS
export NativePrivateSpendQ58CurrentSameSourceSemanticJoin
  (NativeSemanticSource actual_source_witness_supplies_same_native_semantics)
end SS
namespace CC
export NativePrivateSpendQ58CurrentCanonicalSourceClassifier (root SourceWitness)
end CC
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport (SourceView)
end X
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (decode)
end G
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire)
end E
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
local instance operationPrimeFact : Fact (Nat.Prime modulus) :=
  ⟨HegemonCrypto.SmallWood.goldilocks_prime⟩

/-- All fields are immutable graph/address data or literal ordinary native
statement data. No packed values, satisfying assignment, selected mode or
validity proof is a field. The relation is determined by the original input. -/
structure OperationData (template : CS.SourceTemplate) (input : GS.NativeStageInput) where
  graph : Graph Goldilocks
  layout : Layout Goldilocks
  csr : RawCSR Goldilocks
  certificate : RelationCertificate (GS.nativeStage template input).relation graph layout csr
  roles : Roles
  routes : RouteRoles
  inputWords : Nat → Word Goldilocks
  notes : Fin 2 → Fin 18 → Word Goldilocks
  calls : CallsChecked graph roles
  routing : RouteChecked graph roles routes
  recordBinding : RecordRouteBinding routes inputWords (notes 0)
  approval : ApprovalChecked graph roles routes
    (noteWords inputWords (0 : Fin 2) 0) (notes 0 0)
  signer : ApprovalSignerChecked graph roles routes inputWords
  parent : ApprovalParentChecked graph roles routes
  count : FinalCountChecked graph (routes.modes 2) roles.count
  valueZero : GateData graph (routes.modes 2)
    (noteWords inputWords (1 : Fin 2) 0) (.constant 0)
  finalOccupied : GateData graph (routes.modes 2)
    (occupied inputWords (1 : Fin 2)) (.constant 1)
  input1OwnerBinding : routes.input1Owner = outputOwnerWords (noteWords inputWords (1 : Fin 2))
  outputOwnerBinding : ∀ slot : Fin 2,
    (if slot = 0 then routes.output0Owner else routes.output1Owner) = outputOwnerWords (notes slot)
  origin : OutputOriginChecked graph roles routes
  stage : Nat
  emitted : Fin 2 → Bool

/-- Original coinbase metadata with the existing issuance positivity check.
The append position is computed later from the actual reconstructed prefix. -/
structure RewardData where
  stage : Nat
  value : Nat
  owner : Hegemon.Transaction.Poseidon2V8SemanticSpecification.Digest
  positive : 0 < value

def rewardOutput (data : RewardData) (position : Nat) : RewardOutput :=
  { stage := data.stage, position := position, value := data.value, owner := data.owner }

/-- Enrichment retains the literal stage input; erasure cannot change its
producer, salt/binding namespace, nonce or constructed current relation. -/
structure EnrichedStageInput (template : CS.SourceTemplate) where
  input : GS.NativeStageInput
  data : OperationData template input
  rewardsBefore : List RewardData
  rewardsAfter : List RewardData

def eraseConstructor (template : CS.SourceTemplate)
    (constructor : Program (List (EnrichedStageInput template))) :
    Program (List GS.NativeStageInput) :=
  constructor.bind fun inputs => .done (some (inputs.map EnrichedStageInput.input))

def nativeStages (template : CS.SourceTemplate) (inputs : List (EnrichedStageInput template)) :
    List H.Stage := inputs.map fun input => GS.nativeStage template input.input

def nativeConstructor (template : CS.SourceTemplate)
    (constructor : Program (List (EnrichedStageInput template))) : Program (List H.Stage) :=
  GS.nativeConstructor template (eraseConstructor template constructor)

/-- A pure map after the original ordinary constructor. Both failure and
every original read node are preserved; there is no second physical run. -/
theorem erase_constructor_eval (template : CS.SourceTemplate)
    (constructor : Program (List (EnrichedStageInput template))) (oracle : Oracle) :
    (eraseConstructor template constructor).eval oracle =
      (constructor.eval oracle).map (List.map EnrichedStageInput.input) := by
  rw [eraseConstructor, Program.eval_bind]
  cases constructor.eval oracle <;> rfl

theorem native_constructor_eval (template : CS.SourceTemplate)
    (constructor : Program (List (EnrichedStageInput template))) (oracle : Oracle) :
    (nativeConstructor template constructor).eval oracle =
      (constructor.eval oracle).map (nativeStages template) := by
  change ((eraseConstructor template constructor).bind
    (fun inputs => .done (some (inputs.map (GS.nativeStage template))))).eval oracle = _
  rw [Program.eval_bind, erase_constructor_eval]
  cases constructor.eval oracle with
  | none => rfl
  | some inputs =>
      change some ((inputs.map EnrichedStageInput.input).map (GS.nativeStage template)) = _
      rw [List.map_map]
      rfl

private theorem current_program_bind_assoc {α β γ : Type} (program : Program α)
    (next : α → Program β) (last : β → Program γ) :
    (program.bind next).bind last =
      program.bind (fun value => (next value).bind last) := by
  induction program with
  | done result => cases result <;> rfl
  | read raw cont ih =>
      simp only [Program.bind]
      congr 1
      funext digest
      exact ih digest

/-- Equal to the direct enriched map, including rejected/error paths. -/
theorem native_constructor_erasure (template : CS.SourceTemplate)
    (constructor : Program (List (EnrichedStageInput template))) :
    nativeConstructor template constructor =
      constructor.bind (fun inputs => .done (some (nativeStages template inputs))) := by
  change ((constructor.bind (fun inputs => .done (some (inputs.map EnrichedStageInput.input)))).bind
    (fun inputs => .done (some (inputs.map (GS.nativeStage template))))) = _
  rw [current_program_bind_assoc]
  congr 1
  funext inputs
  change Program.done (some ((inputs.map EnrichedStageInput.input).map (GS.nativeStage template))) = _
  rw [List.map_map]
  rfl

def source {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values) (position : Nat) : SourceApproval :=
  { relation := (GS.nativeStage template input).relation
    packed := packed
    graph := data.graph
    layout := data.layout
    csr := data.csr
    certificate := data.certificate
    roles := data.roles
    routes := data.routes
    inputWords := data.inputWords
    outputWords := data.notes 0
    calls := data.calls
    routing := data.routing
    recordBinding := data.recordBinding
    approval := data.approval
    signer := data.signer
    parent := data.parent
    stage := data.stage
    outputPosition := position }

def final {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values) (position : Nat) : SourceFinal :=
  { source := source data packed position
    count := data.count
    valueZero := data.valueZero
    occupied := data.finalOccupied
    ownerBinding := data.input1OwnerBinding }

theorem source_relation_and_packed {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values) (position : Nat) :
    (source data packed position).relation = (GS.nativeStage template input).relation ∧
      (source data packed position).packed = packed := ⟨rfl, rfl⟩

/-- A helper for the consumer's actual branch check; neither premise is
stored in ordinary data. The consumer obtains valid from the SAME witness. -/
theorem source_valid_of_mode1 {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values) (position : Nat)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (selected : natural (sourceAssignment packed) (data.routes.modes 1) = 1) :
    SourceValid (source data packed position) := ⟨valid, selected⟩

theorem final_valid_of_mode2 {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values) (position : Nat)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (selected : natural (sourceAssignment packed) (data.routes.modes 2) = 1) :
    FinalValid (final data packed position) := ⟨valid, selected⟩

theorem recovered_assignment_has_unique_mode {template : CS.SourceTemplate}
    {input : GS.NativeStageInput} (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed) :
    ∃! mode : Fin 6, natural (sourceAssignment packed) (data.routes.modes mode) = 1 := by
  have sem := relation_derives_structural_semantics (GS.nativeStage template input).relation packed
    valid data.graph data.layout data.csr data.certificate
  exact unique_mode_from_topology data.graph data.layout (sourceAssignment packed) sem
    data.routes.modes data.routing.selector

/-- Actual geometry/producer/trace are kept by the existing G3→G1 theorem.
This constructs semantics from the actual witness rather than accepting an
arbitrary Satisfies or NativeSourceTrace value in an operation-data field. -/
theorem actual_source_witness_supplies_operation_semantics
    {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (producer : Program E.Wire)
    (branch : Branches G.decode
      (CC.root producer input.ns (GS.nativeStage template input).relation input.nonce))
    (view : X.SourceView
      (CC.root producer input.ns (GS.nativeStage template input).relation input.nonce))
    (witness : CC.SourceWitness producer input.ns (GS.nativeStage template input).relation
      input.nonce branch view) :
    SS.NativeSemanticSource producer input.ns (GS.nativeStage template input).relation
      input.nonce branch view data.graph data.layout :=
  SS.actual_source_witness_supplies_same_native_semantics producer input.ns
    (GS.nativeStage template input).relation input.nonce branch view
    data.graph data.layout data.csr data.certificate witness

def otherOutput {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (sourcePosition position : Nat) (slot : Fin 2)
    (selected : slot = 1 ∨ natural (sourceAssignment packed) (data.routes.modes 1) ≠ 1) :
    OtherOutput :=
  { source := source data packed sourcePosition
    valid := valid
    slot := slot
    note := data.notes slot
    ownerBinding := data.outputOwnerBinding slot
    originData := data.origin
    selected := selected
    position := position }

/-- Output0 branches on the SAME recovered assignment's actual Approval
selector. A zero-value Approval remains an Approval when its emitted flag
is true; this function itself does not filter a slot by value or flag. -/
def output0 {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (position : Nat) : Produced :=
  if selected : natural (sourceAssignment packed) (data.routes.modes 1) = 1 then
    .approval ⟨source data packed position, source_valid_of_mode1 data packed position valid selected⟩
  else .other (otherOutput data packed valid position position 0 (Or.inr selected))

def output1 {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (sourcePosition position : Nat) : Produced :=
  .other (otherOutput data packed valid sourcePosition position 1 (Or.inl rfl))

theorem output0_position {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (position : Nat) : (output0 data packed valid position).position = position := by
  unfold output0
  split <;> rfl

theorem output1_position {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (sourcePosition position : Nat) : (output1 data packed valid sourcePosition position).position = position := rfl

/-- Literal native snapshot data only. The outcome consumer derives both
NativeSourceTrace and RawAppendTrace by its own append induction. The table
must describe the already reconstructed outputs on this exact prefix. -/
def nativePublic (input : GS.NativeStageInput) : Fin 77 → Goldilocks :=
  fun i => (V8SmzaOracleParser.wordAt input.ns.binding i.val : Goldilocks)

structure SnapshotData {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values) (position : Nat)
    (outputs : List Produced) where
  publicBinding : (source data packed position).graph.publicBindings = public77 (nativePublic input)
  merkle : ∀ slot : Fin 2, MerkleChecked data.graph data.inputWords slot
  anchorPrefix : List Produced
  prefixBefore : anchorPrefix.IsPrefix outputs
  table : RawNoteTable anchorPrefix
  root : (fromLog 32 0 (anchorPrefix.map table.note)).root =
    List.ofFn fun lane : Fin 7 => (nativePublic input ⟨17 + lane.val, by omega⟩).val
  earlier : ∀ parent ∈ anchorPrefix, parent.stage < data.stage

/-- Retained historical anchors obtain their raw positions from the whole
constructed append stream, rather than receiving a separate valid trace. -/
theorem raw_append_prefix {outputs «prefix» : List Produced}
    (trace : RawAppendTrace outputs) (isPrefix : «prefix».IsPrefix outputs) :
    RawAppendTrace «prefix» := by
  induction trace generalizing «prefix» with
  | empty =>
      rw [isPrefix.eq_of_length_le (by simp)]
      exact RawAppendTrace.empty
  | @append outputs before output position ih =>
      by_cases short : «prefix».length ≤ outputs.length
      · exact ih ((List.isPrefix_append_of_length short).mp isPrefix)
      · have long : (outputs ++ [output]).length ≤ «prefix».length := by
          simp only [List.length_append, List.length_cons, List.length_nil]
          omega
        rw [isPrefix.eq_of_length_le long]
        exact RawAppendTrace.append before output position

def snapshot {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    {data : OperationData template input} {packed : Current.Values} {position : Nat}
    {outputs : List Produced} (raw : SnapshotData data packed position outputs)
    (append : RawAppendTrace outputs) :
    NativeSnapshot outputs (source data packed position) :=
  { «public» := nativePublic input
    publicBinding := raw.publicBinding
    merkle := raw.merkle
    anchorPrefix := raw.anchorPrefix
    prefixBefore := raw.prefixBefore
    prefixAppend := raw_append_prefix append raw.prefixBefore
    table := raw.table
    root := raw.root
    earlier := raw.earlier }

theorem snapshot_public {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    {data : OperationData template input} {packed : Current.Values} {position : Nat}
    {outputs : List Produced} (raw : SnapshotData data packed position outputs)
    (append : RawAppendTrace outputs) :
    (snapshot raw append).«public» = nativePublic input := rfl

def appendSlot0 {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (outputs : List Produced) : List Produced :=
  if data.emitted 0 then outputs ++ [output0 data packed valid outputs.length] else outputs

def appendSlot1 {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (sourcePosition : Nat) (outputs : List Produced) : List Produced :=
  if data.emitted 1 then outputs ++ [output1 data packed valid sourcePosition outputs.length] else outputs

/-- This is a constructor proof, not a supplied valid native history. The
consumer's recursion supplies before from prior constructed source steps. -/
theorem append_slot0_native_trace {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (outputs : List Produced) (before : NativeSourceTrace outputs)
    (raw : SnapshotData data packed outputs.length outputs) :
    NativeSourceTrace (appendSlot0 data packed valid outputs) := by
  unfold appendSlot0
  split
  · unfold output0
    split
    · exact NativeSourceTrace.approval before _ rfl
        (snapshot raw (native_trace_raw_append before))
    · exact NativeSourceTrace.other before _ rfl
  · exact before

theorem append_slot1_native_trace {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (sourcePosition : Nat) (outputs : List Produced) (before : NativeSourceTrace outputs) :
    NativeSourceTrace (appendSlot1 data packed valid sourcePosition outputs) := by
  unfold appendSlot1
  split
  · exact NativeSourceTrace.other before _ rfl
  · exact before

theorem append_slot0_raw_trace {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (outputs : List Produced) (before : RawAppendTrace outputs) :
    RawAppendTrace (appendSlot0 data packed valid outputs) := by
  unfold appendSlot0
  split
  · exact RawAppendTrace.append before _ (output0_position data packed valid outputs.length)
  · exact before

theorem append_slot1_raw_trace {template : CS.SourceTemplate} {input : GS.NativeStageInput}
    (data : OperationData template input) (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input).relation packed)
    (sourcePosition : Nat) (outputs : List Produced) (before : RawAppendTrace outputs) :
    RawAppendTrace (appendSlot1 data packed valid sourcePosition outputs) := by
  unfold appendSlot1
  split
  · exact RawAppendTrace.append before _
      (output1_position data packed valid sourcePosition outputs.length)
  · exact before

def appendRewards : List RewardData → List Produced → List Produced
  | [], outputs => outputs
  | reward :: rest, outputs =>
      appendRewards rest (outputs ++ [.reward (rewardOutput reward outputs.length)])

theorem append_rewards_native_trace (rewards : List RewardData) (outputs : List Produced)
    (before : NativeSourceTrace outputs) : NativeSourceTrace (appendRewards rewards outputs) := by
  induction rewards generalizing outputs with
  | nil => exact before
  | cons reward rest ih =>
      exact ih _ (NativeSourceTrace.reward before (rewardOutput reward outputs.length)
        reward.positive rfl)

theorem append_rewards_raw_trace (rewards : List RewardData) (outputs : List Produced)
    (before : RawAppendTrace outputs) : RawAppendTrace (appendRewards rewards outputs) := by
  induction rewards generalizing outputs with
  | nil => exact before
  | cons reward rest ih =>
      exact ih _ (RawAppendTrace.append before (.reward (rewardOutput reward outputs.length)) rfl)

/-- The stage's prefix is AFTER preceding original rewards, BEFORE this
stage's two source outputs and its following original rewards. Final uses
this prefix; Approval output0 also reads this same prefix. -/
def stagePrefix {template : CS.SourceTemplate} (input : EnrichedStageInput template)
    (outputs : List Produced) : List Produced := appendRewards input.rewardsBefore outputs

def appendOutputs {template : CS.SourceTemplate} (input : EnrichedStageInput template)
    (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input.input).relation packed)
    (outputs : List Produced) : List Produced :=
  let before := stagePrefix input outputs
  let first := appendSlot0 input.data packed valid before
  let second := appendSlot1 input.data packed valid before.length first
  appendRewards input.rewardsAfter second

theorem append_native_trace {template : CS.SourceTemplate} (input : EnrichedStageInput template)
    (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input.input).relation packed)
    (outputs : List Produced) (before : NativeSourceTrace outputs)
    (raw : SnapshotData input.data packed (stagePrefix input outputs).length
      (stagePrefix input outputs)) :
    NativeSourceTrace (appendOutputs input packed valid outputs) := by
  have atStage : NativeSourceTrace (stagePrefix input outputs) :=
    append_rewards_native_trace input.rewardsBefore outputs before
  have first := append_slot0_native_trace input.data packed valid _ atStage raw
  have second := append_slot1_native_trace input.data packed valid
    (stagePrefix input outputs).length _ first
  exact append_rewards_native_trace input.rewardsAfter _ second

theorem append_outputs_raw_trace {template : CS.SourceTemplate} (input : EnrichedStageInput template)
    (packed : Current.Values)
    (valid : Current.Satisfies (GS.nativeStage template input.input).relation packed)
    (outputs : List Produced) (before : RawAppendTrace outputs) :
    RawAppendTrace (appendOutputs input packed valid outputs) := by
  have atStage : RawAppendTrace (stagePrefix input outputs) :=
    append_rewards_raw_trace input.rewardsBefore outputs before
  have first := append_slot0_raw_trace input.data packed valid _ atStage
  have second := append_slot1_raw_trace input.data packed valid
    (stagePrefix input outputs).length _ first
  exact append_rewards_raw_trace input.rewardsAfter _ second

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentNativeOperationData
