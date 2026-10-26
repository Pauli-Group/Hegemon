import HegemonCrypto.NativePrivateSpendCurrentApprovalTransition
import HegemonCrypto.NativePrivateSpendCurrentOutputOrigin

/-! Current source-shaped chronological history. Source operations produce
owner and credential facts. Native assumptions concern only append positions,
previous-note readback and positive rewards; they do not contain authorization,
lineage or replay-success conclusions. The root theorem starts from the empty
log and constructs every accumulator lineage, or a concrete current primitive
failure on source inputs in this SAME trace. A current native-path/readback
adapter is separate from this theorem, as in the retained PR205 boundary. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentChronologicalApprovalHistory
open NativePrivateSpendCurrentSixCaseSemantics NativePrivateSpendCurrentAcceptedHistory
open NativePrivateSpendCurrentProtocolHistory NativePrivateSpendCurrentRoleTransport
open NativePrivateSpendCurrentApprovalTransition NativePrivateSpendCurrentOutputOrigin
open NativePrivateSpendCurrentEvaluatorIdentity NativePrivateSpendCurrentRoleGames
open NativePrivateSpendCurrentSourceCallContract NativePrivateSpendRoleBridge
open NativeLaunchConstraintAdapterBridge NativePrivateSpendLocalSemantics
open NativePrivateSpendPackedLowering NativePrivateSpendCompffPrimitiveGames
open NativePrivateSpendArithmeticTopology
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
noncomputable section
variable [Fact (Nat.Prime modulus)]

abbrev SatisfiedApproval := { source : SourceApproval // SourceValid source }

/-- Other output data are actual source note words and graph operations.
Satisfaction/branch evidence is the G1 input, not an authorization conclusion. -/
structure OtherOutput where
  source : SourceApproval
  valid : Current.Satisfies source.relation source.packed
  slot : Fin 2
  note : Fin 18 → Word K
  ownerBinding : (if slot = 0 then source.routes.output0Owner else source.routes.output1Owner) =
    outputOwnerWords note
  originData : OutputOriginChecked source.graph source.roles source.routes
  selected : slot = 1 ∨
    natural (sourceAssignment source.packed) (source.routes.modes 1) ≠ 1
  position : Nat

theorem OtherOutput.sem (output : OtherOutput) :
    StructuralSemantics output.source.graph output.source.layout
      (sourceAssignment output.source.packed) :=
  relation_derives_structural_semantics output.source.relation output.source.packed output.valid
    output.source.graph output.source.layout output.source.csr output.source.certificate

def OtherOutput.origin (output : OtherOutput) : OwnerOrigin :=
  let z := sourceAssignment output.source.packed
  if output.slot = 1 then .ordinary (digestNaturals z output.originData.recipient1)
  else if natural z (output.source.routes.modes 3) = 1 then
    .htlc (sourceHtlcInput output.source.graph output.source.layout z output.sem
      output.source.roles output.originData.htlcFrame)
  else .ordinary (digestNaturals z output.originData.recipient0)

def OtherOutput.owner (output : OtherOutput) : Digest :=
  digestNaturals (sourceAssignment output.source.packed) (outputOwnerWords output.note)

theorem other_output_owner (output : OtherOutput) :
    output.owner = originOwner output.origin := by
  classical
  let source := output.source
  let z := sourceAssignment source.packed
  by_cases last : output.slot = 1
  · have routing := source_route_equations source.graph source.layout z output.sem
      source.roles source.routes source.routing
    have equalOwner : digestNaturals z source.routes.output1Owner =
        digestNaturals z source.routes.normal1Owner := by
      apply congrArg List.ofFn
      funext lane
      exact congrArg ZMod.val (routing.normalOutput1 lane)
    have bound := output.ownerBinding
    have first : output.slot ≠ 0 := by omega
    rw [if_neg first] at bound
    change digestNaturals z (outputOwnerWords output.note) = _
    rw [← bound]
    simpa only [OtherOutput.origin, if_pos last, originOwner] using
      equalOwner.trans (source_ordinary_output source.graph source.layout z output.sem _ _
        output.originData.ordinary1)
  · have first : output.slot = 0 := by omega
    have inactive : natural z (source.routes.modes 1) ≠ 1 := by
      rcases output.selected with last' | inactive
      · exact False.elim (last last')
      · exact inactive
    have classifications := (nonapproval_output_origins source.graph source.layout z output.sem
      source.roles source.routes source.calls source.routing output.originData inactive).1
    have bound := output.ownerBinding
    rw [if_pos first] at bound
    change digestNaturals z (outputOwnerWords output.note) = _
    rw [← bound]
    rcases classifications with ⟨lockZero, ordinary⟩ | ⟨lockOne, locked⟩
    · have notLock : natural z (source.routes.modes 3) ≠ 1 := by omega
      change natural (sourceAssignment output.source.packed) (output.source.routes.modes 3) ≠ 1
        at notLock
      simpa only [OtherOutput.origin, if_neg last, if_neg notLock, originOwner] using ordinary
    · change natural (sourceAssignment output.source.packed) (output.source.routes.modes 3) = 1
        at lockOne
      simpa only [OtherOutput.origin, if_neg last, if_pos lockOne, originOwner] using locked

theorem other_origin_is_not_accumulator (output : OtherOutput)
    (input : AccumulatorOwnerInput) : output.origin ≠ .accumulator input := by
  classical
  unfold OtherOutput.origin
  dsimp only
  split
  · simp
  · split <;> simp

structure RewardOutput where
  stage : Nat
  position : Nat
  value : Nat
  owner : Digest

inductive Produced where
  | reward (output : RewardOutput)
  | other (output : OtherOutput)
  | approval (source : SatisfiedApproval)

def Produced.position : Produced → Nat
  | .reward output => output.position
  | .other output => output.position
  | .approval source => source.val.outputPosition

def Produced.stage : Produced → Nat
  | .reward output => output.stage
  | .other output => output.source.stage
  | .approval source => source.val.stage

def Produced.value : Produced → Nat
  | .reward output => output.value
  | .other output => natural (sourceAssignment output.source.packed) (output.note 0)
  | .approval source => (sourceRecord source.val).afterValue

def Produced.owner : Produced → Digest
  | .reward output => output.owner
  | .other output => output.owner
  | .approval source => (sourceRecord source.val).afterOwner

def Produced.origin : Produced → Option OwnerOrigin
  | .reward _ => none
  | .other output => some output.origin
  | .approval source => some (.accumulator
      (accumulatorInput (sourceRecord source.val).context (sourceRecord source.val).after))

def consumerInput (source : SatisfiedApproval) : AccumulatorOwnerInput :=
  accumulatorInput (sourceRecord source.val).context (sourceRecord source.val).before

/-- Includes the default empty-opening target; count-nonzero alone cannot
exclude an accumulator evaluator output equal to the known empty SINGLE identity. -/
def CurrentHistoryBad (outputs : List Produced) : Prop :=
  ∃ source : SatisfiedApproval, Produced.approval source ∈ outputs ∧
    (accumulatorOwner (consumerInput source) = nativeEmptyOwner ∨
      ∃ parent ∈ outputs, ∃ origin, parent.origin = some origin ∧
        AccumulatorOriginFailure origin (consumerInput source))

theorem history_bad_mono (before after : List Produced)
    (included : ∀ output ∈ before, output ∈ after)
    (bad : CurrentHistoryBad before) : CurrentHistoryBad after := by
  rcases bad with ⟨source, present, empty | ⟨parent, member, origin, originEq, failure⟩⟩
  · exact ⟨source, included _ present, Or.inl empty⟩
  · exact ⟨source, included _ present, Or.inr ⟨parent, included _ member, origin, originEq, failure⟩⟩

/-- Source-native readback is raw value/owner data at the original circuit
predecessor position. Earlier stage and append position are native facts.
The actual fixed SINGLE default is retained as a target branch, not invented as
an authorized producer. Note/Merkle collision is a separate adapter outcome. -/
def NativeReadback (outputs : List Produced) (source : SatisfiedApproval) : Prop :=
  (sourceRecord source.val).occupied = true →
    (sourceRecord source.val).beforeOwner = nativeEmptyOwner ∨
    ∃ parent ∈ outputs,
      (sourceRecord source.val).predecessor = some parent.position ∧
      parent.stage < source.val.stage ∧
      (sourceRecord source.val).beforeValue = parent.value ∧
      (sourceRecord source.val).beforeOwner = parent.owner

/-- No constructor assumes an Approval edge, authenticated bitmap or history
success. The native conditions are append/data readback, plus the retained
positive-genesis/coinbase condition used by PR205. -/
inductive SourceTrace : List Produced → Prop where
  | empty : SourceTrace []
  | reward {outputs} (trace : SourceTrace outputs) (output : RewardOutput)
      (positive : 0 < output.value) (position : output.position = outputs.length) :
      SourceTrace (outputs ++ [.reward output])
  | other {outputs} (trace : SourceTrace outputs) (output : OtherOutput)
      (position : output.position = outputs.length) :
      SourceTrace (outputs ++ [.other output])
  | approval {outputs} (trace : SourceTrace outputs) (source : SatisfiedApproval)
      (position : source.val.outputPosition = outputs.length)
      (readback : NativeReadback outputs source) :
      SourceTrace (outputs ++ [.approval source])

/-- Every append obtains its actual global position; no uniqueness premise
is supplied to the lineage theorem. -/
theorem source_trace_positions {outputs : List Produced} (trace : SourceTrace outputs) :
    outputs.map Produced.position = List.range outputs.length := by
  induction trace with
  | empty => rfl
  | reward trace output positive position ih =>
    simp only [List.map_append, List.map_cons, List.map_nil, Produced.position,
      position, ih, List.length_append, List.length_cons, List.length_nil,
      List.range_succ]
  | other trace output position ih =>
    simp only [List.map_append, List.map_cons, List.map_nil, Produced.position,
      position, ih, List.length_append, List.length_cons, List.length_nil,
      List.range_succ]
  | approval trace source position readback ih =>
    simp only [List.map_append, List.map_cons, List.map_nil, Produced.position,
      position, ih, List.length_append, List.length_cons, List.length_nil,
      List.range_succ]

theorem source_trace_positions_unique {outputs : List Produced}
    (trace : SourceTrace outputs) : (outputs.map Produced.position).Nodup := by
  rw [source_trace_positions trace]
  exact List.nodup_range

theorem reward_positive_of_mem {outputs : List Produced} (trace : SourceTrace outputs)
    (reward : RewardOutput) (member : Produced.reward reward ∈ outputs) :
    0 < reward.value := by
  induction trace with
  | empty => simp at member
  | reward trace output positive position ih =>
    rcases List.mem_append.mp member with old | last
    · exact ih old
    · have same := Produced.reward.inj (List.mem_singleton.mp last)
      cases same
      exact positive
  | other trace output position ih =>
    rcases List.mem_append.mp member with old | last
    · exact ih old
    · have impossible := List.mem_singleton.mp last
      cases impossible
  | approval trace source position readback ih =>
    rcases List.mem_append.mp member with old | last
    · exact ih old
    · have impossible := List.mem_singleton.mp last
      cases impossible

def OriginalRecords (outputs : List Produced) (records : List Record) : Prop :=
  ∀ record ∈ records, ∃ source : SatisfiedApproval,
    Produced.approval source ∈ outputs ∧ record = sourceRecord source.val

def Ready (outputs : List Produced) (source : SatisfiedApproval)
    (certificate : CertifiedAccumulator) : Prop :=
  certificate.position = source.val.outputPosition ∧
    certificate.context = (sourceRecord source.val).context ∧
    certificate.bitmap = (sourceRecord source.val).after ∧
    OriginalRecords outputs certificate.records ∧
    certificate.records.Pairwise (fun left right => left.stage < right.stage) ∧
    ∀ record ∈ certificate.records, record.stage ≤ source.val.stage

def Good (outputs : List Produced) : Prop :=
  ∀ source : SatisfiedApproval, Produced.approval source ∈ outputs →
    ∃ certificate, Ready outputs source certificate

theorem ready_mono (before after : List Produced)
    (included : ∀ output ∈ before, output ∈ after) (source : SatisfiedApproval)
    (certificate : CertifiedAccumulator) (ready : Ready before source certificate) :
    Ready after source certificate := by
  rcases ready with ⟨position, context, bitmap, original, order, stages⟩
  refine ⟨position, context, bitmap, ?_, order, stages⟩
  intro record member
  obtain ⟨actual, present, same⟩ := original record member
  exact ⟨actual, included _ present, same⟩

theorem ready_first (outputs : List Produced) (source : SatisfiedApproval)
    (certificate : CertifiedAccumulator)
    (position : certificate.position = source.val.outputPosition)
    (context : certificate.context = (sourceRecord source.val).context)
    (bitmap : certificate.bitmap = (sourceRecord source.val).after)
    (records : certificate.records = [sourceRecord source.val]) :
    Ready (outputs ++ [.approval source]) source certificate := by
  refine ⟨position, context, bitmap, ?_, ?_, ?_⟩
  · intro record member
    rw [records] at member
    exact ⟨source, by simp, List.mem_singleton.mp member⟩
  · rw [records]
    simp
  · intro record member
    rw [records] at member
    rcases List.mem_singleton.mp member with rfl
    exact Nat.le_refl _

theorem ready_advance (outputs : List Produced) (source parent : SatisfiedApproval)
    (prior next : CertifiedAccumulator) (ready : Ready outputs parent prior)
    (earlier : parent.val.stage < source.val.stage)
    (position : next.position = source.val.outputPosition)
    (context : next.context = (sourceRecord source.val).context)
    (bitmap : next.bitmap = (sourceRecord source.val).after)
    (records : next.records = prior.records.concat (sourceRecord source.val)) :
    Ready (outputs ++ [.approval source]) source next := by
  refine ⟨position, context, bitmap, ?_, ?_, ?_⟩
  · intro record member
    rw [records] at member
    have cases : record ∈ prior.records ∨ record = sourceRecord source.val := by simpa using member
    rcases cases with old | rfl
    · obtain ⟨actual, present, same⟩ := ready.2.2.2.1 record old
      exact ⟨actual, List.mem_append_left _ present, same⟩
    · exact ⟨source, by simp, rfl⟩
  · rw [records, List.concat_eq_append, List.pairwise_append]
    refine ⟨ready.2.2.2.2.1, by simp, ?_⟩
    intro left member right last
    rcases List.mem_singleton.mp last with rfl
    exact lt_of_le_of_lt (ready.2.2.2.2.2 left member) earlier
  · intro record member
    rw [records] at member
    have cases : record ∈ prior.records ∨ record = sourceRecord source.val := by simpa using member
    rcases cases with old | rfl
    · exact le_trans (ready.2.2.2.2.2 record old) earlier.le
    · exact Nat.le_refl _

/-- Original-record authentication is derived after provenance: every record
is an actual source Approval and its edge checks follow from its relation. -/
theorem original_records_authenticated (outputs : List Produced)
    (records : List Record) (original : OriginalRecords outputs records) :
    ∀ record ∈ records, EdgeChecks record := by
  intro record member
  obtain ⟨source, _, rfl⟩ := original record member
  exact source_edge_checks source.val source.property

theorem source_trace_lineages_or_current_bad (outputs : List Produced)
    (trace : SourceTrace outputs) : Good outputs ∨ CurrentHistoryBad outputs := by
  classical
  induction trace with
  | empty =>
    left
    intro source member
    simp at member
  | @reward priorOutputs trace output positive position ih =>
    rcases ih with good | bad
    · left
      intro source member
      have old : Produced.approval source ∈ priorOutputs := by simpa using member
      obtain ⟨certificate, ready⟩ := good source old
      exact ⟨certificate, ready_mono _ _ (fun item present => List.mem_append_left _ present)
        source certificate ready⟩
    · exact Or.inr (history_bad_mono _ _ (fun item present => List.mem_append_left _ present) bad)
  | @other priorOutputs trace output position ih =>
    rcases ih with good | bad
    · left
      intro source member
      have old : Produced.approval source ∈ priorOutputs := by simpa using member
      obtain ⟨certificate, ready⟩ := good source old
      exact ⟨certificate, ready_mono _ _ (fun item present => List.mem_append_left _ present)
        source certificate ready⟩
    · exact Or.inr (history_bad_mono _ _ (fun item present => List.mem_append_left _ present) bad)
  | @approval priorOutputs trace source position readback ih =>
    rcases ih with good | bad
    · have sourceOwner := source_parent_owner source.val source.property
      have complete (certificate : CertifiedAccumulator)
          (ready : Ready (priorOutputs ++ [.approval source]) source certificate) :
          Good (priorOutputs ++ [.approval source]) := by
        intro actual member
        rcases List.mem_append.mp member with old | last
        · obtain ⟨prior, readyPrior⟩ := good actual old
          exact ⟨prior, ready_mono _ _ (fun item present => List.mem_append_left _ present)
            actual prior readyPrior⟩
        · have same : actual = source := Produced.approval.inj (List.mem_singleton.mp last)
          subst actual
          exact ⟨certificate, ready⟩
      by_cases occupied : (sourceRecord source.val).occupied = true
      · rcases readback occupied with default | ⟨parent, member, predecessor, earlier, value, owner⟩
        · right
          exact ⟨source, by simp, Or.inl ((sourceOwner occupied).symm.trans default)⟩
        · cases parent with
          | reward reward =>
            have rewardPositive : 0 < reward.value := by
              /- Positive rewards are recovered from the source trace below. -/
              exact reward_positive_of_mem trace reward member
            have zero := (source_edge_checks source.val source.property).2.2.1
            change (sourceRecord source.val).beforeValue = reward.value at value
            omega
          | other output =>
            have same : originOwner output.origin = accumulatorOwner (consumerInput source) :=
              (other_output_owner output).symm.trans (owner.symm.trans (sourceOwner occupied))
            rcases accumulator_origin_or_role_failure output.origin (consumerInput source) same with impossible | failure
            · exact False.elim (other_origin_is_not_accumulator output _ impossible)
            · right
              exact ⟨source, by simp, Or.inr ⟨.other output,
                List.mem_append_left _ member, output.origin, rfl, failure⟩⟩
          | approval parent =>
            obtain ⟨prior, readyPrior⟩ := good parent member
            have rawOwner := (source_edge_checks parent.val parent.property).2.2.2.2.2.2
            have sameOwner : (sourceRecord source.val).beforeOwner =
                encodedAccumulator prior.context prior.bitmap := by
              rw [readyPrior.2.1, readyPrior.2.2.1]
              exact owner.trans rawOwner
            rcases source_occupied_approval source.val source.property occupied prior sameOwner with
                ⟨same, next, success, newPosition, newContext, newBitmap, records⟩ | collision
            · left
              exact complete next (ready_advance priorOutputs source parent prior next readyPrior
                earlier newPosition newContext newBitmap records)
            · right
              refine ⟨source, by simp, Or.inr ⟨.approval parent,
                List.mem_append_left _ member, _, rfl, ?_⟩⟩
              simpa only [readyPrior.2.1, readyPrior.2.2.1, consumerInput,
                Produced.origin, AccumulatorOriginFailure] using collision
      · have absent : (sourceRecord source.val).occupied = false := by
          cases state : (sourceRecord source.val).occupied
          · rfl
          · exact False.elim (occupied state)
        obtain ⟨next, success, newPosition, newContext, newBitmap, records⟩ :=
          source_first_approval source.val source.property absent
        exact Or.inl (complete next (ready_first priorOutputs source next newPosition
          newContext newBitmap records))
    · exact Or.inr (history_bad_mono _ _ (fun item present => List.mem_append_left _ present) bad)

end
end HegemonCrypto.NativePrivateSpendCurrentChronologicalApprovalHistory
