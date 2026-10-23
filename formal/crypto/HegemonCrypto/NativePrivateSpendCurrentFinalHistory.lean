import HegemonCrypto.NativePrivateSpendCurrentChronologicalApprovalHistory

/-! Current Final authorization from satisfying source equations and raw
native note/append readback. The lineage certificate is constructed by the
chronological theorem, never an authorization premise. The default empty
opening and unequal-input current owner roles remain explicit failure arms.
Verifier acceptance to a satisfying assignment belongs to G3. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentFinalHistory
open NativePrivateSpendCurrentSixCaseSemantics NativePrivateSpendCurrentAcceptedHistory
open NativePrivateSpendCurrentProtocolHistory NativePrivateSpendCurrentRoleTransport
open NativePrivateSpendCurrentApprovalTransition NativePrivateSpendCurrentOutputOrigin
open NativePrivateSpendCurrentChronologicalApprovalHistory
open NativePrivateSpendCurrentEvaluatorIdentity NativePrivateSpendCurrentRoleGames
open NativePrivateSpendCurrentSourceCallContract NativePrivateSpendRoleBridge
open NativeLaunchConstraintAdapterBridge NativePrivateSpendLocalSemantics
open NativePrivateSpendPackedLowering NativePrivateSpendSelectedNullifier
open NativePrivateSpendMerkleContinuation
open NativePrivateSpendArithmeticTopology NativePrivateSpendCompffPrimitiveGames
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
noncomputable section
variable [Fact (Nat.Prime modulus)]

/-- Only current graph operation/address data; no authorization field. -/
structure SourceFinal where
  source : SourceApproval
  count : FinalCountChecked source.graph (source.routes.modes 2) source.roles.count
  valueZero : GateData source.graph (source.routes.modes 2)
    (noteWords source.inputWords (1 : Fin 2) 0) (.constant 0)
  occupied : GateData source.graph (source.routes.modes 2)
    (NativePrivateSpendSelectedNullifier.occupied source.inputWords (1 : Fin 2)) (.constant 1)
  ownerBinding : source.routes.input1Owner =
    outputOwnerWords (noteWords source.inputWords (1 : Fin 2))

def FinalValid (final : SourceFinal) : Prop :=
  Current.Satisfies final.source.relation final.source.packed ∧
    natural (sourceAssignment final.source.packed) (final.source.routes.modes 2) = 1

def finalContext (final : SourceFinal) : Context :=
  sourceContext (sourceAssignment final.source.packed) final.source.roles

def finalBitmap (final : SourceFinal) : Finset Slot :=
  sourceBitmap (sourceAssignment final.source.packed) final.source.roles.approved

def finalInput (final : SourceFinal) : AccumulatorOwnerInput :=
  accumulatorInput (finalContext final) (finalBitmap final)

def finalOwner (final : SourceFinal) : Digest :=
  digestNaturals (sourceAssignment final.source.packed)
    (outputOwnerWords (noteWords final.source.inputWords (1 : Fin 2)))

def finalValue (final : SourceFinal) : Nat :=
  natural (sourceAssignment final.source.packed)
    (noteWords final.source.inputWords (1 : Fin 2) 0)

theorem final_source_facts (final : SourceFinal) (valid : FinalValid final) :
    finalValue final = 0 ∧
    natural (sourceAssignment final.source.packed)
      (NativePrivateSpendSelectedNullifier.occupied final.source.inputWords (1 : Fin 2)) = 1 ∧
    finalOwner final = accumulatorOwner (finalInput final) ∧
    2 ≤ (finalBitmap final).card := by
  let source := final.source
  let z := sourceAssignment source.packed
  have sem := relation_derives_structural_semantics source.relation source.packed valid.1
    source.graph source.layout source.csr source.certificate
  have zero := NativePrivateSpendHtlcRecipient.selected_gate source.graph source.layout z
    sem _ _ _ final.valueZero valid.2
  have occupied := NativePrivateSpendHtlcRecipient.selected_gate source.graph source.layout z
    sem _ _ _ final.occupied valid.2
  have count := (final_count_from_source source.graph source.layout z sem _ _
    final.count valid.2).1
  have countBitmap := source_bitmap_count source.graph source.layout z sem
    source.roles.approved source.roles.count source.approval.beforeBits source.calls.count
  have hashOwner := source_accumulator_owner source.graph source.layout z sem
    source.roles source.calls source.roles.approved source.roles.count
    source.roles.accumulatorInner source.roles.accumulator
    (fun i => boolean_sound source.graph source.layout z sem _ (source.approval.beforeBits i))
    source.calls.count source.calls.accumulatorInner source.calls.accumulator
  have ownerEq : digestNaturals z source.routes.input1Owner =
      digestNaturals z source.roles.accumulator := by
    apply congrArg List.ofFn
    funext lane
    exact congrArg ZMod.val (NativePrivateSpendHtlcRecipient.selected_gate
      source.graph source.layout z sem _ _ _ (source.routing.finalAccumulator lane) valid.2)
  rw [final.ownerBinding] at ownerEq
  refine ⟨?_, ?_, ownerEq.trans hashOwner, ?_⟩
  · simpa only [finalValue, natural, NativeLaunchConstraintAdapterBridge.read, ZMod.val_zero]
      using congrArg ZMod.val zero
  · simpa only [natural, NativeLaunchConstraintAdapterBridge.read, ZMod.val_one]
      using congrArg ZMod.val occupied
  · change 2 ≤ (sourceBitmap z source.roles.approved).card
    rw [← countBitmap]
    exact count

/-- Raw occupied input-1 note readback from the original chronological log.
It supplies no lineage, approved signer, authorized owner or replay success. -/
def FinalNativeReadback (outputs : List Produced) (final : SourceFinal) : Prop :=
  finalOwner final = nativeEmptyOwner ∨
    ∃ parent ∈ outputs, parent.stage < final.source.stage ∧
      finalValue final = parent.value ∧ finalOwner final = parent.owner

def FinalHistoryBad (outputs : List Produced) (final : SourceFinal) : Prop :=
  accumulatorOwner (finalInput final) = nativeEmptyOwner ∨
    ∃ parent ∈ outputs, ∃ origin, parent.origin = some origin ∧
      AccumulatorOriginFailure origin (finalInput final)

/-- Every returned approval record is an original same-trace source record,
its signer is selected and credential-backed, its input/output values are
zero, its stages strictly increase, and at least two signers are distinct. -/
def FinalAuthorized (outputs : List Produced) (final : SourceFinal) : Prop :=
  ∃ parent : SatisfiedApproval, Produced.approval parent ∈ outputs ∧
    parent.val.stage < final.source.stage ∧ ∃ certificate : CertifiedAccumulator,
      Ready outputs parent certificate ∧ certificate.context = finalContext final ∧
      certificate.bitmap = finalBitmap final ∧
      OriginalRecords outputs certificate.records ∧
      (∀ record ∈ certificate.records, EdgeChecks record) ∧
      certificate.records.Pairwise (fun left right => left.stage < right.stage) ∧
      (certificate.records.map Record.signer).Nodup ∧ 2 ≤ certificate.records.length

theorem current_relation_history_final_authorization (outputs : List Produced)
    (trace : SourceTrace outputs) (final : SourceFinal) (valid : FinalValid final)
    (readback : FinalNativeReadback outputs final) :
    FinalAuthorized outputs final ∨ CurrentHistoryBad outputs ∨ FinalHistoryBad outputs final := by
  classical
  rcases source_trace_lineages_or_current_bad outputs trace with good | bad
  · have facts := final_source_facts final valid
    rcases readback with default | ⟨parent, present, earlier, value, owner⟩
    · exact Or.inr (Or.inr (Or.inl (facts.2.2.1.symm.trans default)))
    · cases parent with
      | reward reward =>
        have positive := reward_positive_of_mem trace reward present
        change finalValue final = reward.value at value
        have zero := facts.1
        omega
      | other output =>
        have ownerEq : originOwner output.origin = accumulatorOwner (finalInput final) :=
          (other_output_owner output).symm.trans (owner.symm.trans facts.2.2.1)
        rcases accumulator_origin_or_role_failure output.origin (finalInput final) ownerEq with same | failure
        · exact False.elim (other_origin_is_not_accumulator output _ same)
        · exact Or.inr (Or.inr (Or.inr ⟨.other output, present, output.origin, rfl, failure⟩))
      | approval parent =>
        obtain ⟨certificate, ready⟩ := good parent present
        have sourceOwner := (source_edge_checks parent.val parent.property).2.2.2.2.2.2
        have sameOwner : encodedAccumulator (finalContext final) (finalBitmap final) =
            encodedAccumulator certificate.context certificate.bitmap := by
          rw [ready.2.1, ready.2.2.1]
          exact facts.2.2.1.symm.trans (owner.trans sourceOwner)
        rcases final_authorization_or_collision (finalContext final) (finalBitmap final)
          certificate sameOwner facts.2.2.2 with authorized | collision
        · refine Or.inl ⟨parent, present, earlier, certificate, ready, authorized.1.symm,
            authorized.2.1.symm, ready.2.2.2.1,
            original_records_authenticated outputs certificate.records ready.2.2.2.1,
            ready.2.2.2.2.1, authorized.2.2.1, authorized.2.2.2⟩
        · refine Or.inr (Or.inr (Or.inr ⟨.approval parent, present, _, rfl, ?_⟩))
          have reversed : accumulatorCollision
              (accumulatorInput certificate.context certificate.bitmap, finalInput final) :=
            ⟨fun eq => collision.1 eq.symm, collision.2.symm⟩
          simpa only [Produced.origin, AccumulatorOriginFailure, ready.2.1,
            ready.2.2.1, finalInput] using reversed
  · exact Or.inr (Or.inl bad)
end
end HegemonCrypto.NativePrivateSpendCurrentFinalHistory
