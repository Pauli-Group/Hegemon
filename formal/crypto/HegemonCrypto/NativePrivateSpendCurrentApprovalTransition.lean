import HegemonCrypto.NativePrivateSpendCurrentRoleTransport

/-! A current source Approval produces its edge checks. The native parent
readback is a raw note/position equality, never an authorization or successful
history premise. Collision alternatives retain the actual fixed inputs. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentApprovalTransition
open NativePrivateSpendCurrentSixCaseSemantics NativePrivateSpendCurrentAcceptedHistory
open NativePrivateSpendCurrentProtocolHistory NativePrivateSpendCurrentRoleTransport
open NativePrivateSpendRoleBridge NativePrivateSpendCurrentSourceCallContract
open NativePrivateSpendArithmeticTopology NativePrivateSpendPackedLowering
open NativePrivateSpendCsrCertificate NativeLaunchConstraintAdapterBridge
open NativePrivateSpendLocalSemantics NativePrivateSpendMerkleContinuation
open NativePrivateSpendSelectedNullifier NativePrivateSpendCurrentRoleGames
open NativePrivateSpendCompffPrimitiveGames
noncomputable section
variable [Fact (Nat.Prime modulus)]

/-- Immutable graph/operation/address data for one source-addressed record. -/
structure SourceApproval where
  relation : Current.Relation
  packed : Current.Values
  graph : Graph K
  layout : Layout K
  csr : RawCSR K
  certificate : RelationCertificate relation graph layout csr
  roles : Roles
  routes : RouteRoles
  inputWords : Nat → Word K
  outputWords : Fin 18 → Word K
  calls : CallsChecked graph roles
  routing : RouteChecked graph roles routes
  recordBinding : RecordRouteBinding routes inputWords outputWords
  approval : ApprovalChecked graph roles routes
    (noteWords inputWords (0 : Fin 2) 0) (outputWords 0)
  signer : ApprovalSignerChecked graph roles routes inputWords
  parent : ApprovalParentChecked graph roles routes
  stage : Nat
  outputPosition : Nat

def sourceRecord (source : SourceApproval) : Record :=
  recordFromSource source.stage source.outputPosition source.packed source.roles
    source.routes source.inputWords source.signer.who source.outputWords

def SourceValid (source : SourceApproval) : Prop :=
  Current.Satisfies source.relation source.packed ∧
    natural (sourceAssignment source.packed) (source.routes.modes 1) = 1

def EdgeChecks (record : Record) : Prop :=
  record.after = insert record.signer record.before ∧ record.signer ∉ record.before ∧
    record.beforeValue = 0 ∧ record.afterValue = 0 ∧
    singleKeyEvaluator record.signerKey = record.signerAuthority ∧
    record.signerAuthority = canonicalDigestWords (record.context.tags record.signer) ∧
    record.afterOwner = encodedAccumulator record.context record.after

theorem source_edge_checks (source : SourceApproval) (valid : SourceValid source) :
    EdgeChecks (sourceRecord source) :=
  relation_record_advance_checks source.relation source.packed valid.1 source.graph
    source.layout source.csr source.certificate source.stage source.outputPosition
    source.roles source.routes source.inputWords source.outputWords source.calls
    source.routing source.recordBinding source.approval source.signer valid.2

theorem source_occupied (source : SourceApproval) :
    (sourceRecord source).occupied = true ↔
      read (sourceAssignment source.packed) source.routes.occupied0 = 1 := by
  simp only [sourceRecord, recordFromSource, source.recordBinding.occupied,
    decide_eq_true_eq]

theorem source_absent (source : SourceApproval) (valid : SourceValid source)
    (absent : (sourceRecord source).occupied = false) :
    (sourceRecord source).before = ∅ := by
  let z := sourceAssignment source.packed
  have sem := relation_derives_structural_semantics source.relation source.packed
    valid.1 source.graph source.layout source.csr source.certificate
  have noOne : read z source.routes.occupied0 ≠ 1 := by
    intro one
    have active := (source_occupied source).mpr one
    rw [absent] at active
    cases active
  have zero : read z source.routes.occupied0 = 0 := by
    rcases boolean_sound source.graph source.layout z sem _ source.parent.occupiedBit with zero | one
    · exact zero
    · exact False.elim (noOne one)
  exact (approval_parent_bitmap source.graph source.layout z sem source.roles source.routes
    source.calls source.routing source.parent source.approval.beforeBits valid.2).1 zero

theorem source_parent_owner (source : SourceApproval) (valid : SourceValid source)
    (occupied : (sourceRecord source).occupied = true) :
    (sourceRecord source).beforeOwner =
      encodedAccumulator (sourceRecord source).context (sourceRecord source).before := by
  let z := sourceAssignment source.packed
  have sem := relation_derives_structural_semantics source.relation source.packed
    valid.1 source.graph source.layout source.csr source.certificate
  have owner := source_occupied_approval_owner source.graph source.layout z sem
    source.roles source.routes source.calls source.routing source.approval.beforeBits
    valid.2 ((source_occupied source).mp occupied)
  rw [source.recordBinding.inputOwner] at owner
  exact owner

omit [Fact (Nat.Prime modulus)] in
theorem advance_checked (record : Record) (prior : CertifiedAccumulator)
    (same : prior.context = record.context) (before : record.before = prior.bitmap)
    (checks : EdgeChecks record) :
    ∃ next, advance record prior same = .ok next ∧
      next.position = record.outputPosition ∧ next.context = record.context ∧
      next.bitmap = record.after ∧ next.records = prior.records.concat record := by
  classical
  have checked : record.before = prior.bitmap ∧
      record.after = insert record.signer prior.bitmap ∧ record.signer ∉ prior.bitmap ∧
      record.beforeValue = 0 ∧ record.afterValue = 0 ∧
      singleKeyEvaluator record.signerKey = record.signerAuthority ∧
      record.signerAuthority = canonicalDigestWords (record.context.tags record.signer) ∧
      record.afterOwner = encodedAccumulator record.context record.after := by
    simpa only [EdgeChecks, before] using And.intro before checks
  unfold advance
  rw [dif_pos checked]
  exact ⟨_, rfl, rfl, rfl, rfl, rfl⟩

theorem source_first_approval (source : SourceApproval) (valid : SourceValid source)
    (absent : (sourceRecord source).occupied = false) :
    ∃ next, firstAccumulator (sourceRecord source) = .ok next ∧
      next.position = source.outputPosition ∧ next.context = (sourceRecord source).context ∧
      next.bitmap = (sourceRecord source).after ∧ next.records = [sourceRecord source] := by
  exact advance_checked (sourceRecord source) _ rfl (source_absent source valid absent)
    (source_edge_checks source valid)

/-- An occupied value-zero source Approval extends its genuine historical
lineage, or returns a concrete unequal-input accumulator collision. The
prior is an induction value constructed by earlier source steps, not a
caller-supplied authorization field in the source record. -/
theorem source_occupied_approval (source : SourceApproval) (valid : SourceValid source)
    (occupied : (sourceRecord source).occupied = true) (prior : CertifiedAccumulator)
    (readback : (sourceRecord source).beforeOwner =
      encodedAccumulator prior.context prior.bitmap) :
    (∃ same : prior.context = (sourceRecord source).context,
      ∃ next, advance (sourceRecord source) prior same = .ok next ∧
        next.position = source.outputPosition ∧ next.context = (sourceRecord source).context ∧
        next.bitmap = (sourceRecord source).after ∧
        next.records = prior.records.concat (sourceRecord source)) ∨
    accumulatorCollision
      (accumulatorInput prior.context prior.bitmap,
       accumulatorInput (sourceRecord source).context (sourceRecord source).before) := by
  rcases occupied_approval_parent_join (sourceRecord source) prior readback
    (source_parent_owner source valid occupied) with joined | collision
  · exact Or.inl ⟨joined.1, advance_checked (sourceRecord source) prior joined.1
      joined.2.symm (source_edge_checks source valid)⟩
  · exact Or.inr collision
end
end HegemonCrypto.NativePrivateSpendCurrentApprovalTransition
