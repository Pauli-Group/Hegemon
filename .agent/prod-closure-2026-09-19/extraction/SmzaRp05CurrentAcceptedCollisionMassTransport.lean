import SmzaRp05CurrentFilteredCollisionReadback
import SmzaRp05CurrentFilteredCollisionEventSpec
import SmzaRp05DependentAdviceEvent
import SmzaRp05OrdinarySoundnessStandardTotal
import SmzaRp05CurrentPhysicalBranchClaims
import SmzaRp05CurrentNonchallengeRecordView
import SmzaRp05CurrentNonchallengeSelectorTransport
import SmzaRp05CurrentSelectedChallengeClaims

/-! # Same-branch erased collision mass on current active fibers

The original branch collision is retained as a workspace event.  On every
supported basis of the partially decompressed physical state, totality gives
its actual fixed table; the existing erasure lemma then places that same
basis in the current filtered-collision event on the sparse active fiber.
No event probability or resampling premise is used.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCollisionMassTransport

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes HegemonCrypto.FiniteOracleDatabase
open SmzaRp05FilteredReadback (globalLeafStatement)
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets SmzaRoleDomainConditioning
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05DependentAdviceEvent SmzaRp05OrdinarySoundnessStandardTotal
open SmzaRp05CurrentFilteredCollisionReadback
open SmzaRp05CurrentFilteredCollisionEventSpec
open SmzaRp05CurrentNonchallengeRecordView
open SmzaRp05CurrentNonchallengeSelectorTransport (nonchallengeSelectorProjection
  nonchallenge_selector_projection_other_role_transform)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet
  nonchallenge_raw_key_set_unrecognized)
open SmzaRp05ActualEventRecertification
open SmzaRp05FilteredCollision
open SmzaRp05ChallengeRecordErasure
open SmzaRp04StatementRecordFilter
open SmzaRawDatabaseRecords V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle V8Smz9CoherentMerkleGeometry

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

private def statementErasedCollision
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (statement : List Byte) :
    SmzaRp05CurrentAdaptiveExecution.Work
      (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (VectorOutput Counter) → Prop :=
  fun _ database => ¬ SmzaRecordedTracePath.RecordsCollisionFree
    (oneStatementFilter (globalLeafStatement ctx.leafNamespace) statement
      (eraseChallengeRecords
        (rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter) database)))

/-- Original one-statement, challenge-erased collision mass is dominated by
the sum of the checked current filtered-collision projections on the same
physical branches and their actual fixed fibers.  `fixedOtherTotal` is the
standard-on-fixed-coordinates fact supplied by the ordinary/physical branch
compiler; it is not a probability or event-mass assumption. -/
theorem statement_erased_collision_mass_le_current_filtered_fibers
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (cap : Nat) (statement : List Byte)
    (emptyAuthorization : ∀ base, ctx.authorizedOf base = ∅)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (fixedOtherTotal : ∀ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      HegemonCrypto.CmsOracleDatabaseBridge.TotalAt key.val
        (otherRoleTransform ctx blockCap state)) :
    normSquared (workspaceEventProjection (statementErasedCollision ctx statement)
      (otherRoleTransform ctx blockCap state)) ≤
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (fun (memory : SmzaRp05ConditionedExecution.ActiveMemory ctx)
              (active : SmzaRp05ConditionedExecution.ActiveDatabase ctx blockCap) => event
            (filteredCollisionEventSpec (activeContext ctx blockCap fixed) cap)
            (activeMemoryEquiv ctx memory) active)
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap state))) := by
  let transformed := otherRoleTransform ctx blockCap state
  let original := statementErasedCollision ctx statement
  let dependent := dependentFixedEvent ctx blockCap (fun _ => original)
  have originalEq :
      normSquared (workspaceEventProjection original transformed) =
        normSquared (workspaceEventProjection dependent transformed) := by
    unfold normSquared workspaceEventProjection
    apply Finset.sum_congr rfl
    intro basis _
    by_cases collision : original basis.workspace basis.database
    · by_cases basisNonzero : transformed basis ≠ 0
      · obtain ⟨fixed, fiber⟩ := fixed_table_exists_of_nonzero_basis
          ctx blockCap transformed fixedOtherTotal basis basisNonzero
        have dependentAt : dependent basis.workspace basis.database :=
          ⟨fixed, fiber, collision⟩
        simp only [if_pos collision, if_pos dependentAt]
      · have basisZero : transformed basis = 0 := by
          exact not_ne_iff.mp basisNonzero
        simp only [basisZero, ite_self, map_zero]
    · have dependentFalse : ¬ dependent basis.workspace basis.database := by
        rintro ⟨_fixed, _fiber, witnessedCollision⟩
        exact collision witnessedCollision
      simp only [if_neg collision, if_neg dependentFalse]
  rw [originalEq,
    dependent_event_mass_eq_sum_active_event_masses ctx blockCap dummy
      (fun _ => original) transformed]
  apply Finset.sum_le_sum
  intro fixed _
  apply SmzaRp05CurrentPhysicalBranchClaims.workspace_event_mass_le_of_inclusion
  intro memory active collision
  have activeCollision := fresh_erased_merged_collision_implies_active_filtered_collision
    ctx blockCap fixed active ∅ statement (by simp) collision
  have eventCollision : event
      (filteredCollisionEventSpec (activeContext ctx blockCap fixed) cap)
      (activeMemoryEquiv ctx memory) active := by
    change filteredRawCollision ctx.leafNamespace
      (ctx.authorizedOf memory.original.2.2.2)
      (fun key => ctx.keyBytes key.val) ctx.counter active
    rw [emptyAuthorization]
    exact activeCollision
  exact eventCollision

/-- Erased collision selection ignores every coordinate changed by role
conditioning, so its original Born mass is preserved by that transform. -/
theorem statement_erased_collision_mass_other_role_transform
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (statement : List Byte)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (workspaceEventProjection (statementErasedCollision ctx statement) state) =
      normSquared (workspaceEventProjection (statementErasedCollision ctx statement)
        (otherRoleTransform ctx blockCap state)) := by
  classical
  let keys := nonchallengeRawKeySet ctx
  let completion (view : XKey keys → Option (VectorOutput Counter)) :
      Database Key (VectorOutput Counter) :=
    fun key => if member : key ∈ keys then view ⟨key, member⟩ else none
  let select (view : XKey keys → Option (VectorOutput Counter))
      (work : SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) :=
    statementErasedCollision ctx statement work (completion view)
  have sameEvent : (fun work database => select (xView keys database) work) =
      statementErasedCollision ctx statement := by
    funext work database
    have recordsEq := erased_raw_records_eq_of_nonchallenge_key_agreement
      ctx.keyBytes (vectorOutputBytes ctx.counter)
      (completion (xView keys database)) database (by
        intro key unrecognized
        have member : key ∈ keys := Finset.mem_filter.mpr
          ⟨Finset.mem_univ key, unrecognized⟩
        simp only [completion, dif_pos member, xView])
    exact congrArg (fun records => ¬ SmzaRecordedTracePath.RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ctx.leafNamespace) statement records))
      recordsEq
  have projectionEq : ∀ current : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork),
      nonchallengeSelectorProjection keys select current =
        workspaceEventProjection (statementErasedCollision ctx statement) current := by
    intro current
    unfold nonchallengeSelectorProjection
    rw [sameEvent]
  have outside : ∀ key, key ∈ fixedOtherKeys ctx blockCap → key ∉ keys := by
    intro key fixedMember nonchallengeMember
    have parsedNone := nonchallenge_raw_key_set_unrecognized ctx key nonchallengeMember
    have fixedOther := (mem_fixed_other_keys ctx blockCap key).mp fixedMember
    exact fixedOther (by simp [RoleActive, parsedNone])
  have commute := nonchallenge_selector_projection_other_role_transform
    ctx blockCap keys select state outside
  rw [projectionEq, projectionEq] at commute
  rw [commute, other_role_transform_norm_squared]

/-- Charge the collision event on the original state, before role conditioning,
to the counted collision projections on its literal fixed fibers. -/
theorem original_statement_erased_collision_mass_le_current_filtered_fibers
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (cap : Nat) (statement : List Byte)
    (emptyAuthorization : ∀ base, ctx.authorizedOf base = ∅)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (fixedOtherTotal : ∀ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      HegemonCrypto.CmsOracleDatabaseBridge.TotalAt key.val
        (otherRoleTransform ctx blockCap state)) :
    normSquared (workspaceEventProjection (statementErasedCollision ctx statement) state) ≤
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (fun (memory : ActiveMemory ctx) (active : ActiveDatabase ctx blockCap) => event
            (filteredCollisionEventSpec (activeContext ctx blockCap fixed) cap)
            (activeMemoryEquiv ctx memory) active)
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap state))) := by
  rw [statement_erased_collision_mass_other_role_transform ctx blockCap statement state]
  exact statement_erased_collision_mass_le_current_filtered_fibers
    ctx blockCap dummy cap statement emptyAuthorization state fixedOtherTotal

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCollisionMassTransport
