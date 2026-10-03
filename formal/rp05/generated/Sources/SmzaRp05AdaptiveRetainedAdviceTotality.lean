import SmzaRp05AdaptiveRetainedAdviceTransport

/-! # Scheduled physical-read totality survives same-table conditioning -/
namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceTotality

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05ConditionedExecution SmzaRp05CurrentAdaptiveExecution
open SmzaRp05ConditionedEventJoin SmzaRp05RoleReadTotality
open SmzaRp05AdaptiveRetainedAdviceTransport
open V8Smz9CoherentVectorMerkle SmzaRp04RawMcaSampling

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem fixed_fiber_total_at_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : TotalAt key.val state) :
    TotalAt key (fixedFiberToActive ctx blockCap dummy fixed state) := by
  intro basis absent
  unfold fixedFiberToActive activeRegisterEmbed databaseSlice
  split
  · exact total _ ((merge_fixed_active_at_active ctx blockCap fixed basis.database key).trans absent)
  · rfl

/-- Totality at one active read address follows from that same address in
the original physical state. No normalized or postselected premise enters. -/
theorem same_fiber_standard_at
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : TotalAt key.val (globalDecompress state)) :
    TotalAt key (globalDecompress
      (routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state))) := by
  apply (standard_at_iff_selected key _).mpr
  unfold routedPhysicalFiber
  rw [← reindex_decompress_at, ← fixed_fiber_to_active_decompress_active]
  have selectedTotal := (standard_at_iff_selected key.val state).mp total
  have omitted : key.val ∉ (fixedOtherKeys ctx blockCap).toList := by
    intro member
    exact ((mem_fixed_other_keys ctx blockCap key.val).mp (by simpa using member)) key.property
  have transformedTotal : TotalAt key.val
      (decompressAt key.val (otherRoleTransform ctx blockCap state)) := by
    unfold otherRoleTransform decompressFinset
    rw [decompress_at_decompress_list_commutes]
    exact total_at_decompress_list_of_not_mem key.val _ _ omitted selectedTotal
  have activeTotal := fixed_fiber_total_at_active ctx blockCap dummy fixed key
    (decompressAt key.val (otherRoleTransform ctx blockCap state)) transformedTotal
  intro basis absent
  exact activeTotal ((basisWorkspaceEquiv (activeMemoryEquiv ctx)).symm basis) absent

theorem active_read_keys_original_member
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : List Key)
    (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (member : key ∈ activeReadKeys ctx blockCap keys) : key.val ∈ keys := by
  obtain ⟨original, originalMember, selected⟩ := List.mem_filterMap.mp member
  by_cases live : RoleActive ctx.role blockCap ctx.keyBytes original
  · simp only [dif_pos live] at selected
    have same := congrArg Subtype.val (Option.some.inj selected)
    simpa only [← same] using originalMember
  · simp [live] at selected

/-- The compiled active key schedule is standard-total whenever the
original full schedule is standard-total on the common reached state. -/
theorem same_fiber_standard_on_active_schedule
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (keys : List Key)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : StandardOn keys state) :
    StandardOn (activeReadKeys ctx blockCap keys)
      (routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state)) := by
  intro key member
  exact same_fiber_standard_at ctx blockCap dummy fixed key state
    (total key.val (active_read_keys_original_member ctx blockCap keys key member))

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceTotality
