import SmzaRp05AdaptiveRetainedAdviceTransport

/-! # Actual fixed-role answers on nonzero physical branches

The branch log retains the actual observed vectors. Nonzero amplitude in
the same terminal fixed-table fiber forces each fixed-role log entry to be
that very table value. This holds for all attempted nonces and repetitions.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceReadback

open scoped Classical
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05ConditionedExecution SmzaRp05CurrentAdaptiveExecution
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05AdaptiveRetainedAdviceTransport
open SmzaRp05RoleReadTotality SmzaRp05ScheduledRoleExecution
open V8Smz9CoherentVectorMerkle SmzaRp04RawMcaSampling
open SmzaRp05ExecutableMerkleVerifier (Program)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem nonzero_mixed_branch_fixed_answers
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : ActiveState ctx blockCap)
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput Counter) (VectorOutput Counter) (ActiveMemory ctx))
    (nonzero : mixedRun ctx blockCap fixed encode decode program branch state basis ≠ 0)
    (call : RawInput × VectorOutput Counter)
    (recorded : call ∈ answerLog decode program branch)
    (inactive : ¬RoleActive ctx.role blockCap ctx.keyBytes (encode call.1)) :
    fixed ⟨encode call.1, inactive⟩ = call.2 := by
  induction program generalizing state with
  | done result => cases recorded
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      simp only [answerLog, List.mem_cons] at recorded
      rcases recorded with same | later
      · subst call
        by_contra mismatch
        simp only [mixedRun, dif_neg inactive, if_neg mismatch, mixed_run_zero,
          Pi.zero_apply] at nonzero
        exact nonzero rfl
      · exact ih (decode raw answer) branch _ nonzero later

/-- This is a support fact about the original physical execution and its
original answer branch. The advice table is the actual terminal fiber;
there is no arbitrary allAdvice argument or desired-event premise. -/
theorem nonzero_physical_fiber_fixed_answers
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput Counter) (VectorOutput Counter) (ActiveMemory ctx))
    (nonzero : fixedFiberToActive ctx blockCap dummy fixed
      (otherRoleTransform ctx blockCap (physicalRun encode decode program branch state)) basis ≠ 0)
    (call : RawInput × VectorOutput Counter)
    (recorded : call ∈ answerLog decode program branch)
    (inactive : ¬RoleActive ctx.role blockCap ctx.keyBytes (encode call.1)) :
    fixed ⟨encode call.1, inactive⟩ = call.2 := by
  rw [physical_run_to_mixed_same_fiber] at nonzero
  exact nonzero_mixed_branch_fixed_answers ctx blockCap fixed encode decode program branch
    _ basis nonzero call recorded inactive

/-- Fixed-domain membership implies literal challenge-parser recognition. -/
theorem fixed_key_recognized
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (key : Key)
    (member : key ∈ (fixedOtherKeys ctx blockCap).toList) :
    ∃ query, parseStageQuery (ctx.keyBytes key) = some query := by
  have fixed := (mem_fixed_other_keys ctx blockCap key).mp (by simpa using member)
  cases parsed : parseStageQuery (ctx.keyBytes key) with
  | none => exact False.elim (fixed (by simp [RoleActive, parsed]))
  | some query => exact ⟨query, rfl⟩

theorem physical_run_preserves_standard_on
    (keys : List Key)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : StandardOn keys state) :
    StandardOn keys (physicalRun encode decode program branch state) := by
  induction program generalizing state with
  | done result => exact total
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      exact ih (decode raw answer) branch _
        (standard_on_physical_read_branch keys (encode raw) answer state total)

/-- Decompressing the fixed coordinates makes all of them populated on
every nonzero basis. This is derived from their standard totality, without
performing or charging any additional oracle reads. -/
theorem nonzero_conditioned_state_has_fixed_table
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : StandardOn (fixedOtherKeys ctx blockCap).toList state)
    (basis : Basis Key (VectorOutput Counter) (VectorOutput Counter)
      (SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork)))
    (nonzero : otherRoleTransform ctx blockCap state basis ≠ 0) :
    ∃ fixed : FixedTable ctx blockCap, fixedFiber ctx blockCap fixed basis.database := by
  have populated : ∀ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      ∃ answer, basis.database key.val = some answer := by
    intro key
    have member : key.val ∈ fixedOtherKeys ctx blockCap :=
      (mem_fixed_other_keys ctx blockCap key.val).mpr key.property
    have selectedTotal := (standard_at_iff_selected key.val state).mp
      (total key.val (by simpa using member))
    have transformedTotal : TotalAt key.val (otherRoleTransform ctx blockCap state) := by
      unfold otherRoleTransform
      rw [← Finset.insert_erase member, decompress_finset_insert _ _ _ (by
        intro erased
        exact (Finset.mem_erase.mp erased).1 rfl)]
      unfold decompressFinset
      rw [decompress_at_decompress_list_commutes]
      apply total_at_decompress_list_of_not_mem key.val _ _ _ selectedTotal
      simp
    cases present : basis.database key.val with
    | none => exact False.elim (nonzero (transformedTotal basis present))
    | some answer => exact ⟨answer, rfl⟩
  let fixed : FixedTable ctx blockCap := fun key => Classical.choose (populated key)
  exact ⟨fixed, fun key => Classical.choose_spec (populated key)⟩

/-- A terminal branch of the certified common execution has a complete
same-oracle fixed table on every nonzero conditioned basis. Recognition
comes from fixed-domain membership, and every repeated suffix read preserves
that support. No whole-table totality assumption is supplied by the caller. -/
theorem certified_physical_branch_has_fixed_table
    {contexts : Role → Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (role : Role) (blockCap : Role → Nat)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (basis : Basis Key (VectorOutput Counter) (VectorOutput Counter)
      (SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork)))
    (nonzero : otherRoleTransform (contexts role) blockCap
      (physicalRun encode decode program branch (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) basis ≠ 0) :
    ∃ fixed : FixedTable (contexts role) blockCap,
      fixedFiber (contexts role) blockCap fixed basis.database := by
  have prefixTotal := certified_initial_run_standard_on_roles (contexts role)
    (CertifiedFor.program certified role) registers (fixedOtherKeys (contexts role) blockCap).toList
    (fixed_key_recognized (contexts role) blockCap)
  rw [CertifiedFor.program_run_eq_skeleton certified role] at prefixTotal
  exact nonzero_conditioned_state_has_fixed_table (contexts role) blockCap _
    (physical_run_preserves_standard_on _ encode decode program branch _ prefixTotal) basis nonzero

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceReadback
