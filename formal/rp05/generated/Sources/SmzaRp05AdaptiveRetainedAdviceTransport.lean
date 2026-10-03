import SmzaRp05AdaptiveRetainedAdviceMass

/-! # Literal mixed fixed-table and active read transport

Conditioning turns an observed fixed-role answer into a diagonal check of
the same table entry. It leaves an active-key answer as a physical CMS read.
This file derives that distinction from the original physical read operator.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceTransport

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05ConditionedExecution SmzaRp05CurrentAdaptiveExecution
open SmzaRp05PhysicalTerminalRead SmzaRp05PhysicalReadSupport
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05AdaptivePhysicalReadBound
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05DependentAdviceEvent SmzaRp05ConditionedEventJoin
open V8Smz9CoherentVectorMerkle SmzaRp04RawMcaSampling
open SmzaRp05ExecutableMerkleVerifier (Program)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem other_role_read_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (answer : VectorOutput Counter)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    otherRoleTransform ctx blockCap (physicalReadBranch key.val answer state) =
      physicalReadBranch key.val answer (otherRoleTransform ctx blockCap state) := by
  have outside : ∀ changed ∈ (fixedOtherKeys ctx blockCap).toList, key.val ≠ changed := by
    intro changed member same
    have fixed := (mem_fixed_other_keys ctx blockCap changed).mp (by simpa using member)
    exact fixed (same ▸ key.property)
  simp only [physical_read_branch_eq_selected, otherRoleTransform, decompressFinset]
  rw [← decompress_at_decompress_list_commutes]
  rw [← coordinate_projection_decompress_list_of_outside _ _ _ _ outside]
  rw [← decompress_at_decompress_list_commutes]

theorem other_role_read_fixed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (key : FixedOtherKey ctx.role blockCap ctx.keyBytes)
    (answer : VectorOutput Counter)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    otherRoleTransform ctx blockCap (physicalReadBranch key.val answer state) =
      coordinateEventProjection key.val answer (otherRoleTransform ctx blockCap state) := by
  have member : key.val ∈ fixedOtherKeys ctx blockCap :=
    (mem_fixed_other_keys ctx blockCap key.val).mpr key.property
  have outside : ∀ changed ∈ ((fixedOtherKeys ctx blockCap).erase key.val).toList,
      key.val ≠ changed := by
    intro changed recorded same
    have erased : changed ∈ (fixedOtherKeys ctx blockCap).erase key.val := by
      simpa using recorded
    exact (Finset.mem_erase.mp erased).1 same.symm
  have factor (input : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
      otherRoleTransform ctx blockCap input =
        decompressAt key.val (decompressFinset ((fixedOtherKeys ctx blockCap).erase key.val) input) := by
    unfold otherRoleTransform
    conv_lhs => rw [← Finset.insert_erase member]
    have keyNotErased : key.val ∉ (fixedOtherKeys ctx blockCap).erase key.val := by
      intro erased
      exact (Finset.mem_erase.mp erased).1 rfl
    exact decompress_finset_insert _ _ _ keyNotErased
  rw [physical_read_branch_eq_selected, factor, factor]
  unfold decompressFinset
  rw [← decompress_at_decompress_list_commutes, decompress_at_involutive]
  rw [← coordinate_projection_decompress_list_of_outside _ _ _ _ outside]
  rw [← decompress_at_decompress_list_commutes]

theorem fixed_fiber_coordinate_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (answer : VectorOutput Counter)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed (coordinateEventProjection key.val answer state) =
      coordinateEventProjection key answer (fixedFiberToActive ctx blockCap dummy fixed state) := by
  funext basis
  rcases basis with ⟨input, phase, memory, database⟩
  simp only [fixedFiberToActive, activeRegisterEmbed, databaseSlice,
    coordinateEventProjection, basisRegisters, merge_fixed_active_at_active]
  by_cases routed : OnActiveRoute vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (input, phase, memory)
  · by_cases read : database key = some answer <;> simp [routed, read]
  · by_cases read : database key = some answer <;> simp [routed, read]

theorem fixed_fiber_coordinate_fixed
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (key : FixedOtherKey ctx.role blockCap ctx.keyBytes)
    (answer : VectorOutput Counter)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed (coordinateEventProjection key.val answer state) =
      if fixed key = answer then fixedFiberToActive ctx blockCap dummy fixed state else 0 := by
  funext basis
  rcases basis with ⟨input, phase, memory, database⟩
  by_cases routed : OnActiveRoute vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (input, phase, memory)
  · simp only [fixedFiberToActive, activeRegisterEmbed, databaseSlice,
      basisRegisters, coordinateEventProjection, routed, if_true,
      merge_fixed_active_at_fixed]
    by_cases read : fixed key = answer
    · simp only [read, if_pos]
      rw [fixedFiberToActive]
      simp [activeRegisterEmbed, databaseSlice, basisRegisters, routed]
    · simp [read]
  · by_cases read : fixed key = answer
    · simp [fixedFiberToActive, activeRegisterEmbed, basisRegisters, routed, read]
    · simp only [fixedFiberToActive, activeRegisterEmbed, basisRegisters,
        if_neg routed, if_neg read]
      rfl

/-- The actual original physical read, conditioned and restricted to its
same fixed fiber, has the stated mixed operator. -/
theorem physical_read_to_same_fiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (key : Key) (answer : VectorOutput Counter)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed
      (otherRoleTransform ctx blockCap (physicalReadBranch key answer state)) =
      if live : RoleActive ctx.role blockCap ctx.keyBytes key then
        physicalReadBranch ⟨key, live⟩ answer
          (fixedFiberToActive ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state))
      else if fixed ⟨key, live⟩ = answer then
        fixedFiberToActive ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state)
      else 0 := by
  by_cases live : RoleActive ctx.role blockCap ctx.keyBytes key
  · rw [dif_pos live, other_role_read_active ctx blockCap ⟨key, live⟩]
    rw [physical_read_branch_eq_selected]
    rw [fixed_fiber_to_active_decompress_active]
    rw [fixed_fiber_coordinate_active]
    rw [fixed_fiber_to_active_decompress_active]
    rw [← physical_read_branch_eq_selected]
  · rw [dif_neg live, other_role_read_fixed ctx blockCap ⟨key, live⟩]
    change fixedFiberToActive ctx blockCap dummy fixed
        (coordinateEventProjection (⟨key, live⟩ : FixedOtherKey ctx.role blockCap ctx.keyBytes).val
          answer (otherRoleTransform ctx blockCap state)) = _
    exact fixed_fiber_coordinate_fixed ctx blockCap dummy fixed ⟨key, live⟩
      answer (otherRoleTransform ctx blockCap state)

/-- The original answer-branch index is retained, including zero branches
whose reported answer disagrees with the same fixed oracle table. -/
def mixedRun
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest) :
    (program : Program Result) → Branches decode program → ActiveState ctx blockCap →
      ActiveState ctx blockCap
  | .done _, _, state => state
  | .read raw next, ⟨answer, branch⟩, state =>
      mixedRun ctx blockCap fixed encode decode (next (decode raw answer)) branch
        (if live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw) then
          physicalReadBranch ⟨encode raw, live⟩ answer state
        else if fixed ⟨encode raw, live⟩ = answer then state else 0)

/-- Whole answer-adaptive transport follows by structural recursion on the
literal verifier program. The physical branch and its weight are unchanged. -/
theorem physical_run_to_mixed_same_fiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed
      (otherRoleTransform ctx blockCap (physicalRun encode decode program branch state)) =
      mixedRun ctx blockCap fixed encode decode program branch
        (fixedFiberToActive ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state)) := by
  induction program generalizing state with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      simp only [physicalRun, mixedRun]
      rw [ih]
      change mixedRun ctx blockCap fixed encode decode (next (decode raw answer)) branch
        (fixedFiberToActive ctx blockCap dummy fixed
          (otherRoleTransform ctx blockCap (physicalReadBranch (encode raw) answer state))) = _
      rw [physical_read_to_same_fiber]

def activeReadEncode
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (encode : RawInput → Key) (raw : RawInput) : ActiveKey ctx.role blockCap ctx.keyBytes :=
  if live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw) then ⟨encode raw, live⟩
  else dummy

/-- Fixed-domain reads are executed using this fiber's actual table. Only
active reads remain in the executable physical-read tree. -/
def compileFixedReads
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest) :
    Program Result → Program Result
  | .done result => .done result
  | .read raw next =>
      if live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw) then
        .read raw (fun digest => compileFixedReads ctx blockCap fixed encode decode (next digest))
      else compileFixedReads ctx blockCap fixed encode decode
        (next (decode raw (fixed ⟨encode raw, live⟩)))

def mixedMass
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (selectedEvent : ActiveMemory ctx → ActiveDatabase ctx blockCap → Prop) :
    Program Result → ActiveState ctx blockCap → ℝ
  | .done _, state => normSquared (workspaceEventProjection selectedEvent state)
  | .read raw next, state =>
      if live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw) then
        ∑ answer : VectorOutput Counter,
          mixedMass ctx blockCap fixed encode decode selectedEvent (next (decode raw answer))
            (physicalReadBranch ⟨encode raw, live⟩ answer state)
      else mixedMass ctx blockCap fixed encode decode selectedEvent
        (next (decode raw (fixed ⟨encode raw, live⟩))) state

theorem mixed_mass_eq_compiled_adaptive_mass
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (selectedEvent : ActiveMemory ctx → ActiveDatabase ctx blockCap → Prop)
    (program : Program Result) (state : ActiveState ctx blockCap) :
    mixedMass ctx blockCap fixed encode decode selectedEvent program state =
      adaptiveReadMass (activeReadEncode ctx blockCap dummy encode) decode selectedEvent
        (compileFixedReads ctx blockCap fixed encode decode program) state := by
  induction program generalizing state with
  | done result => rfl
  | read raw next ih =>
      by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
      · simp only [mixedMass, compileFixedReads, dif_pos live, adaptiveReadMass,
          activeReadEncode]
        exact Finset.sum_congr rfl fun answer _ => ih (decode raw answer) _
      · simp only [mixedMass, compileFixedReads, dif_neg live]
        exact ih _ state

theorem physical_read_zero
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (answer : VectorOutput Counter) :
    physicalReadBranch key answer (0 : ActiveState ctx blockCap) = 0 := by
  have decompressZero : decompressAt key (0 : ActiveState ctx blockCap) = 0 := by
    funext basis
    simp [decompress_at_eq_sum_kernel]
  rw [physical_read_branch_eq_selected, decompressZero]
  have projected : coordinateEventProjection key answer (0 : ActiveState ctx blockCap) = 0 := by
    funext basis
    simp [coordinateEventProjection]
  rw [projected, decompressZero]

theorem mixed_run_zero
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program) :
    mixedRun ctx blockCap fixed encode decode program branch 0 = 0 := by
  induction program with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      simp only [mixedRun]
      split
      · rw [physical_read_zero, ih]
      · split <;> exact ih _ branch

/-- Summing the original physical branch indices removes only impossible
fixed-table answers, each of which has exactly zero amplitude. -/
theorem mixed_mass_eq_original_branch_sum
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (selectedEvent : ActiveMemory ctx → ActiveDatabase ctx blockCap → Prop)
    (program : Program Result) (state : ActiveState ctx blockCap) :
    mixedMass ctx blockCap fixed encode decode selectedEvent program state =
      letI := physicalBranchesFintype decode program
      ∑ branch : Branches decode program,
        normSquared (workspaceEventProjection selectedEvent
          (mixedRun ctx blockCap fixed encode decode program branch state)) := by
  induction program generalizing state with
  | done result =>
      simp [mixedMass, mixedRun, Branches]
  | read raw next ih =>
      letI (answer : VectorOutput Counter) := physicalBranchesFintype decode (next (decode raw answer))
      letI := physicalBranchesFintype decode (Program.read raw next)
      change _ = ∑ branch : (answer : VectorOutput Counter) × Branches decode (next (decode raw answer)), _
      rw [Fintype.sum_sigma]
      by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
      · simp only [mixedMass, mixedRun, dif_pos live]
        exact Finset.sum_congr rfl fun answer _ => ih (decode raw answer) _
      · simp only [mixedMass, mixedRun, dif_neg live]
        rw [Fintype.sum_eq_single (fixed ⟨encode raw, live⟩)]
        · have selectedEq : fixed ⟨encode raw, live⟩ = fixed ⟨encode raw, live⟩ := rfl
          have selectedState :
              (if fixed ⟨encode raw, live⟩ = fixed ⟨encode raw, live⟩
                then state else (0 : ActiveState ctx blockCap)) = state := by
            rw [if_pos selectedEq]
          rw [selectedState]
          exact ih (decode raw (fixed ⟨encode raw, live⟩)) state
        · intro answer different
          have mismatch : fixed ⟨encode raw, live⟩ ≠ answer := Ne.symm different
          simp only [if_neg mismatch, mixed_run_zero]
          simp [workspaceEventProjection, normSquared]

/-- The compiled active-read tree has exactly the Born mass of the same
original physical branches after conditioning and fixed-fiber restriction. -/
theorem original_physical_fiber_sum_eq_compiled_adaptive_mass
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (selectedEvent : ActiveMemory ctx → ActiveDatabase ctx blockCap → Prop)
    (program : Program Result)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    (letI := physicalBranchesFintype decode program
      ∑ branch : Branches decode program,
        normSquared (workspaceEventProjection selectedEvent
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap
              (physicalRun encode decode program branch state))))) =
      adaptiveReadMass (activeReadEncode ctx blockCap dummy encode) decode selectedEvent
        (compileFixedReads ctx blockCap fixed encode decode program)
        (fixedFiberToActive ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state)) := by
  simp_rw [physical_run_to_mixed_same_fiber]
  rw [← mixed_mass_eq_original_branch_sum, mixed_mass_eq_compiled_adaptive_mass]

theorem reads_at_most_mono
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (left right : Nat) (within : left ≤ right)
    (bound : ReadsAtMost decode left program) : ReadsAtMost decode right program := by
  induction program generalizing left right with
  | done result =>
      simp [ReadsAtMost]
  | read raw next ih =>
      cases left with
      | zero => exact False.elim bound
      | succ left =>
          cases right with
          | zero => omega
          | succ right =>
              intro answer
              exact ih (decode raw answer) left right (by omega) (bound answer)

/-- Removing fixed reads cannot increase the maximum active read count. -/
theorem compile_fixed_reads_depth
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (depth : Nat) (bound : ReadsAtMost decode depth program) :
    ReadsAtMost decode depth (compileFixedReads ctx blockCap fixed encode decode program) := by
  induction program generalizing depth with
  | done result => simp [compileFixedReads, ReadsAtMost]
  | read raw next ih =>
      cases depth with
      | zero => exact False.elim bound
      | succ depth =>
          by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
          · simp only [compileFixedReads, dif_pos live]
            intro answer
            exact ih (decode raw answer) depth (bound answer)
          · simp only [compileFixedReads, dif_neg live]
            exact reads_at_most_mono decode _ depth (depth + 1) (by omega)
              (ih (decode raw (fixed ⟨encode raw, live⟩)) depth (bound _))

def activeReadKeys
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : List Key) : List (ActiveKey ctx.role blockCap ctx.keyBytes) :=
  keys.filterMap fun key =>
    if live : RoleActive ctx.role blockCap ctx.keyBytes key then some ⟨key, live⟩ else none

/-- The active suffix visits only the active part of the original key
schedule. The dummy encoder value is never reached by its executable tree. -/
theorem compile_fixed_reads_keys
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (keys : List Key)
    (within : ReadsWithinKeys encode decode keys program) :
    ReadsWithinKeys (activeReadEncode ctx blockCap dummy encode) decode
      (activeReadKeys ctx blockCap keys) (compileFixedReads ctx blockCap fixed encode decode program) := by
  induction program with
  | done result => trivial
  | read raw next ih =>
      by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
      · simp only [compileFixedReads, dif_pos live, ReadsWithinKeys]
        constructor
        · unfold activeReadEncode activeReadKeys
          rw [dif_pos live]
          exact List.mem_filterMap.mpr ⟨encode raw, within.1, by simp [live]⟩
        · intro answer
          exact ih (decode raw answer) (within.2 answer)
      · simp only [compileFixedReads, dif_neg live]
        exact ih _ (within.2 _)

section WorkspaceReindex
variable {Left Right : Type}
variable [Fintype Left] [DecidableEq Left] [Fintype Right] [DecidableEq Right]

theorem reindex_decompress_at
    (equivalence : Left ≃ Right) (key : Key)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Left) :
    reindexWorkspaceState equivalence (decompressAt key state) =
      decompressAt key (reindexWorkspaceState equivalence state) := by
  funext basis
  simp only [reindexWorkspaceState, decompress_at_eq_sum_kernel, basisWorkspaceEquiv]
  rfl

theorem reindex_physical_read
    (equivalence : Left ≃ Right) (key : Key) (answer : VectorOutput Counter)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Left) :
    reindexWorkspaceState equivalence (physicalReadBranch key answer state) =
      physicalReadBranch key answer (reindexWorkspaceState equivalence state) := by
  simp only [physical_read_branch_eq_selected]
  rw [reindex_decompress_at]
  have projected : reindexWorkspaceState equivalence
      (coordinateEventProjection key answer (decompressAt key state)) =
      coordinateEventProjection key answer
        (reindexWorkspaceState equivalence (decompressAt key state)) := by
    rfl
  rw [projected, reindex_decompress_at]

theorem adaptive_read_mass_reindex
    (equivalence : Left ≃ Right)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (selectedEvent : Right → Database Key (VectorOutput Counter) → Prop)
    (program : Program Result)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Left) :
    adaptiveReadMass encode decode (fun workspace database => selectedEvent (equivalence workspace) database)
        program state =
      adaptiveReadMass encode decode selectedEvent program (reindexWorkspaceState equivalence state) := by
  induction program generalizing state with
  | done result =>
      simp only [adaptiveReadMass]
      rw [← reindex_workspace_state_norm_squared equivalence]
      congr 1
      funext basis
      simp [workspaceEventProjection, reindexWorkspaceState, basisWorkspaceEquiv]
  | read raw next ih =>
      simp only [adaptiveReadMass]
      apply Finset.sum_congr rfl
      intro answer _
      rw [ih, reindex_physical_read]

end WorkspaceReindex

/-- The literal conditioned physical branch sum is expressed in the exact
native event and workspace consumed by the homogeneous fixed-fiber bound. -/
theorem original_physical_fiber_sum_eq_native_adaptive_mass
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    (letI := physicalBranchesFintype decode program
      ∑ branch : Branches decode program,
        normSquared (workspaceEventProjection
          (activeFiberEvent ctx blockCap fixed (event (contextAtFixed ctx blockCap fixed)))
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap
              (physicalRun encode decode program branch state))))) =
      adaptiveReadMass (activeReadEncode ctx blockCap dummy encode) decode
        (event (activeContext ctx blockCap fixed))
        (compileFixedReads ctx blockCap fixed encode decode program)
        (routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state)) := by
  rw [original_physical_fiber_sum_eq_compiled_adaptive_mass]
  have events : activeFiberEvent ctx blockCap fixed (event (contextAtFixed ctx blockCap fixed)) =
      fun memory database => event (activeContext ctx blockCap fixed)
        (activeMemoryEquiv ctx memory) database := by
    funext memory database
    exact congrFun (SmzaRp05ActiveFiberEvent.active_fiber_current_role_event_eq_native
      (contextAtFixed ctx blockCap fixed) blockCap fixed memory) database
  rw [events, adaptive_read_mass_reindex]
  rfl

/-- The dependent advice event is disintegrated on each original physical
answer branch, then the finite sums are exchanged. Each advice value keeps
the exact branch amplitudes from the common physical execution. -/
theorem physical_dependent_branch_sum_eq_compiled_fiber_sum
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    (letI := physicalBranchesFintype decode program
      ∑ branch : Branches decode program,
        normSquared (workspaceEventProjection (dependentCurrentRoleEvent ctx blockCap)
          (otherRoleTransform ctx blockCap (physicalRun encode decode program branch state)))) =
      ∑ fixed : FixedTable ctx blockCap,
        adaptiveReadMass (activeReadEncode ctx blockCap dummy encode) decode
          (event (activeContext ctx blockCap fixed))
          (compileFixedReads ctx blockCap fixed encode decode program)
          (routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state)) := by
  letI := physicalBranchesFintype decode program
  change (∑ branch : Branches decode program,
    normSquared (workspaceEventProjection (dependentFixedEvent ctx blockCap
      (fun fixed => event (contextAtFixed ctx blockCap fixed)))
      (otherRoleTransform ctx blockCap (physicalRun encode decode program branch state)))) = _
  simp_rw [dependent_event_mass_eq_sum_active_event_masses ctx blockCap dummy]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro fixed _
  exact original_physical_fiber_sum_eq_native_adaptive_mass ctx blockCap dummy fixed
    encode decode program state

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceTransport
