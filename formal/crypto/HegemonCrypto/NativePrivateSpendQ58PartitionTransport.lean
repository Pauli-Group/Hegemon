import SmzaRp05AdaptiveRetainedAdviceReadback

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58PartitionTransport

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open V8Smz9CoherentVectorMerkle SmzaRp04RawMcaSampling
open SmzaRp05PhysicalTerminalRead SmzaRp05PhysicalReadSupport
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)

noncomputable section
set_option autoImplicit false
variable {Key Counter Work Result : Type}

abbrev FixedKey (live : Key → Prop) := { key : Key // ¬live key }
abbrev FixedTable (live : Key → Prop) := FixedKey live → VectorOutput Counter
abbrev CmsState := State Key (VectorOutput Counter) (VectorOutput Counter) Work

def fixedKeys [Fintype Key] (live : Key → Prop) : Finset Key :=
  Finset.univ.filter fun key => ¬live key

@[simp] theorem mem_fixed_keys [Fintype Key] (live : Key → Prop) (key : Key) :
    key ∈ fixedKeys live ↔ ¬live key := by simp [fixedKeys]

def onFiber (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (database : Database Key (VectorOutput Counter)) : Prop :=
  ∀ key : FixedKey live, database key.val = some (fixed key)

def projectFiber (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    CmsState (Key := Key) (Counter := Counter) (Work := Work) :=
  fun basis => if onFiber live fixed basis.database then state basis else 0

def otherTransform [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter] [Fintype Work] [DecidableEq Work]
    (live : Key → Prop)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :=
  decompressFinset (fixedKeys live) state

def conditioned [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter] [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :=
  projectFiber live fixed (otherTransform live state)

private theorem fiber_set_active [DecidableEq Key]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (database : Database Key (VectorOutput Counter))
    (key : Key) (active : live key) (coordinate : Option (VectorOutput Counter)) :
    onFiber live fixed (setDatabaseCoordinate database key coordinate) ↔
      onFiber live fixed database := by
  have different (other : FixedKey live) : other.val ≠ key := by
    intro same
    exact other.property (same ▸ active)
  constructor
  · intro source other
    simpa only [setDatabaseCoordinate, if_neg (different other)] using source other
  · intro source other
    simpa only [setDatabaseCoordinate, if_neg (different other)] using source other

private theorem project_decompress_active
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (key : Key) (active : live key)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    projectFiber live fixed (decompressAt key state) =
      decompressAt key (projectFiber live fixed state) := by
  funext target
  by_cases inside : onFiber live fixed target.database
  · change (if onFiber live fixed target.database then
        decompressAt key state target else 0) = _
    rw [if_pos inside, decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro coordinate _
    have updated := (fiber_set_active live fixed target.database key active coordinate).mpr inside
    simp only [projectFiber, updated, if_true]
  · change (if onFiber live fixed target.database then
        decompressAt key state target else 0) = _
    rw [if_neg inside, decompress_at_eq_sum_kernel]
    symm
    apply Finset.sum_eq_zero
    intro coordinate _
    have outside : ¬onFiber live fixed
        (setDatabaseCoordinate target.database key coordinate) := by
      intro updated
      exact inside ((fiber_set_active live fixed target.database key active coordinate).mp updated)
    simp only [projectFiber, outside, if_false, zero_mul]

private theorem project_coordinate
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (key : Key) (answer : VectorOutput Counter)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    projectFiber live fixed (coordinateEventProjection key answer state) =
      coordinateEventProjection key answer (projectFiber live fixed state) := by
  funext basis
  by_cases inside : onFiber live fixed basis.database <;>
    by_cases read : basis.database key = some answer <;>
    simp [projectFiber, coordinateEventProjection, inside, read]

private theorem project_coordinate_fixed
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (key : Key) (inactive : ¬live key) (answer : VectorOutput Counter)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    projectFiber live fixed (coordinateEventProjection key answer state) =
      if fixed ⟨key, inactive⟩ = answer then projectFiber live fixed state else 0 := by
  funext basis
  by_cases inside : onFiber live fixed basis.database
  · have known := inside ⟨key, inactive⟩
    by_cases same : fixed ⟨key, inactive⟩ = answer
    · simp [projectFiber, coordinateEventProjection, inside, known, same]
    · have different : basis.database key ≠ some answer := by
        rw [known]
        exact fun equal => same (Option.some.inj equal)
      simp [projectFiber, coordinateEventProjection, inside, same, different]
  · by_cases same : fixed ⟨key, inactive⟩ = answer <;>
      simp [projectFiber, inside, same]

private theorem other_read_active
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (key : Key) (active : live key)
    (answer : VectorOutput Counter)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    otherTransform live (physicalReadBranch key answer state) =
      physicalReadBranch key answer (otherTransform live state) := by
  have outside : ∀ changed ∈ (fixedKeys live).toList, key ≠ changed := by
    intro changed member same
    have inactive : ¬live changed := (mem_fixed_keys live changed).mp (by simpa using member)
    exact inactive (same ▸ active)
  simp only [physical_read_branch_eq_selected, otherTransform, decompressFinset]
  rw [← decompress_at_decompress_list_commutes]
  rw [← coordinate_projection_decompress_list_of_outside _ _ _ _ outside]
  rw [← decompress_at_decompress_list_commutes]

private theorem other_read_fixed
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (key : Key) (inactive : ¬live key)
    (answer : VectorOutput Counter)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    otherTransform live (physicalReadBranch key answer state) =
      coordinateEventProjection key answer (otherTransform live state) := by
  have member : key ∈ fixedKeys live := (mem_fixed_keys live key).mpr inactive
  have outside : ∀ changed ∈ ((fixedKeys live).erase key).toList, key ≠ changed := by
    intro changed recorded same
    have erased : changed ∈ (fixedKeys live).erase key := by simpa using recorded
    exact (Finset.mem_erase.mp erased).1 same.symm
  have factor (input : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
      otherTransform live input =
        decompressAt key (decompressFinset ((fixedKeys live).erase key) input) := by
    unfold otherTransform
    conv_lhs => rw [← Finset.insert_erase member]
    exact decompress_finset_insert _ _ _ (by simp)
  rw [physical_read_branch_eq_selected, factor, factor]
  unfold decompressFinset
  rw [← decompress_at_decompress_list_commutes, decompress_at_involutive]
  rw [← coordinate_projection_decompress_list_of_outside _ _ _ _ outside]
  rw [← decompress_at_decompress_list_commutes]

theorem physical_read_to_same_fiber
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (key : Key) (answer : VectorOutput Counter)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    conditioned live fixed (physicalReadBranch key answer state) =
      if active : live key then physicalReadBranch key answer (conditioned live fixed state)
      else if fixed ⟨key, active⟩ = answer then conditioned live fixed state else 0 := by
  by_cases active : live key
  · rw [dif_pos active]
    unfold conditioned
    rw [other_read_active live key active]
    rw [physical_read_branch_eq_selected, physical_read_branch_eq_selected]
    rw [project_decompress_active live fixed key active]
    have commute := project_coordinate live fixed key answer
      (decompressAt key (otherTransform live state))
    have deciders : (inferInstance : DecidableEq (VectorOutput Counter)) =
        (fun left right => Classical.propDecidable (left = right)) :=
      Subsingleton.elim _ _
    rw [← deciders] at commute
    rw [commute, project_decompress_active live fixed key active]
  · rw [dif_neg active]
    unfold conditioned
    rw [other_read_fixed live key active]
    have checked := project_coordinate_fixed live fixed key active answer
      (otherTransform live state)
    have deciders : (inferInstance : DecidableEq (VectorOutput Counter)) =
        (fun left right => Classical.propDecidable (left = right)) :=
      Subsingleton.elim _ _
    rw [← deciders] at checked
    by_cases same : fixed ⟨key, active⟩ = answer
    · simpa only [if_pos same] using checked
    · simpa only [if_neg same] using checked

def mixedRun [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter] [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter → V8SmzaOracleParser.RawDigest) :
    (program : Program Result) → Branches decode program →
      CmsState (Key := Key) (Counter := Counter) (Work := Work) →
      CmsState (Key := Key) (Counter := Counter) (Work := Work)
  | .done _, _, state => state
  | .read raw next, ⟨answer, branch⟩, state =>
      mixedRun live fixed encode decode (next (decode raw answer)) branch
        (if active : live (encode raw) then physicalReadBranch (encode raw) answer state
        else if fixed ⟨encode raw, active⟩ = answer then state else 0)

theorem physical_run_to_mixed_same_fiber
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter → V8SmzaOracleParser.RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    conditioned live fixed (physicalRun encode decode program branch state) =
      mixedRun live fixed encode decode program branch (conditioned live fixed state) := by
  induction program generalizing state with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      simp only [physicalRun, mixedRun]
      rw [ih]
      change mixedRun live fixed encode decode (next (decode raw answer)) branch
        (conditioned live fixed (physicalReadBranch (encode raw) answer state)) = _
      rw [physical_read_to_same_fiber]

private theorem decompress_zero
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work] (key : Key) :
    decompressAt key (0 : CmsState (Key := Key) (Counter := Counter) (Work := Work)) = 0 := by
  funext basis
  rw [decompress_at_eq_sum_kernel]
  simp

private theorem physical_read_zero
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work] (key : Key) (answer : VectorOutput Counter) :
    physicalReadBranch key answer
        (0 : CmsState (Key := Key) (Counter := Counter) (Work := Work)) = 0 := by
  rw [physical_read_branch_eq_selected, decompress_zero]
  have projected : coordinateEventProjection key answer
      (0 : CmsState (Key := Key) (Counter := Counter) (Work := Work)) = 0 := by
    funext basis
    simp [coordinateEventProjection]
  rw [projected, decompress_zero]

private theorem mixed_run_zero
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter → V8SmzaOracleParser.RawDigest)
    (program : Program Result) (branch : Branches decode program) :
    mixedRun live fixed encode decode program branch
      (0 : CmsState (Key := Key) (Counter := Counter) (Work := Work)) = 0 := by
  induction program with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      simp only [mixedRun]
      split
      · rw [physical_read_zero, ih]
      · split <;> exact ih (decode raw answer) branch

private theorem nonzero_mixed_branch_fixed_answers
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter → V8SmzaOracleParser.RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work))
    (basis : Basis Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (nonzero : mixedRun live fixed encode decode program branch state basis ≠ 0)
    (call : V8SmzaOracleParser.RawInput × VectorOutput Counter)
    (recorded : call ∈ answerLog decode program branch)
    (inactive : ¬live (encode call.1)) :
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

theorem nonzero_physical_fiber_fixed_answers
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter → V8SmzaOracleParser.RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work))
    (basis : Basis Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (nonzero : conditioned live fixed (physicalRun encode decode program branch state) basis ≠ 0)
    (call : V8SmzaOracleParser.RawInput × VectorOutput Counter)
    (recorded : call ∈ answerLog decode program branch)
    (inactive : ¬live (encode call.1)) :
    fixed ⟨encode call.1, inactive⟩ = call.2 := by
  rw [physical_run_to_mixed_same_fiber] at nonzero
  exact nonzero_mixed_branch_fixed_answers live fixed encode decode program branch
    _ basis nonzero call recorded inactive

theorem historical_physical_run_to_mixed_same_fiber
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (selected : SmzaChallengeStageTargets.Role)
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (fixed : FixedTable (Counter := Counter)
      (SmzaRoleDomainConditioning.RoleActive selected blockCap keyBytes))
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter → V8SmzaOracleParser.RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : CmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    conditioned (SmzaRoleDomainConditioning.RoleActive selected blockCap keyBytes)
        fixed (physicalRun encode decode program branch state) =
      mixedRun (SmzaRoleDomainConditioning.RoleActive selected blockCap keyBytes)
        fixed encode decode program branch
        (conditioned (SmzaRoleDomainConditioning.RoleActive selected blockCap keyBytes) fixed state) :=
  physical_run_to_mixed_same_fiber _ fixed encode decode program branch state

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58PartitionTransport
