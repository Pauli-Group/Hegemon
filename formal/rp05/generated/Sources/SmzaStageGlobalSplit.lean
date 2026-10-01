import SmzaStageControlledSplit

/-! Exact orthogonal active-sector decomposition for actual CMS queries and
physical Record/Split. No success record, operator-equality axiom, or global
soundness coefficient is introduced. -/
namespace HegemonCrypto.SmallWood.SmzaStageGlobalSplit

open V8Smz9CoherentMerklePartition SmzaRecordSplitR3 SmzaRecordSupportR5
open SmzaOnlineAssemblyActiveR6
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open V8Smz9HiddenLeafQrom V8Smz9CoherentMerkleInstrument
open scoped BigOperators Classical
noncomputable section

section Sectors
variable {B S : Type*}

def sectorProject (sector : B → S) (selected : S) (state : B → ℂ) : B → ℂ :=
  fun basis => if sector basis = selected then state basis else 0

theorem sector_project_sub (sector : B → S) (selected : S) (left right : B → ℂ) :
    sectorProject sector selected (left - right) =
      sectorProject sector selected left - sectorProject sector selected right := by
  funext basis
  by_cases same : sector basis = selected <;> simp [sectorProject, same]

theorem mass_sector_sum [Fintype B] [Fintype S]
    (sector : B → S) (state : B → ℂ) :
    mass state = ∑ selected, mass (sectorProject sector selected state) := by
  unfold mass
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro basis _
  simp_rw [sectorProject, apply_ite Complex.normSq]
  simp [eq_comm]

theorem kernel_sector_project [Fintype B] (sector : B → S)
    (gate : B → B → ℂ)
    (preserves : ∀ source target, gate source target ≠ 0 → sector source = sector target)
    (selected : S) (state : B → ℂ) :
    applyKernel gate (sectorProject sector selected state) =
      sectorProject sector selected (applyKernel gate state) := by
  funext target
  unfold applyKernel sectorProject
  by_cases targetIn : sector target = selected
  · rw [if_pos targetIn]
    apply Finset.sum_congr rfl
    intro source _
    by_cases sourceIn : sector source = selected
    · simp [sourceIn]
    · have zero : gate source target = 0 := by
        by_contra nonzero
        exact sourceIn ((preserves source target nonzero).trans targetIn)
      simp [sourceIn, zero]
  · rw [if_neg targetIn]
    apply Finset.sum_eq_zero
    intro source _
    by_cases sourceIn : sector source = selected
    · have zero : gate source target = 0 := by
        by_contra nonzero
        exact targetIn ((preserves source target nonzero).symm.trans sourceIn)
      simp [sourceIn, zero]
    · simp [sourceIn]

theorem permutation_sector_project (sector : B → S) (permutation : B ≃ B)
    (preserves : ∀ basis, sector (permutation basis) = sector basis)
    (selected : S) (state : B → ℂ) :
    permute permutation (sectorProject sector selected state) =
      sectorProject sector selected (permute permutation state) := by
  funext basis
  have inverse : sector (permutation.symm basis) = sector basis := by
    simpa using (preserves (permutation.symm basis)).symm
  simp [permute, sectorProject, inverse]

def commutator [Fintype B] (gate : B → B → ℂ) (permutation : B ≃ B)
    (state : B → ℂ) : B → ℂ :=
  permute permutation (applyKernel gate state) - applyKernel gate (permute permutation state)

theorem commutator_sector_project [Fintype B]
    (sector : B → S) (gate : B → B → ℂ) (permutation : B ≃ B)
    (kernelPreserves : ∀ source target, gate source target ≠ 0 → sector source = sector target)
    (splitPreserves : ∀ basis, sector (permutation basis) = sector basis)
    (selected : S) (state : B → ℂ) :
    commutator gate permutation (sectorProject sector selected state) =
      sectorProject sector selected (commutator gate permutation state) := by
  unfold commutator
  rw [kernel_sector_project sector gate kernelPreserves,
    permutation_sector_project sector permutation splitPreserves,
    permutation_sector_project sector permutation splitPreserves,
    kernel_sector_project sector gate kernelPreserves, sector_project_sub]

theorem commutator_mass_sector_sum [Fintype B] [Fintype S]
    (sector : B → S) (gate : B → B → ℂ) (permutation : B ≃ B)
    (kernelPreserves : ∀ source target, gate source target ≠ 0 → sector source = sector target)
    (splitPreserves : ∀ basis, sector (permutation basis) = sector basis)
    (state : B → ℂ) :
    mass (commutator gate permutation state) =
      ∑ selected, mass (commutator gate permutation (sectorProject sector selected state)) := by
  rw [mass_sector_sum sector]
  apply Finset.sum_congr rfl
  intro selected _
  rw [commutator_sector_project sector gate permutation kernelPreserves splitPreserves]

end Sectors

section Physical
set_option linter.unusedSectionVars false
open SmzaStageControlledSplit SmzaChallengeStageTargets SmzaFixedAdvicePrefix
open V8Smz9CoherentVectorMerkle
variable {Key Counter Target Label Cell Private Advice : Type*}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
variable [Fintype Target] [Fintype Label] [Fintype Cell] [Fintype Private]

abbrev StageBasis (Key Counter Target Label Cell Private : Type*) :=
  SmzaStageControlledSplit.PhysicalBasis Key Counter Target Label Cell Private

local notation "SB" => StageBasis Key Counter Target Label Cell Private

def fullSplit (value : Database Key (VectorOutput Counter) → Target → Label) :
    SB ≃ SB :=
  SmzaStageControlledSplit.registerPermutation fun database => splitRegisters (value database)

def activeSector (empty : Cell) (basis : SB) : Finset Target :=
  activeTargets empty basis.workspace.2

theorem split_preserves_sector (empty : Cell)
    (value : Database Key (VectorOutput Counter) → Target → Label) (basis : SB) :
    activeSector empty (fullSplit value basis) = activeSector empty basis :=
  split_preserves_active_targets empty (value basis.database) basis.workspace.2

theorem query_preserves_sector (empty : Cell) (cap : Nat) (source target : SB)
    (nonzero : boundedKernel vectorPhaseSystem cap source target ≠ 0) :
    activeSector empty source = activeSector empty target := by
  have workspace : target.workspace = source.workspace := by
    by_contra different
    simp [boundedKernel, kernel, different] at nonzero
  exact congrArg (fun registers => activeTargets empty registers.2) workspace.symm

theorem full_eq_restricted_on_sector (empty : Cell) (selected : Finset Target)
    (value : Database Key (VectorOutput Counter) → Target → Label)
    (state : SB → ℂ)
    (supported : ∀ basis, state basis ≠ 0 → activeSector empty basis ⊆ selected) :
    permute (fullSplit value) state = permute (restrictedSplit selected value) state := by
  apply permute_eq_on_support
  intro basis nonzero
  have registers := full_split_eq_restricted_on_sector empty selected
    (value basis.database) basis.workspace.2 (supported basis nonzero)
  cases basis
  simp only [fullSplit, restrictedSplit, SmzaStageControlledSplit.registerPermutation,
    Equiv.coe_fn_mk] at *
  simp only [registers]

theorem projected_support (empty : Cell) (selected : Finset Target)
    (state : SB → ℂ) :
    ∀ basis, sectorProject (activeSector empty) selected state basis ≠ 0 →
      activeSector empty basis ⊆ selected := by
  intro basis nonzero
  have same : activeSector empty basis = selected := by
    by_contra different
    simp [sectorProject, different] at nonzero
  simpa only [same] using (Finset.Subset.refl selected)

/-- Exact direct sum for the full counter-vector CMS call and physical Record
slots. Sectors are orthogonal components, not measured or discarded states. -/
theorem stage_commutator_direct_sum (empty : Cell) (cap : Nat)
    (value : Database Key (VectorOutput Counter) → Target → Label)
    (state : SB → ℂ) :
    mass (commutator (boundedKernel vectorPhaseSystem cap) (fullSplit value) state) =
      ∑ selected : Finset Target,
        mass (commutator (boundedKernel vectorPhaseSystem cap)
          (restrictedSplit selected value)
          (sectorProject (activeSector empty) selected state)) := by
  rw [commutator_mass_sector_sum (activeSector empty) (boundedKernel vectorPhaseSystem cap)
    (fullSplit value) (query_preserves_sector empty cap)
    (split_preserves_sector empty value) state]
  apply Finset.sum_congr rfl
  intro selected _
  congr 1
  unfold commutator
  rw [full_eq_restricted_on_sector empty selected value _
    (projected_support empty selected state)]
  have kernelSupport : ∀ basis,
      applyKernel (boundedKernel vectorPhaseSystem cap)
        (sectorProject (activeSector empty) selected state) basis ≠ 0 →
      activeSector empty basis ⊆ selected := by
    rw [kernel_sector_project (activeSector empty) _ (query_preserves_sector empty cap)]
    exact projected_support empty selected _
  rw [full_eq_restricted_on_sector empty selected value _ kernelSupport]

theorem projected_zero_above_cap (empty : Cell) (cap : Nat) (selected : Finset Target)
    (state : SB → ℂ)
    (recordCap : ∀ basis, state basis ≠ 0 → (activeSector empty basis).card ≤ cap)
    (tooMany : ¬ selected.card ≤ cap) :
    sectorProject (activeSector empty) selected state = 0 := by
  funext basis
  by_cases same : activeSector empty basis = selected
  · have zero : state basis = 0 := by
      by_contra nonzero
      exact tooMany (by simpa only [same] using recordCap basis nonzero)
    simp [sectorProject, same, zero]
  · simp [sectorProject, same]

/-- The actual full-space, stage-selected controlled split bound. It does
not multiply by the number of active sectors or by the counter space. -/
theorem selected_stage_global_split_bound
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (targetBytes : Target → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (empty : Cell) (cap : Nat) (state : SB → ℂ)
    (recordCap : ∀ basis, state basis ≠ 0 → (activeSector empty basis).card ≤ cap) :
    normSquared
      (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
          (boundedQuery vectorPhaseSystem cap state) -
        boundedQuery vectorPhaseSystem cap
          (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) state)) ≤
      (576 * cap / (2^512 : ℝ)) * normSquared state := by
  simp only [← bounded_kernel_apply]
  change mass (commutator (boundedKernel vectorPhaseSystem cap)
    (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) state) ≤
      (576 * cap / (2^512 : ℝ)) * mass state
  rw [stage_commutator_direct_sum]
  calc
    _ ≤ ∑ selected : Finset Target, (576 * cap / (2^512 : ℝ)) *
        mass (sectorProject (activeSector empty) selected state) := by
      apply Finset.sum_le_sum
      intro selected _
      by_cases within : selected.card ≤ cap
      · have localBound := selected_stage_restricted_split_bound next children role fuel
          keyBytes targetBytes counter code advice selected cap within
          (sectorProject (activeSector empty) selected state)
        change normSquared (_ - _) ≤ _
        simpa only [commutator, bounded_kernel_apply, mass,
          HegemonCrypto.CmsCompressedOracle.normSquared] using localBound
      · rw [projected_zero_above_cap empty cap selected state recordCap within]
        simp [commutator, applyKernel, permute, mass]
    _ = _ := by
      rw [← Finset.mul_sum, ← mass_sector_sum (activeSector empty)]

end Physical
end
end HegemonCrypto.SmallWood.SmzaStageGlobalSplit
