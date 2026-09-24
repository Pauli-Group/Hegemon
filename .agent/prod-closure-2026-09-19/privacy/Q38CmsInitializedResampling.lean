import Q38CmsResamplingCoordinates
import Q38ControlledFreshSwapCore
import HegemonCrypto.CmsQuerySequence

/-! The initialized CMS state with a freshly appended uniform label table.
This file connects the exact coordinate/operator identity to the database-size
invariant furnished by an initialized compressed-oracle execution.  The final
section keeps the non-leaf database as an untouched complement and embeds every
selected leaf input with `Sum.inl`.
-/
namespace HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.Q38CmsResamplingCoordinates
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 20000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

variable {Input Output Phase Work Index Branch : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]
variable [Fintype Index] [DecidableEq Index]
variable [Fintype Branch] [DecidableEq Branch]

local notation "CB" => CmsBasis Input Output Phase Work Index Branch
local notation "FB" => FreshBasis Input Output Phase Work Index Branch
local notation "FC" => Core Input Branch (Input × Phase × Work) Output

/- The finite-average aggregation belongs to the concrete leaf-domain module.
It is excluded from this CMS-only prefix while localizing the RSS boundary.
/-- Pointwise bounds may be summed and multiplied by the fixed disturbance
constant without elaborating the (potentially very large) concrete index
type. -/
theorem four_mul_finite_sum_mono
    {A : Type} [Fintype A] (left right : A → ℝ)
    (bound : ∀ index, left index ≤ right index) :
    4 * ∑ index, left index ≤ 4 * ∑ index, right index := by
  classical
  exact mul_le_mul_of_nonneg_left
    (Finset.sum_le_sum fun index _ => bound index) (by norm_num)

/-- Pull the scalar factors in the full-domain bound outside a finite sum.
This algebra is kept polymorphic so Lean never normalizes the concrete
1,307-byte leaf-input `Fintype` while checking it. -/
theorem four_mul_sum_product_factor
    {A : Type} [Fintype A] (query scale : ℝ) (mass : A → ℝ) :
    4 * ∑ index, query * scale * mass index =
      4 * query * scale * ∑ index, mass index := by
  classical
  rw [← Finset.mul_sum]
  ring

/-- Combine averaging, a finite branch sum, its pointwise bounds, and the
fixed disturbance factor in a universe-0 lemma.  The concrete full CMS basis
is instantiated only after this proof has elaborated. -/
theorem average_four_mul_sum_product_bound
    {Secret A : Type}
    [Fintype Secret] [Nonempty Secret] [Fintype A]
    (query scale : ℝ) (mass : A → ℝ) (value : Secret → A → ℝ)
    (bound : ∀ index,
      uniformAverage (fun secret => value secret index) ≤
        query * scale * mass index) :
    uniformAverage (fun secret => 4 * ∑ index, value secret index) ≤
      4 * query * scale * ∑ index, mass index := by
  classical
  rw [average_mul_left, average_sum]
  exact (four_mul_finite_sum_mono
    (fun index => uniformAverage (fun secret => value secret index))
    (fun index => query * scale * mass index) bound).trans_eq
      (four_mul_sum_product_factor query scale mass)

/-- Core-shaped specialization of the preceding aggregation lemma.  Its
`Fintype` is assembled once over type variables, so specializing to the
concrete 1,307-byte leaf key does not ask the elaborator to unfold the full
`Core` instance during higher-order unification. -/
theorem average_four_mul_core_sum_product_bound
    {CoreInput CoreOutput CorePhase CoreWork CoreBranch Secret : Type}
    [Fintype CoreInput] [Fintype CoreOutput] [Fintype CorePhase]
    [Fintype CoreWork] [Fintype CoreBranch]
    [Fintype Secret] [Nonempty Secret]
    (query scale : ℝ)
    (mass : Core CoreInput CoreBranch
      (CoreInput × CorePhase × CoreWork) CoreOutput → ℝ)
    (value : Secret → Core CoreInput CoreBranch
      (CoreInput × CorePhase × CoreWork) CoreOutput → ℝ)
    (bound : ∀ basis,
      uniformAverage (fun secret => value secret basis) ≤
        query * scale * mass basis) :
    uniformAverage (fun secret =>
      4 * ∑ basis : Core CoreInput CoreBranch
        (CoreInput × CorePhase × CoreWork) CoreOutput,
          value secret basis) ≤
      4 * query * scale *
        ∑ basis : Core CoreInput CoreBranch
          (CoreInput × CorePhase × CoreWork) CoreOutput, mass basis := by
  exact average_four_mul_sum_product_bound query scale mass value bound
-/

/-- Append a genuinely fresh uniform label table to an arbitrary compressed
oracle core.  Input, phase, measured branch and work registers are retained. -/
def initializedFreshState (core : FC → ℂ) : CB → ℂ :=
  fun basis =>
    core (basis.workspace.2.1, basis.database,
      (basis.input, basis.phase, basis.workspace.2.2)) *
      ((Real.sqrt (Fintype.card (Index → Output) : ℝ) : ℂ)⁻¹)

/-- The initialized CMS state is exactly the abstract fresh-label state under
the coordinate permutation; this is equality of the complete state. -/
theorem J_initializedFreshState (core : FC → ℂ) :
    J (initializedFreshState core) = freshLabels (Index := Index) core := by
  ext basis
  rfl

/-- Native CMS squared norm and fresh-coordinate squared norm agree for a
difference of arbitrary states. -/
theorem J_sub_norm_squared (left right : CB → ℂ) :
    ‖J left - J right‖ ^ 2 = normSquared (left - right) := by
  rw [EuclideanSpace.norm_sq_eq]
  unfold normSquared
  change (∑ b : FB, ‖J left b - J right b‖ ^ 2) = _
  calc
    _ = ∑ b : FB, Complex.normSq (J left b - J right b) := by
      apply Finset.sum_congr rfl
      intro b _
      exact Complex.sq_norm _
    _ = ∑ b : CB, Complex.normSq (left b - right b) := J_isometry left right
    _ = ∑ b : CB, Complex.normSq ((left - right) b) := by rfl

/-- A CMS database bound gives the support premise required by the
fresh-label disturbance theorem.  No query log is read as classical data. -/
theorem core_database_size_le_of_bounded (core : FC → ℂ) (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := Index) core))
    (basis : FC) (nonzero : core basis ≠ 0) :
    size basis.2.1 ≤ queries := by
  by_contra notBounded
  have above : queries < size basis.2.1 := Nat.lt_of_not_ge notBounded
  let cmsBasis : CB :=
    { input := basis.2.2.1
      phase := basis.2.2.2.1
      workspace := (fun _ => 0, basis.1, basis.2.2.2.2)
      database := basis.2.1 }
  have zeroAmplitude := bounded_state_apply_eq_zero_of_lt bounded cmsBasis (by
    change queries < size basis.2.1
    exact above)
  have constantNonzero :
      ((Real.sqrt (Fintype.card (Index → Output) : ℝ) : ℂ)⁻¹) ≠ 0 := by
    apply inv_ne_zero
    exact_mod_cast
      (ne_of_gt (Real.sqrt_pos.2
        (show (0 : ℝ) < Fintype.card (Index → Output) by positivity)))
  have amplitudeNonzero : initializedFreshState core cmsBasis ≠ 0 := by
    change core basis * ((Real.sqrt (Fintype.card (Index → Output) : ℝ) : ℂ)⁻¹) ≠ 0
    exact mul_ne_zero nonzero constantNonzero
  exact amplitudeNonzero zeroAmplitude

/-- Forget only the presentation of a reached CMS state: the measured branch
is moved into the core coordinate while input, phase, work and database stay
unchanged. -/
def coreOfCmsState
    (state : HegemonCrypto.CmsCompressedOracle.State
      Input Output Phase (Branch × Work)) : FC → ℂ :=
  fun basis => state
    { input := basis.2.2.1
      phase := basis.2.2.2.1
      workspace := (basis.1, basis.2.2.2.2)
      database := basis.2.1 }

/-- Appending the uniform label table cannot create support on a larger CMS
database.  This is the exact bridge from query reachability to the state used
by the resampling operator. -/
theorem initializedFreshState_bounded_of_core_state_bounded
    (state : HegemonCrypto.CmsCompressedOracle.State
      Input Output Phase (Branch × Work))
    (queries : Nat) (bounded : BoundedState queries state) :
    BoundedState queries
      (initializedFreshState (Index := Index) (coreOfCmsState state)) := by
  unfold BoundedState
  funext basis
  by_cases within : size basis.database ≤ queries
  · simp only [HegemonCrypto.CmsCompressedOracle.project, within,
      true_and, if_true]
  · have above : queries < size basis.database := Nat.lt_of_not_ge within
    have zero := bounded_state_apply_eq_zero_of_lt bounded
      { input := basis.input
        phase := basis.phase
        workspace := (basis.workspace.2.1, basis.workspace.2.2)
        database := basis.database } above
    simp only [HegemonCrypto.CmsCompressedOracle.project, within,
      false_and, if_false, initializedFreshState, coreOfCmsState, zero,
      zero_mul]

/-- An initialized raw CMS execution supplies the database bound after the
fresh label table is appended.  The bound is inherited from the existing
query-sequence theorem; it is not a new query-count assumption. -/
theorem raw_run_initializedFreshState_bounded
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Branch × Work)))
    (state : HegemonCrypto.CmsCompressedOracle.State
      Input Output Phase (Branch × Work))
    (initialBound : Nat)
    (capacity : initialBound + steps.length ≤ queryBound)
    (bounded : BoundedState initialBound state) :
    BoundedState queryBound
      (initializedFreshState (Index := Index)
        (coreOfCmsState (rawRun system queryBound steps state))) :=
  initializedFreshState_bounded_of_core_state_bounded _ queryBound
    (raw_run_bounded_of_bounded system queryBound steps state
      initialBound capacity bounded)

/- The leaf-domain specialization is split from this CMS-only prefix while
localizing the RSS boundary.  Its retained source follows verbatim.
section FullDomain

variable {Other : Type} [Fintype Other] [DecidableEq Other]

local notation "FullInput" => LeafInput ⊕ Other
local notation "FullCore" =>
  Core FullInput Branch (FullInput × Phase × Work) DigestRegister

/- `FullInput` contains the concrete 1,307-byte leaf key.  The recursively
derived `Fintype FullCore` therefore carries an enormous reducible instance
term, even though none of the arguments below computes its enumeration.
Keep the same finite type but choose the opaque classical enumeration once at
this section boundary.  This prevents later higher-order applications from
normalizing the concrete function-space enumeration while preserving every
finite sum and cardinality proposition extensionally. -/
local instance fullInputFintype : Fintype FullInput := Fintype.ofFinite _
local instance fullCoreFintype : Fintype FullCore := Fintype.ofFinite _

/- The leaf-support/cardinality development is compiled independently in
`Q38CmsInitializedLeafOverlap`; keeping its former source here commented
preserves a reviewable split boundary without re-elaborating it.
/-- The portion of a full compressed database lying in the leaf domain. -/
def recordedLeafInputs
    (database : FullInput → Option DigestRegister) : Finset LeafInput :=
  Finset.univ.filter fun input => database (Sum.inl input) ≠ none

theorem recordedLeafInputs_card_le_size
    (database : FullInput → Option DigestRegister) :
    (recordedLeafInputs database).card ≤ size database := by
  let embedded : Finset FullInput :=
    (recordedLeafInputs database).image Sum.inl
  have inlInjective : Function.Injective (@Sum.inl LeafInput Other) := by
    intro left right equal
    exact Sum.inl.inj equal
  have cardEmbedded : embedded.card = (recordedLeafInputs database).card := by
    exact Finset.card_image_of_injective _ inlInjective
  rw [← cardEmbedded]
  apply Finset.card_le_card
  intro input member
  rcases Finset.mem_image.mp member with ⟨leaf, recorded, rfl⟩
  rw [mem_support_iff]
  have present : database (Sum.inl leaf) ≠ none := by
    simpa only [recordedLeafInputs, Finset.mem_filter, Finset.mem_univ, true_and] using recorded
  cases value : database (Sum.inl leaf) with
  | none => exact (present value).elim
  | some output => exact ⟨output, value⟩

def leafIntersects (recorded patched : Finset LeafInput) : Prop :=
  ∃ input ∈ recorded, input ∈ patched

theorem leaf_overlap_indicator_bound
    (recorded patched : Finset LeafInput) :
    (if leafIntersects recorded patched then (1 : ℝ) else 0) ≤
      ∑ input ∈ recorded, if input ∈ patched then (1 : ℝ) else 0 := by
  by_cases hit : leafIntersects recorded patched
  · obtain ⟨input, member, patchedMember⟩ := hit
    rw [if_pos ⟨input, member, patchedMember⟩]
    have bound := Finset.single_le_sum
      (f := fun input => if input ∈ patched then (1 : ℝ) else 0)
      (fun input _ => by positivity) member
    simpa only [if_pos patchedMember] using bound
  · rw [if_neg hit]
    exact Finset.sum_nonneg fun _ _ => by positivity

theorem indexed_leaf_record_overlap (recorded : Finset LeafInput) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      if leafIntersects recorded
        (indexedSupport rawInputIndex leafTapeProjection tapes)
      then (1 : ℝ) else 0) ≤
      (recorded.card : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
  apply (average_mono _ _ fun tapes =>
    leaf_overlap_indicator_bound recorded _).trans
  simp only [uniformAverage, Finset.mul_sum]
  rw [Finset.sum_comm]
  calc
    _ ≤ ∑ _input ∈ recorded, (2 ^ 512 : ℝ)⁻¹ := by
      apply Finset.sum_le_sum
      intro input _
      exact average_support_indicator_le
        (indexedSupport rawInputIndex leafTapeProjection)
        (2 ^ 512 : ℝ)⁻¹
        (fun input =>
          (indexed_leaf_tape_support_count
            rawInputIndex leafTapeProjection input).le)
        input
    _ = _ := by simp

theorem source_leaf_record_overlap (recorded : Finset LeafInput)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      if leafIntersects recorded
        (sourcePatchSupport Finset.univ (fun _ => header salt)
          (fun i => suffix (data i)) tapes)
      then (1 : ℝ) else 0) ≤
      (recorded.card : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
  apply (average_mono _ _ ?_).trans (indexed_leaf_record_overlap recorded)
  intro tapes
  have implication :
      leafIntersects recorded
        (sourcePatchSupport Finset.univ (fun _ => header salt)
          (fun i => suffix (data i)) tapes) →
      leafIntersects recorded
        (indexedSupport rawInputIndex leafTapeProjection tapes) := by
    rintro ⟨input, member, source⟩
    exact ⟨input, member,
      source_patch_support_subset Finset.univ (fun _ => header salt)
        (fun i => suffix (data i)) tapes source⟩
  by_cases hit : leafIntersects recorded
      (sourcePatchSupport Finset.univ (fun _ => header salt)
        (fun i => suffix (data i)) tapes)
  · simp only [if_pos hit, if_pos (implication hit), le_refl]
  · simp only [if_neg hit]
    positivity

def fullPhysicalSelected
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (tapes : LeafIndex → LeafTape) : Branch → LeafIndex → FullInput :=
  fun branch index => Sum.inl
    (sourceLeafInput (header (salt branch)) (suffix (data branch index))
      index (tapes index))
-/

/-- The adaptive fresh-tape bound on the actual full oracle domain.  Non-leaf
database coordinates are retained in the core and never selected or reset. -/
theorem full_domain_resampling_disturbance
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (core : FullCore → ℂ)
    (queries : Nat)
    (supported : ∀ basis, core basis ≠ 0 →
      (recordedLeafInputs basis.2.1).card ≤ queries) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      ‖exchangeMany (fullPhysicalSelected salt data tapes) indices
          (freshLabels (Index := LeafIndex) core) - freshLabels core‖ ^ 2) ≤
      4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ *
        ∑ basis : FullCore, ‖core basis‖ ^ 2 := by
  apply (average_mono _ _ fun tapes =>
    controlled_swap_disturbance_mass
      (fullPhysicalSelected salt data tapes) indices core).trans
  have perBasis (basis : FullCore) :
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        if ∃ index ∈ indices,
          basis.2.1 (fullPhysicalSelected salt data tapes basis.1 index) ≠ none
        then ‖core basis‖ ^ 2 else 0) ≤
      (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ * ‖core basis‖ ^ 2 := by
    by_cases zero : core basis = 0
    · have zeroNorm : ‖core basis‖ ^ 2 = 0 := by simp only [zero, norm_zero,
        zero_pow (by decide : 2 ≠ 0)]
      rw [zeroNorm]
      simp only [ite_self, mul_zero]
      exact le_of_eq
        (uniform_average_const (A := LeafIndex → LeafTape) (0 : ℝ))
    · have pointwise (tapes : LeafIndex → LeafTape) :
          (if ∃ index ∈ indices,
              basis.2.1 (fullPhysicalSelected salt data tapes basis.1 index) ≠ none
            then ‖core basis‖ ^ 2 else 0) ≤
          (if leafIntersects (recordedLeafInputs basis.2.1)
              (sourcePatchSupport Finset.univ
                (fun _ => header (salt basis.1))
                (fun i => suffix (data basis.1 i)) tapes)
            then (1 : ℝ) else 0) * ‖core basis‖ ^ 2 := by
        by_cases hit : ∃ index ∈ indices,
            basis.2.1 (fullPhysicalSelected salt data tapes basis.1 index) ≠ none
        · have selectedHit : ∃ index ∈ indices,
              basis.2.1
                (fullPhysicalSelected salt data tapes basis.1 index) ≠ none := hit
          obtain ⟨index, member, recorded⟩ := hit
          have overlaps : leafIntersects (recordedLeafInputs basis.2.1)
              (sourcePatchSupport Finset.univ
                (fun _ => header (salt basis.1))
                (fun i => suffix (data basis.1 i)) tapes) := by
            refine ⟨sourceLeafInput (header (salt basis.1))
              (suffix (data basis.1 index)) index (tapes index), ?_, ?_⟩
            · simpa only [recordedLeafInputs, Finset.mem_filter,
                Finset.mem_univ, true_and, fullPhysicalSelected] using recorded
            · exact Finset.mem_image.mpr ⟨index, Finset.mem_univ _, rfl⟩
          rw [if_pos selectedHit, if_pos overlaps, one_mul]
        · rw [if_neg hit]
          positivity
      apply (average_mono _ _ pointwise).trans
      rw [average_mul_right]
      apply mul_le_mul_of_nonneg_right _ (sq_nonneg _)
      exact (source_leaf_record_overlap (recordedLeafInputs basis.2.1)
        (salt basis.1) (data basis.1)).trans
          (mul_le_mul_of_nonneg_right
            (by exact_mod_cast supported basis zero) (by positivity))
  exact average_four_mul_core_sum_product_bound
    (CoreInput := FullInput) (CoreOutput := DigestRegister)
    (CorePhase := Phase) (CoreWork := Work) (CoreBranch := Branch)
    (Secret := LeafIndex → LeafTape)
    (queries : ℝ) (2 ^ 512 : ℝ)⁻¹
    (fun basis => ‖core basis‖ ^ 2)
    (fun tapes basis =>
      if ∃ index ∈ indices,
        basis.2.1 (fullPhysicalSelected salt data tapes basis.1 index) ≠ none
      then ‖core basis‖ ^ 2 else 0)
    perBasis

/-- The initialized CMS query-support invariant itself discharges the only
support premise of the full-domain adaptive disturbance theorem. -/
theorem full_core_leaf_support_of_bounded
    (core : FullCore → ℂ) (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := LeafIndex) core))
    (basis : FullCore) (nonzero : core basis ≠ 0) :
    (recordedLeafInputs basis.2.1).card ≤ queries :=
  (recordedLeafInputs_card_le_size basis.2.1).trans
    (core_database_size_le_of_bounded core queries bounded basis nonzero)

/-- Actual full-domain CMS endpoint: the native compressed-state disturbance
of the exact branch-controlled D·swap·D operator, with the non-leaf database,
input, phase and workspace retained. -/
theorem initialized_cms_full_domain_resampling_disturbance
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (core : FullCore → ℂ)
    (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := LeafIndex) core)) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      normSquared
        (controlledCompressed (fullPhysicalSelected salt data tapes) indices
            (initializedFreshState core) - initializedFreshState core)) ≤
      4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ *
        ∑ basis : FullCore, ‖core basis‖ ^ 2 := by
  have abstractBound := full_domain_resampling_disturbance
    salt data indices core queries
      (full_core_leaf_support_of_bounded core queries bounded)
  have identify (tapes : LeafIndex → LeafTape) :
      normSquared
          (controlledCompressed (fullPhysicalSelected salt data tapes) indices
              (initializedFreshState core) - initializedFreshState core) =
        ‖exchangeMany (fullPhysicalSelected salt data tapes) indices
            (freshLabels (Index := LeafIndex) core) - freshLabels core‖ ^ 2 := by
    rw [← J_sub_norm_squared]
    rw [J_controlled_many, J_initializedFreshState]
  simpa only [identify] using abstractBound

end FullDomain
-/

end
end HegemonCrypto.SmallWood.Q38CmsInitializedResampling
