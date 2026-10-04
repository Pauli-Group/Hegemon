import Q38CmsInitializedFullDomainPerBasis
import Q38CmsInitializedFullDomainAggregationInterface
import Q38CmsInitializedFullDomainSupportInterface

namespace HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.Q38CmsInitializedFullDomainAggregationProbe
open HegemonCrypto.SmallWood.Q38CmsInitializedFullDomainAggregationInterface
open HegemonCrypto.SmallWood.Q38CmsInitializedFullDomainSupportInterface
open HegemonCrypto.SmallWood.Q38CmsResamplingCoordinates
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 20000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {Phase Work Branch Other : Type}
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype Other] [DecidableEq Other]

local notation "FullInput" => LeafInput ⊕ Other
local notation "FullCore" =>
  Core FullInput Branch (FullInput × Phase × Work) DigestRegister

/-- Package the averaging, basis sum and pointwise bounds before any concrete
CMS basis is introduced.  At the concrete call site Lean therefore only
instantiates this theorem; it does not compare two separately elaborated
`Fintype` trees for the full core. -/
private theorem average_disturbance_of_basis_bounds
    {Secret Basis : Type}
    [Fintype Secret] [Nonempty Secret] [Fintype Basis]
    (disturbance : Secret → ℝ)
    (value : Secret → Basis → ℝ) (mass : Basis → ℝ)
    (query scale : ℝ)
    (pointwise : ∀ secret,
      disturbance secret ≤ 4 * ∑ basis, value secret basis)
    (perBasis : ∀ basis,
      uniformAverage (fun secret => value secret basis) ≤
        query * scale * mass basis) :
    uniformAverage disturbance ≤
      4 * query * scale * ∑ basis, mass basis := by
  apply (average_mono _ _ pointwise).trans
  exact average_four_mul_finset_product_bound
    (domain := (Finset.univ : Finset Basis))
    (query := query) (scale := scale) (mass := mass) (value := value)
    (bound := fun basis _ => perBasis basis)

/-- An indicator whose `Decidable` dictionary is fixed independently of how
the surrounding concrete finite type was synthesized. -/
private noncomputable def stableIte {A : Type} (condition : Prop)
    (yes no : A) : A :=
  @ite A condition (Classical.propDecidable condition) yes no

/-- `ite` is independent of the chosen decision procedure.  Proving this
before any concrete bounded existential is substituted avoids reducing the
8,388,608-coordinate decision tree. -/
private theorem ite_decidable_irrel {A : Type} {condition : Prop}
    (left right : Decidable condition) (yes no : A) :
    @ite A condition left yes no = @ite A condition right yes no := by
  cases Subsingleton.elim left right
  rfl

/-- Keep the controlled-swap theorem and the averaging theorem in one
polymorphic declaration.  In particular, their finite `Core` sums are
elaborated from the same abstract component instances, before the concrete
leaf-key type is substituted. -/
private theorem controlled_average_of_basis_bounds
    {Key Output CoreWork Index CoreBranch Tape : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype CoreWork]
    [Fintype Index] [DecidableEq Index]
    [Fintype CoreBranch]
    [Fintype Tape] [Nonempty Tape]
    (selected : (Index → Tape) → CoreBranch → Index → Key)
    (indices : List Index)
    (core : Core Key CoreBranch CoreWork Output → ℂ)
    (query scale : ℝ)
    (secretFintype : Fintype (Index → Tape))
    (perBasis : ∀ basis,
      @uniformAverage (Index → Tape) secretFintype inferInstance
        (fun tapes =>
        stableIte
          (∃ index ∈ indices,
            basis.2.1 (selected tapes basis.1 index) ≠ none)
          (‖core basis‖ ^ 2) 0) ≤
      query * scale * ‖core basis‖ ^ 2) :
    uniformAverage (fun tapes : Index → Tape =>
      ‖exchangeMany (selected tapes) indices
          (freshLabels (Index := Index) core) - freshLabels core‖ ^ 2) ≤
      4 * query * scale *
        ∑ basis : Core Key CoreBranch CoreWork Output,
          ‖core basis‖ ^ 2 := by
  have secretFintypeEq :
      secretFintype = (inferInstance : Fintype (Index → Tape)) :=
    Subsingleton.elim _ _
  cases secretFintypeEq
  exact average_disturbance_of_basis_bounds
    (disturbance := fun tapes : Index → Tape =>
      ‖exchangeMany (selected tapes) indices
          (freshLabels (Index := Index) core) - freshLabels core‖ ^ 2)
    (value := fun tapes basis =>
      stableIte
        (∃ index ∈ indices,
          basis.2.1 (selected tapes basis.1 index) ≠ none)
        (‖core basis‖ ^ 2) 0)
    (mass := fun basis => ‖core basis‖ ^ 2)
    (query := query) (scale := scale)
    (pointwise := fun tapes => by
      have raw := controlled_swap_disturbance_mass
        (selected tapes) indices core
      have sumEq :
          (∑ basis : Core Key CoreBranch CoreWork Output,
            if ∃ index ∈ indices,
              basis.2.1 (selected tapes basis.1 index) ≠ none
            then ‖core basis‖ ^ 2 else 0) =
          ∑ basis : Core Key CoreBranch CoreWork Output,
            stableIte
              (∃ index ∈ indices,
                basis.2.1 (selected tapes basis.1 index) ≠ none)
              (‖core basis‖ ^ 2) 0 := by
        apply Finset.sum_congr rfl
        intro basis _
        unfold stableIte
        exact ite_decidable_irrel _ _ _ _
      exact raw.trans_eq (congrArg (fun total : ℝ => 4 * total) sumEq))
    (perBasis := perBasis)

/-- The initialized support implication is likewise checked while the leaf
and oracle-index types are still abstract.  The concrete wrapper below only
unfolds the recorded-left statistic in its conclusion. -/
private theorem sum_left_recorded_support_of_bounded
    {Left Right Output Phase Work Index CoreBranch : Type}
    [Fintype Left] [DecidableEq Left]
    [Fintype Right] [DecidableEq Right]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    [Fintype Index] [DecidableEq Index]
    [Fintype CoreBranch] [DecidableEq CoreBranch]
    (core : Core (Left ⊕ Right) CoreBranch
      ((Left ⊕ Right) × Phase × Work) Output → ℂ)
    (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := Index) core))
    (basis : Core (Left ⊕ Right) CoreBranch
      ((Left ⊕ Right) × Phase × Work) Output)
    (nonzero : core basis ≠ 0) :
    (Finset.univ.filter fun input : Left =>
      basis.2.1 (Sum.inl input) ≠ none).card ≤ queries := by
  exact (sum_left_recorded_card_le_size basis.2.1).trans
    (core_database_size_le_of_bounded core queries bounded basis nonzero)

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
  let tableFintype : Fintype (LeafIndex → LeafTape) := inferInstance
  let selected : (LeafIndex → LeafTape) → Branch → LeafIndex → FullInput :=
    fun tapes => fullPhysicalSelected salt data tapes
  have perBasis (basis : FullCore) :
      @uniformAverage (LeafIndex → LeafTape) tableFintype inferInstance
        (fun tapes =>
        stableIte
          (∃ index ∈ indices,
            basis.2.1 (selected tapes basis.1 index) ≠ none)
          (‖core basis‖ ^ 2) 0) ≤
      (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ * ‖core basis‖ ^ 2 := by
    have valuesEq :
        (fun tapes : LeafIndex → LeafTape =>
          stableIte
            (∃ index ∈ indices,
              basis.2.1 (selected tapes basis.1 index) ≠ none)
            (‖core basis‖ ^ 2) 0) =
        (fun tapes : LeafIndex → LeafTape =>
          if ∃ index ∈ indices,
            basis.2.1
              (fullPhysicalSelected salt data tapes basis.1 index) ≠ none
          then ‖core basis‖ ^ 2 else 0) := by
      funext tapes
      unfold stableIte selected
      exact ite_decidable_irrel _ _ _ _
    rw [valuesEq]
    exact full_domain_per_basis_bound
      (Phase := Phase) (Work := Work) (Branch := Branch) (Other := Other)
      salt data indices core queries basis supported
  exact controlled_average_of_basis_bounds
    (Key := FullInput) (Output := DigestRegister)
    (CoreWork := FullInput × Phase × Work)
    (Index := LeafIndex) (CoreBranch := Branch) (Tape := LeafTape)
    (selected := selected)
    (indices := indices) (core := core)
    (query := (queries : ℝ)) (scale := (2 ^ 512 : ℝ)⁻¹)
    (secretFintype := tableFintype)
    (perBasis := perBasis)

theorem full_core_leaf_support_of_bounded
    (core : FullCore → ℂ) (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := LeafIndex) core))
    (basis : FullCore) (nonzero : core basis ≠ 0) :
    (recordedLeafInputs basis.2.1).card ≤ queries := by
  change (Finset.univ.filter fun input : LeafInput =>
    basis.2.1 (Sum.inl input) ≠ none).card ≤ queries
  exact sum_left_recorded_support_of_bounded
    (Left := LeafInput) (Right := Other) (Output := DigestRegister)
    (Phase := Phase) (Work := Work) (Index := LeafIndex)
    (CoreBranch := Branch) core queries bounded basis nonzero

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

end
end HegemonCrypto.SmallWood.Q38CmsInitializedResampling
