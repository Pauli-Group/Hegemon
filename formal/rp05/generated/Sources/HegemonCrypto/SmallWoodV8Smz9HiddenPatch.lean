import HegemonCrypto.SmallWoodV8Smz9HiddenLeafQrom
import Mathlib.Analysis.InnerProductSpace.PiL2
import Mathlib.Algebra.Order.Chebyshev
import Mathlib.Algebra.BigOperators.Fin

/-!
# Physical finite hidden-patch hybrids

The oracle query is a complex-linear Hilbert-space isometry, not an arbitrary
norm-preserving function. Inter-query operations are also linear isometries and
are fixed independently of the hidden secret. The changed-input probability is
an explicit premise about input supports, not a premise about final states.

This module first establishes the ordinary mean-square hybrid theorem. It does
not identify that theorem with the stronger averaged-density `4 q² p` bound.
-/

namespace HegemonCrypto.SmallWood.V8Smz9HiddenPatch

open V8Smz9HiddenLeafQrom
open scoped BigOperators

noncomputable section

set_option linter.unusedSectionVars false
set_option maxHeartbeats 1000000
set_option maxRecDepth 5000

variable {Input Output Workspace Secret : Type*}
variable [Fintype Input] [Fintype Output] [Fintype Workspace]
variable [AddGroup Output] [DecidableEq Input]

abbrev State := EuclideanSpace ℂ (QueryBasis Input Output Workspace)

/-- The genuine Hilbert-space linear isometry associated to an oracle query. -/
def query (oracle : Input → Output) :
    State (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      State (Input := Input) (Output := Output) (Workspace := Workspace) :=
  LinearIsometryEquiv.piLpCongrLeft 2 ℂ ℂ (oracleQueryBasisEquiv oracle)

theorem query_apply (oracle : Input → Output)
    (state : State (Input := Input) (Output := Output) (Workspace := Workspace))
    (basis : QueryBasis Input Output Workspace) :
    query oracle state basis = state (basis.1, basis.2.1 - oracle basis.1, basis.2.2) := rfl

def project (support : Finset Input)
    (state : State (Input := Input) (Output := Output) (Workspace := Workspace)) :
    State (Input := Input) (Output := Output) (Workspace := Workspace) :=
  WithLp.toLp 2 (fun basis => if basis.1 ∈ support then state basis else 0)

def weight (support : Finset Input)
    (state : State (Input := Input) (Output := Output) (Workspace := Workspace)) : ℝ :=
  ∑ basis, if basis.1 ∈ support then ‖state basis‖ ^ 2 else 0

theorem project_norm_sq (support : Finset Input)
    (state : State (Input := Input) (Output := Output) (Workspace := Workspace)) :
    ‖project support state‖ ^ 2 = weight support state := by
  rw [EuclideanSpace.norm_sq_eq]
  unfold weight
  apply Finset.sum_congr rfl
  intro basis _
  by_cases member : basis.1 ∈ support <;> simp [project, member]

theorem query_difference_eq_projected (oldOracle newOracle : Input → Output)
    (support : Finset Input)
    (same : ∀ input, input ∉ support → oldOracle input = newOracle input)
    (state : State (Input := Input) (Output := Output) (Workspace := Workspace)) :
    query newOracle state - query oldOracle state =
      query newOracle (project support state) - query oldOracle (project support state) := by
  ext basis
  by_cases member : basis.1 ∈ support
  · simp [query_apply, project, member]
  · simp [query_apply, project, member, same basis.1 member]

/-- One physical query loses at most four times the mass on changed inputs. -/
theorem query_difference_sq_le (oldOracle newOracle : Input → Output)
    (support : Finset Input)
    (same : ∀ input, input ∉ support → oldOracle input = newOracle input)
    (state : State (Input := Input) (Output := Output) (Workspace := Workspace)) :
    ‖query newOracle state - query oldOracle state‖ ^ 2 ≤ 4 * weight support state := by
  rw [query_difference_eq_projected oldOracle newOracle support same state]
  have bound := norm_sub_le (query newOracle (project support state))
    (query oldOracle (project support state))
  rw [LinearIsometryEquiv.norm_map, LinearIsometryEquiv.norm_map] at bound
  rw [← project_norm_sq]
  nlinarith [norm_nonneg (query newOracle (project support state) -
    query oldOracle (project support state)), norm_nonneg (project support state)]

/-- The reference circuit and all its inter-query unitaries do not depend on `Secret`. -/
def run (oracle : Input → Output)
    (steps : ℕ → State (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      State (Input := Input) (Output := Output) (Workspace := Workspace))
    (initial : State (Input := Input) (Output := Output) (Workspace := Workspace)) :
    ℕ → State (Input := Input) (Output := Output) (Workspace := Workspace)
  | 0 => initial
  | n + 1 => steps n (query oracle (run oracle steps initial n))

theorem run_norm (oracle : Input → Output) (steps : ℕ → State (Input := Input)
    (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := Input) (Output := Output) (Workspace := Workspace)) (n : ℕ) :
    ‖run oracle steps initial n‖ = ‖initial‖ := by
  induction n with
  | zero => rfl
  | succ n ih => simpa [run] using ih

theorem run_distance_le_sum (oldOracle newOracle : Input → Output)
    (steps : ℕ → State (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := Input) (Output := Output) (Workspace := Workspace)) (n : ℕ) :
    ‖run newOracle steps initial n - run oldOracle steps initial n‖ ≤
      ∑ k ∈ Finset.range n, ‖query newOracle (run oldOracle steps initial k) -
        query oldOracle (run oldOracle steps initial k)‖ := by
  induction n with
  | zero => simp [run]
  | succ n ih =>
      rw [run, run, ← map_sub, LinearIsometryEquiv.norm_map, Finset.sum_range_succ]
      calc
        _ ≤ ‖query newOracle (run newOracle steps initial n) -
              query newOracle (run oldOracle steps initial n)‖ +
            ‖query newOracle (run oldOracle steps initial n) -
              query oldOracle (run oldOracle steps initial n)‖ := norm_sub_le_norm_sub_add_norm_sub _ _ _
        _ = ‖run newOracle steps initial n - run oldOracle steps initial n‖ +
            ‖query newOracle (run oldOracle steps initial n) -
              query oldOracle (run oldOracle steps initial n)‖ := by
          rw [← map_sub, LinearIsometryEquiv.norm_map]
        _ ≤ _ := add_le_add ih le_rfl

theorem run_distance_sq_le (oldOracle newOracle : Input → Output)
    (steps : ℕ → State (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := Input) (Output := Output) (Workspace := Workspace)) (n : ℕ) :
    ‖run newOracle steps initial n - run oldOracle steps initial n‖ ^ 2 ≤
      (n : ℝ) * ∑ k ∈ Finset.range n, ‖query newOracle (run oldOracle steps initial k) -
        query oldOracle (run oldOracle steps initial k)‖ ^ 2 := by
  have distance := run_distance_le_sum oldOracle newOracle steps initial n
  have cauchy := sq_sum_le_card_mul_sum_sq (s := Finset.range n)
    (f := fun k => ‖query newOracle (run oldOracle steps initial k) -
      query oldOracle (run oldOracle steps initial k)‖)
  simp only [Finset.card_range] at cauchy
  exact ((sq_le_sq₀ (norm_nonneg _) (Finset.sum_nonneg (fun _ _ => norm_nonneg _))).2
    distance).trans cauchy

variable [Fintype Secret]

/-- Unnormalized probability of a fixed input belonging to the hidden patch. -/
def supportCount (support : Secret → Finset Input) (input : Input) : ℝ :=
  ∑ secret, if input ∈ support secret then 1 else 0

theorem sum_weight_eq (support : Secret → Finset Input)
    (state : State (Input := Input) (Output := Output) (Workspace := Workspace)) :
    (∑ secret, weight (support secret) state) =
      ∑ basis, supportCount support basis.1 * ‖state basis‖ ^ 2 := by
  unfold weight supportCount
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro basis _
  rw [Finset.sum_mul]
  apply Finset.sum_congr rfl
  intro secret _
  by_cases member : basis.1 ∈ support secret <;> simp [member]

/-- Secret independence is explicit: `state` is one fixed vector for the whole sum. -/
theorem sum_weight_le (support : Secret → Finset Input) (p : ℝ)
    (support_bound : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (state : State (Input := Input) (Output := Output) (Workspace := Workspace)) :
    (∑ secret, weight (support secret) state) ≤
      (Fintype.card Secret : ℝ) * p * ‖state‖ ^ 2 := by
  rw [sum_weight_eq, EuclideanSpace.norm_sq_eq, Finset.mul_sum]
  apply Finset.sum_le_sum
  intro basis _
  exact mul_le_mul_of_nonneg_right (support_bound basis.1) (sq_nonneg _)

theorem sum_query_difference_sq_le (oldOracle : Input → Output)
    (newOracle : Secret → Input → Output) (support : Secret → Finset Input) (p : ℝ)
    (same : ∀ secret input, input ∉ support secret → oldOracle input = newOracle secret input)
    (support_bound : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (state : State (Input := Input) (Output := Output) (Workspace := Workspace)) :
    (∑ secret, ‖query (newOracle secret) state - query oldOracle state‖ ^ 2) ≤
      4 * ((Fintype.card Secret : ℝ) * p * ‖state‖ ^ 2) := by
  calc
    _ ≤ ∑ secret, 4 * weight (support secret) state := by
      apply Finset.sum_le_sum
      intro secret _
      exact query_difference_sq_le oldOracle (newOracle secret) (support secret) (same secret) state
    _ = 4 * ∑ secret, weight (support secret) state := by rw [Finset.mul_sum]
    _ ≤ _ := mul_le_mul_of_nonneg_left (sum_weight_le support p support_bound state) (by norm_num)

/-- Ordinary physical hybrid, before dividing by the number of hidden secrets. -/
theorem sum_run_distance_sq_le (oldOracle : Input → Output)
    (newOracle : Secret → Input → Output) (support : Secret → Finset Input) (p : ℝ)
    (same : ∀ secret input, input ∉ support secret → oldOracle input = newOracle secret input)
    (support_bound : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (steps : ℕ → State (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := Input) (Output := Output) (Workspace := Workspace)) (n : ℕ) :
    (∑ secret, ‖run (newOracle secret) steps initial n - run oldOracle steps initial n‖ ^ 2) ≤
      (Fintype.card Secret : ℝ) * (4 * (n : ℝ) ^ 2 * p * ‖initial‖ ^ 2) := by
  calc
    _ ≤ ∑ secret, (n : ℝ) * ∑ k ∈ Finset.range n,
        ‖query (newOracle secret) (run oldOracle steps initial k) -
          query oldOracle (run oldOracle steps initial k)‖ ^ 2 := by
      apply Finset.sum_le_sum
      intro secret _
      exact run_distance_sq_le oldOracle (newOracle secret) steps initial n
    _ = (n : ℝ) * ∑ k ∈ Finset.range n, ∑ secret,
        ‖query (newOracle secret) (run oldOracle steps initial k) -
          query oldOracle (run oldOracle steps initial k)‖ ^ 2 := by
      rw [← Finset.mul_sum, Finset.sum_comm]
    _ ≤ (n : ℝ) * ∑ _k ∈ Finset.range n,
        4 * ((Fintype.card Secret : ℝ) * p * ‖initial‖ ^ 2) := by
      apply mul_le_mul_of_nonneg_left _ (Nat.cast_nonneg n)
      apply Finset.sum_le_sum
      intro k _
      simpa only [run_norm] using
        sum_query_difference_sq_le oldOracle newOracle support p same support_bound
          (run oldOracle steps initial k)
    _ = _ := by simp; ring

/-- Kernel-checked mean-square disturbance for a uniform hidden secret.

For normalized input this is `E ‖ψ_secret - ψ_reference‖² ≤ 4 q² p`.
It implies the usual `2 q sqrt p` vector-distance bound, not by itself the
stronger `4 q² p` averaged-density distance bound.
-/
theorem mean_run_distance_sq_le [Nonempty Secret] (oldOracle : Input → Output)
    (newOracle : Secret → Input → Output) (support : Secret → Finset Input) (p : ℝ)
    (same : ∀ secret input, input ∉ support secret → oldOracle input = newOracle secret input)
    (support_bound : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (steps : ℕ → State (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := Input) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (n : ℕ) :
    (∑ secret, ‖run (newOracle secret) steps initial n - run oldOracle steps initial n‖ ^ 2) /
      (Fintype.card Secret : ℝ) ≤ 4 * (n : ℝ) ^ 2 * p := by
  have card_positive : (0 : ℝ) < Fintype.card Secret := by
    exact_mod_cast Fintype.card_pos
  apply (div_le_iff₀ card_positive).2
  simpa [normalized, mul_comm] using
    sum_run_distance_sq_le oldOracle newOracle support p same support_bound steps initial n

/-- The ordinary averaged vector-distance corollary, in exact square-root form. -/
theorem mean_run_distance_le_sqrt [Nonempty Secret] (oldOracle : Input → Output)
    (newOracle : Secret → Input → Output) (support : Secret → Finset Input) (p : ℝ)
    (p_nonnegative : 0 ≤ p)
    (same : ∀ secret input, input ∉ support secret → oldOracle input = newOracle secret input)
    (support_bound : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (steps : ℕ → State (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := Input) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (n : ℕ) :
    (∑ secret, ‖run (newOracle secret) steps initial n - run oldOracle steps initial n‖) /
      (Fintype.card Secret : ℝ) ≤ Real.sqrt (4 * (n : ℝ) ^ 2 * p) := by
  have card_positive : (0 : ℝ) < Fintype.card Secret := by
    exact_mod_cast Fintype.card_pos
  have loss_nonnegative : 0 ≤ 4 * (n : ℝ) ^ 2 * p :=
    mul_nonneg (mul_nonneg (by norm_num) (sq_nonneg _)) p_nonnegative
  have sum_nonnegative : 0 ≤ ∑ secret,
      ‖run (newOracle secret) steps initial n - run oldOracle steps initial n‖ :=
    Finset.sum_nonneg (fun _ _ => norm_nonneg _)
  apply (sq_le_sq₀ (div_nonneg sum_nonnegative card_positive.le) (Real.sqrt_nonneg _)).1
  rw [Real.sq_sqrt loss_nonnegative, div_pow]
  apply (div_le_iff₀ (sq_pos_of_pos card_positive)).2
  calc
    _ ≤ (Fintype.card Secret : ℝ) *
        ∑ secret, ‖run (newOracle secret) steps initial n - run oldOracle steps initial n‖ ^ 2 := by
      simpa using (sq_sum_le_card_mul_sum_sq (s := (Finset.univ : Finset Secret))
        (f := fun secret => ‖run (newOracle secret) steps initial n - run oldOracle steps initial n‖))
    _ ≤ (Fintype.card Secret : ℝ) *
        ((Fintype.card Secret : ℝ) * (4 * (n : ℝ) ^ 2 * p)) := by
      apply mul_le_mul_of_nonneg_left _ card_positive.le
      simpa [normalized] using
        sum_run_distance_sq_le oldOracle newOracle support p same support_bound steps initial n
    _ = _ := by ring

section IndexedTapes

variable {Index Tape : Type*} [Fintype Index] [DecidableEq Index]
variable [Fintype Tape] [DecidableEq Tape] [Nonempty Tape]

/-- Every raw input selects one coordinate of the independent hidden tape table. -/
def indexedSupport (inputIndex : Input → Index) (inputTape : Input → Tape)
    (hidden : Index → Tape) : Finset Input :=
  Finset.univ.filter (fun input => hidden (inputIndex input) = inputTape input)

theorem coordinate_fiber_count (index : Index) (tape : Tape) :
    (∑ hidden : Index → Tape, if hidden index = tape then (1 : ℝ) else 0) *
      (Fintype.card Tape : ℝ) = Fintype.card (Index → Tape) := by
  have counted := Fintype.card_filter_piFinset_const_eq_of_mem
    (Finset.univ : Finset Tape) index (Finset.mem_univ tape)
  rw [Fintype.piFinset_univ, Finset.card_univ] at counted
  rw [Finset.sum_boole, counted, Fintype.card_fun]
  push_cast
  rw [← pow_succ]
  have index_positive : 0 < Fintype.card Index :=
    Fintype.card_pos_iff.mpr ⟨index⟩
  rw [Nat.sub_add_cancel index_positive]

/-- Exact input-wise probability; there is no multiplicative number-of-leaves factor. -/
theorem indexed_support_count (inputIndex : Input → Index) (inputTape : Input → Tape)
    (input : Input) :
    supportCount (indexedSupport inputIndex inputTape) input =
      (Fintype.card (Index → Tape) : ℝ) * (Fintype.card Tape : ℝ)⁻¹ := by
  have tape_positive : (0 : ℝ) < Fintype.card Tape := by exact_mod_cast Fintype.card_pos
  rw [← div_eq_mul_inv]
  apply (eq_div_iff tape_positive.ne').2
  simpa only [supportCount, indexedSupport, Finset.mem_filter, Finset.mem_univ,
    true_and, div_eq_mul_inv] using coordinate_fiber_count (inputIndex input) (inputTape input)

/-- The exact 64-byte source tape specializes the generic support law to 2^-512. -/
theorem indexed_leaf_tape_support_count (inputIndex : Input → Index)
    (inputTape : Input → LeafTape) (input : Input) :
    supportCount (indexedSupport inputIndex inputTape) input =
      (Fintype.card (Index → LeafTape) : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
  rw [indexed_support_count, leaf_tape_cardinality]
  norm_cast

theorem image_subset_indexed_support
    (constructor : Index → Tape → Input) (inputIndex : Input → Index) (inputTape : Input → Tape)
    (index_left_inverse : ∀ index tape, inputIndex (constructor index tape) = index)
    (tape_left_inverse : ∀ index tape, inputTape (constructor index tape) = tape)
    (indices : Finset Index) (hidden : Index → Tape) :
    indices.image (fun index => constructor index (hidden index)) ⊆
      indexedSupport inputIndex inputTape hidden := by
  intro input member
  obtain ⟨index, _member, rfl⟩ := Finset.mem_image.mp member
  simp only [indexedSupport, Finset.mem_filter, Finset.mem_univ, true_and]
  rw [index_left_inverse, tape_left_inverse]

theorem outside_of_subset {A : Type*} (small large : Finset A) (subset : small ⊆ large)
    (input : A) (outside : input ∉ large) : input ∉ small :=
  fun member => outside (subset member)

theorem inl_not_indexed_support {Other : Type*} [Fintype Other] [DecidableEq Other]
    (inputIndex : Input → Index) (inputTape : Input → Tape) (defaultIndex : Index) (defaultTape : Tape)
    (hidden : Index → Tape) (input : Input)
    (outside : Sum.inl input ∉ indexedSupport
      (Sum.elim inputIndex (fun _ : Other => defaultIndex))
      (Sum.elim inputTape (fun _ : Other => defaultTape)) hidden) :
    input ∉ indexedSupport inputIndex inputTape hidden := by
  simpa only [indexedSupport, Finset.mem_filter, Finset.mem_univ, true_and, Sum.elim_inl] using outside

end IndexedTapes

section Measurements

variable {Basis : Type*} [Fintype Basis] [DecidableEq Basis]

/-- A genuine linear computational-basis event projection, including arbitrary workspace. -/
def eventProjection (event : Finset Basis) : EuclideanSpace ℂ Basis →ₗ[ℂ] EuclideanSpace ℂ Basis where
  toFun state := WithLp.toLp 2 (fun basis => if basis ∈ event then state basis else 0)
  map_add' left right := by
    ext basis
    by_cases member : basis ∈ event <;> simp [member]
  map_smul' scalar state := by
    ext basis
    by_cases member : basis ∈ event <;> simp [member]

theorem event_projection_norm_sq_le (event : Finset Basis) (state : EuclideanSpace ℂ Basis) :
    ‖eventProjection event state‖ ^ 2 ≤ ‖state‖ ^ 2 := by
  rw [EuclideanSpace.norm_sq_eq, EuclideanSpace.norm_sq_eq]
  apply Finset.sum_le_sum
  intro basis _
  by_cases member : basis ∈ event
  · simp [eventProjection, member]
  · simp [eventProjection, member]

theorem event_projection_norm_le (event : Finset Basis) (state : EuclideanSpace ℂ Basis) :
    ‖eventProjection event state‖ ≤ ‖state‖ :=
  (sq_le_sq₀ (norm_nonneg _) (norm_nonneg _)).1 (event_projection_norm_sq_le event state)

def born (event : Finset Basis) (state : EuclideanSpace ℂ Basis) : ℝ :=
  ‖eventProjection event state‖ ^ 2

theorem born_difference_le (event : Finset Basis) (left right : EuclideanSpace ℂ Basis)
    (left_normalized : ‖left‖ = 1) (right_normalized : ‖right‖ = 1) :
    |born event left - born event right| ≤ 2 * ‖left - right‖ := by
  have left_bound : ‖eventProjection event left‖ ≤ 1 := by
    simpa only [left_normalized] using event_projection_norm_le event left
  have right_bound : ‖eventProjection event right‖ ≤ 1 := by
    simpa only [right_normalized] using event_projection_norm_le event right
  have reverse_triangle := abs_norm_sub_norm_le (eventProjection event left) (eventProjection event right)
  have projected_difference :
      ‖eventProjection event left - eventProjection event right‖ ≤ ‖left - right‖ := by
    rw [← map_sub]
    exact event_projection_norm_le event (left - right)
  have absolute_difference :
      |‖eventProjection event left‖ - ‖eventProjection event right‖| ≤ ‖left - right‖ :=
    reverse_triangle.trans projected_difference
  calc
    _ = |‖eventProjection event left‖ - ‖eventProjection event right‖| *
        (‖eventProjection event left‖ + ‖eventProjection event right‖) := by
      unfold born
      rw [sq_sub_sq, abs_mul, abs_of_nonneg (add_nonneg (norm_nonneg _) (norm_nonneg _))]
      ring
    _ ≤ ‖left - right‖ * 2 :=
      mul_le_mul absolute_difference (by linarith)
        (add_nonneg (norm_nonneg _) (norm_nonneg _)) (norm_nonneg _)
    _ = _ := mul_comm _ _

/-- A classical secret may be retained through the final measurement.

The common final isometry and event can depend on that classical secret; this
does not permit earlier uncounted secret-dependent oracle queries. Workspace
includes every retained quantum register and any dilation ancillas.
-/
theorem cq_born_difference_le [Nonempty Secret]
    (left right : Secret → EuclideanSpace ℂ Basis)
    (post : Secret → EuclideanSpace ℂ Basis ≃ₗᵢ[ℂ] EuclideanSpace ℂ Basis)
    (event : Secret → Finset Basis)
    (left_normalized : ∀ secret, ‖left secret‖ = 1)
    (right_normalized : ∀ secret, ‖right secret‖ = 1) :
    |(∑ secret, born (event secret) (post secret (left secret))) / (Fintype.card Secret : ℝ) -
      (∑ secret, born (event secret) (post secret (right secret))) / (Fintype.card Secret : ℝ)| ≤
      2 * ((∑ secret, ‖left secret - right secret‖) / (Fintype.card Secret : ℝ)) := by
  have card_nonnegative : (0 : ℝ) ≤ Fintype.card Secret := Nat.cast_nonneg _
  rw [← sub_div, abs_div, abs_of_nonneg card_nonnegative, ← Finset.sum_sub_distrib]
  calc
    _ ≤ (∑ secret, |born (event secret) (post secret (left secret)) -
        born (event secret) (post secret (right secret))|) / (Fintype.card Secret : ℝ) :=
      div_le_div_of_nonneg_right (Finset.abs_sum_le_sum_abs _ _) card_nonnegative
    _ ≤ (∑ secret, 2 * ‖left secret - right secret‖) / (Fintype.card Secret : ℝ) := by
      apply div_le_div_of_nonneg_right _ card_nonnegative
      apply Finset.sum_le_sum
      intro secret _
      have bound := born_difference_le (event secret) (post secret (left secret))
        (post secret (right secret))
        (by simpa only [LinearIsometryEquiv.norm_map] using left_normalized secret)
        (by simpa only [LinearIsometryEquiv.norm_map] using right_normalized secret)
      simpa only [← map_sub, LinearIsometryEquiv.norm_map] using bound
    _ = _ := by rw [← Finset.mul_sum, mul_div_assoc]

end Measurements

section SourceInputs

abbrev LeafIndex := Fin 8388608
abbrev LeafHeader := Fin 151 → Byte

/-- Canonical eight-byte little-endian index, before the 64-byte tape. -/
def indexBytes (index : LeafIndex) : Fin 8 → Byte :=
  finFunctionFinEquiv.symm ⟨index.val, lt_trans index.isLt (by norm_num)⟩

theorem index_bytes_little_endian (index : LeafIndex) :
    (∑ byte : Fin 8, (indexBytes index byte).val * 256 ^ byte.val) = index.val := by
  rw [← finFunctionFinEquiv_apply]
  exact congrArg Fin.val (finFunctionFinEquiv.apply_symm_apply _)

/-- The exact source split: 151 header bytes, 8 index bytes, 64 tape bytes, 1184 suffix bytes. -/
def sourceLeafInput (header : LeafHeader) (suffix : LeafSuffix)
    (index : LeafIndex) (tape : LeafTape) : LeafInput :=
  tapedLeafInput (Fin.append header (indexBytes index)) suffix tape

def leafIndexBytesProjection (input : LeafInput) : Fin 8 → Byte :=
  fun byte => input (Fin.castAdd 1248 (Fin.natAdd 151 byte))

/-- A total decoder; invalid raw indices are harmlessly mapped modulo the source domain. -/
def rawInputIndex (input : LeafInput) : LeafIndex :=
  ⟨(finFunctionFinEquiv (leafIndexBytesProjection input)).val % 8388608,
    Nat.mod_lt _ (by decide)⟩

theorem source_leaf_index_bytes_projection (header : LeafHeader) (suffix : LeafSuffix)
    (index : LeafIndex) (tape : LeafTape) :
    leafIndexBytesProjection (sourceLeafInput header suffix index tape) = indexBytes index := by
  funext byte
  simp [leafIndexBytesProjection, sourceLeafInput, tapedLeafInput]

theorem source_leaf_index_projection (header : LeafHeader) (suffix : LeafSuffix)
    (index : LeafIndex) (tape : LeafTape) :
    rawInputIndex (sourceLeafInput header suffix index tape) = index := by
  apply Fin.ext
  simp only [rawInputIndex, source_leaf_index_bytes_projection, indexBytes,
    Equiv.apply_symm_apply, Nat.mod_eq_of_lt index.isLt]

theorem source_leaf_tape_projection (header : LeafHeader) (suffix : LeafSuffix)
    (index : LeafIndex) (tape : LeafTape) :
    leafTapeProjection (sourceLeafInput header suffix index tape) = tape :=
  taped_leaf_projection _ _ _

/-- The actual simultaneous source-shaped overlay support for an unopened index set. -/
def sourcePatchSupport (unopened : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (hidden : LeafIndex → LeafTape) : Finset LeafInput :=
  unopened.image (fun index => sourceLeafInput (header index) (suffix index) index (hidden index))

theorem source_patch_support_subset (unopened : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (hidden : LeafIndex → LeafTape) :
    sourcePatchSupport unopened header suffix hidden ⊆
      indexedSupport rawInputIndex leafTapeProjection hidden :=
  image_subset_indexed_support (fun index tape => sourceLeafInput (header index) (suffix index) index tape)
    rawInputIndex leafTapeProjection
    (fun index tape => source_leaf_index_projection (header index) (suffix index) index tape)
    (fun index tape => source_leaf_tape_projection (header index) (suffix index) index tape)
    unopened hidden

/-- Simultaneous persistent raw-oracle overlay at the actual unopened leaf inputs. -/
def sourceOverlay (oldOracle : LeafInput → Output) (targets : LeafIndex → Output)
    (unopened : Finset LeafIndex) (header : LeafIndex → LeafHeader)
    (suffix : LeafIndex → LeafSuffix) (hidden : LeafIndex → LeafTape) : LeafInput → Output :=
  fun input => if input ∈ sourcePatchSupport unopened header suffix hidden
    then targets (rawInputIndex input) else oldOracle input

/-- Physical source endpoint: an arbitrary continuation is included in `steps` and `q`.

All raw leaf indices and all 64 tape bytes come from the explicit constructors above.
No number-of-leaves factor is assumed or paid. Public conditioning must establish
that `oldOracle`, the circuit and its initial state are independent of `hidden`.
-/
theorem source_overlay_mean_distance_le (oldOracle : LeafInput → Output)
    (targets : LeafIndex → Output) (unopened : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (steps : ℕ → State (Input := LeafInput) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := LeafInput) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (q : ℕ) :
    (∑ hidden : LeafIndex → LeafTape,
      ‖run (sourceOverlay oldOracle targets unopened header suffix hidden) steps initial q -
        run oldOracle steps initial q‖) / (Fintype.card (LeafIndex → LeafTape) : ℝ) ≤
      Real.sqrt (4 * (q : ℝ) ^ 2 * (2 ^ 512 : ℝ)⁻¹) := by
  apply mean_run_distance_le_sqrt oldOracle
    (sourceOverlay oldOracle targets unopened header suffix)
    (indexedSupport rawInputIndex leafTapeProjection) (2 ^ 512 : ℝ)⁻¹ (by positivity)
    _ _ steps initial normalized q
  · intro hidden input outside
    have outside_source := outside_of_subset _ _
      (source_patch_support_subset unopened header suffix hidden) input outside
    simp only [sourceOverlay, if_neg outside_source]
  · intro input
    exact (indexed_leaf_tape_support_count rawInputIndex leafTapeProjection input).le

/-- Operational per-proof endpoint, including the complete counted continuation,
retained classical secret, arbitrary retained workspace and a final Born measurement.
The safe elementary measurement estimate pays a factor two over vector distance.
-/
theorem source_overlay_cq_born_distance_le [DecidableEq Output] [DecidableEq Workspace]
    (oldOracle : LeafInput → Output) (targets : LeafIndex → Output)
    (unopened : Finset LeafIndex) (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (steps : ℕ → State (Input := LeafInput) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := LeafInput) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (q : ℕ)
    (post : (LeafIndex → LeafTape) → State (Input := LeafInput) (Output := Output)
      (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (event : (LeafIndex → LeafTape) → Finset (QueryBasis LeafInput Output Workspace)) :
    |(∑ hidden : LeafIndex → LeafTape,
        born (event hidden) (post hidden
          (run (sourceOverlay oldOracle targets unopened header suffix hidden) steps initial q))) /
          (Fintype.card (LeafIndex → LeafTape) : ℝ) -
      (∑ hidden : LeafIndex → LeafTape,
        born (event hidden) (post hidden (run oldOracle steps initial q))) /
          (Fintype.card (LeafIndex → LeafTape) : ℝ)| ≤
      2 * Real.sqrt (4 * (q : ℝ) ^ 2 * (2 ^ 512 : ℝ)⁻¹) := by
  have measurement := cq_born_difference_le
    (fun hidden => run (sourceOverlay oldOracle targets unopened header suffix hidden) steps initial q)
    (fun _hidden => run oldOracle steps initial q) post event
    (fun hidden => (run_norm _ steps initial q).trans normalized)
    (fun _hidden => (run_norm oldOracle steps initial q).trans normalized)
  exact measurement.trans (mul_le_mul_of_nonneg_left
    (source_overlay_mean_distance_le oldOracle targets unopened header suffix steps initial normalized q)
    (by norm_num))

section FullRawOracle

variable {Other : Type*} [Fintype Other] [DecidableEq Other]

/-- The other raw-oracle inputs are retained, not replaced by a leaf-only query interface. -/
def fullSourceOverlay (oldLeaf : LeafInput → Output) (other : Other → Output)
    (targets : LeafIndex → Output) (unopened : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (hidden : LeafIndex → LeafTape) : LeafInput ⊕ Other → Output :=
  Sum.elim (sourceOverlay oldLeaf targets unopened header suffix hidden) other

/-- Full finite raw-oracle hybrid: every coherent query may mix leaf and non-leaf inputs. -/
theorem full_source_overlay_mean_distance_le (oldLeaf : LeafInput → Output) (other : Other → Output)
    (targets : LeafIndex → Output) (unopened : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (steps : ℕ → State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (q : ℕ) :
    (∑ hidden : LeafIndex → LeafTape,
      ‖run (fullSourceOverlay oldLeaf other targets unopened header suffix hidden) steps initial q -
        run (Sum.elim oldLeaf other) steps initial q‖) /
          (Fintype.card (LeafIndex → LeafTape) : ℝ) ≤
      Real.sqrt (4 * (q : ℝ) ^ 2 * (2 ^ 512 : ℝ)⁻¹) := by
  apply mean_run_distance_le_sqrt (Sum.elim oldLeaf other)
    (fullSourceOverlay oldLeaf other targets unopened header suffix)
    (indexedSupport (Sum.elim rawInputIndex (fun _ : Other => 0))
      (Sum.elim leafTapeProjection (fun _ : Other => (0 : LeafTape))))
    (2 ^ 512 : ℝ)⁻¹ (by positivity) _ _ steps initial normalized q
  · intro hidden input outside
    cases input with
    | inl input =>
        have outside_leaf := inl_not_indexed_support rawInputIndex leafTapeProjection
          0 (0 : LeafTape) hidden input outside
        have outside_source := outside_of_subset _ _
          (source_patch_support_subset unopened header suffix hidden) input outside_leaf
        simp only [fullSourceOverlay, Sum.elim_inl, sourceOverlay, if_neg outside_source]
    | inr input => rfl
  · intro input
    exact (indexed_leaf_tape_support_count
      (Sum.elim rawInputIndex (fun _ : Other => 0))
      (Sum.elim leafTapeProjection (fun _ : Other => (0 : LeafTape))) input).le

/-- Complete physical per-proof operational bound for the full raw oracle.

The query budget includes the full continuation. Classical context/secret is
retained in the final blockwise isometry and event, and no quantum workspace is
omitted. This elementary operational version is `4q/2^256`, not the optional
stronger discarded-secret `4q²/2^512` bound.
-/
theorem full_source_overlay_cq_born_distance_le [DecidableEq Output] [DecidableEq Workspace]
    (oldLeaf : LeafInput → Output) (other : Other → Output)
    (targets : LeafIndex → Output) (unopened : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (steps : ℕ → State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (initial : State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (q : ℕ)
    (post : (LeafIndex → LeafTape) → State (Input := LeafInput ⊕ Other) (Output := Output)
      (Workspace := Workspace) ≃ₗᵢ[ℂ] State)
    (event : (LeafIndex → LeafTape) → Finset (QueryBasis (LeafInput ⊕ Other) Output Workspace)) :
    |(∑ hidden : LeafIndex → LeafTape,
        born (event hidden) (post hidden
          (run (fullSourceOverlay oldLeaf other targets unopened header suffix hidden) steps initial q))) /
          (Fintype.card (LeafIndex → LeafTape) : ℝ) -
      (∑ hidden : LeafIndex → LeafTape,
        born (event hidden) (post hidden (run (Sum.elim oldLeaf other) steps initial q))) /
          (Fintype.card (LeafIndex → LeafTape) : ℝ)| ≤
      2 * Real.sqrt (4 * (q : ℝ) ^ 2 * (2 ^ 512 : ℝ)⁻¹) := by
  have measurement := cq_born_difference_le
    (fun hidden => run (fullSourceOverlay oldLeaf other targets unopened header suffix hidden) steps initial q)
    (fun _hidden => run (Sum.elim oldLeaf other) steps initial q) post event
    (fun hidden => (run_norm _ steps initial q).trans normalized)
    (fun _hidden => (run_norm (Sum.elim oldLeaf other) steps initial q).trans normalized)
  exact measurement.trans (mul_le_mul_of_nonneg_left
    (full_source_overlay_mean_distance_le oldLeaf other targets unopened header suffix
      steps initial normalized q) (by norm_num))

end FullRawOracle

end SourceInputs

end

end HegemonCrypto.SmallWood.V8Smz9HiddenPatch
