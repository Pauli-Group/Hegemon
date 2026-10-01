import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleInstrument

/-!
# Full partition-controlled extraction commutator

Random signs on extraction labels isolate the block-diagonal part of the
actual query. Convexity bounds the remaining operator without paying for the
number of extraction labels. No zero-diagonal-answer-block claim is used.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CoherentMerklePartition

open scoped BigOperators Classical
open HegemonCrypto.CmsLocalOperator

noncomputable section
set_option maxRecDepth 5000
set_option maxHeartbeats 1000000

section Signs

variable {Label : Type*}

def labelSign (selection : Label → Bool) (label : Label) : ℂ :=
  if selection label then -1 else 1

def flipAt [DecidableEq Label] (label : Label) (selection : Label → Bool) : Label → Bool :=
  Function.update selection label (!(selection label))

theorem label_sign_square (selection : Label → Bool) (label : Label) :
    labelSign selection label * labelSign selection label = 1 := by
  cases value : selection label <;> simp [labelSign, value]

theorem label_sign_norm (selection : Label → Bool) (label : Label) :
    Complex.normSq (labelSign selection label) = 1 := by
  cases value : selection label <;> simp [labelSign, value]

variable [DecidableEq Label]

theorem flip_involutive (label : Label) : Function.Involutive (flipAt label) := by
  intro selection
  funext selected
  by_cases same : selected = label
  · subst selected
    simp [flipAt]
  · simp [flipAt, same]

theorem flip_ne_self (label : Label) (selection : Label → Bool) :
    flipAt label selection ≠ selection := by
  intro same
  have atLabel := congrFun same label
  cases value : selection label <;> simp [flipAt, value] at atLabel

theorem sign_flip_self (label : Label) (selection : Label → Bool) :
    labelSign (flipAt label selection) label = -labelSign selection label := by
  cases value : selection label <;> simp [labelSign, flipAt, value]

theorem sign_flip_other (left right : Label) (different : right ≠ left)
    (selection : Label → Bool) :
    labelSign (flipAt left selection) right = labelSign selection right := by
  simp [labelSign, flipAt, different]

variable [Fintype Label]

theorem sign_pair_sum_of_ne (left right : Label) (different : left ≠ right) :
    (∑ selection : Label → Bool, labelSign selection left * labelSign selection right) = 0 := by
  apply Finset.sum_ninvolution (flipAt left)
  · intro selection
    rw [sign_flip_self, sign_flip_other left right different.symm]
    ring
  · intro selection _
    exact flip_ne_self left selection
  · intro selection
    exact Finset.mem_univ _
  · exact flip_involutive left

theorem sign_pair_sum (left right : Label) :
    (∑ selection : Label → Bool, labelSign selection left * labelSign selection right) =
      if left = right then (Fintype.card (Label → Bool) : ℂ) else 0 := by
  by_cases same : left = right
  · subst right
    simp only [ite_true]
    simp_rw [label_sign_square]
    simp
  · simpa only [same, ite_false] using sign_pair_sum_of_ne left right same

theorem sum_signed_sum {Index : Type*} [Fintype Index]
    (label : Index → Label) (target : Label) (value : Index → ℂ) :
    (∑ selection : Label → Bool,
        labelSign selection target * ∑ index, value index * labelSign selection (label index)) =
      (Fintype.card (Label → Bool) : ℂ) *
        ∑ index, if label index = target then value index else 0 := by
  simp_rw [Finset.mul_sum]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro index _
  have rearrange (selection : Label → Bool) :
      labelSign selection target * (value index * labelSign selection (label index)) =
        value index * (labelSign selection (label index) * labelSign selection target) := by ring
  simp_rw [rearrange]
  rw [← Finset.mul_sum, sign_pair_sum]
  by_cases same : label index = target
  · simp [same, mul_comm]
  · simp [same]

theorem average_signed_kernel {Index : Type*} [Fintype Index]
    (label : Index → Label) (target : Label) (state kernel : Index → ℂ) :
    (Fintype.card (Label → Bool) : ℂ)⁻¹ *
      (∑ selection : Label → Bool,
        labelSign selection target *
          ∑ index, (labelSign selection (label index) * state index) * kernel index) =
        ∑ index, if label index = target then state index * kernel index else 0 := by
  have rearrange (selection : Label → Bool) (index : Index) :
      (labelSign selection (label index) * state index) * kernel index =
        (state index * kernel index) * labelSign selection (label index) := by ring
  simp_rw [rearrange]
  rw [sum_signed_sum]
  have nonzero : (Fintype.card (Label → Bool) : ℂ) ≠ 0 := by exact_mod_cast Fintype.card_ne_zero
  rw [← mul_assoc, inv_mul_cancel₀ nonzero, one_mul]

end Signs

section FiniteStates

variable {Basis Index : Type*} [Fintype Basis]

def mass (state : Basis → ℂ) : ℝ := ∑ basis, Complex.normSq (state basis)

def applyKernel (kernel : Basis → Basis → ℂ) (state : Basis → ℂ) : Basis → ℂ :=
  fun target => ∑ source, state source * kernel source target

def permute (equivalence : Basis ≃ Basis) (state : Basis → ℂ) : Basis → ℂ :=
  state ∘ equivalence.symm

theorem permute_mass (equivalence : Basis ≃ Basis) (state : Basis → ℂ) :
    mass (permute equivalence state) = mass state :=
  equivalence.symm.sum_comp (fun basis => Complex.normSq (state basis))

def average [Fintype Index] (states : Index → Basis → ℂ) : Basis → ℂ :=
  fun basis => ((Fintype.card Index : ℝ)⁻¹ : ℂ) * ∑ index, states index basis

theorem mass_average_le [Fintype Index] [Nonempty Index] (states : Index → Basis → ℂ) :
    mass (average states) ≤ (Fintype.card Index : ℝ)⁻¹ * ∑ index, mass (states index) := by
  have positive : (0 : ℝ) < Fintype.card Index := by exact_mod_cast Fintype.card_pos
  unfold mass average
  have order : (Fintype.card Index : ℝ)⁻¹ * ∑ index, ∑ basis, Complex.normSq (states index basis) =
      ∑ basis, (Fintype.card Index : ℝ)⁻¹ * ∑ index, Complex.normSq (states index basis) := by
    simp_rw [Finset.mul_sum]
    exact Finset.sum_comm
  rw [order]
  apply Finset.sum_le_sum
  intro basis _
  rw [Complex.normSq_mul]
  have cauchy := normSq_sum_le_card_mul_sum_normSq Finset.univ (fun index => states index basis)
  simp only [Finset.card_univ] at cauchy
  have coefficient : Complex.normSq (((Fintype.card Index : ℝ)⁻¹ : ℂ)) =
      (Fintype.card Index : ℝ)⁻¹ ^ 2 := by simp [pow_two]
  rw [coefficient]
  calc
    _ ≤ (Fintype.card Index : ℝ)⁻¹ ^ 2 *
        (Fintype.card Index * ∑ index, Complex.normSq (states index basis)) :=
      mul_le_mul_of_nonneg_left cauchy (sq_nonneg _)
    _ = _ := by field_simp

omit [Fintype Basis] in
theorem average_const [Fintype Index] [Nonempty Index] (state : Basis → ℂ) :
    average (fun _ : Index => state) = state := by
  funext basis
  have nonzero : (Fintype.card Index : ℂ) ≠ 0 := by exact_mod_cast Fintype.card_ne_zero
  simp [average, nonzero]

omit [Fintype Basis] in
theorem average_sub [Fintype Index] (left right : Index → Basis → ℂ) :
    average (fun index => left index - right index) = average left - average right := by
  funext basis
  simp [average, Finset.sum_sub_distrib, mul_sub]

theorem mass_sub_le (left right : Basis → ℂ) :
    mass (left - right) ≤ 2 * mass left + 2 * mass right := by
  unfold mass
  rw [Finset.mul_sum, Finset.mul_sum, ← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro basis _
  have nonnegative := Complex.normSq_nonneg (left basis + right basis)
  simp only [Complex.normSq_apply, Complex.add_re, Complex.add_im] at nonnegative
  simp only [Pi.sub_apply, Complex.normSq_apply, Complex.sub_re, Complex.sub_im]
  nlinarith

theorem kernel_permutation_commutes (kernel : Basis → Basis → ℂ)
    (equivalence : Basis ≃ Basis)
    (invariant : ∀ source target, kernel (equivalence source) (equivalence target) = kernel source target)
    (state : Basis → ℂ) :
    applyKernel kernel (permute equivalence state) = permute equivalence (applyKernel kernel state) := by
  funext target
  unfold applyKernel permute
  dsimp only [Function.comp_def]
  rw [← equivalence.sum_comp (fun source => state (equivalence.symm source) * kernel source target)]
  apply Finset.sum_congr rfl
  intro source _
  rw [equivalence.symm_apply_apply]
  have same := invariant source (equivalence.symm target)
  rw [equivalence.apply_symm_apply] at same
  rw [same]

end FiniteStates

section Dephasing

variable {Basis Label : Type*} [Fintype Basis] [Fintype Label] [DecidableEq Label]

def signedState (label : Basis → Label) (selection : Label → Bool) (state : Basis → ℂ) : Basis → ℂ :=
  fun basis => labelSign selection (label basis) * state basis

omit [Fintype Label] [DecidableEq Label] in
theorem signed_mass (label : Basis → Label) (selection : Label → Bool) (state : Basis → ℂ) :
    mass (signedState label selection state) = mass state := by
  unfold mass signedState
  simp only [Complex.normSq_mul, label_sign_norm, one_mul]

def diagonalKernel (label : Basis → Label) (kernel : Basis → Basis → ℂ) : Basis → Basis → ℂ :=
  fun source target => if label source = label target then kernel source target else 0

def offState (label : Basis → Label) (kernel : Basis → Basis → ℂ) (state : Basis → ℂ) : Basis → ℂ :=
  applyKernel kernel state - applyKernel (diagonalKernel label kernel) state

def signCommutator (label : Basis → Label) (kernel : Basis → Basis → ℂ)
    (selection : Label → Bool) (state : Basis → ℂ) : Basis → ℂ :=
  signedState label selection (applyKernel kernel state) -
    applyKernel kernel (signedState label selection state)

theorem diagonal_is_sign_average (label : Basis → Label) (kernel : Basis → Basis → ℂ)
    (state : Basis → ℂ) :
    applyKernel (diagonalKernel label kernel) state =
      average (fun selection => signedState label selection
        (applyKernel kernel (signedState label selection state))) := by
  funext target
  unfold average signedState applyKernel diagonalKernel
  simp only [Complex.ofReal_natCast]
  rw [average_signed_kernel]
  apply Finset.sum_congr rfl
  intro source _
  split_ifs <;> simp

theorem off_is_average_signed_commutator (label : Basis → Label) (kernel : Basis → Basis → ℂ)
    (state : Basis → ℂ) :
    offState label kernel state =
      average (fun selection => signedState label selection (signCommutator label kernel selection state)) := by
  rw [offState, diagonal_is_sign_average, ← average_const (Index := Label → Bool) (applyKernel kernel state),
    ← average_sub]
  apply congrArg average
  funext selection basis
  simp only [signedState, signCommutator, Pi.sub_apply, mul_sub, ← mul_assoc, label_sign_square, one_mul]

theorem off_mass_bound (label : Basis → Label) (kernel : Basis → Basis → ℂ)
    (bound : ℝ)
    (binaryBound : ∀ selection state, mass (signCommutator label kernel selection state) ≤ bound * mass state)
    (state : Basis → ℂ) : mass (offState label kernel state) ≤ bound * mass state := by
  rw [off_is_average_signed_commutator]
  refine (mass_average_le _).trans ?_
  simp_rw [signed_mass]
  calc
    _ ≤ (Fintype.card (Label → Bool) : ℝ)⁻¹ * ∑ _selection : Label → Bool, bound * mass state := by
      apply mul_le_mul_of_nonneg_left
      · exact Finset.sum_le_sum fun selection _ => binaryBound selection state
      · positivity
    _ = _ := by
      simp [← mul_assoc]

/-- Dimension-free full controlled-permutation bound. Only the already proved
Boolean coarsening estimate and a structural kernel symmetry are premises. -/
theorem full_permutation_commutator_bound (label : Basis → Label) (kernel : Basis → Basis → ℂ)
    (equivalence : Basis ≃ Basis)
    (preservesLabel : ∀ basis, label (equivalence basis) = label basis)
    (sameLabelKernel : ∀ source target, label source = label target →
      kernel (equivalence source) (equivalence target) = kernel source target)
    (bound : ℝ)
    (binaryBound : ∀ selection state, mass (signCommutator label kernel selection state) ≤ bound * mass state)
    (state : Basis → ℂ) :
    mass (permute equivalence (applyKernel kernel state) - applyKernel kernel (permute equivalence state)) ≤
      4 * bound * mass state := by
  have invariant : ∀ source target,
      diagonalKernel label kernel (equivalence source) (equivalence target) =
        diagonalKernel label kernel source target := by
    intro source target
    by_cases same : label source = label target
    · simp [diagonalKernel, preservesLabel, same, sameLabelKernel source target same]
    · simp [diagonalKernel, preservesLabel, same]
  have commutes := kernel_permutation_commutes (diagonalKernel label kernel) equivalence invariant state
  have offEquality : permute equivalence (applyKernel kernel state) -
      applyKernel kernel (permute equivalence state) =
      permute equivalence (offState label kernel state) - offState label kernel (permute equivalence state) := by
    funext basis
    have atBasis := congrFun commutes basis
    simp only [offState, permute, Function.comp_def, Pi.sub_apply] at atBasis ⊢
    rw [atBasis]
    ring
  rw [offEquality]
  have triangle := mass_sub_le (permute equivalence (offState label kernel state))
    (offState label kernel (permute equivalence state))
  rw [permute_mass] at triangle
  have first := off_mass_bound label kernel bound binaryBound state
  have second := off_mass_bound label kernel bound binaryBound (permute equivalence state)
  rw [permute_mass] at second
  nlinarith

end Dephasing

section ConcreteCms

open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open V8Smz9CoherentMerkleInstrument

variable {Input Output Phase Answer Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Answer] [DecidableEq Answer] [AddGroup Answer]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Full answer-register translation controlled by the extraction value. -/
def answerShift (value : Database Input Output → Answer) :
    HegemonCrypto.CmsCompressedOracle.Basis Input Output Phase (Answer × Workspace) ≃
      HegemonCrypto.CmsCompressedOracle.Basis Input Output Phase (Answer × Workspace) where
  toFun basis := { basis with workspace :=
    (basis.workspace.1 + value basis.database, basis.workspace.2) }
  invFun basis := { basis with workspace :=
    (basis.workspace.1 - value basis.database, basis.workspace.2) }
  left_inv basis := by cases basis; simp
  right_inv basis := by cases basis; simp

def boundedKernel (system : PhaseSystem Output Phase) (queryBound : ℕ)
    (source target : HegemonCrypto.CmsCompressedOracle.Basis Input Output Phase (Answer × Workspace)) : ℂ :=
  if size source.database ≤ queryBound ∧ size target.database ≤ queryBound
    then kernel system queryBound source target else 0

omit [AddGroup Answer] in
theorem bounded_kernel_apply (system : PhaseSystem Output Phase) (queryBound : ℕ)
    (state : State Input Output Phase (Answer × Workspace)) :
    applyKernel (boundedKernel system queryBound) state = boundedQuery system queryBound state := by
  funext target
  by_cases targetBound : size target.database ≤ queryBound
  · simp only [applyKernel, boundedQuery, project, targetBound, and_self, ite_true]
    unfold queryState
    apply Finset.sum_congr rfl
    intro source _
    by_cases sourceBound : size source.database ≤ queryBound <;>
      simp [boundedKernel, project, sourceBound, targetBound]
  · simp [applyKernel, boundedKernel, boundedQuery, project, targetBound]

omit [Fintype Phase] [Fintype Answer] [Fintype Workspace] in
theorem bounded_kernel_same_label_shift (system : PhaseSystem Output Phase) (queryBound : ℕ)
    (value : Database Input Output → Answer)
    (source target : HegemonCrypto.CmsCompressedOracle.Basis Input Output Phase (Answer × Workspace))
    (same : value source.database = value target.database) :
    boundedKernel system queryBound (answerShift value source) (answerShift value target) =
      boundedKernel system queryBound source target := by
  simp [boundedKernel, kernel, answerShift, same, Prod.ext_iff]

omit [Fintype Input] [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase] [Fintype Answer] [DecidableEq Answer] [AddGroup Answer]
  [Fintype Workspace] [DecidableEq Workspace] in
theorem signed_state_is_reflection (value : Database Input Output → Answer)
    (selection : Answer → Bool) (state : State Input Output Phase (Answer × Workspace)) :
    signedState (fun basis => value basis.database) selection state =
      partitionReflection (fun database => selection (value database) = true) state := by
  funext basis
  cases selected : selection (value basis.database) <;>
    simp [signedState, labelSign, partitionReflection, selected]

omit [AddGroup Answer] in
theorem sign_commutator_is_cms_reflection (system : PhaseSystem Output Phase) (queryBound : ℕ)
    (value : Database Input Output → Answer) (selection : Answer → Bool)
    (state : State Input Output Phase (Answer × Workspace)) :
    signCommutator (fun basis => value basis.database) (boundedKernel system queryBound) selection state =
      reflectionCommutator system (fun database => selection (value database) = true) queryBound state := by
  unfold signCommutator reflectionCommutator
  rw [bounded_kernel_apply, signed_state_is_reflection, signed_state_is_reflection, bounded_kernel_apply]

/-- Every finite extraction answer is handled coherently at once. The only
probabilistic premise is classical instability for Boolean coarsenings; the
full operator bound is derived, not supplied. -/
theorem full_answer_bounded_query_bound (system : PhaseSystem Output Phase) (queryBound : ℕ)
    (value : Database Input Output → Answer) (bound : ℝ)
    (instability : ∀ test : Answer → Prop,
      RealInstabilityBound (fun database => test (value database)) queryBound bound)
    (state : State Input Output Phase (Answer × Workspace)) :
    normSquared (permute (answerShift value) (boundedQuery system queryBound state) -
      boundedQuery system queryBound (permute (answerShift value) state)) ≤
      192 * bound * normSquared state := by
  have result := full_permutation_commutator_bound
    (fun basis : HegemonCrypto.CmsCompressedOracle.Basis Input Output Phase (Answer × Workspace) => value basis.database)
    (boundedKernel system queryBound) (answerShift value) (by intro basis; rfl)
    (bounded_kernel_same_label_shift system queryBound value)
    (48 * bound) (by
      intro selection selectedState
      rw [sign_commutator_is_cms_reflection]
      exact reflection_commutator_bound system _ queryBound selectedState
        (instability (fun answer => selection answer = true))) state
  rw [bounded_kernel_apply, bounded_kernel_apply] at result
  change normSquared _ ≤ 4 * (48 * bound) * normSquared state at result
  convert result using 1
  ring

omit [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase] [Fintype Answer] [DecidableEq Answer]
  [Fintype Workspace] [DecidableEq Workspace] in
theorem answer_shift_preserves_bounded (value : Database Input Output → Answer) (supportBound : ℕ)
    (state : State Input Output Phase (Answer × Workspace)) (bounded : BoundedState supportBound state) :
    BoundedState supportBound (permute (answerShift value) state) := by
  funext basis
  have atBasis := congrFun bounded ((answerShift value).symm basis)
  simpa [project, permute, Function.comp_def, answerShift, Equiv.symm] using atBasis

/-- Exact full controlled-answer commutator for the actual compressed query,
on its reachable strict pre-query subspace. -/
theorem full_answer_actual_query_bound (system : PhaseSystem Output Phase) (queryBound supportBound : ℕ)
    (value : Database Input Output → Answer) (bound : ℝ)
    (instability : ∀ test : Answer → Prop,
      RealInstabilityBound (fun database => test (value database)) queryBound bound)
    (state : State Input Output Phase (Answer × Workspace))
    (below : supportBound < queryBound) (bounded : BoundedState supportBound state) :
    normSquared (permute (answerShift value) (queryState system queryBound state) -
      queryState system queryBound (permute (answerShift value) state)) ≤
      192 * bound * normSquared state := by
  have result := full_answer_bounded_query_bound system queryBound value bound instability state
  rw [bounded_query_eq_query system queryBound supportBound state below bounded,
    bounded_query_eq_query system queryBound supportBound _ below
      (answer_shift_preserves_bounded value supportBound state bounded)] at result
  exact result

end ConcreteCms

section SourceEndpoint

open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument V8Smz9HiddenLeafQrom

variable {Key Answer Target Workspace : Type*} [Fintype Key] [DecidableEq Key]

/-- A deterministic encoding of the complete source trace inherits both
classical flip bounds. Its output can contain all extraction answers. -/
theorem source_value_instability (keyBytes : Key ↪ RawInput) (fuel : ℕ)
    (targets : List (SourceStage × RawDigest)) (queryBound : ℕ)
    (targetBudget : targets.length ≤ queryBound) (value : Database Key DigestRegister → Answer)
    (stable : ∀ left right, sourceLabel keyBytes rawDigestBits.symm fuel targets left =
      sourceLabel keyBytes rawDigestBits.symm fuel targets right → value left = value right)
    (test : Answer → Prop) :
    InstabilityBound (fun database => test (value database)) queryBound
      ((3 * queryBound : ℚ) / (2 ^ 512 : ℚ)) := by
  constructor
  · refine ⟨by positivity, ?_⟩
    intro database outside recordBudget key
    apply source_step_change_bound keyBytes rawDigestBits.symm fuel targets queryBound targetBudget
      database recordBudget key _
    intro output accepted same
    apply outside
    change test (value (query database key output)) at accepted
    simpa only [stable _ _ same] using accepted
  · refine ⟨by positivity, ?_⟩
    intro database inside recordBudget key
    apply source_step_change_bound keyBytes rawDigestBits.symm fuel targets queryBound targetBudget
      database recordBudget key _
    intro output rejected same
    apply rejected
    rw [stable _ _ same]
    exact inside

omit [DecidableEq Key] in
/-- The faithful complete-source one-hot encoding supplies the deterministic
stability premise above; no answer is discarded or measured. -/
theorem source_one_hot_stable (keyBytes : Key ↪ RawInput) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) (target : Target)
    (left right : Database Key DigestRegister)
    (same : sourceLabel keyBytes rawDigestBits.symm fuel (targets target) left =
      sourceLabel keyBytes rawDigestBits.symm fuel (targets target) right) :
    sourceOneHotValue keyBytes fuel targets target left =
      sourceOneHotValue keyBytes fuel targets target right := by
  unfold sourceOneHotValue
  apply congrArg (fun label : SourceLabelRange keyBytes fuel targets => Pi.single label (1 : ZMod 2))
  exact Subtype.ext same

variable [Fintype Answer] [DecidableEq Answer] [AddGroup Answer]
variable [Fintype Workspace] [DecidableEq Workspace]

set_option exponentiation.threshold 1024 in
/-- Source-specific full multi-answer commutator. Unlike the earlier binary
reflection endpoint, this changes the actual answer register by the entire
encoded extraction output. `stable` is a deterministic source-code property,
discharged for the faithful complete source encoding by `source_one_hot_stable`.
Targets are fixed in this theorem; arbitrary private answer/workspace states
and their entanglement are quantified without normalization assumptions. -/
theorem source_actual_full_extraction_bound (keyBytes : Key ↪ RawInput) (fuel : ℕ)
    (targets : List (SourceStage × RawDigest)) (queryBound supportBound : ℕ)
    (targetBudget : targets.length ≤ queryBound) (below : supportBound < queryBound)
    (value : Database Key DigestRegister → Answer)
    (stable : ∀ left right, sourceLabel keyBytes rawDigestBits.symm fuel targets left =
      sourceLabel keyBytes rawDigestBits.symm fuel targets right → value left = value right)
    (state : State Key DigestRegister DigestRegister (Answer × Workspace))
    (bounded : BoundedState supportBound state) :
    normSquared (permute (answerShift value) (queryState digestPhaseSystem queryBound state) -
      queryState digestPhaseSystem queryBound (permute (answerShift value) state)) ≤
      (576 * queryBound / (2 ^ 512 : ℝ)) * normSquared state := by
  have result := full_answer_actual_query_bound digestPhaseSystem queryBound supportBound value
    (((3 * queryBound : ℚ) / (2 ^ 512 : ℚ)) : ℝ)
    (fun test => by
      simpa only [Rat.cast_div] using
        (source_value_instability keyBytes fuel targets queryBound targetBudget value stable test).toReal)
    state below bounded
  convert result using 1
  push_cast
  ring

end SourceEndpoint

section CoherentTargets

open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument V8Smz9HiddenLeafQrom

variable {Input Output Phase Target Answer Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Target] [DecidableEq Target]
variable [Fintype Answer] [DecidableEq Answer] [AddGroup Answer]
variable [Fintype Workspace] [DecidableEq Workspace]

def targetBasisEquiv :
    (Target × HegemonCrypto.CmsCompressedOracle.Basis Input Output Phase (Answer × Workspace)) ≃
      HegemonCrypto.CmsCompressedOracle.Basis Input Output Phase (Target × Answer × Workspace) where
  toFun pair :=
    { input := pair.2.input
      phase := pair.2.phase
      database := pair.2.database
      workspace := (pair.1, pair.2.workspace.1, pair.2.workspace.2) }
  invFun basis := (basis.workspace.1,
    { input := basis.input, phase := basis.phase, database := basis.database, workspace := basis.workspace.2 })
  left_inv pair := by rcases pair with ⟨target, basis⟩; cases basis; rfl
  right_inv basis := by cases basis; rfl

def targetSlice (state : State Input Output Phase (Target × Answer × Workspace)) (target : Target) :
    State Input Output Phase (Answer × Workspace) :=
  fun basis => state (targetBasisEquiv (target, basis))

omit [DecidableEq Output] [AddCommGroup Output] [DecidableEq Phase]
  [DecidableEq Target] [DecidableEq Answer] [AddGroup Answer] [DecidableEq Workspace] in
theorem mass_eq_sum_target_slices (state : State Input Output Phase (Target × Answer × Workspace)) :
    normSquared state = ∑ target, normSquared (targetSlice state target) := by
  unfold normSquared
  rw [← targetBasisEquiv.sum_comp (fun basis => Complex.normSq (state basis))]
  rw [Fintype.sum_prod_type]
  rfl

omit [Fintype Phase] [Fintype Target] [Fintype Answer] [AddGroup Answer] [Fintype Workspace] in
theorem kernel_target_basis (system : PhaseSystem Output Phase) (queryBound : ℕ)
    (source target : Target × HegemonCrypto.CmsCompressedOracle.Basis Input Output Phase (Answer × Workspace)) :
    kernel system queryBound (targetBasisEquiv source) (targetBasisEquiv target) =
      if target.1 = source.1 then kernel system queryBound source.2 target.2 else 0 := by
  by_cases same : target.1 = source.1
  · simp [kernel, targetBasisEquiv, same, Prod.ext_iff]
  · simp [kernel, targetBasisEquiv, same, Prod.ext_iff]

omit [AddGroup Answer] in
theorem target_slice_query (system : PhaseSystem Output Phase) (queryBound : ℕ)
    (state : State Input Output Phase (Target × Answer × Workspace)) (target : Target) :
    targetSlice (queryState system queryBound state) target =
      queryState system queryBound (targetSlice state target) := by
  funext basis
  unfold targetSlice queryState
  rw [← targetBasisEquiv.sum_comp (fun source => state source *
    kernel system queryBound source (targetBasisEquiv (target, basis)))]
  rw [Fintype.sum_prod_type]
  simp_rw [kernel_target_basis]
  rw [Finset.sum_eq_single target]
  · simp
  · intro other _ different
    simp [Ne.symm different]
  · simp

omit [DecidableEq Input] [Fintype Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase] [Fintype Target] [DecidableEq Target]
  [Fintype Answer] [DecidableEq Answer] [Fintype Workspace] [DecidableEq Workspace] in
theorem target_slice_extraction (value : Target → Database Input Output → Answer)
    (state : State Input Output Phase (Target × Answer × Workspace)) (target : Target) :
    targetSlice (extractionLinearEquiv value state) target =
      permute (answerShift (value target)) (targetSlice state target) := by
  rfl

omit [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase] [Fintype Target] [DecidableEq Target]
  [Fintype Answer] [DecidableEq Answer] [AddGroup Answer] [Fintype Workspace] [DecidableEq Workspace] in
theorem target_slice_bounded (supportBound : ℕ)
    (state : State Input Output Phase (Target × Answer × Workspace))
    (bounded : BoundedState supportBound state) (target : Target) :
    BoundedState supportBound (targetSlice state target) := by
  funext basis
  have atBasis := congrFun bounded (targetBasisEquiv (target, basis))
  simpa [project, targetSlice, targetBasisEquiv] using atBasis

end CoherentTargets

section CoherentSourceEndpoint

open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument V8Smz9HiddenLeafQrom

variable {Key Target Answer Workspace : Type*}
variable [Fintype Key] [DecidableEq Key] [Fintype Target] [DecidableEq Target]
variable [Fintype Answer] [DecidableEq Answer] [AddGroup Answer]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Complete source-encoded extraction/query commutator with arbitrary
superposed target, answer and private-workspace registers. No target-count
factor is introduced by the orthogonal target decomposition. -/
theorem coherent_source_extraction_commutator_bound (keyBytes : Key ↪ RawInput) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) (queryBound supportBound : ℕ)
    (targetBudget : ∀ target, (targets target).length ≤ queryBound) (below : supportBound < queryBound)
    (value : Target → Database Key DigestRegister → Answer)
    (stable : ∀ target left right, sourceLabel keyBytes rawDigestBits.symm fuel (targets target) left =
      sourceLabel keyBytes rawDigestBits.symm fuel (targets target) right → value target left = value target right)
    (state : State Key DigestRegister DigestRegister (Target × Answer × Workspace))
    (bounded : BoundedState supportBound state) :
    normSquared (extractionLinearEquiv value (queryState digestPhaseSystem queryBound state) -
      queryState digestPhaseSystem queryBound (extractionLinearEquiv value state)) ≤
      (576 * queryBound / (2 ^ 512 : ℝ)) * normSquared state := by
  rw [mass_eq_sum_target_slices, mass_eq_sum_target_slices state, Finset.mul_sum]
  apply Finset.sum_le_sum
  intro target _
  have sliceSub : ∀ left right : State Key DigestRegister DigestRegister (Target × Answer × Workspace),
      targetSlice (left - right) target = targetSlice left target - targetSlice right target := by
    intro left right
    rfl
  rw [sliceSub, target_slice_extraction, target_slice_query, target_slice_query, target_slice_extraction]
  exact source_actual_full_extraction_bound keyBytes fuel (targets target) queryBound supportBound
    (targetBudget target) below (value target) (stable target) (targetSlice state target)
    (target_slice_bounded supportBound state bounded target)

/-- Faithful full-source endpoint: the answer is the injected complete source
trace, not an arbitrary Boolean predicate or caller-supplied extracted object.
The codec premise is purely an injective finite representation; the previous
one-hot construction supplies such a representation without an efficiency claim. -/
theorem coherent_faithful_source_commutator_bound (keyBytes : Key ↪ RawInput) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest))
    (encoding : SourceLabelRange keyBytes fuel targets ↪ Answer)
    (queryBound supportBound : ℕ)
    (targetBudget : ∀ target, (targets target).length ≤ queryBound) (below : supportBound < queryBound)
    (state : State Key DigestRegister DigestRegister (Target × Answer × Workspace))
    (bounded : BoundedState supportBound state) :
    normSquared (extractionLinearEquiv
        (fun target database => encoding (sourceRangeValue keyBytes fuel targets target database))
        (queryState digestPhaseSystem queryBound state) -
      queryState digestPhaseSystem queryBound
        (extractionLinearEquiv
          (fun target database => encoding (sourceRangeValue keyBytes fuel targets target database)) state)) ≤
      (576 * queryBound / (2 ^ 512 : ℝ)) * normSquared state := by
  apply coherent_source_extraction_commutator_bound keyBytes fuel targets queryBound supportBound
    targetBudget below _ _ state bounded
  intro target left right same
  exact congrArg encoding (Subtype.ext same)

end CoherentSourceEndpoint

end
end HegemonCrypto.SmallWood.V8Smz9CoherentMerklePartition
