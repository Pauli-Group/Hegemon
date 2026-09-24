import HegemonCrypto.SmallWoodV8Smz9RuntimeRandomness
import Mathlib.Probability.ProbabilityMassFunction.Monad

/-!
# V8/SMZ9 ideal-iid rejection-sampler distribution

This file constructs a normalized PMF on actual finite terminating rejection traces under one
explicit ideal premise: raw 64-bit proposals are iid uniform.  It does not assume that an output
coin is uniform.  Instead, for each stopping index it samples uniformly from the actual
rejected-word subtype followed by the accepted-word subtype, proves that the concrete
`firstAccepted` scan returns the decoded accepted proposal, and then mixes those conditional laws
with the exact normalized geometric stopping law.  The resulting mass of every length-`k + 1`
terminating trace is exactly `(2^64) ^ -(k + 1)`, which characterizes the iid raw-proposal law on
this terminating-trace space.

The result is generic in the requested finite output count: the output PMF is the independent
product of Goldilocks uniforms, equivalently the uniform PMF on the complete output vector.  The
SMZ9 instantiation fixes that count at 12,201 field coins.

Nothing here certifies `getrandom`, a caller-supplied `CryptoRng`, Rayon scheduling, provider
availability, or a global byte order across concurrent calls.  `epsilonFieldOutputStatistical` is
the exact statistical event distance between a caller-supplied successful *field-output* law and
the proved ideal law; it excludes the salt and leaf tapes.  The repository supplies no bound on
that narrow term.  Production additionally needs a quantum-computational distinguishing bound for
the complete joint field, salt, and tape law.  The model is an extensional finite-terminating-trace
characterization, not a construction of an OS-backed infinite stream or its stopping-time measure.
-/

namespace HegemonCrypto
namespace SmallWood
namespace V8Smz9RuntimeDistribution

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9RuntimeRandomness
open scoped ENNReal BigOperators

noncomputable def uniformFintypePMF (alpha : Type*) [Fintype alpha] [Nonempty alpha] : PMF alpha :=
  ⟨fun _ => (Fintype.card alpha : ℝ≥0∞)⁻¹, by
    convert hasSum_fintype (fun _ : alpha => (Fintype.card alpha : ℝ≥0∞)⁻¹) using 1
    simp only [Finset.sum_const, nsmul_eq_mul]
    symm
    apply ENNReal.mul_inv_cancel
    · simp
    · simp⟩

@[simp] theorem uniformFintypePMF_apply
    (alpha : Type*) [Fintype alpha] [Nonempty alpha] (a : alpha) :
    uniformFintypePMF alpha a = (Fintype.card alpha : ℝ≥0∞)⁻¹ := rfl

noncomputable def pmfMap {alpha beta : Type*} (p : PMF alpha) (f : alpha → beta) : PMF beta :=
  p.bind (PMF.pure ∘ f)

open scoped Classical in
theorem pmfMap_apply {alpha beta : Type*} (p : PMF alpha) (f : alpha → beta) (b : beta) :
    pmfMap p f b = ∑' a, if b = f a then p a else 0 := by
  simp [pmfMap, PMF.bind_apply, Function.comp_def]

theorem pmfMap_bind {alpha beta gamma : Type*}
    (p : PMF alpha) (f : alpha → PMF beta) (g : beta → gamma) :
    pmfMap (p.bind f) g = p.bind fun a => pmfMap (f a) g := by
  exact PMF.bind_bind p f (PMF.pure ∘ g)

@[simp] theorem pmfMap_pure {alpha beta : Type*} (a : alpha) (f : alpha → beta) :
    pmfMap (PMF.pure a) f = PMF.pure (f a) := by
  simp [pmfMap, Function.comp_def]

@[simp] theorem pmfMap_id {alpha : Type*} (p : PMF alpha) :
    pmfMap p id = p := by
  change p.bind PMF.pure = p
  exact PMF.bind_pure p

theorem pmfMap_comp {alpha beta gamma : Type*}
    (p : PMF alpha) (f : alpha → beta) (g : beta → gamma) :
    pmfMap (pmfMap p f) g = pmfMap p (g ∘ f) := by
  simp [pmfMap, PMF.bind_bind, Function.comp_def]

instance : Nonempty RejectedRawWord :=
  ⟨⟨⟨fieldModulus, field_modulus_lt_raw_word_cardinality⟩, le_rfl⟩⟩

instance : Nonempty AcceptedRawWord := ⟨acceptedRawWordEquiv 0⟩

/-- Actual typed proposal trace conditioned on first acceptance at index `attempt`. -/
abbrev ExactAttemptTrace (attempt : Nat) := RejectedPrefix attempt × AcceptedRawWord

def exactAttemptCandidates {attempt : Nat} (trace : ExactAttemptTrace attempt) : List RawWord :=
  (List.ofFn trace.1).map Subtype.val ++ [trace.2.val]

def exactAttemptOutput {attempt : Nat} (trace : ExactAttemptTrace attempt) : IdealFieldCoin :=
  acceptedRawWordEquiv.symm trace.2

theorem exact_attempt_candidates_return_output {attempt : Nat}
    (trace : ExactAttemptTrace attempt) :
    firstAccepted (exactAttemptCandidates trace) = some (exactAttemptOutput trace) := by
  change firstAccepted
      ((List.ofFn trace.1).map Subtype.val ++ [encodeCoin (acceptedRawWordEquiv.symm trace.2)]) = _
  exact first_accepted_after_rejected_prefix (List.ofFn trace.1)
    (acceptedRawWordEquiv.symm trace.2)

/-- Conditional law of iid uniform raw proposals given first acceptance at `attempt`.
It samples the rejected and accepted raw-word subtypes, never an output coin directly. -/
noncomputable def exactAttemptConditionalPMF (attempt : Nat) : PMF (ExactAttemptTrace attempt) :=
  (uniformFintypePMF (RejectedPrefix attempt)).bind fun rejected =>
    pmfMap (uniformFintypePMF AcceptedRawWord) fun accepted => (rejected, accepted)

theorem uniform_accepted_word_pushforward :
    pmfMap (uniformFintypePMF AcceptedRawWord) acceptedRawWordEquiv.symm =
      uniformFintypePMF IdealFieldCoin := by
  apply PMF.ext
  intro coin
  rw [pmfMap_apply]
  simp only [uniformFintypePMF_apply, tsum_fintype]
  rw [Finset.sum_eq_single (acceptedRawWordEquiv coin)]
  · rw [Fintype.card_congr acceptedRawWordEquiv]
    rw [if_pos (acceptedRawWordEquiv.symm_apply_apply coin).symm]
  · intro candidate _ candidate_ne
    rw [if_neg]
    intro equality
    apply candidate_ne
    have mapped := congrArg acceptedRawWordEquiv equality
    simpa using mapped.symm
  · intro not_mem
    exact (not_mem (Finset.mem_univ _)).elim

theorem accepted_pair_map_apply_self
    {attempt : Nat} (rejected : RejectedPrefix attempt) (accepted : AcceptedRawWord) :
    pmfMap (uniformFintypePMF AcceptedRawWord) (fun word => (rejected, word))
        (rejected, accepted) =
      (Fintype.card AcceptedRawWord : ℝ≥0∞)⁻¹ := by
  rw [pmfMap_apply, tsum_fintype]
  rw [Finset.sum_eq_single accepted]
  · rw [if_pos rfl, uniformFintypePMF_apply]
  · intro other _ other_ne
    rw [if_neg]
    intro equality
    exact other_ne (Prod.mk.inj equality).2.symm
  · intro not_mem
    exact (not_mem (Finset.mem_univ _)).elim

theorem accepted_pair_map_apply_of_rejected_ne
    {attempt : Nat} {rejected targetRejected : RejectedPrefix attempt}
    (hne : targetRejected ≠ rejected)
    (targetAccepted : AcceptedRawWord) :
    pmfMap (uniformFintypePMF AcceptedRawWord) (fun word => (rejected, word))
        (targetRejected, targetAccepted) = 0 := by
  rw [pmfMap_apply, tsum_fintype]
  apply Finset.sum_eq_zero
  intro accepted _
  rw [if_neg]
  intro equality
  exact hne (Prod.mk.inj equality).1

theorem exact_attempt_conditional_trace_mass
    (attempt : Nat) (trace : ExactAttemptTrace attempt) :
    exactAttemptConditionalPMF attempt trace =
      (Fintype.card (RejectedPrefix attempt) : ℝ≥0∞)⁻¹ *
        (Fintype.card AcceptedRawWord : ℝ≥0∞)⁻¹ := by
  rw [exactAttemptConditionalPMF, PMF.bind_apply, tsum_fintype]
  rw [Finset.sum_eq_single trace.1]
  · rw [uniformFintypePMF_apply, accepted_pair_map_apply_self]
  · intro rejected _ rejected_ne
    rw [accepted_pair_map_apply_of_rejected_ne rejected_ne.symm, mul_zero]
  · intro not_mem
    exact (not_mem (Finset.mem_univ _)).elim

theorem exact_attempt_conditional_trace_mass_geometry
    (attempt : Nat) (trace : ExactAttemptTrace attempt) :
    exactAttemptConditionalPMF attempt trace =
      (rejectedWordCount : ℝ≥0∞)⁻¹ ^ attempt * (fieldModulus : ℝ≥0∞)⁻¹ := by
  rw [exact_attempt_conditional_trace_mass, exact_attempt_fiber_cardinality,
    accepted_raw_word_cardinality, Nat.cast_pow, ENNReal.inv_pow]

theorem exact_attempt_conditional_output_uniform (attempt : Nat) :
    pmfMap (exactAttemptConditionalPMF attempt) exactAttemptOutput =
      uniformFintypePMF IdealFieldCoin := by
  rw [exactAttemptConditionalPMF, pmfMap_bind]
  conv_rhs => rw [← PMF.bind_const (uniformFintypePMF (RejectedPrefix attempt))
    (uniformFintypePMF IdealFieldCoin)]
  apply congrArg (PMF.bind (uniformFintypePMF (RejectedPrefix attempt)))
  funext rejected
  rw [pmfMap_comp]
  change pmfMap (uniformFintypePMF AcceptedRawWord) acceptedRawWordEquiv.symm = _
  exact uniform_accepted_word_pushforward

noncomputable def idealRejectionRatioENN : ℝ≥0∞ :=
  ENNReal.ofReal idealRejectionRatio

theorem ideal_rejection_ratio_enn_lt_one : idealRejectionRatioENN < 1 := by
  exact ENNReal.ofReal_lt_one.mpr ideal_rejection_ratio_lt_one

theorem ideal_rejection_ratio_enn_eq_raw_fraction :
    idealRejectionRatioENN =
      (rejectedWordCount : ℝ≥0∞) / (rawWordCardinality : ℝ≥0∞) := by
  rw [idealRejectionRatioENN, idealRejectionRatio]
  rw [ENNReal.ofReal_div_of_pos]
  · norm_num
  · norm_num [rawWordCardinality]

noncomputable def idealAcceptanceRatioENN : ℝ≥0∞ := 1 - idealRejectionRatioENN

theorem ideal_acceptance_ratio_enn_eq_raw_fraction :
    idealAcceptanceRatioENN =
      (fieldModulus : ℝ≥0∞) / (rawWordCardinality : ℝ≥0∞) := by
  calc
    idealAcceptanceRatioENN = ENNReal.ofReal (1 - idealRejectionRatio) := by
      rw [idealAcceptanceRatioENN, idealRejectionRatioENN,
        ENNReal.ofReal_sub 1 ideal_rejection_ratio_nonnegative]
      norm_num
    _ = ENNReal.ofReal (fieldModulus / rawWordCardinality : ℝ) := by
      congr 1
      norm_num [idealRejectionRatio, rejectedWordCount, rawWordCardinality,
        fieldModulus, goldilocksModulus]
    _ = (fieldModulus : ℝ≥0∞) / (rawWordCardinality : ℝ≥0∞) := by
      rw [ENNReal.ofReal_div_of_pos]
      · norm_num
      · norm_num [rawWordCardinality]

/-- Exact geometric law of failures before the first acceptance under iid uniform raw words. -/
noncomputable def iidUniformFirstAcceptanceAttemptPMF : PMF Nat :=
  ⟨fun attempt => idealRejectionRatioENN ^ attempt * idealAcceptanceRatioENN,
    ENNReal.summable.hasSum_iff.mpr <| by
    rw [ENNReal.tsum_mul_right, ENNReal.tsum_geometric]
    unfold idealAcceptanceRatioENN
    exact ENNReal.inv_mul_cancel
      (ne_of_gt (tsub_pos_iff_lt.mpr ideal_rejection_ratio_enn_lt_one))
      (ne_of_lt (lt_of_le_of_lt (tsub_le_self : 1 - idealRejectionRatioENN ≤ 1)
        ENNReal.one_lt_top))⟩

@[simp] theorem iid_uniform_first_acceptance_attempt_mass (attempt : Nat) :
    iidUniformFirstAcceptanceAttemptPMF attempt =
      idealRejectionRatioENN ^ attempt * idealAcceptanceRatioENN := rfl

/-- A real terminating rejection trace: a stopping index and all typed raw proposals at it. -/
abbrev IidUniformTerminatingTrace := Σ attempt, ExactAttemptTrace attempt

def iidUniformTraceCandidates (trace : IidUniformTerminatingTrace) : List RawWord :=
  exactAttemptCandidates trace.2

def iidUniformTraceOutput (trace : IidUniformTerminatingTrace) : IdealFieldCoin :=
  exactAttemptOutput trace.2

theorem iid_uniform_trace_candidates_return_output (trace : IidUniformTerminatingTrace) :
    firstAccepted (iidUniformTraceCandidates trace) = some (iidUniformTraceOutput trace) := by
  exact exact_attempt_candidates_return_output trace.2

/-- Normalized trace law induced by iid uniform raw proposals and first-accept rejection. -/
noncomputable def iidUniformRejectionTracePMF : PMF IidUniformTerminatingTrace :=
  iidUniformFirstAcceptanceAttemptPMF.bind fun attempt =>
    pmfMap (exactAttemptConditionalPMF attempt) (Sigma.mk attempt)

/--
Every concrete terminating trace has its exact geometric-attempt mass times its exact conditional
raw-trace mass.  This is the iid raw-proposal factorization; the output coin is not sampled here.
-/
theorem iid_uniform_rejection_trace_mass_factorization
    (trace : IidUniformTerminatingTrace) :
    iidUniformRejectionTracePMF trace =
      iidUniformFirstAcceptanceAttemptPMF trace.1 *
        exactAttemptConditionalPMF trace.1 trace.2 := by
  rcases trace with ⟨attempt, trace⟩
  rw [iidUniformRejectionTracePMF, PMF.bind_apply]
  rw [tsum_eq_single attempt]
  · congr 1
    rw [pmfMap_apply]
    rw [tsum_eq_single trace]
    · rw [if_pos rfl]
    · intro candidate candidate_ne
      rw [if_neg]
      intro equality
      cases equality
      exact candidate_ne rfl
  · intro attempt attempt_ne
    rw [mul_eq_zero]
    right
    rw [pmfMap_apply]
    apply ENNReal.tsum_eq_zero.mpr
    intro candidate
    rw [if_neg]
    intro equality
    apply attempt_ne
    exact (congrArg Sigma.fst equality).symm

theorem iid_uniform_rejection_trace_mass
    (trace : IidUniformTerminatingTrace) :
    iidUniformRejectionTracePMF trace =
      idealRejectionRatioENN ^ trace.1 * idealAcceptanceRatioENN *
        ((rejectedWordCount : ℝ≥0∞)⁻¹ ^ trace.1 *
          (fieldModulus : ℝ≥0∞)⁻¹) := by
  rw [iid_uniform_rejection_trace_mass_factorization,
    iid_uniform_first_acceptance_attempt_mass,
    exact_attempt_conditional_trace_mass_geometry]

/-- Each terminating trace has exactly the iid raw-word cylinder mass for its full prefix. -/
theorem iid_uniform_rejection_trace_mass_eq_iid_raw_prefix
    (trace : IidUniformTerminatingTrace) :
    iidUniformRejectionTracePMF trace =
      (rawWordCardinality : ℝ≥0∞)⁻¹ ^ (trace.1 + 1) := by
  rw [iid_uniform_rejection_trace_mass,
    ideal_rejection_ratio_enn_eq_raw_fraction,
    ideal_acceptance_ratio_enn_eq_raw_fraction]
  rw [ENNReal.div_eq_inv_mul, ENNReal.div_eq_inv_mul, pow_succ]
  calc
    ((rawWordCardinality : ℝ≥0∞)⁻¹ * rejectedWordCount) ^ trace.1 *
          ((rawWordCardinality : ℝ≥0∞)⁻¹ * fieldModulus) *
          ((rejectedWordCount : ℝ≥0∞)⁻¹ ^ trace.1 *
            (fieldModulus : ℝ≥0∞)⁻¹) =
        ((rejectedWordCount : ℝ≥0∞) * (rejectedWordCount : ℝ≥0∞)⁻¹) ^
            trace.1 *
          ((fieldModulus : ℝ≥0∞) * (fieldModulus : ℝ≥0∞)⁻¹) *
          (((rawWordCardinality : ℝ≥0∞)⁻¹ ^ trace.1) *
            (rawWordCardinality : ℝ≥0∞)⁻¹) := by ring
    _ = (rawWordCardinality : ℝ≥0∞)⁻¹ ^ trace.1 *
          (rawWordCardinality : ℝ≥0∞)⁻¹ := by
      rw [ENNReal.mul_inv_cancel, ENNReal.mul_inv_cancel]
      · simp
      all_goals norm_num [rejectedWordCount, fieldModulus, goldilocksModulus]

/--
The exact iid cylinder masses uniquely determine the normalized law on finite terminating traces.
This is the precise bridge from the factorized construction to iid uniform raw proposals stopped
at their first accepted word; it does not identify any concrete entropy provider with that law.
-/
theorem iid_uniform_rejection_trace_law_unique
    (law : PMF IidUniformTerminatingTrace)
    (hasIidTerminatingMass :
      ∀ trace, law trace =
        (rawWordCardinality : ℝ≥0∞)⁻¹ ^ (trace.1 + 1)) :
    law = iidUniformRejectionTracePMF := by
  apply PMF.ext
  intro trace
  rw [hasIidTerminatingMass trace,
    iid_uniform_rejection_trace_mass_eq_iid_raw_prefix trace]

theorem iid_uniform_rejection_output_law :
    pmfMap iidUniformRejectionTracePMF iidUniformTraceOutput =
      uniformFintypePMF IdealFieldCoin := by
  rw [iidUniformRejectionTracePMF, pmfMap_bind]
  conv_rhs => rw [← PMF.bind_const iidUniformFirstAcceptanceAttemptPMF
    (uniformFintypePMF IdealFieldCoin)]
  apply congrArg (PMF.bind iidUniformFirstAcceptanceAttemptPMF)
  funext attempt
  rw [pmfMap_comp]
  change pmfMap (exactAttemptConditionalPMF attempt) exactAttemptOutput = _
  exact exact_attempt_conditional_output_uniform attempt

noncomputable def iidFinitePMF {alpha : Type*} (p : PMF alpha) :
    (count : Nat) → PMF (Fin count → alpha)
  | 0 => PMF.pure Fin.elim0
  | count + 1 =>
      p.bind fun head =>
        pmfMap (iidFinitePMF p count) fun tail => Fin.cons head tail

open scoped Classical in
theorem pmfMap_fin_cons_apply {alpha : Type*} {count : Nat} (p : PMF (Fin count → alpha))
    (head : alpha) (xs : Fin (count + 1) → alpha) :
    pmfMap p (fun tail => Fin.cons head tail) xs =
      if xs 0 = head then p (Fin.tail xs) else 0 := by
  rw [pmfMap_apply]
  by_cases first_eq : xs 0 = head
  · rw [if_pos first_eq, tsum_eq_single (Fin.tail xs)]
    · rw [if_pos]
      funext index
      refine Fin.cases ?_ ?_ index
      · exact first_eq
      · intro i
        rfl
    · intro tail tail_ne
      rw [if_neg]
      intro equality
      apply tail_ne
      funext i
      exact (congrFun equality i.succ).symm
  · rw [if_neg first_eq]
    apply ENNReal.tsum_eq_zero.mpr
    intro tail
    rw [if_neg]
    intro equality
    apply first_eq
    exact congrFun equality 0

open scoped Classical in
theorem iidFinitePMF_apply {alpha : Type*} (p : PMF alpha) :
    ∀ (count : Nat) (xs : Fin count → alpha),
      iidFinitePMF p count xs = ∏ index, p (xs index) := by
  intro count
  induction count with
  | zero =>
      intro xs
      have xs_eq : xs = Fin.elim0 := Subsingleton.elim _ _
      subst xs
      rw [iidFinitePMF, PMF.pure_apply_self]
      simp
  | succ count inductionHypothesis =>
      intro xs
      rw [iidFinitePMF, PMF.bind_apply]
      simp_rw [pmfMap_fin_cons_apply]
      rw [tsum_eq_single (xs 0)]
      · rw [if_pos rfl, inductionHypothesis, Fin.prod_univ_succ]
        congr 1
      · intro head head_ne
        rw [if_neg head_ne.symm, mul_zero]

theorem iidFinitePMF_map {alpha beta : Type*} (f : alpha → beta) (p : PMF alpha) :
    ∀ count,
      pmfMap (iidFinitePMF p count) (fun xs index => f (xs index)) =
        iidFinitePMF (pmfMap p f) count := by
  intro count
  induction count with
  | zero =>
      rw [iidFinitePMF, pmfMap_pure, iidFinitePMF]
      congr 1
      funext index
      exact Fin.elim0 index
  | succ count inductionHypothesis =>
      rw [iidFinitePMF, pmfMap_bind, iidFinitePMF]
      change
        (p.bind fun head =>
          pmfMap (pmfMap (iidFinitePMF p count) (fun tail => Fin.cons head tail))
            (fun xs index => f (xs index))) =
          (p.bind (PMF.pure ∘ f)).bind fun head =>
            pmfMap (iidFinitePMF (pmfMap p f) count) fun tail => Fin.cons head tail
      rw [PMF.bind_bind]
      simp only [PMF.pure_bind, Function.comp_apply]
      apply congrArg (PMF.bind p)
      funext head
      have map_after_cons :
          ((fun xs : Fin (count + 1) → alpha => fun index => f (xs index)) ∘
              fun tail : Fin count → alpha => Fin.cons head tail) =
            ((fun tail : Fin count → beta => Fin.cons (f head) tail) ∘
              fun tail : Fin count → alpha => fun index => f (tail index)) := by
        funext tail index
        refine Fin.cases ?_ ?_ index
        · rfl
        · intro i
          rfl
      rw [pmfMap_comp, map_after_cons, ← pmfMap_comp, inductionHypothesis]

theorem iidFiniteUniformPMF_eq_uniformFintype
    (alpha : Type*) [Fintype alpha] [Nonempty alpha] (count : Nat) :
    iidFinitePMF (uniformFintypePMF alpha) count =
      uniformFintypePMF (Fin count → alpha) := by
  apply PMF.ext
  intro xs
  rw [iidFinitePMF_apply, uniformFintypePMF_apply]
  simp_rw [uniformFintypePMF_apply]
  simp only [Finset.prod_const, Finset.card_univ, Fintype.card_fin, Fintype.card_fun,
    Nat.cast_pow, ENNReal.inv_pow]

noncomputable def iidUniformRejectionTraceVectorPMF (count : Nat) :
    PMF (Fin count → IidUniformTerminatingTrace) :=
  iidFinitePMF iidUniformRejectionTracePMF count

noncomputable def iidUniformRejectionSamplerOutputPMF (count : Nat) :
    PMF (RuntimeFieldCoins count) :=
  pmfMap (iidUniformRejectionTraceVectorPMF count) fun traces index =>
    iidUniformTraceOutput (traces index)

/-- Independent repetition gives the product of the exact iid raw-prefix masses. -/
theorem iid_uniform_rejection_trace_vector_mass
    (count : Nat) (traces : Fin count → IidUniformTerminatingTrace) :
    iidUniformRejectionTraceVectorPMF count traces =
      ∏ index, (rawWordCardinality : ℝ≥0∞)⁻¹ ^ ((traces index).1 + 1) := by
  rw [iidUniformRejectionTraceVectorPMF, iidFinitePMF_apply]
  simp_rw [iid_uniform_rejection_trace_mass_eq_iid_raw_prefix]

/-- The generic finite rejection-sampler output law is the independent product of uniforms. -/
theorem iid_uniform_rejection_outputs (count : Nat) :
    iidUniformRejectionSamplerOutputPMF count =
      iidFinitePMF (uniformFintypePMF IdealFieldCoin) count := by
  rw [iidUniformRejectionSamplerOutputPMF, iidUniformRejectionTraceVectorPMF,
    iidFinitePMF_map, iid_uniform_rejection_output_law]

/-- Equivalent joint formulation: every finite output vector is uniformly distributed. -/
theorem iid_uniform_rejection_output_vector_uniform (count : Nat) :
    iidUniformRejectionSamplerOutputPMF count =
      uniformFintypePMF (RuntimeFieldCoins count) := by
  rw [iid_uniform_rejection_outputs,
    iidFiniteUniformPMF_eq_uniformFintype IdealFieldCoin count]

theorem iid_uniform_rejection_output_vector_mass
    (count : Nat) (outputs : RuntimeFieldCoins count) :
    iidUniformRejectionSamplerOutputPMF count outputs =
      (fieldModulus : ℝ≥0∞) ⁻¹ ^ count := by
  rw [iid_uniform_rejection_output_vector_uniform, uniformFintypePMF_apply,
    runtime_field_coin_space_cardinality, Nat.cast_pow, ENNReal.inv_pow]

theorem exact_smz9_iid_uniform_rejection_output_law :
    iidUniformRejectionSamplerOutputPMF honestAlgebraicFieldCoinCount =
      uniformFintypePMF (RuntimeFieldCoins honestAlgebraicFieldCoinCount) :=
  iid_uniform_rejection_output_vector_uniform honestAlgebraicFieldCoinCount

theorem exact_smz9_iid_uniform_rejection_output_mass
    (outputs : RuntimeFieldCoins honestAlgebraicFieldCoinCount) :
    iidUniformRejectionSamplerOutputPMF honestAlgebraicFieldCoinCount outputs =
      (fieldModulus : ℝ≥0∞) ⁻¹ ^ 12201 := by
  rw [iid_uniform_rejection_output_vector_mass]
  have count_eq : honestAlgebraicFieldCoinCount = 12201 := by decide
  rw [count_eq]

/-- Event mass for a discrete probability law. -/
noncomputable def pmfEventMass {alpha : Type*} (p : PMF alpha) (event : Set alpha) : ℝ≥0∞ := by
  classical
  exact ∑' value, if value ∈ event then p value else 0

/-- Exact statistical event distance for two discrete laws. -/
noncomputable def pmfStatisticalDistance {alpha : Type*} (actual ideal : PMF alpha) : ℝ≥0∞ :=
  ⨆ event : Set alpha,
    max (pmfEventMass actual event - pmfEventMass ideal event)
      (pmfEventMass ideal event - pmfEventMass actual event)

/--
Narrow statistical distance for the successful 12,201-field-output law.  The repository proves
the ideal second argument above; it supplies no bound connecting the OS-backed runtime law
`actual` to it.  This definition does not include the salt or leaf tapes and is not the required
quantum-computational full-RNG advantage.
-/
noncomputable def epsilonFieldOutputStatistical
    (actual : PMF (RuntimeFieldCoins honestAlgebraicFieldCoinCount)) : ℝ≥0∞ :=
  pmfStatisticalDistance actual
    (iidUniformRejectionSamplerOutputPMF honestAlgebraicFieldCoinCount)

end V8Smz9RuntimeDistribution
end SmallWood
end HegemonCrypto
