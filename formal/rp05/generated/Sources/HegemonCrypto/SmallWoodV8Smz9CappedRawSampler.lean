import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler

/-!
# Finite capped rejection sampling, including the abort atom

Every probability below is the pushforward of one fixed finite iid raw-word
vector. No uncapped terminating-trace law or postselected-uniform premise is
used. Accepted and rejected machine words are separated by an exact finite
sum type; the source u64 encoding is connected separately.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CappedRawSampler

open V8Smz9RuntimeDistribution V8Smz9RawCounterCompiler
open scoped ENNReal BigOperators Classical

noncomputable section

set_option maxRecDepth 5000
set_option maxHeartbeats 1500000

abbrev SplitWord (accepted rejected : ℕ) := Fin accepted ⊕ Fin rejected
abbrev FieldOutput (accepted requested : ℕ) := Fin requested → Fin accepted

private theorem cardIndependent (Input : Type*) (left right : Fintype Input) :
    @Fintype.card Input left = @Fintype.card Input right :=
  congrArg (@Fintype.card Input) (Subsingleton.elim left right)

/-- Scan exactly the supplied finite vector, retaining `none` on exhaustion. -/
def scan (accepted rejected : ℕ) : (capacity requested : ℕ) →
    (Fin capacity → SplitWord accepted rejected) → Option (FieldOutput accepted requested)
  | _, 0, _ => some Fin.elim0
  | 0, _ + 1, _ => none
  | capacity + 1, requested + 1, raw =>
      match raw 0 with
      | .inl field => (scan accepted rejected capacity requested (Fin.tail raw)).map (Fin.cons field)
      | .inr _ => scan accepted rejected capacity (requested + 1) (Fin.tail raw)

def rawVectorLaw (accepted rejected capacity : ℕ) [NeZero accepted] :
    PMF (Fin capacity → SplitWord accepted rejected) :=
  iidFinitePMF (uniformFintypePMF (SplitWord accepted rejected)) capacity

def cappedLaw (accepted rejected capacity requested : ℕ) [NeZero accepted] :
    PMF (Option (FieldOutput accepted requested)) :=
  pmfMap (rawVectorLaw accepted rejected capacity) (scan accepted rejected capacity requested)

theorem raw_vector_law_is_uniform (accepted rejected capacity : ℕ) [NeZero accepted] :
    rawVectorLaw accepted rejected capacity =
      uniformFintypePMF (Fin capacity → SplitWord accepted rejected) :=
  iidFiniteUniformPMF_eq_uniformFintype (SplitWord accepted rejected) capacity

theorem capped_law_is_literal_finite_pushforward (accepted rejected capacity requested : ℕ)
    [NeZero accepted] :
    cappedLaw accepted rejected capacity requested =
      pmfMap (uniformFintypePMF (Fin capacity → SplitWord accepted rejected))
        (scan accepted rejected capacity requested) := by
  rw [cappedLaw, raw_vector_law_is_uniform]

theorem capped_law_zero_request (accepted rejected capacity : ℕ) [NeZero accepted] :
    cappedLaw accepted rejected capacity 0 = PMF.pure (some Fin.elim0) := by
  simp [cappedLaw, scan, pmfMap, Function.comp_def]

theorem capped_law_zero_capacity (accepted rejected requested : ℕ) [NeZero accepted] :
    cappedLaw accepted rejected 0 (requested + 1) = PMF.pure none := by
  simp [cappedLaw, rawVectorLaw, iidFinitePMF, pmfMap, scan, Function.comp_def]

theorem capped_law_step (accepted rejected capacity requested : ℕ) [NeZero accepted] :
    cappedLaw accepted rejected (capacity + 1) (requested + 1) =
      (uniformFintypePMF (SplitWord accepted rejected)).bind fun raw =>
        match raw with
        | .inl field => pmfMap (cappedLaw accepted rejected capacity requested)
            (fun output => output.map (Fin.cons field))
        | .inr _ => cappedLaw accepted rejected capacity (requested + 1) := by
  unfold cappedLaw rawVectorLaw
  rw [iidFinitePMF, pmfMap_bind]
  apply congrArg (PMF.bind (uniformFintypePMF (SplitWord accepted rejected)))
  funext head
  rw [pmfMap_comp]
  cases head with
  | inl field =>
    dsimp only
    rw [pmfMap_comp]
    rfl
  | inr rejectedWord => rfl

theorem map_prepend_some_mass {accepted requested : ℕ}
    (law : PMF (Option (FieldOutput accepted requested)))
    (head : Fin accepted) (output : FieldOutput accepted (requested + 1)) :
    pmfMap law (fun tail => tail.map (Fin.cons head)) (some output) =
      if output 0 = head then law (some (Fin.tail output)) else 0 := by
  rw [pmfMap_apply]
  by_cases first : output 0 = head
  · rw [if_pos first, tsum_eq_single (some (Fin.tail output))]
    · rw [if_pos]
      congr 1
      rw [← first, Fin.cons_self_tail]
    · intro other different
      rw [if_neg]
      intro equal
      cases other with
      | none => simp at equal
      | some tail =>
        apply different
        congr 1
        funext index
        change tail index = output index.succ
        have values := congrArg (fun option => option.map (fun vector => vector index.succ)) equal
        simpa using values.symm
  · rw [if_neg first]
    apply ENNReal.tsum_eq_zero.mpr
    intro other
    rw [if_neg]
    intro equal
    cases other with
    | none => simp at equal
    | some tail =>
      apply first
      have values := congrArg (fun option => option.map (fun vector => vector 0)) equal
      simpa using values

theorem map_prepend_none_mass {accepted requested : ℕ}
    (law : PMF (Option (FieldOutput accepted requested))) (head : Fin accepted) :
    pmfMap law (fun tail => tail.map (Fin.cons head))
      (none : Option (FieldOutput accepted (requested + 1))) = law none := by
  rw [pmfMap_apply, tsum_eq_single none]
  · simp
  · intro other different
    cases other with
    | none => contradiction
    | some tail => simp

def wordPointMass (accepted rejected : ℕ) : ℝ≥0∞ := ((accepted + rejected : ℕ) : ℝ≥0∞)⁻¹
def rejectionMass (accepted rejected : ℕ) : ℝ≥0∞ := rejected * wordPointMass accepted rejected
def acceptanceMass (accepted rejected : ℕ) : ℝ≥0∞ := accepted * wordPointMass accepted rejected

theorem capped_some_mass_step (accepted rejected capacity requested : ℕ) [NeZero accepted]
    (output : FieldOutput accepted (requested + 1)) :
    cappedLaw accepted rejected (capacity + 1) (requested + 1) (some output) =
      rejectionMass accepted rejected * cappedLaw accepted rejected capacity (requested + 1) (some output) +
        wordPointMass accepted rejected * cappedLaw accepted rejected capacity requested (some (Fin.tail output)) := by
  rw [capped_law_step, PMF.bind_apply, tsum_fintype, Fintype.sum_sum_type]
  simp only [uniformFintypePMF_apply, Fintype.card_sum, Fintype.card_fin, map_prepend_some_mass]
  simp [wordPointMass, rejectionMass, mul_assoc, add_comm]

theorem capped_none_mass_step (accepted rejected capacity requested : ℕ) [NeZero accepted] :
    cappedLaw accepted rejected (capacity + 1) (requested + 1) none =
      rejectionMass accepted rejected * cappedLaw accepted rejected capacity (requested + 1) none +
        acceptanceMass accepted rejected * cappedLaw accepted rejected capacity requested none := by
  rw [capped_law_step, PMF.bind_apply, tsum_fintype, Fintype.sum_sum_type]
  simp only [uniformFintypePMF_apply, Fintype.card_sum, Fintype.card_fin, map_prepend_none_mass]
  simp [wordPointMass, rejectionMass, acceptanceMass, mul_assoc, add_comm]

/-- Per-successful-output mass, computed from the finite vector recursion. -/
def successfulPointMass (accepted rejected : ℕ) : ℕ → ℕ → ℝ≥0∞
  | _, 0 => 1
  | 0, _ + 1 => 0
  | capacity + 1, requested + 1 =>
      rejectionMass accepted rejected * successfulPointMass accepted rejected capacity (requested + 1) +
        wordPointMass accepted rejected * successfulPointMass accepted rejected capacity requested

def abortMass (accepted rejected : ℕ) : ℕ → ℕ → ℝ≥0∞
  | _, 0 => 0
  | 0, _ + 1 => 1
  | capacity + 1, requested + 1 =>
      rejectionMass accepted rejected * abortMass accepted rejected capacity (requested + 1) +
        acceptanceMass accepted rejected * abortMass accepted rejected capacity requested

theorem same_finite_vector_successful_output_mass (accepted rejected capacity requested : ℕ)
    [NeZero accepted] (output : FieldOutput accepted requested) :
    cappedLaw accepted rejected capacity requested (some output) =
      successfulPointMass accepted rejected capacity requested := by
  induction capacity generalizing requested with
  | zero =>
    cases requested with
    | zero => simp [capped_law_zero_request, successfulPointMass, Subsingleton.elim output Fin.elim0]
    | succ requested => simp [capped_law_zero_capacity, successfulPointMass]
  | succ capacity induction =>
    cases requested with
    | zero => simp [capped_law_zero_request, successfulPointMass, Subsingleton.elim output Fin.elim0]
    | succ requested => rw [capped_some_mass_step, induction, induction, successfulPointMass]

theorem same_finite_vector_abort_mass (accepted rejected capacity requested : ℕ)
    [NeZero accepted] : cappedLaw accepted rejected capacity requested none =
      abortMass accepted rejected capacity requested := by
  induction capacity generalizing requested with
  | zero =>
    cases requested with
    | zero => simp [capped_law_zero_request, abortMass]
    | succ requested => simp [capped_law_zero_capacity, abortMass]
  | succ capacity induction =>
    cases requested with
    | zero => simp [capped_law_zero_request, abortMass]
    | succ requested => rw [capped_none_mass_step, induction, induction, abortMass]

def successMass (accepted rejected capacity requested : ℕ) : ℝ≥0∞ :=
  (accepted : ℝ≥0∞) ^ requested * successfulPointMass accepted rejected capacity requested

theorem finite_success_abort_normalization (accepted rejected capacity requested : ℕ)
    [NeZero accepted] :
    abortMass accepted rejected capacity requested + successMass accepted rejected capacity requested = 1 := by
  have total := (cappedLaw accepted rejected capacity requested).tsum_coe
  rw [tsum_fintype, Fintype.sum_option] at total
  simp only [same_finite_vector_abort_mass, same_finite_vector_successful_output_mass,
    Finset.sum_const, Finset.card_univ, FieldOutput, Fintype.card_fun, Fintype.card_fin,
    nsmul_eq_mul, Nat.cast_pow] at total
  exact total

theorem successful_mass_is_success_weight_times_uniform (accepted rejected capacity requested : ℕ)
    [NeZero accepted] (output : FieldOutput accepted requested) :
    cappedLaw accepted rejected capacity requested (some output) =
      successMass accepted rejected capacity requested *
        uniformFintypePMF (FieldOutput accepted requested) output := by
  rw [same_finite_vector_successful_output_mass]
  simp only [successMass, uniformFintypePMF_apply, FieldOutput, Fintype.card_fun,
    Fintype.card_fin, Nat.cast_pow]
  rw [mul_right_comm, ENNReal.mul_inv_cancel (by simp [NeZero.ne accepted]) (by simp), one_mul]

/-- Exact conditional uniformity, derived from the same finite raw vector.
The nonzero-success premise only makes conditioning defined; it is not a
uniformity or sampler-refinement assumption. -/
theorem conditional_success_is_uniform (accepted rejected capacity requested : ℕ)
    [NeZero accepted] (positive : successMass accepted rejected capacity requested ≠ 0)
    (output : FieldOutput accepted requested) :
    cappedLaw accepted rejected capacity requested (some output) /
        successMass accepted rejected capacity requested =
      uniformFintypePMF (FieldOutput accepted requested) output := by
  have finite : successMass accepted rejected capacity requested ≠ ∞ := by
    have total := finite_success_abort_normalization accepted rejected capacity requested
    intro infinite
    rw [infinite, add_top] at total
    exact ENNReal.top_ne_one total
  rw [successful_mass_is_success_weight_times_uniform, mul_comm,
    ENNReal.mul_div_cancel_right positive finite]

theorem successful_point_mass_positive (accepted rejected capacity requested : ℕ)
    [NeZero accepted] (enough : requested ≤ capacity) :
    0 < successfulPointMass accepted rejected capacity requested := by
  induction capacity generalizing requested with
  | zero =>
    have zero : requested = 0 := by omega
    simp [zero, successfulPointMass]
  | succ capacity induction =>
    cases requested with
    | zero => simp [successfulPointMass]
    | succ requested =>
      have tailPositive := induction requested (by omega)
      have pointPositive : 0 < wordPointMass accepted rejected := by simp [wordPointMass]
      rw [successfulPointMass]
      positivity

theorem success_mass_positive (accepted rejected capacity requested : ℕ)
    [NeZero accepted] (enough : requested ≤ capacity) :
    0 < successMass accepted rejected capacity requested := by
  have pointPositive := successful_point_mass_positive accepted rejected capacity requested enough
  have acceptedPositive : 0 < (accepted : ℝ≥0∞) := by
    exact_mod_cast (Nat.pos_of_ne_zero (NeZero.ne accepted))
  unfold successMass
  positivity

/-- An integer count: each leading rejection has `rejected` choices and each
leading acceptance has `accepted` choices. The remaining vector stays finite. -/
def abortCount (accepted rejected : ℕ) : ℕ → ℕ → ℕ
  | _, 0 => 0
  | 0, _ + 1 => 1
  | capacity + 1, requested + 1 =>
      rejected * abortCount accepted rejected capacity (requested + 1) +
        accepted * abortCount accepted rejected capacity requested

theorem finite_abort_mass_integer_formula (accepted rejected capacity requested : ℕ) :
    abortMass accepted rejected capacity requested =
      (abortCount accepted rejected capacity requested : ℝ≥0∞) *
        wordPointMass accepted rejected ^ capacity := by
  induction capacity generalizing requested with
  | zero => cases requested <;> simp [abortMass, abortCount]
  | succ capacity induction =>
    cases requested with
    | zero => simp [abortMass, abortCount]
    | succ requested =>
      rw [abortMass, induction, induction, abortCount]
      simp only [Nat.cast_add, Nat.cast_mul, rejectionMass, acceptanceMass, pow_succ]
      ring

theorem same_finite_vector_abort_probability_formula (accepted rejected capacity requested : ℕ)
    [NeZero accepted] :
    cappedLaw accepted rejected capacity requested none =
      (abortCount accepted rejected capacity requested : ℝ≥0∞) /
        ((accepted + rejected : ℕ) : ℝ≥0∞) ^ capacity := by
  rw [same_finite_vector_abort_mass, finite_abort_mass_integer_formula]
  simp [wordPointMass, div_eq_mul_inv, ENNReal.inv_pow]

def acceptedCount {accepted rejected capacity : ℕ}
    (raw : Fin capacity → SplitWord accepted rejected) : ℕ :=
  ∑ index, match raw index with | .inl _ => 1 | .inr _ => 0

def rejectedCount {accepted rejected capacity : ℕ}
    (raw : Fin capacity → SplitWord accepted rejected) : ℕ :=
  ∑ index, match raw index with | .inl _ => 0 | .inr _ => 1

theorem accepted_rejected_count_partition {accepted rejected capacity : ℕ}
    (raw : Fin capacity → SplitWord accepted rejected) :
    acceptedCount raw + rejectedCount raw = capacity := by
  unfold acceptedCount rejectedCount
  rw [← Finset.sum_add_distrib]
  have each : ∀ index : Fin capacity,
      (match raw index with | .inl _ => 1 | .inr _ => 0) +
        (match raw index with | .inl _ => 0 | .inr _ => 1) = 1 := by
    intro index
    cases raw index <;> rfl
  simp only [each, Finset.sum_const, Finset.card_univ, Fintype.card_fin, smul_eq_mul, mul_one]

theorem scan_none_iff_insufficient (accepted rejected capacity requested : ℕ)
    (raw : Fin capacity → SplitWord accepted rejected) :
    scan accepted rejected capacity requested raw = none ↔ acceptedCount raw < requested := by
  induction capacity generalizing requested with
  | zero => cases requested <;> simp [scan, acceptedCount]
  | succ capacity induction =>
    cases requested with
    | zero => simp [scan]
    | succ requested =>
      have headTail : acceptedCount raw =
          (match raw 0 with | .inl _ => 1 | .inr _ => 0) + acceptedCount (Fin.tail raw) := by
        exact Fin.sum_univ_succ _
      cases first : raw 0 with
      | inl field =>
        simp only [scan, first, Option.map_eq_none_iff, induction]
        simp only [first] at headTail
        omega
      | inr rejectedWord =>
        simp only [scan, first, induction]
        simp only [first] at headTail
        omega

theorem scan_none_iff_rejection_threshold (accepted rejected capacity requested : ℕ)
    (raw : Fin capacity → SplitWord accepted rejected) (enoughCapacity : requested ≤ capacity) :
    scan accepted rejected capacity requested raw = none ↔ capacity - requested + 1 ≤ rejectedCount raw := by
  rw [scan_none_iff_insufficient]
  have partition := accepted_rejected_count_partition raw
  omega

theorem finite_uniform_pushforward_fiber_mass {Input Output : Type*}
    [Fintype Input] [Nonempty Input] (f : Input → Output) (output : Output) :
    pmfMap (uniformFintypePMF Input) f output =
      (Fintype.card { input : Input // f input = output } : ℝ≥0∞) *
        (Fintype.card Input : ℝ≥0∞)⁻¹ := by
  rw [pmfMap_apply, tsum_fintype, Fintype.card_subtype]
  simp only [uniformFintypePMF_apply, eq_comm (a := output)]
  rw [← Finset.sum_filter]
  simp

theorem abort_count_is_finite_vector_fiber_cardinality (accepted rejected capacity requested : ℕ)
    [NeZero accepted] :
    abortCount accepted rejected capacity requested =
      Fintype.card { raw : Fin capacity → SplitWord accepted rejected //
        scan accepted rejected capacity requested raw = none } := by
  have counted := finite_uniform_pushforward_fiber_mass
    (scan accepted rejected capacity requested) none
  rw [← capped_law_is_literal_finite_pushforward,
    same_finite_vector_abort_mass, finite_abort_mass_integer_formula] at counted
  simp only [Fintype.card_fun, Fintype.card_sum, Fintype.card_fin, Nat.cast_pow,
    ] at counted
  have scalarNonzero : wordPointMass accepted rejected ^ capacity ≠ 0 := by
    simp [wordPointMass]
  have scalarFinite : wordPointMass accepted rejected ^ capacity ≠ ∞ := by
    simp [wordPointMass, NeZero.ne accepted]
  have counted' :
      (abortCount accepted rejected capacity requested : ℝ≥0∞) * wordPointMass accepted rejected ^ capacity =
        (Fintype.card { raw : Fin capacity → SplitWord accepted rejected //
          scan accepted rejected capacity requested raw = none } : ℝ≥0∞) * wordPointMass accepted rejected ^ capacity := by
    convert counted using 1
    simp [wordPointMass, ENNReal.inv_pow]
    congr 2
    exact cardIndependent _ _ _
  have cancelled := ENNReal.mul_left_inj scalarNonzero scalarFinite |>.mp counted'
  exact_mod_cast cancelled

def decodeSplit {accepted rejected : ℕ} : SplitWord accepted rejected → Option (Fin accepted)
  | .inl field => some field
  | .inr _ => none

def splitAcceptedList {accepted rejected capacity : ℕ}
    (raw : Fin capacity → SplitWord accepted rejected) : List (Fin accepted) :=
  (List.ofFn raw).filterMap decodeSplit

theorem scan_exact_first_accepted_list (accepted rejected capacity requested : ℕ)
    (raw : Fin capacity → SplitWord accepted rejected) :
    (scan accepted rejected capacity requested raw).map List.ofFn =
      if requested ≤ (splitAcceptedList raw).length
        then some ((splitAcceptedList raw).take requested) else none := by
  induction capacity generalizing requested with
  | zero => cases requested <;> simp [scan, splitAcceptedList]
  | succ capacity induction =>
    cases requested with
    | zero => simp [scan]
    | succ requested =>
      have listHeadTail : splitAcceptedList raw =
          match raw 0 with
          | .inl field => field :: splitAcceptedList (Fin.tail raw)
          | .inr _ => splitAcceptedList (Fin.tail raw) := by
        rw [splitAcceptedList, List.ofFn_succ]
        cases raw 0 <;> rfl
      rw [listHeadTail]
      cases first : raw 0 with
      | inl field =>
        simp only [scan, first, Option.map_map, List.length_cons, Nat.add_le_add_iff_right, List.take_succ_cons]
        simp only [Function.comp_def]
        have mapped :
            (fun tail : FieldOutput accepted requested => List.ofFn (Fin.cons field tail)) =
              List.cons field ∘ List.ofFn := by funext tail; exact List.ofFn_cons field tail
        rw [mapped, ← Option.map_map, induction]
        split <;> rfl
      | inr rejectedWord => simp only [scan, first, induction]

abbrev sourceFieldSize : ℕ := V8Smz9RuntimeRandomness.fieldModulus
abbrev sourceRejectedSize : ℕ := V8Smz9RuntimeRandomness.rejectedWordCount

instance : NeZero sourceFieldSize := ⟨by decide⟩

/-- Exact accepted/rejected partition of the u64 interval, in its usual order. -/
def sourceWordEquiv : SplitWord sourceFieldSize sourceRejectedSize ≃ Fin (2 ^ 64) :=
  finSumFinEquiv.trans (finCongr (by decide : sourceFieldSize + sourceRejectedSize = 2 ^ 64))

theorem source_word_decode_is_canonical (word : SplitWord sourceFieldSize sourceRejectedSize) :
    decodeFieldWord (sourceWordEquiv word).val = decodeSplit word := by
  cases word with
  | inl field =>
    change (if canonical : field.val < sourceFieldSize then some ⟨field.val, canonical⟩ else none) = some field
    simp only [dif_pos field.isLt]
  | inr rejectedWord =>
    change decodeFieldWord (sourceFieldSize + rejectedWord.val) = none
    unfold decodeFieldWord
    rw [dif_neg (by change ¬ (sourceFieldSize + rejectedWord.val < sourceFieldSize); omega)]

def sourceVectorEquiv (capacity : ℕ) :
    (Fin capacity → SplitWord sourceFieldSize sourceRejectedSize) ≃
      (Fin capacity → Fin (2 ^ 64)) :=
  Equiv.piCongrRight fun _ => sourceWordEquiv

def sourceScan (capacity requested : ℕ) (raw : Fin capacity → Fin (2 ^ 64)) :
    Option (FieldOutput sourceFieldSize requested) :=
  scan sourceFieldSize sourceRejectedSize capacity requested ((sourceVectorEquiv capacity).symm raw)

def sourceCappedLaw (capacity requested : ℕ) : PMF (Option (FieldOutput sourceFieldSize requested)) :=
  pmfMap (uniformFintypePMF (Fin capacity → Fin (2 ^ 64))) (sourceScan capacity requested)

theorem literal_u64_capped_law (capacity requested : ℕ) :
    sourceCappedLaw capacity requested = cappedLaw sourceFieldSize sourceRejectedSize capacity requested := by
  have splitLaw := V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv (sourceVectorEquiv capacity).symm
  have pushed := congrArg
    (fun law => pmfMap law (scan sourceFieldSize sourceRejectedSize capacity requested)) splitLaw
  rw [pmfMap_comp, ← capped_law_is_literal_finite_pushforward] at pushed
  exact pushed

theorem literal_u64_success_is_uniform (capacity requested : ℕ) (enoughCapacity : requested ≤ capacity)
    (output : FieldOutput sourceFieldSize requested) :
    sourceCappedLaw capacity requested (some output) /
        successMass sourceFieldSize sourceRejectedSize capacity requested =
      uniformFintypePMF (FieldOutput sourceFieldSize requested) output := by
  rw [literal_u64_capped_law]
  exact conditional_success_is_uniform sourceFieldSize sourceRejectedSize capacity requested
    (ne_of_gt (success_mass_positive sourceFieldSize sourceRejectedSize capacity requested enoughCapacity)) output

theorem literal_u64_abort_probability (capacity requested : ℕ) :
    sourceCappedLaw capacity requested none =
      (abortCount sourceFieldSize sourceRejectedSize capacity requested : ℝ≥0∞) /
        (2 ^ 64 : ℝ≥0∞) ^ capacity := by
  rw [literal_u64_capped_law, same_finite_vector_abort_probability_formula]
  rw [show sourceFieldSize + sourceRejectedSize = 2 ^ 64 by decide, Nat.cast_pow, Nat.cast_ofNat]

theorem literal_u64_parser_first_prefix (capacity requested : ℕ) (raw : Fin capacity → Fin (2 ^ 64)) :
    (sourceScan capacity requested raw).map List.ofFn =
      let accepted := acceptedFieldWords ((List.ofFn raw).map Fin.val)
      if requested ≤ accepted.length then some (accepted.take requested) else none := by
  rw [sourceScan, scan_exact_first_accepted_list]
  have equalLists : splitAcceptedList ((sourceVectorEquiv capacity).symm raw) =
      acceptedFieldWords ((List.ofFn raw).map Fin.val) := by
    have rawDecode : ∀ word : Fin (2 ^ 64),
        decodeSplit (sourceWordEquiv.symm word) = decodeFieldWord word.val := by
      intro word
      simpa using (source_word_decode_is_canonical (sourceWordEquiv.symm word)).symm
    have splitList : List.ofFn ((sourceVectorEquiv capacity).symm raw) =
        (List.ofFn raw).map sourceWordEquiv.symm := by
      simp [List.map_ofFn, sourceVectorEquiv, Function.comp_def]
      funext index
      rfl
    rw [splitAcceptedList, splitList]
    simp only [acceptedFieldWords, List.filterMap_map, Function.comp_def, rawDecode]
  rw [equalLists]

abbrev RawWordBlock := Fin 8 → Fin (2 ^ 64)

/-- Counter-major, then word-major flattening of the same complete block vector. -/
def blockWordsEquiv (blocks : ℕ) :
    (Fin blocks → RawWordBlock) ≃ (Fin (blocks * 8) → Fin (2 ^ 64)) :=
  (Equiv.curry (Fin blocks) (Fin 8) (Fin (2 ^ 64))).symm.trans
    (Equiv.arrowCongr (finProdFinEquiv : Fin blocks × Fin 8 ≃ Fin (blocks * 8)) (Equiv.refl _))

theorem block_words_exact_coordinate {blocks : ℕ} (vector : Fin blocks → RawWordBlock)
    (counter : Fin blocks) (word : Fin 8) :
    blockWordsEquiv blocks vector (finProdFinEquiv (counter, word)) = vector counter word := by
  simp [blockWordsEquiv]

def blockCappedLaw (blocks requested : ℕ) : PMF (Option (FieldOutput sourceFieldSize requested)) :=
  pmfMap (uniformFintypePMF (Fin blocks → RawWordBlock))
    (fun vector => sourceScan (blocks * 8) requested (blockWordsEquiv blocks vector))

theorem same_uniform_blocks_capped_law (blocks requested : ℕ) :
    blockCappedLaw blocks requested = sourceCappedLaw (blocks * 8) requested := by
  have flatLaw := V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv (blockWordsEquiv blocks)
  have pushed := congrArg (fun law => pmfMap law (sourceScan (blocks * 8) requested)) flatLaw
  rw [pmfMap_comp] at pushed
  exact pushed

theorem same_uniform_blocks_conditional_output (blocks requested : ℕ)
    (enough : requested ≤ blocks * 8) (output : FieldOutput sourceFieldSize requested) :
    blockCappedLaw blocks requested (some output) /
      successMass sourceFieldSize sourceRejectedSize (blocks * 8) requested =
        uniformFintypePMF (FieldOutput sourceFieldSize requested) output := by
  rw [same_uniform_blocks_capped_law]
  exact literal_u64_success_is_uniform (blocks * 8) requested enough output

/-- Exact finite counting formula for the exhaustion event, without a
postselection or independent-sigma-field assumption. -/
theorem literal_u64_abort_is_rejection_tail_cardinality (capacity requested : ℕ)
    (enoughCapacity : requested ≤ capacity) :
    sourceCappedLaw capacity requested none =
      (Fintype.card { raw : Fin capacity → SplitWord sourceFieldSize sourceRejectedSize //
        capacity - requested + 1 ≤ rejectedCount raw } : ℝ≥0∞) /
          (2 ^ 64 : ℝ≥0∞) ^ capacity := by
  rw [literal_u64_abort_probability, abort_count_is_finite_vector_fiber_cardinality]
  congr 2
  apply Fintype.card_congr
  exact Equiv.subtypeEquivRight fun raw =>
    scan_none_iff_rejection_threshold sourceFieldSize sourceRejectedSize capacity requested raw enoughCapacity

theorem decs_92_block_abort_is_exact_37_rejection_event :
    blockCappedLaw 92 700 none =
      (Fintype.card { raw : Fin 736 → SplitWord sourceFieldSize sourceRejectedSize //
        37 ≤ rejectedCount raw } : ℝ≥0∞) / (2 ^ 64 : ℝ≥0∞) ^ 736 := by
  rw [same_uniform_blocks_capped_law]
  exact literal_u64_abort_is_rejection_tail_cardinality 736 700 (by decide)

/-- A 4150-word request is an example, not the general source gamma width. -/
theorem example_523_block_abort_is_exact_35_rejection_event :
    blockCappedLaw 523 4150 none =
      (Fintype.card { raw : Fin 4184 → SplitWord sourceFieldSize sourceRejectedSize //
        35 ≤ rejectedCount raw } : ℝ≥0∞) / (2 ^ 64 : ℝ≥0∞) ^ 4184 := by
  rw [same_uniform_blocks_capped_law]
  exact literal_u64_abort_is_rejection_tail_cardinality 4184 4150 (by decide)

theorem small_finite_count_regression : abortCount 2 1 3 2 = 7 := by decide

theorem decode_le_of_finite_bytes {count : ℕ} (bytes : Fin count → HegemonCrypto.CanonicalBytes.Byte) :
    HegemonCrypto.CanonicalBytes.decodeLE (List.ofFn bytes) =
      ∑ index, (bytes index).val * 256 ^ index.val := by
  induction count with
  | zero => simp [HegemonCrypto.CanonicalBytes.decodeLE]
  | succ count induction =>
    rw [List.ofFn_succ, HegemonCrypto.CanonicalBytes.decodeLE, induction, Fin.sum_univ_succ]
    simp only [Fin.val_zero, pow_zero, mul_one, Fin.val_succ]
    rw [Finset.mul_sum]
    congr 1
    apply Finset.sum_congr rfl
    intro index _
    rw [pow_succ]
    ring

/-- The standard little-endian eight-byte/u64 bijection. -/
def eightBytesWordEquiv : (Fin 8 → HegemonCrypto.CanonicalBytes.Byte) ≃ Fin (2 ^ 64) :=
  finFunctionFinEquiv.trans (finCongr (by decide : 256 ^ 8 = 2 ^ 64))

theorem eight_bytes_word_is_literal_le (bytes : Fin 8 → HegemonCrypto.CanonicalBytes.Byte) :
    (eightBytesWordEquiv bytes).val = HegemonCrypto.CanonicalBytes.decodeLE (List.ofFn bytes) := by
  rw [decode_le_of_finite_bytes]
  rfl

abbrev RawByteBlock := Fin 64 → HegemonCrypto.CanonicalBytes.Byte

/-- Preserve all 64 bytes; word `w` consists of bytes `8*w` through `8*w+7`. -/
def byteBlockWordsEquiv : RawByteBlock ≃ RawWordBlock :=
  ((Equiv.arrowCongr (finProdFinEquiv : Fin 8 × Fin 8 ≃ Fin (8 * 8))
    (Equiv.refl HegemonCrypto.CanonicalBytes.Byte)).symm.trans
      (Equiv.curry (Fin 8) (Fin 8) HegemonCrypto.CanonicalBytes.Byte)).trans
        (Equiv.piCongrRight fun _ => eightBytesWordEquiv)

theorem byte_block_word_has_exact_le_coordinates (bytes : RawByteBlock) (word : Fin 8) :
    (byteBlockWordsEquiv bytes word).val =
      HegemonCrypto.CanonicalBytes.decodeLE
        (List.ofFn fun byte : Fin 8 => bytes (finProdFinEquiv (word, byte))) := by
  exact eight_bytes_word_is_literal_le _

def byteBlockVectorEquiv (blocks : ℕ) : (Fin blocks → RawByteBlock) ≃ (Fin blocks → RawWordBlock) :=
  Equiv.piCongrRight fun _ => byteBlockWordsEquiv

theorem byte_block_vector_at_index {blocks : ℕ}
    (vector : Fin blocks → RawByteBlock) (counter : Fin blocks) :
    byteBlockVectorEquiv blocks vector counter = byteBlockWordsEquiv (vector counter) := rfl

def byteBlockCappedLaw (blocks requested : ℕ) : PMF (Option (FieldOutput sourceFieldSize requested)) :=
  pmfMap (uniformFintypePMF (Fin blocks → RawByteBlock)) fun vector =>
    sourceScan (blocks * 8) requested (blockWordsEquiv blocks (byteBlockVectorEquiv blocks vector))

theorem same_uniform_byte_blocks_capped_law (blocks requested : ℕ) :
    byteBlockCappedLaw blocks requested = blockCappedLaw blocks requested := by
  have wordLaw := V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv (byteBlockVectorEquiv blocks)
  have pushed := congrArg (fun law => pmfMap law fun vector =>
    sourceScan (blocks * 8) requested (blockWordsEquiv blocks vector)) wordLaw
  rw [pmfMap_comp] at pushed
  exact pushed

theorem literal_uniform_byte_blocks_conditional_output (blocks requested : ℕ)
    (enough : requested ≤ blocks * 8) (output : FieldOutput sourceFieldSize requested) :
    byteBlockCappedLaw blocks requested (some output) /
      successMass sourceFieldSize sourceRejectedSize (blocks * 8) requested =
        uniformFintypePMF (FieldOutput sourceFieldSize requested) output := by
  rw [same_uniform_byte_blocks_capped_law]
  exact same_uniform_blocks_conditional_output blocks requested enough output

theorem literal_uniform_byte_blocks_abort_probability (blocks requested : ℕ) :
    byteBlockCappedLaw blocks requested none =
      (abortCount sourceFieldSize sourceRejectedSize (blocks * 8) requested : ℝ≥0∞) /
        (2 ^ 64 : ℝ≥0∞) ^ (blocks * 8) := by
  rw [same_uniform_byte_blocks_capped_law, same_uniform_blocks_capped_law]
  exact literal_u64_abort_probability (blocks * 8) requested

def sourceDigestOfByteBlock (bytes : RawByteBlock) : V8Smz9WholeViewObservation.Sha512Digest :=
  ⟨List.ofFn bytes, by simp⟩

theorem source_digest_words_are_exact_byte_block_words (bytes : RawByteBlock) :
    (sourceDigestOfByteBlock bytes).rawWords =
      (List.ofFn (byteBlockWordsEquiv bytes)).map Fin.val := by
  apply List.ext_getElem
  · simp [V8Smz9WholeViewObservation.Sha512Digest.rawWords]
  · intro index leftBound rightBound
    have wordBound : index < 8 := by simpa using rightBound
    simp only [V8Smz9WholeViewObservation.Sha512Digest.rawWords, List.getElem_map,
      List.getElem_range, List.getElem_ofFn]
    rw [byte_block_word_has_exact_le_coordinates]
    apply congrArg HegemonCrypto.CanonicalBytes.decodeLE
    apply List.ext_getElem
    · simp [sourceDigestOfByteBlock]
      omega
    · intro byte leftByte rightByte
      simp only [List.getElem_take, List.getElem_drop, List.getElem_ofFn, sourceDigestOfByteBlock]
      congr 1
      apply Fin.ext
      simp [finProdFinEquiv, Nat.add_comm, Nat.mul_comm]

private theorem flatten_ofFn_of_coordinates {Item : Type*} {blocks width : ℕ}
    (vector : Fin blocks → Fin width → Item) (flat : Fin (blocks * width) → Item)
    (coordinate : ∀ counter word, flat (finProdFinEquiv (counter, word)) = vector counter word) :
    (List.ofFn fun counter => List.ofFn (vector counter)).flatten = List.ofFn flat := by
  conv_rhs => rw [List.ofFn_mul]
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext counter
  apply congrArg List.ofFn
  funext word
  have order : finProdFinEquiv (counter, word) =
      (⟨counter.val * width + word.val, by
        calc
          counter.val * width + word.val < (counter.val + 1) * width := by
            exact (Nat.add_lt_add_left word.isLt _).trans_eq (by rw [Nat.add_mul, Nat.one_mul])
          _ ≤ blocks * width := Nat.mul_le_mul_right width counter.isLt⟩ : Fin (blocks * width)) := by
    apply Fin.ext
    change word.val + width * counter.val = counter.val * width + word.val
    rw [Nat.add_comm, Nat.mul_comm width counter.val]
  rw [← order]
  exact (coordinate counter word).symm

private theorem block_words_list_flatten {blocks : ℕ} (vector : Fin blocks → RawWordBlock) :
    (List.ofFn fun counter => List.ofFn (vector counter)).flatten =
      List.ofFn (blockWordsEquiv blocks vector) :=
  flatten_ofFn_of_coordinates vector (blockWordsEquiv blocks vector)
    (block_words_exact_coordinate vector)

private theorem block_words_mapped_list_flatten {blocks : ℕ} (vector : Fin blocks → RawWordBlock) :
    (List.ofFn fun counter => (List.ofFn (vector counter)).map Fin.val).flatten =
      (List.ofFn (blockWordsEquiv blocks vector)).map Fin.val := by
  have mapped := congrArg (List.map Fin.val) (block_words_list_flatten vector)
  rw [List.map_flatten, List.map_ofFn] at mapped
  exact mapped

theorem literal_counter_candidates_are_exact_flat_words {blocks : ℕ}
    (vector : Fin blocks → RawByteBlock) :
    counterVectorCandidates (fun counter => sourceDigestOfByteBlock (vector counter)) =
      (List.ofFn (blockWordsEquiv blocks (byteBlockVectorEquiv blocks vector))).map Fin.val := by
  unfold counterVectorCandidates
  rw [← block_words_mapped_list_flatten (byteBlockVectorEquiv blocks vector)]
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext counter
  rw [source_digest_words_are_exact_byte_block_words]
  exact congrArg (fun words : RawWordBlock => (List.ofFn words).map Fin.val)
    (byte_block_vector_at_index vector counter).symm

/-- Equality with the existing literal list-of-64-bytes counter parser, not
merely with an idealized field-output oracle. The `none` branch is preserved. -/
theorem exact_literal_byte_counter_parser {blocks : ℕ} (requested : ℕ)
    (vector : Fin blocks → RawByteBlock) :
    parseCounterVector requested (fun counter => sourceDigestOfByteBlock (vector counter)) =
      (sourceScan (blocks * 8) requested
        (blockWordsEquiv blocks (byteBlockVectorEquiv blocks vector))).map List.ofFn := by
  rw [literal_u64_parser_first_prefix]
  unfold parseCounterVector
  rw [literal_counter_candidates_are_exact_flat_words]

def literalByteParserLaw (blocks requested : ℕ) : PMF (Option (List (Fin sourceFieldSize))) :=
  pmfMap (uniformFintypePMF (Fin blocks → RawByteBlock)) fun vector =>
    parseCounterVector requested (fun counter => sourceDigestOfByteBlock (vector counter))

theorem literal_byte_parser_law_is_capped_law (blocks requested : ℕ) :
    literalByteParserLaw blocks requested =
      pmfMap (byteBlockCappedLaw blocks requested) (Option.map List.ofFn) := by
  unfold literalByteParserLaw byteBlockCappedLaw
  rw [pmfMap_comp]
  apply congrArg (pmfMap (uniformFintypePMF (Fin blocks → RawByteBlock)))
  funext vector
  exact exact_literal_byte_counter_parser requested vector

private theorem pmfMap_injective_point {Input Output : Type*} (law : PMF Input)
    (f : Input → Output) (injective : Function.Injective f) (input : Input) :
    pmfMap law f (f input) = law input := by
  rw [pmfMap_apply, tsum_eq_single input]
  · simp
  · intro other different
    rw [if_neg]
    intro equal
    exact different (injective equal).symm

theorem literal_byte_parser_conditional_output (blocks requested : ℕ)
    (enough : requested ≤ blocks * 8) (output : FieldOutput sourceFieldSize requested) :
    literalByteParserLaw blocks requested (some (List.ofFn output)) /
      successMass sourceFieldSize sourceRejectedSize (blocks * 8) requested =
        uniformFintypePMF (FieldOutput sourceFieldSize requested) output := by
  have injective : Function.Injective
      (fun value : Option (FieldOutput sourceFieldSize requested) => value.map List.ofFn) := by
    intro left right equal
    cases left <;> cases right
    · rfl
    · simp at equal
    · simp at equal
    · congr 1
      exact List.ofFn_injective (Option.some.inj equal)
  rw [literal_byte_parser_law_is_capped_law]
  change pmfMap (byteBlockCappedLaw blocks requested) (Option.map List.ofFn)
      ((some output).map List.ofFn) / _ = _
  rw [pmfMap_injective_point _ _ injective]
  exact literal_uniform_byte_blocks_conditional_output blocks requested enough output

theorem literal_byte_parser_abort_probability (blocks requested : ℕ) :
    literalByteParserLaw blocks requested none =
      (abortCount sourceFieldSize sourceRejectedSize (blocks * 8) requested : ℝ≥0∞) /
        (2 ^ 64 : ℝ≥0∞) ^ (blocks * 8) := by
  rw [literal_byte_parser_law_is_capped_law]
  have noneMass : pmfMap (byteBlockCappedLaw blocks requested) (Option.map List.ofFn)
      (none : Option (List (Fin sourceFieldSize))) = byteBlockCappedLaw blocks requested none := by
    rw [pmfMap_apply, tsum_eq_single none]
    · simp
    · intro other different
      cases other with
      | none => contradiction
      | some output => simp
  rw [noneMass]
  exact literal_uniform_byte_blocks_abort_probability blocks requested

theorem exact_decs_source_request_counts :
    digestCallCap 700 = 92 ∧ 8 * digestCallCap 700 = 736 ∧
      8 * digestCallCap 700 - 700 + 1 = 37 := by decide

/-- Gamma width depends on the public statement's retained CSR rows. -/
def gammaRequestedWords (retainedRows : ℕ) : ℕ := 5 * max 830 retainedRows

theorem gamma_source_cap_upper_bound (retainedRows : ℕ) (bounded : retainedRows ≤ 20605) :
    gammaRequestedWords retainedRows ≤ 103025 ∧
      digestCallCap (gammaRequestedWords retainedRows) ≤ 12883 := by
  have width : max 830 retainedRows ≤ 20605 := max_le (by decide) bounded
  unfold gammaRequestedWords digestCallCap
  constructor
  · omega
  · split <;> omega

theorem gamma_example_and_maximum_counts :
    digestCallCap 4150 = 523 ∧ 8 * digestCallCap 4150 - 4150 + 1 = 35 ∧
      digestCallCap 103025 = 12883 ∧ 8 * digestCallCap 103025 = 103064 ∧
        8 * digestCallCap 103025 - 103025 + 1 = 40 := by decide

end

end HegemonCrypto.SmallWood.V8Smz9CappedRawSampler
