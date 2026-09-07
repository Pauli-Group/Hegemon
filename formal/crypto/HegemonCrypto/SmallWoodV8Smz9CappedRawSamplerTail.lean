import HegemonCrypto.SmallWoodV8Smz9CappedRawSampler
import Mathlib.Data.Fintype.Powerset
import Mathlib.Data.Nat.Choose.Bounds

/-!
# Exact finite-vector capped-sampler rejection tails

The abort event is covered by the finite family of sets of rejected coordinates.
The resulting union bound is derived from the actual fiber cardinality, not an
assumed binomial law or a normal approximation. No full vector is enumerated.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CappedRawSamplerTail

open V8Smz9RuntimeDistribution V8Smz9CappedRawSampler V8Smz9RawCounterCompiler
open scoped BigOperators Classical ENNReal

noncomputable section

set_option maxRecDepth 5000
set_option maxHeartbeats 1500000
set_option exponentiation.threshold 4096

def rejects {accepted rejected : ℕ} : SplitWord accepted rejected → Prop
  | .inl _ => False
  | .inr _ => True

def rejectionIndices {accepted rejected capacity : ℕ}
    (raw : Fin capacity → SplitWord accepted rejected) : Finset (Fin capacity) :=
  Finset.univ.filter fun index => rejects (raw index)

theorem rejection_indices_card {accepted rejected capacity : ℕ}
    (raw : Fin capacity → SplitWord accepted rejected) :
    (rejectionIndices raw).card = rejectedCount raw := by
  unfold rejectionIndices rejectedCount
  rw [Finset.card_filter]
  apply Finset.sum_congr rfl
  intro index _
  cases raw index <;> simp [rejects]

def rejectedWordEquiv (accepted rejected : ℕ) :
    { word : SplitWord accepted rejected // rejects word } ≃ Fin rejected where
  toFun word := by
    rcases word with ⟨word, rejectedWord⟩
    cases word with
    | inl _ => exact False.elim rejectedWord
    | inr value => exact value
  invFun value := ⟨.inr value, trivial⟩
  left_inv word := by
    rcases word with ⟨word, rejectedWord⟩
    cases word with
    | inl _ => exact False.elim rejectedWord
    | inr _ => rfl
  right_inv _ := rfl

theorem coordinate_rejection_fiber_card (accepted rejected capacity : ℕ)
    (selected : Finset (Fin capacity)) (index : Fin capacity) :
    Fintype.card { word : SplitWord accepted rejected // index ∈ selected → rejects word } =
      if index ∈ selected then rejected else accepted + rejected := by
  by_cases member : index ∈ selected
  · simp only [member, true_implies, if_true]
    exact (Fintype.card_congr (rejectedWordEquiv accepted rejected)).trans (Fintype.card_fin rejected)
  · simp [member, Fintype.card_sum, Fintype.card_fin]

theorem selected_rejection_fiber_card (accepted rejected capacity : ℕ)
    (selected : Finset (Fin capacity)) :
    Fintype.card { raw : Fin capacity → SplitWord accepted rejected //
      ∀ index ∈ selected, rejects (raw index) } =
        rejected ^ selected.card * (accepted + rejected) ^ (capacity - selected.card) := by
  have separated := Fintype.card_congr
    (Equiv.subtypePiEquivPi (α := Fin capacity)
      (β := fun _ => SplitWord accepted rejected)
      (p := fun index word => index ∈ selected → rejects word) :
      { raw : Fin capacity → SplitWord accepted rejected // ∀ index ∈ selected, rejects (raw index) } ≃
        ((index : Fin capacity) →
          { word : SplitWord accepted rejected // index ∈ selected → rejects word }))
  rw [Fintype.card_pi] at separated
  simp only [coordinate_rejection_fiber_card] at separated
  rw [Finset.prod_ite] at separated
  have inside : (Finset.univ.filter fun index : Fin capacity => index ∈ selected) = selected := by
    ext index
    simp
  have outside : (Finset.univ.filter fun index : Fin capacity => index ∉ selected) =
      Finset.univ \ selected := by
    ext index
    simp
  rw [inside, outside, Finset.prod_const, Finset.prod_const,
    Finset.card_sdiff_of_subset (Finset.subset_univ selected)] at separated
  simpa only [Finset.card_univ, Fintype.card_fin] using separated

/-- The actual finite tail fiber is covered by its `k`-coordinate cylinders.
The cylinders may overlap; cardinality subadditivity pays exactly `choose C k`. -/
theorem rejection_tail_fiber_card_union_bound (accepted rejected capacity threshold : ℕ) :
    Fintype.card { raw : Fin capacity → SplitWord accepted rejected //
      threshold ≤ rejectedCount raw } ≤
        Nat.choose capacity threshold * rejected ^ threshold *
          (accepted + rejected) ^ (capacity - threshold) := by
  let family : Finset (Finset (Fin capacity)) := Finset.univ.powersetCard threshold
  let cylinder (selected : Finset (Fin capacity)) :
      Finset (Fin capacity → SplitWord accepted rejected) :=
    Finset.univ.filter fun raw => ∀ index ∈ selected, rejects (raw index)
  have covered : (Finset.univ.filter fun raw : Fin capacity → SplitWord accepted rejected =>
      threshold ≤ rejectedCount raw) ⊆ family.biUnion cylinder := by
    intro raw member
    have enough : threshold ≤ (rejectionIndices raw).card := by
      rw [rejection_indices_card]
      exact (Finset.mem_filter.mp member).2
    obtain ⟨selected, contained, size⟩ := Finset.exists_subset_card_eq enough
    apply Finset.mem_biUnion.mpr
    refine ⟨selected, Finset.mem_powersetCard.mpr ⟨Finset.subset_univ selected, size⟩, ?_⟩
    apply Finset.mem_filter.mpr
    refine ⟨Finset.mem_univ raw, ?_⟩
    intro index indexMember
    exact (Finset.mem_filter.mp (contained indexMember)).2
  have each : ∀ selected ∈ family, (cylinder selected).card =
      rejected ^ threshold * (accepted + rejected) ^ (capacity - threshold) := by
    intro selected member
    have size := (Finset.mem_powersetCard.mp member).2
    have count := selected_rejection_fiber_card accepted rejected capacity selected
    rw [Fintype.card_subtype, size] at count
    exact count
  rw [Fintype.card_subtype]
  calc
    _ ≤ (family.biUnion cylinder).card := Finset.card_le_card covered
    _ ≤ ∑ selected ∈ family, (cylinder selected).card := Finset.card_biUnion_le
    _ = Nat.choose capacity threshold * rejected ^ threshold *
        (accepted + rejected) ^ (capacity - threshold) := by
      rw [Finset.sum_congr rfl each]
      simp only [Finset.sum_const, family, Finset.card_powersetCard, Finset.card_univ,
        Fintype.card_fin, nsmul_eq_mul, Nat.cast_id]
      ring

private theorem cancel_capacity_factor (numerator base : ℝ≥0∞) (capacity threshold : ℕ)
    (nonzero : base ≠ 0) (finite : base ≠ ∞) (bounded : threshold ≤ capacity) :
    (numerator * base ^ (capacity - threshold)) / base ^ capacity =
      numerator / base ^ threshold := by
  have powers : base ^ capacity = base ^ threshold * base ^ (capacity - threshold) := by
    rw [← pow_add, Nat.add_sub_of_le bounded]
  rw [powers]
  exact ENNReal.mul_div_mul_right _ _ (pow_ne_zero _ nonzero) (ENNReal.pow_ne_top finite)

def unionNumerator (capacity threshold : ℕ) : ℕ :=
  Nat.choose capacity threshold * (2 ^ 32 - 1) ^ threshold

def unionBound (capacity threshold : ℕ) : ℝ≥0∞ :=
  (unionNumerator capacity threshold : ℝ≥0∞) / (2 ^ 64 : ℝ≥0∞) ^ threshold

theorem uniform_raw_rejection_tail_union_bound (capacity threshold : ℕ)
    (bounded : threshold ≤ capacity) :
    (Fintype.card { raw : Fin capacity → SplitWord sourceFieldSize sourceRejectedSize //
      threshold ≤ rejectedCount raw } : ℝ≥0∞) / (2 ^ 64 : ℝ≥0∞) ^ capacity ≤
        unionBound capacity threshold := by
  have count := rejection_tail_fiber_card_union_bound sourceFieldSize sourceRejectedSize
    capacity threshold
  have total : sourceFieldSize + sourceRejectedSize = 2 ^ 64 := by decide
  have rejectsSize : sourceRejectedSize = 2 ^ 32 - 1 := by decide
  rw [total, rejectsSize] at count
  have realCount : (Fintype.card { raw : Fin capacity → SplitWord sourceFieldSize sourceRejectedSize //
      threshold ≤ rejectedCount raw } : ℝ≥0∞) ≤
        (unionNumerator capacity threshold : ℝ≥0∞) * (2 ^ 64 : ℝ≥0∞) ^ (capacity - threshold) := by
    exact_mod_cast count
  calc
    _ ≤ ((unionNumerator capacity threshold : ℝ≥0∞) * (2 ^ 64 : ℝ≥0∞) ^ (capacity - threshold)) /
        (2 ^ 64 : ℝ≥0∞) ^ capacity := by
      gcongr
    _ = unionBound capacity threshold := by
      exact cancel_capacity_factor (unionNumerator capacity threshold) (2 ^ 64)
        capacity threshold (by positivity) (by simp) bounded

theorem union_bound_capacity_mono (threshold left right : ℕ) (bounded : left ≤ right) :
    unionBound left threshold ≤ unionBound right threshold := by
  unfold unionBound unionNumerator
  gcongr

theorem literal_u64_abort_lower_threshold_bound (capacity requested threshold : ℕ)
    (enough : requested ≤ capacity) (thresholdBound : threshold ≤ capacity)
    (lowerThreshold : threshold ≤ capacity - requested + 1) :
    sourceCappedLaw capacity requested none ≤ unionBound capacity threshold := by
  rw [literal_u64_abort_is_rejection_tail_cardinality capacity requested enough]
  have count := Fintype.card_subtype_mono
    (fun raw : Fin capacity → SplitWord sourceFieldSize sourceRejectedSize =>
      capacity - requested + 1 ≤ rejectedCount raw)
    (fun raw : Fin capacity → SplitWord sourceFieldSize sourceRejectedSize =>
      threshold ≤ rejectedCount raw)
    (fun _ bound => lowerThreshold.trans bound)
  calc
    _ ≤ (Fintype.card { raw : Fin capacity → SplitWord sourceFieldSize sourceRejectedSize //
        threshold ≤ rejectedCount raw } : ℝ≥0∞) / (2 ^ 64 : ℝ≥0∞) ^ capacity := by
      gcongr
    _ ≤ unionBound capacity threshold := uniform_raw_rejection_tail_union_bound capacity threshold thresholdBound

/-- The threshold remains the exact source exhaustion threshold, including
all raw candidates in the original finite vector. -/
theorem literal_u64_abort_choose_union_bound (capacity requested : ℕ)
    (positiveRequest : 0 < requested) (enough : requested ≤ capacity) :
    sourceCappedLaw capacity requested none ≤ unionBound capacity (capacity - requested + 1) := by
  rw [literal_u64_abort_is_rejection_tail_cardinality capacity requested enough]
  exact uniform_raw_rejection_tail_union_bound capacity (capacity - requested + 1) (by omega)

theorem literal_byte_parser_abort_choose_union_bound (blocks requested : ℕ)
    (positiveRequest : 0 < requested) (enough : requested ≤ blocks * 8) :
    literalByteParserLaw blocks requested none ≤ unionBound (blocks * 8) (blocks * 8 - requested + 1) := by
  have same : literalByteParserLaw blocks requested none = sourceCappedLaw (blocks * 8) requested none := by
    rw [literal_byte_parser_abort_probability, literal_u64_abort_probability]
  rw [same]
  exact literal_u64_abort_choose_union_bound (blocks * 8) requested positiveRequest enough

theorem literal_byte_parser_abort_lower_threshold_bound (blocks requested threshold : ℕ)
    (enough : requested ≤ blocks * 8) (thresholdBound : threshold ≤ blocks * 8)
    (lowerThreshold : threshold ≤ blocks * 8 - requested + 1) :
    literalByteParserLaw blocks requested none ≤ unionBound (blocks * 8) threshold := by
  have same : literalByteParserLaw blocks requested none = sourceCappedLaw (blocks * 8) requested none := by
    rw [literal_byte_parser_abort_probability, literal_u64_abort_probability]
  rw [same]
  exact literal_u64_abort_lower_threshold_bound (blocks * 8) requested threshold enough thresholdBound lowerThreshold

/-- Positive requests have 32 through 39 spare candidates, hence an exhaustion
threshold between 33 and 40. The largest request need not minimize it. -/
theorem positive_request_capacity_threshold (requested : ℕ) (positive : 0 < requested) :
    requested ≤ digestCallCap requested * 8 ∧
      33 ≤ digestCallCap requested * 8 - requested + 1 ∧
        digestCallCap requested * 8 - requested + 1 ≤ 40 := by
  unfold digestCallCap
  rw [if_neg (by omega : requested ≠ 0)]
  omega

theorem gamma_all_row_capacity_threshold (retainedRows : ℕ) (bounded : retainedRows ≤ 20605) :
    let requested := gammaRequestedWords retainedRows
    let capacity := digestCallCap requested * 8
    requested ≤ capacity ∧ 33 ≤ capacity ∧ 33 ≤ capacity - requested + 1 ∧ capacity ≤ 103064 := by
  have requestLower : 4150 ≤ gammaRequestedWords retainedRows := by
    unfold gammaRequestedWords
    have lower := Nat.le_max_left 830 retainedRows
    omega
  have cap := positive_request_capacity_threshold (gammaRequestedWords retainedRows) (by omega)
  have upper := gamma_source_cap_upper_bound retainedRows bounded
  dsimp only
  omega

theorem gamma_maximum_size_is_not_minimum_threshold :
    gammaRequestedWords 20600 = 103000 ∧
      digestCallCap (gammaRequestedWords 20600) * 8 = 103032 ∧
      digestCallCap (gammaRequestedWords 20600) * 8 - gammaRequestedWords 20600 + 1 = 33 ∧
      digestCallCap (gammaRequestedWords 20605) * 8 - gammaRequestedWords 20605 + 1 = 40 := by decide

-- Keep concrete binomial coefficients unexpanded during elaboration; the arithmetic
-- certificates below expand only the short descending-factorial expression.
attribute [local irreducible] unionNumerator Nat.choose

/-- Uniform over all permitted retained-row counts, not merely the maximum
request size. The threshold-33 event contains every source gamma abort. -/
theorem gamma_all_rows_literal_abort_union_bound (retainedRows : ℕ) (bounded : retainedRows ≤ 20605) :
    literalByteParserLaw (digestCallCap (gammaRequestedWords retainedRows))
      (gammaRequestedWords retainedRows) none ≤ unionBound 103064 33 := by
  have capacity := gamma_all_row_capacity_threshold retainedRows bounded
  exact (literal_byte_parser_abort_lower_threshold_bound
    (digestCallCap (gammaRequestedWords retainedRows)) (gammaRequestedWords retainedRows) 33
      capacity.1 capacity.2.1 capacity.2.2.1).trans
        (union_bound_capacity_mono 33 _ 103064 capacity.2.2.2)

private theorem certificate_of_descending_factorial (capacity threshold bits : ℕ)
    (certificate : (capacity.descFactorial threshold / threshold.factorial) *
      (2 ^ 32 - 1) ^ threshold * 2 ^ bits ≤ (2 ^ 64) ^ threshold) :
    unionNumerator capacity threshold * 2 ^ bits ≤ (2 ^ 64) ^ threshold := by
  unfold unionNumerator
  rw [Nat.choose_eq_descFactorial_div_factorial]
  exact certificate

/-- Descending factorials compute only 37 factors, never the full vector
space or the 736-row recursive Pascal triangle. -/
theorem decs_exact_integer_certificate :
    unionNumerator 736 37 * 2 ^ 976 ≤ (2 ^ 64) ^ 37 := by
  exact certificate_of_descending_factorial 736 37 976 (by decide)

/-- This computation uses 40 descending factors, independent of the raw
sample-space cardinality and the 103,064 candidate capacity. -/
theorem gamma_maximum_size_integer_certificate :
    unionNumerator 103064 40 * 2 ^ 773 ≤ (2 ^ 64) ^ 40 := by
  exact certificate_of_descending_factorial 103064 40 773 (by decide)

theorem gamma_all_rows_integer_certificate :
    unionNumerator 103064 33 * 2 ^ 629 ≤ (2 ^ 64) ^ 33 := by
  exact certificate_of_descending_factorial 103064 33 629 (by decide)

private theorem integer_certificate_gives_probability_bound (numerator denominator bits : ℕ)
    (positiveDenominator : 0 < denominator) (certificate : numerator * 2 ^ bits ≤ denominator) :
    (numerator : ℝ≥0∞) / (denominator : ℝ≥0∞) ≤ (2 ^ bits : ℝ≥0∞)⁻¹ := by
  have realCertificate : (numerator : ℝ≥0∞) * (2 ^ bits : ℝ≥0∞) ≤ (denominator : ℝ≥0∞) := by
    exact_mod_cast certificate
  apply (ENNReal.div_le_iff (by positivity) (by simp)).mpr
  calc
    (numerator : ℝ≥0∞) = ((numerator : ℝ≥0∞) * (2 ^ bits : ℝ≥0∞)) / (2 ^ bits : ℝ≥0∞) := by
      rw [ENNReal.mul_div_cancel_right (by positivity) (by simp)]
    _ ≤ (denominator : ℝ≥0∞) / (2 ^ bits : ℝ≥0∞) := by
      gcongr
    _ = (2 ^ bits : ℝ≥0∞)⁻¹ * (denominator : ℝ≥0∞) := by
      rw [div_eq_mul_inv, mul_comm]

theorem decs_union_bound_le_two_pow_neg_976 : unionBound 736 37 ≤ (2 ^ 976 : ℝ≥0∞)⁻¹ := by
  have bound := integer_certificate_gives_probability_bound (unionNumerator 736 37)
    ((2 ^ 64) ^ 37) 976 (by positivity) decs_exact_integer_certificate
  have denominator : (((2 ^ 64) ^ 37 : ℕ) : ℝ≥0∞) = (2 ^ 64 : ℝ≥0∞) ^ 37 := by norm_num
  rw [denominator] at bound
  exact bound

theorem gamma_union_bound_le_two_pow_neg_773 : unionBound 103064 40 ≤ (2 ^ 773 : ℝ≥0∞)⁻¹ := by
  have bound := integer_certificate_gives_probability_bound (unionNumerator 103064 40)
    ((2 ^ 64) ^ 40) 773 (by positivity) gamma_maximum_size_integer_certificate
  have denominator : (((2 ^ 64) ^ 40 : ℕ) : ℝ≥0∞) = (2 ^ 64 : ℝ≥0∞) ^ 40 := by norm_num
  rw [denominator] at bound
  exact bound

theorem gamma_all_rows_union_bound_le_two_pow_neg_629 : unionBound 103064 33 ≤ (2 ^ 629 : ℝ≥0∞)⁻¹ := by
  have bound := integer_certificate_gives_probability_bound (unionNumerator 103064 33)
    ((2 ^ 64) ^ 33) 629 (by positivity) gamma_all_rows_integer_certificate
  have denominator : (((2 ^ 64) ^ 33 : ℕ) : ℝ≥0∞) = (2 ^ 64 : ℝ≥0∞) ^ 33 := by norm_num
  rw [denominator] at bound
  exact bound

theorem decs_literal_abort_le_two_pow_neg_976 :
    literalByteParserLaw 92 700 none ≤ (2 ^ 976 : ℝ≥0∞)⁻¹ := by
  exact (literal_byte_parser_abort_choose_union_bound 92 700 (by decide) (by decide)).trans
    decs_union_bound_le_two_pow_neg_976

theorem gamma_maximum_literal_abort_le_two_pow_neg_773 :
    literalByteParserLaw 12883 103025 none ≤ (2 ^ 773 : ℝ≥0∞)⁻¹ := by
  exact (literal_byte_parser_abort_choose_union_bound 12883 103025 (by decide) (by decide)).trans
    gamma_union_bound_le_two_pow_neg_773

theorem gamma_all_rows_literal_abort_le_two_pow_neg_629 (retainedRows : ℕ) (bounded : retainedRows ≤ 20605) :
    literalByteParserLaw (digestCallCap (gammaRequestedWords retainedRows))
      (gammaRequestedWords retainedRows) none ≤ (2 ^ 629 : ℝ≥0∞)⁻¹ :=
  (gamma_all_rows_literal_abort_union_bound retainedRows bounded).trans
    gamma_all_rows_union_bound_le_two_pow_neg_629

private theorem bounded_square_times_sum {first second firstUpper secondUpper : ℝ≥0∞}
    (queries : ℕ) (bounded : queries ≤ 2 ^ 128)
    (firstBound : first ≤ firstUpper) (secondBound : second ≤ secondUpper) :
    (queries : ℝ≥0∞) ^ 2 * (first + second) ≤
      (2 ^ 128 : ℝ≥0∞) ^ 2 * (firstUpper + secondUpper) := by
  have queryBound : (queries : ℝ≥0∞) ≤ (2 ^ 128 : ℝ≥0∞) := by exact_mod_cast bounded
  gcongr

/-- An arithmetic composition allowance, not a theorem granting adaptive
freshness or identifying these fixed-vector laws with a quantum experiment. -/
theorem maximum_size_query_squared_allowance (queries : ℕ) (bounded : queries ≤ 2 ^ 128) :
    (queries : ℝ≥0∞) ^ 2 *
      (literalByteParserLaw 92 700 none + literalByteParserLaw 12883 103025 none) ≤
        (2 ^ 516 : ℝ≥0∞)⁻¹ := by
  exact (bounded_square_times_sum queries bounded decs_literal_abort_le_two_pow_neg_976
    gamma_maximum_literal_abort_le_two_pow_neg_773).trans (by
      apply (ENNReal.toReal_le_toReal (by finiteness) (by finiteness)).mp
      norm_num [ENNReal.toReal_mul, ENNReal.toReal_add, ENNReal.toReal_pow, ENNReal.toReal_inv])

/-- The uniform source gamma allowance uses every permitted retained-row
count. This remains arithmetic over fixed-vector laws, not QROM freshness. -/
theorem whole_query_squared_allowance (retainedRows queries : ℕ)
    (rowsBounded : retainedRows ≤ 20605) (queriesBounded : queries ≤ 2 ^ 128) :
    (queries : ℝ≥0∞) ^ 2 *
      (literalByteParserLaw 92 700 none +
        literalByteParserLaw (digestCallCap (gammaRequestedWords retainedRows))
          (gammaRequestedWords retainedRows) none) ≤ (2 ^ 372 : ℝ≥0∞)⁻¹ := by
  exact (bounded_square_times_sum queries queriesBounded decs_literal_abort_le_two_pow_neg_976
    (gamma_all_rows_literal_abort_le_two_pow_neg_629 retainedRows rowsBounded)).trans (by
      apply (ENNReal.toReal_le_toReal (by finiteness) (by finiteness)).mp
      norm_num [ENNReal.toReal_mul, ENNReal.toReal_add, ENNReal.toReal_pow, ENNReal.toReal_inv])

end

end HegemonCrypto.SmallWood.V8Smz9CappedRawSamplerTail
