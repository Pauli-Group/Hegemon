import HegemonCrypto.NativePrivateSpendQ58Compff01OpeningContinuation

/-! Literal current pcs_commit source columns. No degree or source/public equality
certificate is an input: coefficient arrays and the original PCS coins construct
all26230 degree≤69 polynomials. Rust field/interpolation refinement stays an
explicit compiler trust contract; this module proves the algebraic constructor. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58Compff01SourceColumns
open Polynomial
open V8Smz9ZeroKnowledge V8Smz9RuntimeFieldLayout V8Smz9EagerPrivacy
open V8Smz9PiopOpeningRecovery
open NativePrivateSpendQ58Compff01OpeningContinuation
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev Row := Fin 26210
abbrev WitnessValues := Row → Fin 64 → Goldilocks
abbrev WitnessCoins := Row → Fin 6 → Goldilocks
abbrev NonlinearMasks := Fin 5 → Fin 75 → Goldilocks
abbrev LinearCoins := Fin 5 → Fin 132 → Goldilocks
abbrev PcsCoins := Fin 10 → Fin 6 → Goldilocks

def packing (lane : Fin 64) : Goldilocks := (lane.val : Goldilocks)

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: packing_injective"

theorem packing_injective : Function.Injective packing := by
  intro left right same
  have boundLeft : left.val < Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus := left.isLt.trans_le (by decide)
  have boundRight : right.val < Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus := right.isLt.trans_le (by decide)
  have values := congrArg ZMod.val same
  simp only [packing, ZMod.val_natCast, Nat.mod_eq_of_lt boundLeft,
    Nat.mod_eq_of_lt boundRight] at values
  exact Fin.ext values

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: base_degree63"

theorem base_degree63 (values : Fin 64 → Goldilocks) :
    (sourceWitnessBasePolynomial values).natDegree ≤ 63 := by
  unfold sourceWitnessBasePolynomial
  apply natDegree_sum_le_of_forall_le
  intro lane _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, zero_add]
  change (Lagrange.basis (Finset.univ : Finset (Fin 64)) packing lane).natDegree ≤ 63
  have degree : (Lagrange.basis (Finset.univ : Finset (Fin 64)) packing lane).natDegree = 63 := by
    simpa only [Finset.card_univ, Fintype.card_fin] using
      Lagrange.natDegree_basis (s := (Finset.univ : Finset (Fin 64))) (v := packing)
        packing_injective.injOn (Finset.mem_univ lane)
  exact degree.le

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: shifted_degree"

theorem shifted_degree {count : Nat} (coefficients : Fin count → Goldilocks) (shift : Nat) :
    (X ^ shift * coefficientPolynomial coefficients).natDegree ≤ shift + (count - 1) := by
  exact natDegree_mul_le.trans (by
    rw [natDegree_X_pow]
    exact Nat.add_le_add_left (coefficient_polynomial_nat_degree_le coefficients) shift)

/-- poly_restore: subtract the six high coefficients' contribution before
interpolating the low64 coefficients, then append the same original coins. -/
def restoreWitness (values : Fin 64 → Goldilocks) (coins : Fin 6 → Goldilocks) :
    Goldilocks[X] :=
  sourceWitnessBasePolynomial
    (fun lane => values lane - (X ^ 64 * coefficientPolynomial coins).eval (packing lane)) +
      X ^ 64 * coefficientPolynomial coins

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: restore_witness_degree"

theorem restore_witness_degree (values : Fin 64 → Goldilocks) (coins : Fin 6 → Goldilocks) :
    (restoreWitness values coins).natDegree ≤ 69 := by
  apply (natDegree_add_le _ _).trans
  exact max_le ((base_degree63 _).trans (by decide)) (shifted_degree coins 64)

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: restore_witness_at_packing"

theorem restore_witness_at_packing (values : Fin 64 → Goldilocks)
    (coins : Fin 6 → Goldilocks) (node : Fin 64) :
    (restoreWitness values coins).eval (packing node) = values node := by
  have baseAt : ∀ data : Fin 64 → Goldilocks,
      (sourceWitnessBasePolynomial data).eval (packing node) = data node := by
    intro data
    change (∑ lane : Fin 64, C (data lane) * sourcePackingLagrange packing lane).eval
      (packing node) = _
    simp only [eval_finsetSum, eval_mul, eval_C]
    simp_rw [source_packing_lagrange_evaluation packing packing_injective]
    simp
  simp only [restoreWitness, eval_add, baseAt]
  ring

def low {high : Nat} (mask : Fin (64 + high) → Goldilocks) : Fin 64 → Goldilocks :=
  fun index => mask (Fin.castAdd high index)
def high {count : Nat} (mask : Fin (64 + count) → Goldilocks) : Fin count → Goldilocks :=
  fun index => mask (Fin.natAdd 64 index)

/-- The literal width2 mutation: put coin_t in row64+t of the first column,
subtract it from row(delta+t) of the last, and zero all last rows below delta. -/
def unstackPair {count : Nat} (delta : Nat)
    (mask : Fin (64 + count) → Goldilocks) (coins : Fin 6 → Goldilocks) :
    Fin 2 → Goldilocks[X] :=
  ![coefficientPolynomial (low mask) + X ^ 64 * coefficientPolynomial coins,
    X ^ delta * (coefficientPolynomial (high mask) - coefficientPolynomial coins)]

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: unstack_pair_degree"

theorem unstack_pair_degree {count : Nat} (delta : Nat)
    (fits : delta + max (count - 1) 5 ≤ 69)
    (mask : Fin (64 + count) → Goldilocks) (coins : Fin 6 → Goldilocks) (column : Fin 2) :
    (unstackPair delta mask coins column).natDegree ≤ 69 := by
  fin_cases column
  · change (coefficientPolynomial (low mask) + X ^ 64 * coefficientPolynomial coins).natDegree ≤ 69
    exact (natDegree_add_le _ _).trans (max_le
      ((coefficient_polynomial_nat_degree_le _).trans (by decide)) (shifted_degree coins 64))
  · change (X ^ delta * (coefficientPolynomial (high mask) - coefficientPolynomial coins)).natDegree ≤ 69
    apply natDegree_mul_le.trans
    apply le_trans _ fits
    rw [natDegree_X_pow]
    exact Nat.add_le_add_left ((natDegree_sub_le _ _).trans
      (max_le_max (coefficient_polynomial_nat_degree_le _) (coefficient_polynomial_nat_degree_le coins))) delta

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: pair_recombines"

theorem pair_recombines {count : Nat} (delta power : Nat) (layout : power + delta = 64)
    (mask : Fin (64 + count) → Goldilocks) (coins : Fin 6 → Goldilocks) (point : Goldilocks) :
    (unstackPair delta mask coins 0).eval point +
      point ^ power * (unstackPair delta mask coins 1).eval point =
        (coefficientPolynomial mask).eval point := by
  rw [coefficient_polynomial_split 64 count mask]
  change (coefficientPolynomial (low mask) + X ^ 64 * coefficientPolynomial coins).eval point +
      point ^ power * (X ^ delta *
        (coefficientPolynomial (high mask) - coefficientPolynomial coins)).eval point =
      (coefficientPolynomial (low mask) + X ^ 64 * coefficientPolynomial (high mask)).eval point
  simp only [eval_add, eval_mul, eval_pow, eval_X, eval_sub]
  have powers : point ^ power * point ^ delta = point ^ 64 := by rw [← pow_add, layout]
  calc
    _ = (coefficientPolynomial (low mask)).eval point +
        (point ^ power * point ^ delta) * (coefficientPolynomial (high mask)).eval point +
        (point ^ 64 - point ^ power * point ^ delta) * (coefficientPolynomial coins).eval point := by ring
    _ = _ := by rw [powers]; ring

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: coefficient_array_at"

/-- Coefficient extraction from the exact finite source array, zero outside.
This makes the following cell equations statements about literal Rust writes. -/
theorem coefficient_array_at {count : Nat} (coefficients : Fin count → Goldilocks) (degree : Nat) :
    (coefficientPolynomial coefficients).coeff degree =
      if within : degree < count then coefficients ⟨degree, within⟩ else 0 := by
  unfold coefficientPolynomial
  rw [finsetSum_coeff]
  simp only [coeff_C_mul_X_pow]
  by_cases within : degree < count
  · rw [dif_pos within]
    let selected : Fin count := ⟨degree, within⟩
    have single : (∑ index : Fin count, if degree = index.val then coefficients index else 0) =
        (if degree = selected.val then coefficients selected else 0) := by
      apply Finset.sum_eq_single selected
      · intro other _ different
        have valuesDiffer : degree ≠ other.val := by
          intro same
          exact different (Fin.ext same.symm)
        simp [valuesDiffer]
      · intro absent
        exact (absent (Finset.mem_univ selected)).elim
    simpa [selected] using single
  · rw [dif_neg within]
    apply Finset.sum_eq_zero
    intro other _
    have valuesDiffer : degree ≠ other.val := by
      intro same
      exact within (by have bound := other.isLt; omega)
    simp [valuesDiffer]

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: unstack_low_row"

/-- Source first-column rows0..63 copy low mask coefficients, rows64..69
copy the same six PCS coins. -/
theorem unstack_low_row {count : Nat} (delta : Nat)
    (mask : Fin (64 + count) → Goldilocks) (coins : Fin 6 → Goldilocks) (row : Fin 70) :
    (unstackPair delta mask coins 0).coeff row.val =
      (if inLow : row.val < 64 then mask (Fin.castAdd count ⟨row.val, inLow⟩) else 0) +
      (if inCoin : 64 ≤ row.val then coins ⟨row.val - 64, by have _ := row.isLt; omega⟩ else 0) := by
  simp only [unstackPair, Matrix.cons_val_zero, coeff_add, coeff_X_pow_mul',
    coefficient_array_at, low]
  split_ifs <;> simp_all <;> omega

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: unstack_high_row"

/-- Source last-column row(delta+t) receives high mask coefficient64+t,
minus its original PCS coin for t<6. All rows below delta are literal zero. -/
theorem unstack_high_row {count : Nat} (delta : Nat)
    (mask : Fin (64 + count) → Goldilocks) (coins : Fin 6 → Goldilocks) (row : Fin 70) :
    (unstackPair delta mask coins 1).coeff row.val =
      if _ : delta ≤ row.val then
        (if inMask : row.val - delta < count then
          mask (Fin.natAdd 64 ⟨row.val - delta, inMask⟩) else 0) -
        (if inCoin : row.val - delta < 6 then coins ⟨row.val - delta, inCoin⟩ else 0)
      else 0 := by
  change (X ^ delta * (coefficientPolynomial (high mask) - coefficientPolynomial coins)).coeff
    row.val = _
  simp only [coeff_X_pow_mul', coeff_sub, coefficient_array_at, high]
  split_ifs <;> rfl

/-- Exactly the source sum-zero linear mask's133 coefficients; only132 fresh
coins are inputs. The constant coefficient remains derived. -/
def linearFull (coins : Fin 132 → Goldilocks) : Fin 133 → Goldilocks :=
  fun index => (sourceLinearMask packing coins).coeff index.val

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: linear_full_reassembles"

theorem linear_full_reassembles (coins : Fin 132 → Goldilocks) :
    coefficientPolynomial (linearFull coins) = sourceLinearMask packing coins := by
  apply coefficient_polynomial_of_coefficients
  exact lt_of_le_of_lt (source_linear_mask_degree packing coins) (by decide)

structure SourceData where
  values : WitnessValues
  witnessCoins : WitnessCoins
  nonlinear : NonlinearMasks
  linearCoins : LinearCoins
  pcs : PcsCoins

def nonlinearColumns (data : SourceData) (column : Fin 10) : Goldilocks[X] :=
  let index := (finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm column
  unstackPair (count := 11) 59 (data.nonlinear index.1) (data.pcs (Fin.castAdd 5 index.1)) index.2

def linearColumns (data : SourceData) (column : Fin 10) : Goldilocks[X] :=
  let index := (finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm column
  unstackPair (count := 69) 1 (linearFull (data.linearCoins index.1))
    (data.pcs (Fin.natAdd 5 index.1)) index.2

/-- Source order:26210 witness columns, five nonlinear pairs, five linear pairs. -/
def sourcePolynomials (data : SourceData) : Fin 26230 → Goldilocks[X] :=
  Fin.append (fun row => restoreWitness (data.values row) (data.witnessCoins row))
    (Fin.append (nonlinearColumns data) (linearColumns data))

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: source_polynomial_degree"

/-- The prior endpoint degree hypothesis is now discharged by original source
inputs, including every PCS coin. No degree or public-mask equality is supplied. -/
theorem source_polynomial_degree (data : SourceData) :
    ∀ column, (sourcePolynomials data column).natDegree < 70 := by
  intro column
  refine Fin.addCases (n := 20) (m := 26210) (fun row => ?_) (fun remaining => ?_) column
  · simpa only [sourcePolynomials, Fin.append_left] using
      Nat.lt_succ_of_le (restore_witness_degree (data.values row) (data.witnessCoins row))
  · refine Fin.addCases (n := 10) (m := 10) (fun nonlinear => ?_) (fun linear => ?_) remaining
    · simpa only [sourcePolynomials, Fin.append_right, Fin.append_left, nonlinearColumns] using
        Nat.lt_succ_of_le (unstack_pair_degree (count := 11) 59 (by decide)
          (data.nonlinear ((finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm nonlinear).1)
          (data.pcs (Fin.castAdd 5 ((finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm nonlinear).1))
          ((finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm nonlinear).2)
    · simpa only [sourcePolynomials, Fin.append_right, linearColumns] using
        Nat.lt_succ_of_le (unstack_pair_degree (count := 69) 1 (by decide)
          (linearFull (data.linearCoins ((finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm linear).1))
          (data.pcs (Fin.natAdd 5 ((finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm linear).1))
          ((finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm linear).2)

def sourceCurrentColumns (data : SourceData) : CurrentColumns :=
  fun column coefficient => (sourcePolynomials data column).coeff coefficient.val

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: source_column_reassembles"

theorem source_column_reassembles (data : SourceData) (column : Fin 26230) :
    coefficientPolynomial (sourceCurrentColumns data column) = sourcePolynomials data column :=
  coefficient_polynomial_of_coefficients _ (source_polynomial_degree data column)

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: source_head_is_polynomial_opening"

/-- Actual current head evaluation, now instantiated with constructed source
columns. There is no degree, matrix, or desired-factorization premise. -/
theorem source_head_is_polynomial_opening (data : SourceData) (points : Fin 6 → Goldilocks)
    (opening : Fin 6) (block : Fin 2) (column : Fin 13115) :
    combinationHeads points (stackedHeads (sourceCurrentColumns data))
      (finProdFinEquiv (opening, block)) column =
      (sourcePolynomials data (finProdFinEquiv (block, column))).eval (points opening) :=
  polynomial_head_is_evaluation points (sourcePolynomials data)
    (source_polynomial_degree data) opening block column

/-- Separate current DECS interpolation contract: rotating58 tails before
13115 heads gives13173 coordinates and degree≤13172, never historical13169. -/
def extendedRowPolynomial (heads : Heads) (tails : Tails) (row : Fin 140) : Goldilocks[X] :=
  Lagrange.interpolate (Finset.univ : Finset (Fin 13173))
    (fun node => (node.val : Goldilocks)) (Fin.append (tails row) (heads row))

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: extended_row_degree13172"

theorem extended_row_degree13172 (heads : Heads) (tails : Tails) (row : Fin 140) :
    (extendedRowPolynomial heads tails row).natDegree ≤ 13172 := by
  apply natDegree_le_of_degree_le
  have bound := Lagrange.degree_interpolate_le
    (s := (Finset.univ : Finset (Fin 13173))) (v := fun node => (node.val : Goldilocks))
    (Fin.append (tails row) (heads row)) current_nodes_distinct.injOn
  simpa only [extendedRowPolynomial, Finset.card_univ, Fintype.card_fin] using bound

abbrev CurrentDecsResponseCoefficients := Fin 5 → Fin 13173 → Goldilocks

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: current_decs_response_degree13172"

theorem current_decs_response_degree13172 (coefficients : CurrentDecsResponseCoefficients)
    (repetition : Fin 5) :
    (coefficientPolynomial (coefficients repetition)).natDegree ≤ 13172 :=
  coefficient_polynomial_nat_degree_le (coefficients repetition)

#eval IO.eprintln "G4_SOURCE_COLUMNS_BEGIN: current_width_delta"

theorem current_width_delta :
    (70 - 6 + 63) / 64 = 1 ∧ 64 * 1 + 6 - 70 = 0 ∧
    (75 - 6 + 63) / 64 = 2 ∧ 64 * 2 + 6 - 75 = 59 ∧
    (133 - 6 + 63) / 64 = 2 ∧ 64 * 2 + 6 - 133 = 1 ∧
    26210 + 5 * 2 + 5 * 2 = 26230 ∧ 2 * 13115 = 26230 := by decide

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58Compff01SourceColumns

#eval IO.eprintln "G4_SOURCE_COLUMNS_COMPLETE: 17 theorems"
