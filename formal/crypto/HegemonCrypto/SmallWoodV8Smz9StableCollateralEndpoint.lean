import HegemonCrypto.SmallWoodV8Smz9StableCollateralBindings

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableCollateral

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

def collateralEndAttempts : List CsrExecutableAttempt :=
  [attempt 20375 72 0 0 [(42137, 1)] 0,
   attempt 20440 80 0 1 [(41427, 304), (42194, 432), (42195, 480)] 0,
   attempt 20441 80 1 1 [(42206, 432), (42207, 480)] 540,
   attempt 20472 82 0 1 [(42200, 304), (42212, 432), (42134, 541), (42218, 432)] 0,
   attempt 20473 82 1 1 [(42201, 304), (42213, 432), (42134, 432), (42135, 541), (42219, 432)] 0,
   attempt 20474 82 2 1 [(42202, 304), (42214, 432), (42135, 432), (42136, 541), (42220, 432)] 0,
   attempt 20475 82 3 1 [(42203, 304), (42215, 432), (42136, 432), (42137, 541), (42221, 432)] 0]

theorem exact_collateral_end_attempts : ∀ entry, entry ∈ collateralEndAttempts →
    entry ∈ exactCsrAttempts := by
  have cert : exactCsrAttempts.filter (fun entry =>
      entry.family == 72 || entry.family == 80 || entry.family == 82) =
      collateralEndAttempts := by decide
  intro entry member
  have filtered : entry ∈ exactCsrAttempts.filter (fun entry =>
      entry.family == 72 || entry.family == 80 || entry.family == 82) := by
    rw [cert]
    exact member
  exact (List.mem_filter.mp filtered).1

theorem accepted_collateral_sources {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mint : publicWords.getD 83 0 = 1) :
    packedWord packed 41427 = packedWord packed 42194 + packedWord packed 42195 * 4294967296 ∧
    publicWords.getD 111 0 = packedWord packed 42206 + packedWord packed 42207 * 4294967296 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have c := collateral_coefficients equations mint
  have l := accepted_csr_attempt_field_equality (attempts _
    (exact_collateral_end_attempts
      (attempt 20440 80 0 1 [(41427, 304), (42194, 432), (42195, 480)] 0) (by decide)))
  have r := accepted_csr_attempt_field_equality (attempts _
    (exact_collateral_end_attempts
      (attempt 20441 80 1 1 [(42206, 432), (42207, 480)] 540) (by decide)))
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, c.mint, c.negMint, c.negMintRadix, c.zero,
    c.negDebt, one_mul, neg_one_mul, add_zero] at l r
  have lfield : (packedWord packed 41427 : F) =
      (packedWord packed 42194 : F) + (packedWord packed 42195 : F) * 4294967296 := by
    simp only [packedWord]
    linear_combination l
  have rfield : (publicWords.getD 111 0 : F) =
      (packedWord packed 42206 : F) + (packedWord packed 42207 : F) * 4294967296 := by
    simp only [packedWord]
    linear_combination r
  have lhi := accepted_high_limb_24 accepted (slot := 0) (by decide)
  have rhi := accepted_high_limb_24 accepted (slot := 3) (by decide)
  have llo := accepted_numeric_32 accepted (lane := 18) (by decide) (by decide)
  have rlo := accepted_numeric_32 accepted (lane := 30) (by decide) (by decide)
  change packedWord packed 42194 < 4294967296 at llo
  change packedWord packed 42206 < 4294967296 at rlo
  norm_num [highLimbSpecs] at lhi rhi
  constructor
  · apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by
      change _ < 18446744069414584321
      omega)
    simpa only [Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat] using lfield
  · apply canonical_nat_cast_injective
      (canonical_public_coordinate accepted.1 (index := 111) (by decide)).2 (by
      change _ < 18446744069414584321
      omega)
    simpa only [Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat] using rfield

theorem borrow_equation_nat {left right previous borrow diff : Nat}
    (hl : left < 4294967296) (hr : right < 4294967296)
    (hp : previous ≤ 1) (hb : borrow ≤ 1) (hd : diff < 4294967296)
    (eq : (left : F) + (borrow : F) * 4294967296 =
      (right : F) + (previous : F) + (diff : F)) :
    left + borrow * 4294967296 = right + previous + diff := by
  apply canonical_nat_cast_injective (by
    change _ < 18446744069414584321
    omega) (by
    change _ < 18446744069414584321
    omega)
  simpa only [Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat] using eq

theorem accepted_collateral_subtract {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mint : publicWords.getD 83 0 = 1) :
    packedWord packed 42212 + packedWord packed 42213 * 4294967296 +
      packedWord packed 42214 * 18446744073709551616 +
      packedWord packed 42215 * 79228162514264337593543950336 ≤
    packedWord packed 42200 + packedWord packed 42201 * 4294967296 +
      packedWord packed 42202 * 18446744073709551616 +
      packedWord packed 42203 * 79228162514264337593543950336 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have c := collateral_coefficients equations mint
  have eqs : ∀ entry, entry ∈ collateralEndAttempts →
      csrFieldSum values packed entry.terms = (values.getD entry.targetRoot 0 : F) := by
    intro entry member
    exact accepted_csr_attempt_field_equality
      (attempts _ (exact_collateral_end_attempts entry member))
  have z := eqs _ (show attempt 20375 72 0 0 [(42137, 1)] 0 ∈ collateralEndAttempts by decide)
  have e0 := eqs _ (show attempt 20472 82 0 1 [(42200, 304), (42212, 432), (42134, 541), (42218, 432)] 0 ∈ collateralEndAttempts by decide)
  have e1 := eqs _ (show attempt 20473 82 1 1 [(42201, 304), (42213, 432), (42134, 432), (42135, 541), (42219, 432)] 0 ∈ collateralEndAttempts by decide)
  have e2 := eqs _ (show attempt 20474 82 2 1 [(42202, 304), (42214, 432), (42135, 432), (42136, 541), (42220, 432)] 0 ∈ collateralEndAttempts by decide)
  have e3 := eqs _ (show attempt 20475 82 3 1 [(42203, 304), (42215, 432), (42136, 432), (42137, 541), (42221, 432)] 0 ∈ collateralEndAttempts by decide)
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, c.mint, c.negMint, c.mintRadix, c.one, c.zero,
    one_mul, neg_one_mul, add_zero] at z e0 e1 e2 e3
  rw [z] at e3
  have b0 : packedWord packed 42134 ≤ 1 := by
    have b := accepted_stable_boolean accepted (lane := 22) (by decide)
    change packedWord packed 42134 = 0 ∨ packedWord packed 42134 = 1 at b
    omega
  have b1 : packedWord packed 42135 ≤ 1 := by
    have b := accepted_stable_boolean accepted (lane := 23) (by decide)
    change packedWord packed 42135 = 0 ∨ packedWord packed 42135 = 1 at b
    omega
  have b2 : packedWord packed 42136 ≤ 1 := by
    have b := accepted_stable_boolean accepted (lane := 24) (by decide)
    change packedWord packed 42136 = 0 ∨ packedWord packed 42136 = 1 at b
    omega
  have f0 : (packedWord packed 42200 : F) + (packedWord packed 42134 : F) * 4294967296 =
      (packedWord packed 42212 : F) + (0 : F) + (packedWord packed 42218 : F) := by
    simp only [packedWord]
    linear_combination e0
  have n0 := borrow_equation_nat
    (accepted_numeric_32 accepted (lane := 24) (by decide) (by decide))
    (accepted_numeric_32 accepted (lane := 36) (by decide) (by decide))
    (by decide) b0
    (accepted_numeric_32 accepted (lane := 42) (by decide) (by decide)) f0
  have f1 : (packedWord packed 42201 : F) + (packedWord packed 42135 : F) * 4294967296 =
      (packedWord packed 42213 : F) + (packedWord packed 42134 : F) + (packedWord packed 42219 : F) := by
    simp only [packedWord]
    linear_combination e1
  have n1 := borrow_equation_nat
    (accepted_numeric_32 accepted (lane := 25) (by decide) (by decide))
    (accepted_numeric_32 accepted (lane := 37) (by decide) (by decide))
    b0 b1
    (accepted_numeric_32 accepted (lane := 43) (by decide) (by decide)) f1
  have f2 : (packedWord packed 42202 : F) + (packedWord packed 42136 : F) * 4294967296 =
      (packedWord packed 42214 : F) + (packedWord packed 42135 : F) + (packedWord packed 42220 : F) := by
    simp only [packedWord]
    linear_combination e2
  have n2 := borrow_equation_nat
    (accepted_numeric_32 accepted (lane := 26) (by decide) (by decide))
    (accepted_numeric_32 accepted (lane := 38) (by decide) (by decide))
    b1 b2
    (accepted_numeric_32 accepted (lane := 44) (by decide) (by decide)) f2
  have f3 : (packedWord packed 42203 : F) + (0 : F) * 4294967296 =
      (packedWord packed 42215 : F) + (packedWord packed 42136 : F) + (packedWord packed 42221 : F) := by
    simp only [packedWord]
    linear_combination e3
  have n3 := borrow_equation_nat
    (accepted_numeric_32 accepted (lane := 27) (by decide) (by decide))
    (accepted_numeric_32 accepted (lane := 39) (by decide) (by decide))
    b2 (by decide)
    (accepted_numeric_32 accepted (lane := 45) (by decide) (by decide)) f3
  simp only [Nat.zero_mul, Nat.add_zero] at n0 n3
  exact four_limb_subtraction n0 n1 n2 n3

/-- Actual repaired HGV8RP03 acceptance implies the mint collateral inequality over Nat. -/
theorem accepted_mint_collateral {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mint : publicWords.getD 83 0 = 1) :
    publicWords.getD 111 0 * packedWord packed 41426 * packedWord packed 41421 ≤
      packedWord packed 41427 * packedWord packed 41425 * 1000000 := by
  have p0 := accepted_collateral_product_nat accepted mint
    (spec := ⟨5, 42194, 41425, 42196, 42199, 0⟩) (by decide)
  have p1 := accepted_collateral_product_nat accepted mint
    (spec := ⟨6, 42195, 41425, 42197, 42198, 42199⟩) (by decide)
  have p2 := accepted_collateral_product_nat accepted mint
    (spec := ⟨7, 42196, 0, 42200, 42204, 0⟩) (by decide)
  have p3 := accepted_collateral_product_nat accepted mint
    (spec := ⟨8, 42197, 0, 42201, 42205, 42204⟩) (by decide)
  have p4 := accepted_collateral_product_nat accepted mint
    (spec := ⟨9, 42198, 0, 42202, 42203, 42205⟩) (by decide)
  have p5 := accepted_collateral_product_nat accepted mint
    (spec := ⟨10, 42206, 41426, 42208, 42211, 0⟩) (by decide)
  have p6 := accepted_collateral_product_nat accepted mint
    (spec := ⟨11, 42207, 41426, 42209, 42210, 42211⟩) (by decide)
  have p7 := accepted_collateral_product_nat accepted mint
    (spec := ⟨12, 42208, 41421, 42212, 42216, 0⟩) (by decide)
  have p8 := accepted_collateral_product_nat accepted mint
    (spec := ⟨13, 42209, 41421, 42213, 42217, 42216⟩) (by decide)
  have p9 := accepted_collateral_product_nat accepted mint
    (spec := ⟨14, 42210, 41421, 42214, 42215, 42217⟩) (by decide)
  norm_num [productRight, productPrevious] at p0 p1 p2 p3 p4 p5 p6 p7 p8 p9
  have lprod := product_two_stage p0 p1 p2 p3 p4
  have rprod := product_two_stage p5 p6 p7 p8 p9
  obtain ⟨lsource, rsource⟩ := accepted_collateral_sources accepted mint
  rw [← lsource] at lprod
  rw [← rsource] at rprod
  rw [lprod, rprod]
  exact accepted_collateral_subtract accepted mint


end HegemonCrypto.SmallWood.V8Smz9SemanticStableCollateral
