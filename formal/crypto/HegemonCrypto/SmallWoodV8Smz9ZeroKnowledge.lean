import HegemonCrypto.SmallWoodZeroKnowledge
import HegemonCrypto.SmallWoodDecsRestore
import HegemonCrypto.SmallWoodLinearPiopExact
import HegemonCrypto.SmallWoodSmz9ProofWire
import HegemonCrypto.SmallWoodV8Smz9QromAccounting

/-!
# V8 SMZ9 algebraic hiding and whole-view release boundary

This module isolates the information-theoretic part of the fresh SMZ9/profile-6 simulator from
the adaptive Fiat--Shamir argument.  The exact coordinate spaces match the production projection:
686 witness polynomials plus ten PIOP mask polynomials opened at six points, 240 PCS unstack
coordinates, all 2,800 LVCS tail coins mapped jointly to 240 combination tails and 2,560 subset
evaluations, and five DECS polynomials represented by twenty opened evaluations plus 368 high
coefficients.  An additive equivalence on each complete coordinate space gives an explicit
bijection of random coins between any two secrets.  The linear mask also reuses the exact
zero-sum coupling, and the auxiliary-witness space is empty.

The equivalences below prove the algebraic coupling for all six concrete source maps.  They model
the exact witness `poly_restore` basis, forty PCS 6-by-6 blocks, nonlinear and DECS evaluation/high
maps, the degree-132 zero-sum linear map, and the joint 2,800-coordinate LVCS tail map.  Their
injectivity proofs use the same exact opening, correction-factor, and interpolation predicates
enforced or audited by the prover and verifier, then construct the corresponding `AddEquiv` values.
The source verifier and the model in this file now share an exact outer acceptance gate: one
canonical SMZ9 decoding, byte-for-byte re-encoding, the compact-authentication bound, the
per-proof honest-map audit, and the deterministic verifier predicate.  The theorems quantify over
every serialized byte string.  Canonical nonce/opening selection, lazy Merkle programming, final
PIOP programming, concrete SHA-512 QROM instantiation, adaptive repeated-proof composition, and
independent review remain separate release premises.
No production authority is constructed here.
-/

namespace HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge

open HegemonCrypto.SmallWood.ZeroKnowledge
open HegemonCrypto.SmallWood.DecsRestore
open HegemonCrypto.SmallWoodSmz9ProofWire
open HegemonCrypto.CanonicalBytes
open Polynomial

set_option maxHeartbeats 0
set_option maxRecDepth 100000

def executableZkRefinementEvidenceId : String :=
  "hegemon.smallwood.poseidon2-v8.smz9.executable-zk-refinement.v1"
def acceptedProofRefinementEvidenceId : String :=
  "hegemon.smallwood.poseidon2-v8.smz9.accepted-proof-refinement.v1"
def leanWireModelId : String :=
  "HegemonCrypto.SmallWoodSmz9ProofWire.decodeProofExact"
def adaptiveQromWholeViewReceiptId : String :=
  "hegemon.formal.smallwood-smz9.adaptive-qrom-whole-view.v1"

theorem exact_security_evidence_ids :
    executableZkRefinementEvidenceId =
        "hegemon.smallwood.poseidon2-v8.smz9.executable-zk-refinement.v1" ∧
      acceptedProofRefinementEvidenceId =
        "hegemon.smallwood.poseidon2-v8.smz9.accepted-proof-refinement.v1" ∧
      leanWireModelId =
        "HegemonCrypto.SmallWoodSmz9ProofWire.decodeProofExact" ∧
      adaptiveQromWholeViewReceiptId =
        "hegemon.formal.smallwood-smz9.adaptive-qrom-whole-view.v1" := by
  exact ⟨rfl, rfl, rfl, rfl⟩

section AffineTransport

variable {Coins View : Type*}
variable [AddCommGroup Coins] [AddCommGroup View]

def transformedAffineView
    (randomnessMap : Coins ≃+ View) (secret : View) (coins : Coins) : View :=
  secret + randomnessMap coins

/-- Transport coins through an invertible linear opening map and an affine secret shift. -/
def transformedAffineCoinsEquiv
    (randomnessMap : Coins ≃+ View) (leftSecret rightSecret : View) : Coins ≃ Coins where
  toFun coins :=
    randomnessMap.symm (leftSecret + randomnessMap coins - rightSecret)
  invFun coins :=
    randomnessMap.symm (rightSecret + randomnessMap coins - leftSecret)
  left_inv coins := by
    apply randomnessMap.injective
    simp only [AddEquiv.apply_symm_apply]
    abel
  right_inv coins := by
    apply randomnessMap.injective
    simp only [AddEquiv.apply_symm_apply]
    abel

theorem transformed_affine_views_are_exactly_coupled
    (randomnessMap : Coins ≃+ View)
    (leftSecret rightSecret : View)
    (coins : Coins) :
    transformedAffineView randomnessMap rightSecret
        (transformedAffineCoinsEquiv randomnessMap leftSecret rightSecret coins) =
      transformedAffineView randomnessMap leftSecret coins := by
  change
    rightSecret + randomnessMap
        (randomnessMap.symm (leftSecret + randomnessMap coins - rightSecret)) =
      leftSecret + randomnessMap coins
  rw [AddEquiv.apply_symm_apply]
  abel

end AffineTransport

def packingFactor : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor
def piopOpeningCount : Nat := 6
def witnessPolynomialCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.relationRowCount
def nonlinearMaskPolynomialCount : Nat := 5
def linearMaskPolynomialCount : Nat := 5
def packedPolynomialCount : Nat := 696
def partialEvaluationColumnCount : Nat := 40
def nonlinearMaskPolynomialDegree : Nat := 488
def linearMaskPolynomialDegree : Nat := 132
def lvcsOpenedCombinationCount : Nat := 12
def lvcsRowCount : Nat := 140
def lvcsSubsetRowCount : Nat := lvcsRowCount - lvcsOpenedCombinationCount
def decsOpeningCount : Nat := 20
def decsEta : Nat := 5
def proofGeometryColumns : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.proofGeometryColumnCount
def decsPolynomialCoefficientCount : Nat := decsOpeningCount + proofGeometryColumns

theorem smz9_algebraic_coordinate_counts_are_exact :
    packingFactor = 64 ∧ piopOpeningCount = 6 ∧ witnessPolynomialCount = 686 ∧
      nonlinearMaskPolynomialCount = 5 ∧ linearMaskPolynomialCount = 5 ∧
      packedPolynomialCount = 696 ∧ partialEvaluationColumnCount = 40 ∧
      nonlinearMaskPolynomialDegree = 488 ∧ linearMaskPolynomialDegree = 132 ∧
      lvcsOpenedCombinationCount = 12 ∧ lvcsRowCount = 140 ∧
      lvcsSubsetRowCount = 128 ∧ decsOpeningCount = 20 ∧ decsEta = 5 ∧
      proofGeometryColumns = 368 ∧ decsPolynomialCoefficientCount = 388 ∧
      witnessPolynomialCount * piopOpeningCount = 4116 ∧
      partialEvaluationColumnCount * piopOpeningCount = 240 ∧
      nonlinearMaskPolynomialCount * (nonlinearMaskPolynomialDegree + 1) = 2445 ∧
      linearMaskPolynomialCount * linearMaskPolynomialDegree = 660 ∧
      lvcsRowCount * decsOpeningCount = 2800 ∧
      (lvcsOpenedCombinationCount + lvcsSubsetRowCount) * decsOpeningCount = 2800 ∧
      decsEta * decsPolynomialCoefficientCount = 1940 ∧
      openedLeafCount = decsOpeningCount ∧ openedLeafTapesBytes = 1280 := by
  decide

abbrev WitnessInterpolationCoins (F : Type*) :=
  Fin witnessPolynomialCount → Fin piopOpeningCount → F
abbrev WitnessOpeningView (F : Type*) :=
  Fin piopOpeningCount → Fin witnessPolynomialCount → F
abbrev PcsUnstackCoins (F : Type*) :=
  Fin piopOpeningCount → Fin partialEvaluationColumnCount → F
abbrev PcsPartialEvaluationView (F : Type*) :=
  Fin piopOpeningCount → Fin partialEvaluationColumnCount → F

/-! Exact executable PCS-unstack map. -/

open scoped BigOperators

noncomputable section

/-! Exact executable witness-interpolation map. -/

def smz9PackingPoint
    {F : Type*} [Field F] (lane : Fin packingFactor) : F :=
  lane.val

/-- Rust places the six sampled witness coins at coefficient degrees 64 through 69. -/
def witnessHighPart
    {F : Type*} [Field F]
    (coins : Fin piopOpeningCount → F) : F[X] :=
  ∑ coin : Fin piopOpeningCount,
    C (coins coin) * X ^ (packingFactor + coin.val)

def witnessBasisPolynomial
    {F : Type*} [Field F]
    (coin : Fin piopOpeningCount) : F[X] :=
  restorePolynomial
    (Finset.univ : Finset (Fin packingFactor))
    smz9PackingPoint
    (X ^ (packingFactor + coin.val))
    (fun _ => 0)

/-!
The Rust audit constructs these same six unit-high `poly_restore` columns.  Their linear
combination is the complete randomness contribution of one witness row.
-/
def witnessRandomnessPolynomial
    {F : Type*} [Field F]
    (coins : Fin piopOpeningCount → F) : F[X] :=
  ∑ coin : Fin piopOpeningCount,
    C (coins coin) * witnessBasisPolynomial coin

def witnessBasisEntry
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (opening coin : Fin piopOpeningCount) : F :=
  (witnessBasisPolynomial coin).eval (points opening)

/-- The 686 independent exact Rust witness-randomness blocks at the six opening points. -/
def exactWitnessInterpolationMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : WitnessInterpolationCoins F) : WitnessOpeningView F :=
  fun opening row =>
    ∑ coin : Fin piopOpeningCount,
      witnessBasisEntry points opening coin * coins row coin

theorem exact_witness_interpolation_map_matches_rust_poly_restore
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : WitnessInterpolationCoins F)
    (opening : Fin piopOpeningCount)
    (row : Fin witnessPolynomialCount) :
    exactWitnessInterpolationMap points coins opening row =
      ∑ coin : Fin piopOpeningCount,
        coins row coin *
          (restorePolynomial
            (Finset.univ : Finset (Fin packingFactor))
            smz9PackingPoint
            (X ^ (packingFactor + coin.val))
            (fun _ => 0)).eval (points opening) := by
  unfold exactWitnessInterpolationMap witnessBasisEntry witnessBasisPolynomial
  apply Finset.sum_congr rfl
  intro coin _
  ring

structure Smz9WitnessInterpolationAdmissible
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) : Prop where
  packingPointsInjective : Function.Injective (smz9PackingPoint (F := F))
  openingPointsInjective : Function.Injective points
  openingsOutsidePacking :
    ∀ opening lane, points opening ≠ smz9PackingPoint lane

theorem witness_high_part_degree_le
    {F : Type*} [Field F]
    (coins : Fin piopOpeningCount → F) :
    (witnessHighPart coins).natDegree ≤
      packingFactor + piopOpeningCount - 1 := by
  unfold witnessHighPart
  apply natDegree_sum_le_of_forall_le
  intro coin _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  have coinBound := coin.isLt
  change coin.val < 6 at coinBound
  change 64 + coin.val ≤ 64 + 6 - 1
  omega

theorem witness_randomness_polynomial_degree_le
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (coins : Fin piopOpeningCount → F) :
    (witnessRandomnessPolynomial coins).natDegree ≤
      packingFactor + piopOpeningCount - 1 := by
  unfold witnessRandomnessPolynomial
  apply natDegree_sum_le_of_forall_le
  intro coin _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, zero_add]
  unfold witnessBasisPolynomial
  apply restore_polynomial_natDegree_le
  · exact admissible.packingPointsInjective.injOn
  · rw [Finset.card_univ, Fintype.card_fin]
    rw [show piopOpeningCount = 6 by rfl]
    omega
  · simp only [natDegree_X_pow]
    have coinBound := coin.isLt
    change coin.val < 6 at coinBound
    change 64 + coin.val ≤ 64 + 6 - 1
    omega

theorem witness_high_part_coeff
    {F : Type*} [Field F]
    (coins : Fin piopOpeningCount → F)
    (selected : Fin piopOpeningCount) :
    (witnessHighPart coins).coeff (packingFactor + selected.val) = coins selected := by
  classical
  unfold witnessHighPart
  change lcoeff F (packingFactor + selected.val)
      (∑ coin : Fin piopOpeningCount,
        C (coins coin) * X ^ (packingFactor + coin.val)) = coins selected
  rw [map_sum]
  simp only [lcoeff_apply]
  rw [Finset.sum_eq_single selected]
  · simp
  · intro other _ otherNe
    have selectedValueNe : selected.val ≠ other.val := by
      intro equal
      apply otherNe
      apply Fin.ext
      exact equal.symm
    simp [selectedValueNe]
  · simp

theorem witness_randomness_polynomial_high_coeff
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (coins : Fin piopOpeningCount → F)
    (selected : Fin piopOpeningCount) :
    (witnessRandomnessPolynomial coins).coeff (packingFactor + selected.val) =
      coins selected := by
  classical
  unfold witnessRandomnessPolynomial
  have coefficientSum :
      (∑ coin : Fin piopOpeningCount,
        C (coins coin) * witnessBasisPolynomial coin).coeff
          (packingFactor + selected.val) =
        ∑ coin : Fin piopOpeningCount,
          (C (coins coin) * witnessBasisPolynomial coin).coeff
            (packingFactor + selected.val) := by
    simpa only [lcoeff_apply] using
      map_sum (lcoeff F (packingFactor + selected.val))
        (fun coin : Fin piopOpeningCount =>
          C (coins coin) * witnessBasisPolynomial coin)
        Finset.univ
  rw [coefficientSum]
  simp only [coeff_C_mul]
  rw [Finset.sum_eq_single selected]
  · unfold witnessBasisPolynomial
    rw [restore_polynomial_same_high_coefficients
      (support := (Finset.univ : Finset (Fin packingFactor)))
      (point := smz9PackingPoint)
      (highPart := X ^ (packingFactor + selected.val))
      (evaluations := fun _ => 0)
      admissible.packingPointsInjective.injOn
      (packingFactor + selected.val) (by
        rw [Finset.card_univ, Fintype.card_fin]
        omega)]
    simp
  · intro other _ otherNe
    unfold witnessBasisPolynomial
    rw [restore_polynomial_same_high_coefficients
      (support := (Finset.univ : Finset (Fin packingFactor)))
      (point := smz9PackingPoint)
      (highPart := X ^ (packingFactor + other.val))
      (evaluations := fun _ => 0)
      admissible.packingPointsInjective.injOn
      (packingFactor + selected.val) (by
        rw [Finset.card_univ, Fintype.card_fin]
        omega)]
    have valueNe : selected.val ≠ other.val := by
      intro equal
      apply otherNe
      exact Fin.ext equal.symm
    simp [valueNe]
  · simp

theorem witness_randomness_polynomial_eval_packing
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (coins : Fin piopOpeningCount → F)
    (lane : Fin packingFactor) :
    (witnessRandomnessPolynomial coins).eval (smz9PackingPoint lane) = 0 := by
  unfold witnessRandomnessPolynomial
  rw [eval_finsetSum]
  apply Finset.sum_eq_zero
  intro coin _
  rw [eval_mul]
  unfold witnessBasisPolynomial
  rw [restore_polynomial_eval
    admissible.packingPointsInjective.injOn (Finset.mem_univ lane)]
  simp

theorem witness_randomness_polynomial_eval_opening
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : Fin piopOpeningCount → F)
    (opening : Fin piopOpeningCount) :
    (witnessRandomnessPolynomial coins).eval (points opening) =
      ∑ coin : Fin piopOpeningCount,
        witnessBasisEntry points opening coin * coins coin := by
  unfold witnessRandomnessPolynomial witnessBasisEntry
  rw [eval_finsetSum]
  apply Finset.sum_congr rfl
  intro coin _
  rw [eval_mul, eval_C]
  ring

def smz9WitnessDeterminationPoint
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) :
    Sum (Fin packingFactor) (Fin piopOpeningCount) → F
  | .inl lane => smz9PackingPoint lane
  | .inr opening => points opening

theorem smz9_witness_determination_point_injective
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    (admissible : Smz9WitnessInterpolationAdmissible points) :
    Function.Injective (smz9WitnessDeterminationPoint points) := by
  intro left right equal
  cases left with
  | inl leftLane =>
      cases right with
      | inl rightLane =>
          exact congrArg Sum.inl (admissible.packingPointsInjective equal)
      | inr rightOpening =>
          exfalso
          exact admissible.openingsOutsidePacking rightOpening leftLane equal.symm
  | inr leftOpening =>
      cases right with
      | inl rightLane =>
          exfalso
          exact admissible.openingsOutsidePacking leftOpening rightLane equal
      | inr rightOpening =>
          exact congrArg Sum.inr (admissible.openingPointsInjective equal)

theorem exact_witness_interpolation_map_injective
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    (admissible : Smz9WitnessInterpolationAdmissible points) :
    Function.Injective (exactWitnessInterpolationMap points) := by
  intro left right sameView
  funext row coin
  let leftPolynomial := witnessRandomnessPolynomial (left row)
  let rightPolynomial := witnessRandomnessPolynomial (right row)
  have leftDegree :
      leftPolynomial.degree < (70 : WithBot Nat) := by
    dsimp [leftPolynomial]
    have bound :
        (witnessRandomnessPolynomial (left row)).natDegree ≤ 69 := by
      simpa [packingFactor,
        Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor,
        piopOpeningCount] using
        witness_randomness_polynomial_degree_le admissible (left row)
    have natBound :
        (witnessRandomnessPolynomial (left row)).natDegree < 70 := by omega
    exact degree_le_natDegree.trans_lt (WithBot.coe_lt_coe.mpr natBound)
  have rightDegree :
      rightPolynomial.degree < (70 : WithBot Nat) := by
    dsimp [rightPolynomial]
    have bound :
        (witnessRandomnessPolynomial (right row)).natDegree ≤ 69 := by
      simpa [packingFactor,
        Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor,
        piopOpeningCount] using
        witness_randomness_polynomial_degree_le admissible (right row)
    have natBound :
        (witnessRandomnessPolynomial (right row)).natDegree < 70 := by omega
    exact degree_le_natDegree.trans_lt (WithBot.coe_lt_coe.mpr natBound)
  have polynomialEqual : leftPolynomial = rightPolynomial := by
    apply Polynomial.eq_of_degrees_lt_of_eval_index_eq
      (Finset.univ : Finset (Sum (Fin packingFactor) (Fin piopOpeningCount)))
      (smz9_witness_determination_point_injective admissible).injOn
    · convert leftDegree using 1
      all_goals
        norm_num [packingFactor,
          Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor,
          piopOpeningCount]
    · convert rightDegree using 1
      all_goals
        norm_num [packingFactor,
          Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor,
          piopOpeningCount]
    · intro index _
      cases index with
      | inl lane =>
          dsimp [leftPolynomial, rightPolynomial, smz9WitnessDeterminationPoint]
          rw [witness_randomness_polynomial_eval_packing admissible]
          rw [witness_randomness_polynomial_eval_packing admissible]
      | inr opening =>
          dsimp [leftPolynomial, rightPolynomial, smz9WitnessDeterminationPoint]
          rw [witness_randomness_polynomial_eval_opening,
            witness_randomness_polynomial_eval_opening]
          exact congrFun (congrFun sameView opening) row
  have coefficientEqual := congrArg
    (fun polynomial : F[X] => polynomial.coeff (packingFactor + coin.val))
    polynomialEqual
  rw [witness_randomness_polynomial_high_coeff admissible,
      witness_randomness_polynomial_high_coeff admissible] at coefficientEqual
  exact coefficientEqual

def exactWitnessInterpolationLinearMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) :
    WitnessInterpolationCoins F →ₗ[F] WitnessOpeningView F where
  toFun := exactWitnessInterpolationMap points
  map_add' := by
    intro left right
    funext opening row
    simp [exactWitnessInterpolationMap, Finset.sum_add_distrib, mul_add]
  map_smul' := by
    intro scalar coins
    funext opening row
    simp [exactWitnessInterpolationMap, Finset.mul_sum, mul_assoc, mul_comm]

def exactWitnessInterpolationAddEquiv
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (admissible : Smz9WitnessInterpolationAdmissible points) :
    WitnessInterpolationCoins F ≃+ WitnessOpeningView F :=
  (LinearEquiv.ofBijective (exactWitnessInterpolationLinearMap points)
    ((Fintype.bijective_iff_injective_and_card
      (exactWitnessInterpolationLinearMap points)).2
      ⟨exact_witness_interpolation_map_injective admissible, by
        simp [WitnessInterpolationCoins, WitnessOpeningView]
        rw [← pow_mul, ← pow_mul, Nat.mul_comm]
      ⟩)).toAddEquiv

theorem exact_witness_interpolation_add_equiv_apply
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (coins : WitnessInterpolationCoins F) :
    exactWitnessInterpolationAddEquiv points admissible coins =
      exactWitnessInterpolationMap points coins := by
  change (exactWitnessInterpolationLinearMap points) coins =
    exactWitnessInterpolationMap points coins
  rfl

inductive PcsUnstackColumnRole
  | nonlinearIntermediate
  | nonlinearFinal
  | linear
  deriving DecidableEq

/-- Rust serializes 35 nonlinear opened-component columns, then five linear ones. -/
def pcsUnstackColumnRole (column : Fin partialEvaluationColumnCount) : PcsUnstackColumnRole :=
  if column.val < 35 then
    if column.val % 7 < 6 then
      .nonlinearIntermediate
    else
      .nonlinearFinal
  else
    .linear

/-- Row factor in each of the three exact Rust PCS-unstack block families. -/
def pcsUnstackRowFactor
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (column : Fin partialEvaluationColumnCount)
    (row : Fin piopOpeningCount) : F :=
  match pcsUnstackColumnRole column with
  | .nonlinearIntermediate => points row ^ 64 - 1
  | .nonlinearFinal => points row ^ 29 * (points row ^ 35 - 1)
  | .linear => points row * (points row ^ 63 - 1)

/-- Direct coefficient obtained from Rust's add-at-row-`64+t`, subtract-at-source-row update. -/
def rustPcsUnstackBlockEntry
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (column : Fin partialEvaluationColumnCount)
    (row coin : Fin piopOpeningCount) : F :=
  match pcsUnstackColumnRole column with
  | .nonlinearIntermediate =>
      points row ^ (64 + coin.val) - points row ^ coin.val
  | .nonlinearFinal =>
      points row ^ (64 + coin.val) - points row ^ (29 + coin.val)
  | .linear =>
      points row ^ (64 + coin.val) - points row ^ (1 + coin.val)

theorem pcs_unstack_block_entry_matches_rust_rows
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (column : Fin partialEvaluationColumnCount)
    (row coin : Fin piopOpeningCount) :
    pcsUnstackRowFactor points column row * points row ^ coin.val =
      rustPcsUnstackBlockEntry points column row coin := by
  unfold pcsUnstackRowFactor rustPcsUnstackBlockEntry
  cases pcsUnstackColumnRole column with
  | nonlinearIntermediate =>
      rw [pow_add]
      ring
  | nonlinearFinal =>
      have exponentIdentity : 64 + coin.val = (29 + coin.val) + 35 := by omega
      rw [exponentIdentity, pow_add]
      ring
  | linear =>
      have exponentIdentity : 64 + coin.val = (1 + coin.val) + 63 := by omega
      rw [exponentIdentity, pow_add]
      ring

def pcsUnstackBlockMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (factor : Fin piopOpeningCount → F)
    (coins : Fin piopOpeningCount → F) : Fin piopOpeningCount → F :=
  fun row =>
    factor row *
      ∑ coin : Fin piopOpeningCount, points row ^ coin.val * coins coin

/-- Forty separate 6-by-6 blocks, in Rust's exact opened-component column order. -/
def exactPcsUnstackMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : PcsUnstackCoins F) : PcsPartialEvaluationView F :=
  fun row column =>
    pcsUnstackBlockMap points (pcsUnstackRowFactor points column)
      (fun coin => coins coin column) row

theorem exact_pcs_unstack_map_apply_rust_formula
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : PcsUnstackCoins F)
    (row : Fin piopOpeningCount)
    (column : Fin partialEvaluationColumnCount) :
    exactPcsUnstackMap points coins row column =
      ∑ coin : Fin piopOpeningCount,
        rustPcsUnstackBlockEntry points column row coin * coins coin column := by
  unfold exactPcsUnstackMap pcsUnstackBlockMap
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro coin _
  rw [← mul_assoc, pcs_unstack_block_entry_matches_rust_rows]

/-- Exact additional SMZ9 opening predicate required by all forty PCS-unstack blocks. -/
structure Smz9PcsUnstackAdmissible
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) : Prop where
  pointsInjective : Function.Injective points
  pointsNonzero : ∀ row, points row ≠ 0
  pow64NeOne : ∀ row, points row ^ 64 ≠ 1
  pow35NeOne : ∀ row, points row ^ 35 ≠ 1
  pow63NeOne : ∀ row, points row ^ 63 ≠ 1

theorem pcs_unstack_row_factor_ne_zero
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    (admissible : Smz9PcsUnstackAdmissible points)
    (column : Fin partialEvaluationColumnCount)
    (row : Fin piopOpeningCount) :
    pcsUnstackRowFactor points column row ≠ 0 := by
  unfold pcsUnstackRowFactor
  cases pcsUnstackColumnRole column with
  | nonlinearIntermediate =>
      simpa using sub_ne_zero.mpr (admissible.pow64NeOne row)
  | nonlinearFinal =>
      exact mul_ne_zero (pow_ne_zero _ (admissible.pointsNonzero row))
        (sub_ne_zero.mpr (admissible.pow35NeOne row))
  | linear =>
      exact mul_ne_zero (admissible.pointsNonzero row)
        (sub_ne_zero.mpr (admissible.pow63NeOne row))

theorem pcs_unstack_block_map_injective
    {F : Type*} [Field F]
    {points factor : Fin piopOpeningCount → F}
    (pointsInjective : Function.Injective points)
    (factorNonzero : ∀ row, factor row ≠ 0) :
    Function.Injective (pcsUnstackBlockMap points factor) := by
  intro left right sameView
  let difference : Fin piopOpeningCount → F := fun coin => left coin - right coin
  have equations :
      ∀ row : Fin piopOpeningCount,
        (∑ coin : Fin piopOpeningCount,
          points row ^ coin.val * difference coin) = 0 := by
    intro row
    have rowEq := congrFun sameView row
    change
      factor row *
          (∑ coin : Fin piopOpeningCount, points row ^ coin.val * left coin) =
        factor row *
          (∑ coin : Fin piopOpeningCount, points row ^ coin.val * right coin) at rowEq
    have scaled :
        factor row *
            (∑ coin : Fin piopOpeningCount,
              points row ^ coin.val * difference coin) = 0 := by
      calc
        factor row *
            (∑ coin : Fin piopOpeningCount,
              points row ^ coin.val * difference coin) =
            factor row *
              ((∑ coin : Fin piopOpeningCount,
                  points row ^ coin.val * left coin) -
                ∑ coin : Fin piopOpeningCount,
                  points row ^ coin.val * right coin) := by
                    congr 1
                    simp_rw [difference, mul_sub]
                    rw [Finset.sum_sub_distrib]
        _ = factor row *
              (∑ coin : Fin piopOpeningCount,
                points row ^ coin.val * left coin) -
            factor row *
              (∑ coin : Fin piopOpeningCount,
                points row ^ coin.val * right coin) := by ring
        _ = 0 := sub_eq_zero.mpr rowEq
    exact (mul_eq_zero.mp scaled).resolve_left (factorNonzero row)
  have differenceZero : difference = 0 :=
    Matrix.eq_zero_of_forall_index_sum_pow_mul_eq_zero pointsInjective equations
  funext coin
  have entryZero := congrFun differenceZero coin
  exact sub_eq_zero.mp (by simpa [difference] using entryZero)

theorem exact_pcs_unstack_map_injective
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    (admissible : Smz9PcsUnstackAdmissible points) :
    Function.Injective (exactPcsUnstackMap points) := by
  intro left right sameView
  funext coin column
  have sameBlock :
      pcsUnstackBlockMap points (pcsUnstackRowFactor points column)
          (fun index => left index column) =
        pcsUnstackBlockMap points (pcsUnstackRowFactor points column)
          (fun index => right index column) := by
    funext row
    exact congrFun (congrFun sameView row) column
  have sameCoins := pcs_unstack_block_map_injective admissible.pointsInjective
    (pcs_unstack_row_factor_ne_zero admissible column) sameBlock
  exact congrFun sameCoins coin

def exactPcsUnstackLinearMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) :
    PcsUnstackCoins F →ₗ[F] PcsPartialEvaluationView F where
  toFun := exactPcsUnstackMap points
  map_add' := by
    intro left right
    funext row column
    simp [exactPcsUnstackMap, pcsUnstackBlockMap, mul_add,
      Finset.sum_add_distrib]
  map_smul' := by
    intro scalar coins
    funext row column
    simp [exactPcsUnstackMap, pcsUnstackBlockMap, Finset.mul_sum, mul_left_comm]

/-- The exact Rust PCS-unstack map promoted to the `AddEquiv` used by the coupling theorem. -/
def exactPcsUnstackAddEquiv
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (admissible : Smz9PcsUnstackAdmissible points) :
    PcsUnstackCoins F ≃+ PcsPartialEvaluationView F :=
  (LinearEquiv.ofBijective (exactPcsUnstackLinearMap points)
    ((Fintype.bijective_iff_injective_and_card
      (exactPcsUnstackLinearMap points)).2
      ⟨exact_pcs_unstack_map_injective admissible, rfl⟩)).toAddEquiv

theorem exact_pcs_unstack_add_equiv_apply
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (admissible : Smz9PcsUnstackAdmissible points)
    (coins : PcsUnstackCoins F) :
    exactPcsUnstackAddEquiv points admissible coins =
      exactPcsUnstackMap points coins := rfl

end

abbrev EvaluationHighCoordinates
    (F : Type*) (polynomialCount lowCount highCount : Nat) :=
  Fin polynomialCount → ((Fin lowCount → F) × (Fin highCount → F))
abbrev NonlinearPiopMaskCoins (F : Type*) :=
  EvaluationHighCoordinates F nonlinearMaskPolynomialCount piopOpeningCount
    (nonlinearMaskPolynomialDegree + 1 - piopOpeningCount)
abbrev NonlinearPiopView (F : Type*) := NonlinearPiopMaskCoins F
abbrev LinearPiopMaskCoins (F : Type*) :=
  EvaluationHighCoordinates F linearMaskPolynomialCount piopOpeningCount
    (linearMaskPolynomialDegree - piopOpeningCount)
abbrev LinearPiopView (F : Type*) := LinearPiopMaskCoins F
abbrev LinearPackingValues (F : Type*) := Fin packingFactor → F
abbrev LinearZeroSumCoins (F : Type*) [AddCommGroup F] :=
  ZeroSumMask (F := F) (Index := Fin packingFactor)
abbrev LvcsRandomTailCoins (F : Type*) :=
  Fin lvcsRowCount → Fin decsOpeningCount → F
abbrev LvcsJointTailView (F : Type*) :=
  (Fin lvcsOpenedCombinationCount → Fin decsOpeningCount → F) ×
    (Fin decsOpeningCount → Fin lvcsSubsetRowCount → F)
abbrev DecsPolynomialCoins (F : Type*) :=
  EvaluationHighCoordinates F decsEta decsOpeningCount proofGeometryColumns
abbrev DecsEvaluationHighView (F : Type*) := DecsPolynomialCoins F
abbrev AuxiliaryWitnessView (F : Type*) := Fin 0 → F

/-! Exact evaluation-plus-high maps used by nonlinear PIOP and DECS. -/

def evaluationHighMap
    {F : Type*} [Field F]
    {polynomialCount lowCount highCount : Nat}
    (points : Fin lowCount → F)
    (coins : EvaluationHighCoordinates F polynomialCount lowCount highCount) :
    EvaluationHighCoordinates F polynomialCount lowCount highCount :=
  fun polynomial =>
    (fun opening =>
      (∑ low : Fin lowCount,
        (coins polynomial).1 low * points opening ^ low.val) +
      ∑ high : Fin highCount,
        (coins polynomial).2 high * points opening ^ (lowCount + high.val),
    (coins polynomial).2)

theorem evaluation_high_map_matches_rust_coefficient_order
    {F : Type*} [Field F]
    {polynomialCount lowCount highCount : Nat}
    (points : Fin lowCount → F)
    (coins : EvaluationHighCoordinates F polynomialCount lowCount highCount)
    (polynomial : Fin polynomialCount)
    (opening : Fin lowCount) :
    (evaluationHighMap points coins polynomial).1 opening =
      (∑ low : Fin lowCount,
        (coins polynomial).1 low * points opening ^ low.val) +
      ∑ high : Fin highCount,
        (coins polynomial).2 high * points opening ^ (lowCount + high.val) := rfl

theorem evaluation_high_map_injective
    {F : Type*} [Field F]
    {polynomialCount lowCount highCount : Nat}
    {points : Fin lowCount → F}
    (pointsInjective : Function.Injective points) :
    Function.Injective
      (evaluationHighMap (polynomialCount := polynomialCount)
        (highCount := highCount) points) := by
  intro left right sameView
  funext polynomial
  apply Prod.ext
  · funext low
    have samePolynomial := congrFun sameView polynomial
    have sameHigh : (left polynomial).2 = (right polynomial).2 :=
      by simpa [evaluationHighMap] using congrArg Prod.snd samePolynomial
    let difference : Fin lowCount → F :=
      fun index => (left polynomial).1 index - (right polynomial).1 index
    have equations :
        ∀ opening : Fin lowCount,
          (∑ index : Fin lowCount,
            points opening ^ index.val * difference index) = 0 := by
      intro opening
      have sameEvaluation :
        (∑ index : Fin lowCount,
            (left polynomial).1 index * points opening ^ index.val) +
            ∑ high : Fin highCount,
              (left polynomial).2 high *
                points opening ^ (lowCount + high.val) =
          (∑ index : Fin lowCount,
            (right polynomial).1 index * points opening ^ index.val) +
            ∑ high : Fin highCount,
              (right polynomial).2 high *
                points opening ^ (lowCount + high.val) := by
          simpa [evaluationHighMap] using
            congrFun (congrArg Prod.fst samePolynomial) opening
      rw [sameHigh] at sameEvaluation
      rw [add_left_inj] at sameEvaluation
      calc
        (∑ index : Fin lowCount,
            points opening ^ index.val * difference index) =
            (∑ index : Fin lowCount,
              (left polynomial).1 index * points opening ^ index.val) -
              ∑ index : Fin lowCount,
                (right polynomial).1 index * points opening ^ index.val := by
                  simp_rw [difference, mul_sub]
                  rw [Finset.sum_sub_distrib]
                  apply congrArg₂ (· - ·) <;>
                    apply Finset.sum_congr rfl <;> intro index _ <;> ring
        _ = 0 := sub_eq_zero.mpr sameEvaluation
    have differenceZero : difference = 0 :=
      Matrix.eq_zero_of_forall_index_sum_pow_mul_eq_zero pointsInjective equations
    have entryZero := congrFun differenceZero low
    exact sub_eq_zero.mp (by simpa [difference] using entryZero)
  · simpa [evaluationHighMap] using
      congrArg Prod.snd (congrFun sameView polynomial)

def evaluationHighLinearMap
    {F : Type*} [Field F]
    {polynomialCount lowCount highCount : Nat}
    (points : Fin lowCount → F) :
    EvaluationHighCoordinates F polynomialCount lowCount highCount →ₗ[F]
      EvaluationHighCoordinates F polynomialCount lowCount highCount where
  toFun := evaluationHighMap points
  map_add' := by
    intro left right
    funext polynomial
    apply Prod.ext
    · funext opening
      simp [evaluationHighMap, Finset.sum_add_distrib, add_mul]
      abel
    · simp [evaluationHighMap]
  map_smul' := by
    intro scalar coins
    funext polynomial
    apply Prod.ext
    · funext opening
      simp [evaluationHighMap]
      rw [mul_add, Finset.mul_sum, Finset.mul_sum]
      apply congrArg₂ (· + ·) <;>
        apply Finset.sum_congr rfl <;> intro index _ <;> ring
    · simp [evaluationHighMap]

noncomputable def evaluationHighAddEquiv
    {F : Type*} [Field F] [Fintype F]
    {polynomialCount lowCount highCount : Nat}
    (points : Fin lowCount → F)
    (pointsInjective : Function.Injective points) :
    EvaluationHighCoordinates F polynomialCount lowCount highCount ≃+
      EvaluationHighCoordinates F polynomialCount lowCount highCount :=
  (LinearEquiv.ofBijective (evaluationHighLinearMap points)
    ((Fintype.bijective_iff_injective_and_card
      (evaluationHighLinearMap points)).2
      ⟨evaluation_high_map_injective pointsInjective, rfl⟩)).toAddEquiv

theorem evaluation_high_add_equiv_apply
    {F : Type*} [Field F] [Fintype F]
    {polynomialCount lowCount highCount : Nat}
    (points : Fin lowCount → F)
    (pointsInjective : Function.Injective points)
    (coins : EvaluationHighCoordinates F polynomialCount lowCount highCount) :
    evaluationHighAddEquiv points pointsInjective coins =
      evaluationHighMap points coins := rfl

/-! Exact zero-sum linear-PIOP map. -/

/-- Mean of `X^degree` over the 64 packing nodes, matching `poly_random_sum_zero`. -/
def packingPowerMean
    {F : Type*} [Field F] (degree : Nat) : F :=
  (packingFactor : F)⁻¹ *
    ∑ lane : Fin packingFactor, (lane.val : F) ^ degree

/-- The contribution of one sampled nonconstant coefficient after Rust derives coefficient zero. -/
def linearAdjustedBasis
    {F : Type*} [Field F]
    (point : F) (degree : Nat) : F :=
  point ^ degree - packingPowerMean degree

theorem linear_adjusted_basis_has_zero_packing_sum
    {F : Type*} [Field F]
    (packingCardinalityNonzero : (packingFactor : F) ≠ 0)
    (degree : Nat) :
    (∑ lane : Fin packingFactor,
      linearAdjustedBasis (lane.val : F) degree) = 0 := by
  simp [linearAdjustedBasis, packingPowerMean, Finset.sum_sub_distrib,
    packingCardinalityNonzero]

/-- The six degree-1-through-6 columns whose rank is audited by the executable verifier. -/
def linearPiopLowBlockMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : Fin piopOpeningCount → F) : Fin piopOpeningCount → F :=
  fun opening =>
    ∑ low : Fin piopOpeningCount,
      coins low * linearAdjustedBasis (points opening) (low.val + 1)

/-- The degree-7-through-132 contribution, whose coefficients are also transmitted verbatim. -/
def linearPiopHighContribution
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : Fin (linearMaskPolynomialDegree - piopOpeningCount) → F) :
    Fin piopOpeningCount → F :=
  fun opening =>
    ∑ high : Fin (linearMaskPolynomialDegree - piopOpeningCount),
      coins high * linearAdjustedBasis (points opening)
        (piopOpeningCount + 1 + high.val)

/--
Exact coefficient ordering of the Rust linear PIOP map: six evaluations first, then the
126 transmitted coefficients for degrees 7 through 132.  Coefficient zero is not sampled;
its contribution is the negative packing-node mean represented by `linearAdjustedBasis`.
-/
def exactLinearPiopMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : LinearPiopMaskCoins F) : LinearPiopView F :=
  fun polynomial =>
    (fun opening =>
      linearPiopLowBlockMap points (coins polynomial).1 opening +
        linearPiopHighContribution points (coins polynomial).2 opening,
    (coins polynomial).2)

/-- Random evaluation polynomial before the deterministic quotient/target affine shift. -/
def linearPiopRandomEvaluation
    {F : Type*} [Field F]
    (coins : LinearPiopMaskCoins F)
    (polynomial : Fin linearMaskPolynomialCount)
    (point : F) : F :=
  (∑ low : Fin piopOpeningCount,
    (coins polynomial).1 low * linearAdjustedBasis point (low.val + 1)) +
  ∑ high : Fin (linearMaskPolynomialDegree - piopOpeningCount),
    (coins polynomial).2 high * linearAdjustedBasis point
      (piopOpeningCount + 1 + high.val)

theorem linear_piop_random_evaluation_has_exact_zero_packing_sum
    {F : Type*} [Field F]
    (packingCardinalityNonzero : (packingFactor : F) ≠ 0)
    (coins : LinearPiopMaskCoins F)
    (polynomial : Fin linearMaskPolynomialCount) :
    (∑ lane : Fin packingFactor,
      linearPiopRandomEvaluation coins polynomial (lane.val : F)) = 0 := by
  have lowZero :
      (∑ lane : Fin packingFactor,
        ∑ low : Fin piopOpeningCount,
          (coins polynomial).1 low *
            linearAdjustedBasis (lane.val : F) (low.val + 1)) = 0 := by
    rw [Finset.sum_comm]
    apply Finset.sum_eq_zero
    intro low _
    rw [← Finset.mul_sum]
    rw [linear_adjusted_basis_has_zero_packing_sum packingCardinalityNonzero]
    simp
  have highZero :
      (∑ lane : Fin packingFactor,
        ∑ high : Fin (linearMaskPolynomialDegree - piopOpeningCount),
          (coins polynomial).2 high *
            linearAdjustedBasis (lane.val : F)
              (piopOpeningCount + 1 + high.val)) = 0 := by
    rw [Finset.sum_comm]
    apply Finset.sum_eq_zero
    intro high _
    rw [← Finset.mul_sum]
    rw [linear_adjusted_basis_has_zero_packing_sum packingCardinalityNonzero]
    simp
  rw [show
    (∑ lane : Fin packingFactor,
      linearPiopRandomEvaluation coins polynomial (lane.val : F)) =
        (∑ lane : Fin packingFactor,
          ∑ low : Fin piopOpeningCount,
            (coins polynomial).1 low *
              linearAdjustedBasis (lane.val : F) (low.val + 1)) +
        ∑ lane : Fin packingFactor,
          ∑ high : Fin (linearMaskPolynomialDegree - piopOpeningCount),
            (coins polynomial).2 high *
              linearAdjustedBasis (lane.val : F)
                (piopOpeningCount + 1 + high.val) by
      simp [linearPiopRandomEvaluation, Finset.sum_add_distrib]]
  rw [lowZero, highZero, add_zero]

/-- Exact numerator in `smallwood_piop_linear_correction_factor`. -/
def linearPiopCorrectionNumerator
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) : F :=
  ∑ lane : Fin packingFactor,
    (∏ opening : Fin piopOpeningCount,
      ((lane.val : F) - points opening))

/-- Exact denominator in `smallwood_piop_linear_correction_factor`. -/
def linearPiopCorrectionDenominator
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) : F :=
  ∏ opening : Fin piopOpeningCount, -points opening

def linearPiopCorrectionFactor
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) : F :=
  linearPiopCorrectionNumerator points *
    (linearPiopCorrectionDenominator points)⁻¹

theorem linear_piop_generic_packing_mean_eq
    {F : Type*} [Field F]
    (degree : Nat) :
    LinearPiopExact.packingMean
        (Finset.univ : Finset (Fin packingFactor))
        (fun lane => (lane.val : F)) degree =
      packingPowerMean degree := by
  simp [LinearPiopExact.packingMean, packingPowerMean]

theorem linear_piop_generic_low_map_eq
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : Fin piopOpeningCount → F) :
    LinearPiopExact.exactLinearLowMap
        (Finset.univ : Finset (Fin packingFactor))
        (fun lane => (lane.val : F)) points coins =
      linearPiopLowBlockMap points coins := by
  funext opening
  rw [LinearPiopExact.exactLinearLowMap_apply]
  simp_rw [linear_piop_generic_packing_mean_eq]
  rfl

theorem linear_piop_generic_correction_factor_eq
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) :
    LinearPiopExact.correctionFactor
        (Finset.univ : Finset (Fin packingFactor))
        (fun lane => (lane.val : F)) points =
      linearPiopCorrectionFactor points := by
  rw [LinearPiopExact.correctionFactor_eq_rust_formula]
  simp [linearPiopCorrectionFactor, linearPiopCorrectionNumerator,
    linearPiopCorrectionDenominator, LinearPiopExact.rootDenominator]
  congr 1

/--
The exact admissibility facts checked for an accepted SMZ9 proof.  The final field names the
specific six-column map above; it is not an unrelated same-size matrix rank assumption.
-/
structure Smz9LinearPiopAdmissible
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) : Prop where
  packingCardinalityNonzero : (packingFactor : F) ≠ 0
  pointsInjective : Function.Injective points
  pointsNonzero : ∀ opening : Fin piopOpeningCount, points opening ≠ 0
  pointsOutsidePacking :
    ∀ (opening : Fin piopOpeningCount) (lane : Fin packingFactor),
      points opening ≠ (lane.val : F)
  correctionFactorNonzero : linearPiopCorrectionFactor points ≠ 0

theorem linear_piop_low_block_map_injective
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    (admissible : Smz9LinearPiopAdmissible points) :
    Function.Injective (linearPiopLowBlockMap points) := by
  have genericInjective := LinearPiopExact.exactLinearLowMap_injective
    (packing := (Finset.univ : Finset (Fin packingFactor)))
    (point := fun lane => (lane.val : F))
    (openings := points)
    (by simpa using admissible.packingCardinalityNonzero)
    admissible.pointsInjective admissible.pointsNonzero
    (by simpa [linear_piop_generic_correction_factor_eq] using
      admissible.correctionFactorNonzero)
  intro left right sameView
  apply genericInjective
  simpa [linear_piop_generic_low_map_eq, piopOpeningCount] using sameView

theorem exact_linear_piop_map_matches_rust_coefficient_order
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (coins : LinearPiopMaskCoins F)
    (polynomial : Fin linearMaskPolynomialCount)
    (opening : Fin piopOpeningCount) :
    (exactLinearPiopMap points coins polynomial).1 opening =
      (∑ low : Fin piopOpeningCount,
        (coins polynomial).1 low *
          ((points opening) ^ (low.val + 1) - packingPowerMean (low.val + 1))) +
      ∑ high : Fin (linearMaskPolynomialDegree - piopOpeningCount),
        (coins polynomial).2 high *
          ((points opening) ^ (piopOpeningCount + 1 + high.val) -
            packingPowerMean (piopOpeningCount + 1 + high.val)) := rfl

theorem exact_linear_piop_map_injective
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    (admissible : Smz9LinearPiopAdmissible points) :
    Function.Injective (exactLinearPiopMap points) := by
  intro left right sameView
  funext polynomial
  apply Prod.ext
  · have samePolynomial := congrFun sameView polynomial
    have sameHigh : (left polynomial).2 = (right polynomial).2 :=
      by simpa [exactLinearPiopMap] using congrArg Prod.snd samePolynomial
    apply linear_piop_low_block_map_injective admissible
    funext opening
    have sameEvaluation := congrFun (congrArg Prod.fst samePolynomial) opening
    simpa [exactLinearPiopMap, sameHigh] using sameEvaluation
  · simpa [exactLinearPiopMap] using
      congrArg Prod.snd (congrFun sameView polynomial)

def exactLinearPiopLinearMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) :
    LinearPiopMaskCoins F →ₗ[F] LinearPiopView F where
  toFun := exactLinearPiopMap points
  map_add' := by
    intro left right
    funext polynomial
    apply Prod.ext
    · funext opening
      simp [exactLinearPiopMap, linearPiopLowBlockMap,
        linearPiopHighContribution, add_mul, Finset.sum_add_distrib]
      abel
    · simp [exactLinearPiopMap]
  map_smul' := by
    intro scalar coins
    funext polynomial
    apply Prod.ext
    · funext opening
      simp [exactLinearPiopMap, linearPiopLowBlockMap,
        linearPiopHighContribution]
      rw [mul_add, Finset.mul_sum, Finset.mul_sum]
      apply congrArg₂ (· + ·) <;>
        apply Finset.sum_congr rfl <;> intro index _ <;> ring
    · simp [exactLinearPiopMap]

noncomputable def exactLinearPiopAddEquiv
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (admissible : Smz9LinearPiopAdmissible points) :
    LinearPiopMaskCoins F ≃+ LinearPiopView F :=
  (LinearEquiv.ofBijective (exactLinearPiopLinearMap points)
    ((Fintype.bijective_iff_injective_and_card
      (exactLinearPiopLinearMap points)).2
      ⟨exact_linear_piop_map_injective admissible, rfl⟩)).toAddEquiv

theorem exact_linear_piop_add_equiv_apply
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (admissible : Smz9LinearPiopAdmissible points)
    (coins : LinearPiopMaskCoins F) :
    exactLinearPiopAddEquiv points admissible coins =
      exactLinearPiopMap points coins := rfl

/-! Exact triangular LVCS random-tail map. -/

/-- Rust `fullrank_cols`: `[0,1,2,3,4,5,70,71,72,73,74,75]`. -/
def smz9LvcsSelectedRow
    (index : Fin lvcsOpenedCombinationCount) : Fin lvcsRowCount :=
  if h : index.val < piopOpeningCount then
    ⟨index.val, by
      have indexBound := index.isLt
      change index.val < 12 at indexBound
      change index.val < 140
      omega⟩
  else
    ⟨70 + (index.val - piopOpeningCount), by
      have indexBound := index.isLt
      change index.val < 12 at indexBound
      change ¬ index.val < 6 at h
      change 70 + (index.val - 6) < 140
      omega⟩

/-- Ascending complement of `smz9LvcsSelectedRow`: rows 6--69 and 76--139. -/
def smz9LvcsSubsetRow
    (index : Fin lvcsSubsetRowCount) : Fin lvcsRowCount :=
  if h : index.val < 64 then
    ⟨piopOpeningCount + index.val, by
      have indexBound := index.isLt
      change index.val < 128 at indexBound
      change 6 + index.val < 140
      omega⟩
  else
    ⟨76 + (index.val - 64), by
      have indexBound := index.isLt
      change index.val < 128 at indexBound
      change ¬ index.val < 64 at h
      change 76 + (index.val - 64) < 140
      omega⟩

theorem every_lvcs_row_is_selected_or_subset
    (row : Fin lvcsRowCount) :
    (∃ selected : Fin lvcsOpenedCombinationCount,
      smz9LvcsSelectedRow selected = row) ∨
    (∃ subset : Fin lvcsSubsetRowCount,
      smz9LvcsSubsetRow subset = row) := by
  by_cases beforeSix : row.val < 6
  · left
    let selected : Fin lvcsOpenedCombinationCount := ⟨row.val, by
      change row.val < 12
      omega⟩
    refine ⟨selected, ?_⟩
    apply Fin.ext
    simp [smz9LvcsSelectedRow, selected, piopOpeningCount, beforeSix]
  · by_cases beforeSeventy : row.val < 70
    · right
      let subset : Fin lvcsSubsetRowCount := ⟨row.val - 6, by
        have rowBound := row.isLt
        change row.val < 140 at rowBound
        change row.val - 6 < 128
        omega⟩
      refine ⟨subset, ?_⟩
      apply Fin.ext
      have subsetBelow : subset.val < 64 := by
        dsimp [subset]
        omega
      simp [smz9LvcsSubsetRow, subset, piopOpeningCount, subsetBelow]
      omega
    · by_cases beforeSeventySix : row.val < 76
      · left
        let selected : Fin lvcsOpenedCombinationCount :=
          ⟨row.val - 64, by
            have rowBound := row.isLt
            change row.val < 140 at rowBound
            change row.val - 64 < 12
            omega⟩
        refine ⟨selected, ?_⟩
        apply Fin.ext
        have selectedNotBelow : ¬ selected.val < 6 := by
          dsimp [selected]
          omega
        simp [smz9LvcsSelectedRow, selected, piopOpeningCount, selectedNotBelow]
        omega
      · right
        let subset : Fin lvcsSubsetRowCount := ⟨row.val - 12, by
          have rowBound := row.isLt
          change row.val < 140 at rowBound
          change row.val - 12 < 128
          omega⟩
        refine ⟨subset, ?_⟩
        apply Fin.ext
        have subsetNotBelow : ¬ subset.val < 64 := by
          dsimp [subset]
          omega
        simp [smz9LvcsSubsetRow, subset, subsetNotBelow]
        omega

/-- Combination row `q = 2*j + beta` uses PIOP opening `j`. -/
def smz9LvcsCombinationOpening
    (combination : Fin lvcsOpenedCombinationCount) : Fin piopOpeningCount :=
  ⟨combination.val / 2, by
    have combinationBound := combination.isLt
    change combination.val < 12 at combinationBound
    change combination.val / 2 < 6
    omega⟩

/-- Exact coefficient `C[q, 70*beta+s] = r_j^s`, with zero outside beta's block. -/
def smz9LvcsCombinationCoefficient
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (combination : Fin lvcsOpenedCombinationCount)
    (row : Fin lvcsRowCount) : F :=
  let start := 70 * (combination.val % 2)
  if start ≤ row.val ∧ row.val < start + 70 then
    points (smz9LvcsCombinationOpening combination) ^ (row.val - start)
  else
    0

/-- The random tails occupy interpolation nodes 0 through 19 after Rust's left rotation. -/
def smz9LvcsTailNode
    (tail : Fin decsOpeningCount) : Fin decsPolynomialCoefficientCount :=
  ⟨tail.val, by
    have tailBound := tail.isLt
    change tail.val < 20 at tailBound
    change tail.val < 388
    omega⟩

/-- One exact Lagrange coefficient in the complete 388-node rotated LVCS polynomial. -/
noncomputable def smz9LvcsTailLagrangeCoefficient
    {F : Type*} [Field F]
    (target : F)
    (tail : Fin decsOpeningCount) : F :=
  (Lagrange.basis
    (Finset.univ : Finset (Fin decsPolynomialCoefficientCount))
    (fun source => (source.val : F))
    (smz9LvcsTailNode tail)).eval target

/-- Exact 20-by-20 tail-evaluation map for one row. -/
noncomputable def smz9LvcsTailEvaluationMap
    {F : Type*} [Field F]
    (targets : Fin decsOpeningCount → F)
    (tail : Fin decsOpeningCount → F) : Fin decsOpeningCount → F :=
  fun opening =>
    ∑ coordinate : Fin decsOpeningCount,
      smz9LvcsTailLagrangeCoefficient (targets opening) coordinate *
        tail coordinate

/-- Exact two-interleaved-Vandermonde selected block for one tail coordinate. -/
def smz9LvcsSelectedBlockMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (values : Fin lvcsOpenedCombinationCount → F) :
    Fin lvcsOpenedCombinationCount → F :=
  fun combination =>
    ∑ selected : Fin lvcsOpenedCombinationCount,
      smz9LvcsCombinationCoefficient points combination
          (smz9LvcsSelectedRow selected) * values selected

def smz9LvcsSelectedTailMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (tails : LvcsRandomTailCoins F) :
    Fin lvcsOpenedCombinationCount → Fin decsOpeningCount → F :=
  fun combination tail =>
    smz9LvcsSelectedBlockMap points
      (fun selected => tails (smz9LvcsSelectedRow selected) tail) combination

def smz9LvcsSubsetCombinationContribution
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (tails : LvcsRandomTailCoins F) :
    Fin lvcsOpenedCombinationCount → Fin decsOpeningCount → F :=
  fun combination tail =>
    ∑ subset : Fin lvcsSubsetRowCount,
      smz9LvcsCombinationCoefficient points combination
          (smz9LvcsSubsetRow subset) *
        tails (smz9LvcsSubsetRow subset) tail

/--
Exact joint Rust wire order: twelve combination tails first, then twenty opening-major
evaluations for the 128 nonselected rows.
-/
noncomputable def exactLvcsJointTailMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin decsOpeningCount → F)
    (tails : LvcsRandomTailCoins F) : LvcsJointTailView F :=
  (
    fun combination tail =>
      smz9LvcsSelectedTailMap points tails combination tail +
        smz9LvcsSubsetCombinationContribution points tails combination tail,
    fun opening subset =>
      smz9LvcsTailEvaluationMap targets
        (fun tail => tails (smz9LvcsSubsetRow subset) tail) opening
  )

structure Smz9LvcsTailAdmissible
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin decsOpeningCount → F) : Prop where
  pointsInjective : Function.Injective points
  targetsInjective : Function.Injective targets
  targetsOutsideInterpolationDomain :
    ∀ (opening : Fin decsOpeningCount)
      (source : Fin decsPolynomialCoefficientCount),
      targets opening ≠ (source.val : F)
  exactSelectedBlockInjective :
    Function.Injective (smz9LvcsSelectedBlockMap points)
  exactTailEvaluationInjective :
    Function.Injective (smz9LvcsTailEvaluationMap targets)

theorem exact_lvcs_joint_tail_map_injective
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    {targets : Fin decsOpeningCount → F}
    (admissible : Smz9LvcsTailAdmissible points targets) :
    Function.Injective (exactLvcsJointTailMap points targets) := by
  intro left right sameView
  have sameSubsetView := congrArg Prod.snd sameView
  have sameSubsetRows :
      ∀ subset : Fin lvcsSubsetRowCount,
        (fun tail => left (smz9LvcsSubsetRow subset) tail) =
          (fun tail => right (smz9LvcsSubsetRow subset) tail) := by
    intro subset
    apply admissible.exactTailEvaluationInjective
    funext opening
    exact congrFun (congrFun sameSubsetView opening) subset
  have sameCombinationView := congrArg Prod.fst sameView
  have sameSelectedTailMap :
      smz9LvcsSelectedTailMap points left =
        smz9LvcsSelectedTailMap points right := by
    funext combination tail
    have entry := congrFun (congrFun sameCombinationView combination) tail
    change
      smz9LvcsSelectedTailMap points left combination tail +
          smz9LvcsSubsetCombinationContribution points left combination tail =
        smz9LvcsSelectedTailMap points right combination tail +
          smz9LvcsSubsetCombinationContribution points right combination tail at entry
    have sameSubsetContribution :
        smz9LvcsSubsetCombinationContribution points left combination tail =
          smz9LvcsSubsetCombinationContribution points right combination tail := by
      apply Finset.sum_congr rfl
      intro subset _
      rw [congrFun (sameSubsetRows subset) tail]
    rw [sameSubsetContribution] at entry
    exact add_right_cancel entry
  have sameSelectedRows :
      ∀ selected : Fin lvcsOpenedCombinationCount,
        (fun tail => left (smz9LvcsSelectedRow selected) tail) =
          (fun tail => right (smz9LvcsSelectedRow selected) tail) := by
    intro selected
    funext tail
    have sameBlock :
        smz9LvcsSelectedBlockMap points
            (fun index => left (smz9LvcsSelectedRow index) tail) =
          smz9LvcsSelectedBlockMap points
            (fun index => right (smz9LvcsSelectedRow index) tail) := by
      funext combination
      exact congrFun (congrFun sameSelectedTailMap combination) tail
    exact congrFun (admissible.exactSelectedBlockInjective sameBlock) selected
  funext row tail
  rcases every_lvcs_row_is_selected_or_subset row with
    ⟨selected, selectedExact⟩ | ⟨subset, subsetExact⟩
  · rw [← selectedExact]
    exact congrFun (sameSelectedRows selected) tail
  · rw [← subsetExact]
    exact congrFun (sameSubsetRows subset) tail

noncomputable def exactLvcsJointTailLinearMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin decsOpeningCount → F) :
    LvcsRandomTailCoins F →ₗ[F] LvcsJointTailView F where
  toFun := exactLvcsJointTailMap points targets
  map_add' := by
    intro left right
    apply Prod.ext
    · funext combination tail
      simp [exactLvcsJointTailMap, smz9LvcsSelectedTailMap,
        smz9LvcsSelectedBlockMap, smz9LvcsSubsetCombinationContribution,
        mul_add, Finset.sum_add_distrib]
      abel
    · funext opening subset
      simp [exactLvcsJointTailMap, smz9LvcsTailEvaluationMap,
        mul_add, Finset.sum_add_distrib]
  map_smul' := by
    intro scalar tails
    apply Prod.ext
    · funext combination tail
      simp [exactLvcsJointTailMap, smz9LvcsSelectedTailMap,
        smz9LvcsSelectedBlockMap, smz9LvcsSubsetCombinationContribution]
      rw [mul_add, Finset.mul_sum, Finset.mul_sum]
      apply congrArg₂ (· + ·) <;>
        apply Finset.sum_congr rfl <;> intro index _ <;> ring
    · funext opening subset
      simp [exactLvcsJointTailMap, smz9LvcsTailEvaluationMap]
      rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro index _
      ring

theorem lvcs_random_tail_and_joint_view_cardinality_equal
    {F : Type*} [Fintype F] :
    Fintype.card (LvcsRandomTailCoins F) =
      Fintype.card (LvcsJointTailView F) := by
  simp only [LvcsRandomTailCoins, LvcsJointTailView]
  simp_rw [Fintype.card_fun, Fintype.card_prod, Fintype.card_fin]
  simp_rw [Fintype.card_fun, Fintype.card_fin]
  norm_num [decsOpeningCount, lvcsRowCount, lvcsOpenedCombinationCount,
    lvcsSubsetRowCount]
  rw [← pow_mul, ← pow_mul, ← pow_mul, ← pow_add]

noncomputable def exactLvcsJointTailAddEquiv
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin decsOpeningCount → F)
    (admissible : Smz9LvcsTailAdmissible points targets) :
    LvcsRandomTailCoins F ≃+ LvcsJointTailView F :=
  (LinearEquiv.ofBijective (exactLvcsJointTailLinearMap points targets)
    ((Fintype.bijective_iff_injective_and_card
      (exactLvcsJointTailLinearMap points targets)).2
      ⟨exact_lvcs_joint_tail_map_injective admissible,
        lvcs_random_tail_and_joint_view_cardinality_equal⟩)).toAddEquiv

theorem exact_lvcs_joint_tail_add_equiv_apply
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin decsOpeningCount → F)
    (admissible : Smz9LvcsTailAdmissible points targets)
    (tails : LvcsRandomTailCoins F) :
    exactLvcsJointTailAddEquiv points targets admissible tails =
      exactLvcsJointTailMap points targets tails := by
  change (exactLvcsJointTailLinearMap points targets) tails =
    exactLvcsJointTailMap points targets tails
  rfl

structure Smz9AlgebraicHidingMaps (F : Type*) [AddCommGroup F] where
  /-- Six random high coefficients for each of the 686 witness polynomials. -/
  witnessInterpolationTransform :
    WitnessInterpolationCoins F ≃+ WitnessOpeningView F
  /-- The exact 240-coordinate PCS unstack randomization and opened-component view. -/
  pcsUnstackTransform : PcsUnstackCoins F ≃+ PcsPartialEvaluationView F
  /-- Five full random degree-488 masks mapped to opened values plus transmitted highs. -/
  nonlinearPiopTransform : NonlinearPiopMaskCoins F ≃+ NonlinearPiopView F
  /-- Five degree-132 zero-sum masks in the 132 transmitted/opened coordinates. -/
  linearPiopTransform : LinearPiopMaskCoins F ≃+ LinearPiopView F
  /-- All 2,800 LVCS tail coins mapped jointly to 240 combination tails and 2,560 subset values. -/
  lvcsJointTailTransform : LvcsRandomTailCoins F ≃+ LvcsJointTailView F
  /-- Interpolation between five degree-387 coefficient vectors and q evaluations plus C highs. -/
  decsEvaluationHighTransform :
    DecsPolynomialCoins F ≃+ DecsEvaluationHighView F

theorem smz9_piop_opening_view_exact_coupling
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : WitnessOpeningView F)
    (coins : WitnessInterpolationCoins F) :
    transformedAffineView maps.witnessInterpolationTransform rightSecret
        (transformedAffineCoinsEquiv maps.witnessInterpolationTransform
          leftSecret rightSecret coins) =
      transformedAffineView maps.witnessInterpolationTransform leftSecret coins :=
  transformed_affine_views_are_exactly_coupled
    maps.witnessInterpolationTransform leftSecret rightSecret coins

theorem smz9_pcs_partial_evaluation_view_exact_coupling
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : PcsPartialEvaluationView F)
    (coins : PcsUnstackCoins F) :
    transformedAffineView maps.pcsUnstackTransform rightSecret
        (transformedAffineCoinsEquiv maps.pcsUnstackTransform
          leftSecret rightSecret coins) =
      transformedAffineView maps.pcsUnstackTransform leftSecret coins :=
  transformed_affine_views_are_exactly_coupled
    maps.pcsUnstackTransform leftSecret rightSecret coins

theorem smz9_nonlinear_piop_view_exact_coupling
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : NonlinearPiopView F)
    (coins : NonlinearPiopMaskCoins F) :
    transformedAffineView maps.nonlinearPiopTransform rightSecret
        (transformedAffineCoinsEquiv maps.nonlinearPiopTransform
          leftSecret rightSecret coins) =
      transformedAffineView maps.nonlinearPiopTransform leftSecret coins :=
  transformed_affine_views_are_exactly_coupled
    maps.nonlinearPiopTransform leftSecret rightSecret coins

theorem smz9_linear_piop_view_exact_coupling
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : LinearPiopView F)
    (coins : LinearPiopMaskCoins F) :
    transformedAffineView maps.linearPiopTransform rightSecret
        (transformedAffineCoinsEquiv maps.linearPiopTransform
          leftSecret rightSecret coins) =
      transformedAffineView maps.linearPiopTransform leftSecret coins :=
  transformed_affine_views_are_exactly_coupled
    maps.linearPiopTransform leftSecret rightSecret coins

theorem smz9_linear_sum_mask_exact_coupling
    {F : Type*} [AddCommGroup F]
    (leftSecret rightSecret : LinearPackingValues F)
    (samePublicSum : vectorSum leftSecret = vectorSum rightSecret)
    (coins : LinearZeroSumCoins F) :
    maskedVectorView rightSecret
        (zeroSumMaskTransport leftSecret rightSecret samePublicSum coins) =
      maskedVectorView leftSecret coins :=
  zero_sum_masked_views_are_exactly_coupled
    leftSecret rightSecret samePublicSum coins

theorem smz9_lvcs_tail_view_exact_coupling
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : LvcsJointTailView F)
    (coins : LvcsRandomTailCoins F) :
    transformedAffineView maps.lvcsJointTailTransform rightSecret
        (transformedAffineCoinsEquiv maps.lvcsJointTailTransform
          leftSecret rightSecret coins) =
      transformedAffineView maps.lvcsJointTailTransform leftSecret coins :=
  transformed_affine_views_are_exactly_coupled
    maps.lvcsJointTailTransform leftSecret rightSecret coins

theorem smz9_decs_evaluation_high_view_exact_coupling
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : DecsEvaluationHighView F)
    (coins : DecsPolynomialCoins F) :
    transformedAffineView maps.decsEvaluationHighTransform rightSecret
        (transformedAffineCoinsEquiv maps.decsEvaluationHighTransform
          leftSecret rightSecret coins) =
      transformedAffineView maps.decsEvaluationHighTransform leftSecret coins :=
  transformed_affine_views_are_exactly_coupled
    maps.decsEvaluationHighTransform leftSecret rightSecret coins

theorem smz9_auxiliary_witness_view_is_unique
    {F : Type*} (left right : AuxiliaryWitnessView F) : left = right := by
  funext index
  exact Fin.elim0 index

/-!
The executable honest prover must be proved to use these exact maps.  Keeping this as a receipt
prevents the abstract bijection theorem from being mistaken for Rust refinement.
-/
structure ExecutableWitnessInterpolationTransformExact
    (F : Type*) [Field F] [Fintype F]
    (map : WitnessInterpolationCoins F ≃+ WitnessOpeningView F) where
  openingPoints : Fin piopOpeningCount → F
  admissible : Smz9WitnessInterpolationAdmissible openingPoints
  mapMatchesExactRustFormula :
    map = exactWitnessInterpolationAddEquiv openingPoints admissible
structure ExecutablePcsUnstackTransformExact
    (F : Type*) [Field F] [Fintype F]
    (map : PcsUnstackCoins F ≃+ PcsPartialEvaluationView F) where
  openingPoints : Fin piopOpeningCount → F
  admissible : Smz9PcsUnstackAdmissible openingPoints
  mapMatchesExactRustFormula : map = exactPcsUnstackAddEquiv openingPoints admissible
structure ExecutableNonlinearPiopTransformExact
    (F : Type*) [Field F] [Fintype F]
    (map : NonlinearPiopMaskCoins F ≃+ NonlinearPiopView F) where
  openingPoints : Fin piopOpeningCount → F
  openingPointsInjective : Function.Injective openingPoints
  mapMatchesExactRustFormula :
    map = evaluationHighAddEquiv openingPoints openingPointsInjective
structure ExecutableLinearPiopTransformExact
    (F : Type*) [Field F] [Fintype F]
    (map : LinearPiopMaskCoins F ≃+ LinearPiopView F) where
  openingPoints : Fin piopOpeningCount → F
  admissible : Smz9LinearPiopAdmissible openingPoints
  mapMatchesExactRustFormula : map = exactLinearPiopAddEquiv openingPoints admissible
structure ExecutableZeroSumLinearMaskExact
    (F : Type*) [Field F] where
  packingCardinalityNonzero : (packingFactor : F) ≠ 0
  everyMaskHasExactPackingSumZero :
    ∀ (coins : LinearPiopMaskCoins F)
      (polynomial : Fin linearMaskPolynomialCount),
      (∑ lane : Fin packingFactor,
        linearPiopRandomEvaluation coins polynomial (lane.val : F)) = 0
structure ExecutableLvcsJointTailTransformExact
    (F : Type*) [Field F] [Fintype F]
    (map : LvcsRandomTailCoins F ≃+ LvcsJointTailView F) where
  openingPoints : Fin piopOpeningCount → F
  decsPoints : Fin decsOpeningCount → F
  admissible : Smz9LvcsTailAdmissible openingPoints decsPoints
  mapMatchesExactRustFormula :
    map = exactLvcsJointTailAddEquiv openingPoints decsPoints admissible
structure ExecutableDecsEvaluationHighTransformExact
    (F : Type*) [Field F] [Fintype F]
    (map : DecsPolynomialCoins F ≃+ DecsEvaluationHighView F) where
  decsPoints : Fin decsOpeningCount → F
  decsPointsInjective : Function.Injective decsPoints
  mapMatchesExactRustFormula :
    map = evaluationHighAddEquiv decsPoints decsPointsInjective
structure ExecutableOpenedWitnessAuxiliaryZeroExact (F : Type*) where
  coordinateCountIsZero : Fintype.card (Fin 0) = 0
  everyTwoViewsEqual : ∀ left right : AuxiliaryWitnessView F, left = right

structure Smz9HonestAlgebraicMapRefinement (F : Type*) [Field F] [Fintype F] where
  maps : Smz9AlgebraicHidingMaps F
  witnessInterpolationTransformMatchesExecutableProver :
    ExecutableWitnessInterpolationTransformExact F maps.witnessInterpolationTransform
  pcsUnstackTransformMatchesExecutableProver :
    ExecutablePcsUnstackTransformExact F maps.pcsUnstackTransform
  nonlinearPiopTransformMatchesExecutableProver :
    ExecutableNonlinearPiopTransformExact F maps.nonlinearPiopTransform
  linearPiopTransformMatchesExecutableProver :
    ExecutableLinearPiopTransformExact F maps.linearPiopTransform
  zeroSumLinearMaskMatchesExecutableProver : ExecutableZeroSumLinearMaskExact F
  lvcsJointTailTransformMatchesExecutableProver :
    ExecutableLvcsJointTailTransformExact F maps.lvcsJointTailTransform
  decsEvaluationHighTransformMatchesExecutableProver :
    ExecutableDecsEvaluationHighTransformExact F maps.decsEvaluationHighTransform
  openedWitnessAuxiliaryCountIsZero : ExecutableOpenedWitnessAuxiliaryZeroExact F

/--
Build the complete six-map refinement from the exact predicates enforced for one accepted proof.
All six maps below are the concrete Rust formulas; the only remaining release assumptions are the
separately named transcript/hash/QROM and independent-review premises later in this file.
-/
noncomputable def smz9HonestAlgebraicMapRefinementOfExactMaps
    {F : Type*} [Field F] [Fintype F]
    (piopPoints : Fin piopOpeningCount → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible piopPoints)
    (pcsAdmissible : Smz9PcsUnstackAdmissible piopPoints)
    (linearAdmissible : Smz9LinearPiopAdmissible piopPoints)
    (decsPoints : Fin decsOpeningCount → F)
    (lvcsAdmissible : Smz9LvcsTailAdmissible piopPoints decsPoints) :
    Smz9HonestAlgebraicMapRefinement F := by
  let maps : Smz9AlgebraicHidingMaps F := {
    witnessInterpolationTransform :=
      exactWitnessInterpolationAddEquiv piopPoints witnessAdmissible
    pcsUnstackTransform := exactPcsUnstackAddEquiv piopPoints pcsAdmissible
    nonlinearPiopTransform :=
      evaluationHighAddEquiv piopPoints witnessAdmissible.openingPointsInjective
    linearPiopTransform := exactLinearPiopAddEquiv piopPoints linearAdmissible
    lvcsJointTailTransform :=
      exactLvcsJointTailAddEquiv piopPoints decsPoints lvcsAdmissible
    decsEvaluationHighTransform :=
      evaluationHighAddEquiv decsPoints lvcsAdmissible.targetsInjective
  }
  exact {
    maps := maps
    witnessInterpolationTransformMatchesExecutableProver := {
      openingPoints := piopPoints
      admissible := witnessAdmissible
      mapMatchesExactRustFormula := rfl
    }
    pcsUnstackTransformMatchesExecutableProver := {
      openingPoints := piopPoints
      admissible := pcsAdmissible
      mapMatchesExactRustFormula := rfl
    }
    nonlinearPiopTransformMatchesExecutableProver := {
      openingPoints := piopPoints
      openingPointsInjective := witnessAdmissible.openingPointsInjective
      mapMatchesExactRustFormula := rfl
    }
    linearPiopTransformMatchesExecutableProver := {
      openingPoints := piopPoints
      admissible := linearAdmissible
      mapMatchesExactRustFormula := rfl
    }
    zeroSumLinearMaskMatchesExecutableProver := {
      packingCardinalityNonzero := linearAdmissible.packingCardinalityNonzero
      everyMaskHasExactPackingSumZero :=
        linear_piop_random_evaluation_has_exact_zero_packing_sum
          linearAdmissible.packingCardinalityNonzero
    }
    lvcsJointTailTransformMatchesExecutableProver := {
      openingPoints := piopPoints
      decsPoints := decsPoints
      admissible := lvcsAdmissible
      mapMatchesExactRustFormula := rfl
    }
    decsEvaluationHighTransformMatchesExecutableProver := {
      decsPoints := decsPoints
      decsPointsInjective := lvcsAdmissible.targetsInjective
      mapMatchesExactRustFormula := rfl
    }
    openedWitnessAuxiliaryCountIsZero := {
      coordinateCountIsZero := by simp
      everyTwoViewsEqual := smz9_auxiliary_witness_view_is_unique
    }
  }

/-! Exact fresh-wire whole-view boundary. -/

def semanticTargetId : String :=
  "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2"
def publicStatementWordCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.publicStatementWordCount
def relationBindingLimbCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.relationBindingLimbCount
def transcriptDigestBytes : Nat := 64
def maximumCompactAuthenticationNodes : Nat :=
  SmallWoodSmz9ProofWire.maximumCompactAuthenticationNodes
def quantumTargetBits : Nat := 128
def adaptiveQromTarget : ℚ := (1 : ℚ) / ((2 ^ quantumTargetBits : Nat) : ℚ)

structure CompiledSmz9RelationBinding (Statement Witness : Type*) where
  v8CompilerRefinement :
    Hegemon.Transaction.Poseidon2V8ConstraintRefinement.FullRelationCompilerRefinementReceipt
      Statement Witness
  relationId : List Byte
  relationIdExactLength : relationId.length = 48
  relationIdExact : relationId.map Fin.val = v8CompilerRefinement.programSha512.take 48
  semanticTargetIdValue : String
  semanticTargetIdExact : semanticTargetIdValue = semanticTargetId
  publicStatementWords : Statement → List CanonicalFieldWord
  publicStatementWordsExact :
    ∀ statement, (publicStatementWords statement).length = publicStatementWordCount
  bindingLimbs : Statement → List CanonicalFieldWord
  bindingLimbsExact :
    ∀ statement, (bindingLimbs statement).length = relationBindingLimbCount
  semanticTarget : Statement → Witness → Prop
  compiledAccepts : Statement → Witness → Bool
  compiledAcceptsIffSemanticTarget :
    ∀ statement witness,
      compiledAccepts statement witness = true ↔ semanticTarget statement witness

theorem compiled_smz9_relation_binding_is_unavailable_from_checked_in_v8_status
    (Statement Witness : Type*) :
    ¬ Nonempty (CompiledSmz9RelationBinding Statement Witness) := by
  intro evidence
  rcases evidence with ⟨relation⟩
  exact
    (Hegemon.Transaction.Poseidon2V8ConstraintRefinement.full_relation_compiler_receipt_is_unavailable_from_checked_in_status
      Statement Witness) ⟨relation.v8CompilerRefinement⟩

structure Smz9ProgrammedMerkleNode where
  level : Nat
  nodeIndex : Nat
  digestBytes : List Byte
deriving DecidableEq, Repr

def Smz9ProgrammedMerkleNode.Canonical (node : Smz9ProgrammedMerkleNode) : Prop :=
  node.digestBytes.length = transcriptDigestBytes

structure Smz9WholeView (VerifierTrace : Type*) where
  proofBytes : List Byte
  verifierTrace : VerifierTrace
  programmedMerkleNodes : List Smz9ProgrammedMerkleNode
  programmedFinalPiopInputWords : List CanonicalFieldWord
  programmedFinalPiopOutputBytes : List Byte
  rawWitnessWordsConsumed : Nat
  concreteSha512Accepts : Bool
deriving DecidableEq, Repr

def Smz9WholeView.Canonical
    {VerifierTrace : Type*} (view : Smz9WholeView VerifierTrace) : Prop :=
  (∃ proof : SmallWoodSmz9ProofWire.ProofWire,
      SmallWoodSmz9ProofWire.decodeProofExact view.proofBytes = some proof ∧
        proof.encode = view.proofBytes) ∧
    view.programmedMerkleNodes.Forall Smz9ProgrammedMerkleNode.Canonical ∧
    view.programmedFinalPiopOutputBytes.length = transcriptDigestBytes ∧
    view.rawWitnessWordsConsumed = 0

def authenticationNodeCount (proof : SmallWoodSmz9ProofWire.ProofWire) : Nat :=
  proof.pcs.decs.authPaths.nodeCount

structure RustLeanSmz9WholeViewRefinement
    (Statement Witness SimulatorCoins VerifierTrace : Type*)
    (relation : CompiledSmz9RelationBinding Statement Witness) where
  simulator : Statement → SimulatorCoins → Smz9WholeView VerifierTrace
  leanVerifierAccepts : Statement → SmallWoodSmz9ProofWire.ProofWire → Bool
  rustVerifierAccepts : Statement → List Byte → Bool
  rebuildVerifierTrace : Statement → List Byte → VerifierTrace
  programmingMatchesVerifierReplay : Statement → Smz9WholeView VerifierTrace → Prop
  simulatorCanonical : ∀ statement coins, (simulator statement coins).Canonical
  rustLeanVerifierReplayExact :
    ∀ statement coins proof,
      SmallWoodSmz9ProofWire.decodeProofExact (simulator statement coins).proofBytes =
          some proof →
        rustVerifierAccepts statement (simulator statement coins).proofBytes =
          leanVerifierAccepts statement proof
  recordedVerifierTraceExact :
    ∀ statement coins,
      (simulator statement coins).verifierTrace =
        rebuildVerifierTrace statement (simulator statement coins).proofBytes
  recordedConcreteAcceptanceExact :
    ∀ statement coins,
      (simulator statement coins).concreteSha512Accepts =
        rustVerifierAccepts statement (simulator statement coins).proofBytes
  verifierAcceptanceEnforcesCompactAuthenticationBound :
    ∀ statement proof,
      leanVerifierAccepts statement proof = true →
        authenticationNodeCount proof ≤ maximumCompactAuthenticationNodes
  oracleProgrammingReplayExact :
    ∀ statement coins,
      programmingMatchesVerifierReplay statement (simulator statement coins)
  relatedStatementsUseExactCompiledTarget :
    ∀ statement witness,
      relation.semanticTarget statement witness →
        relation.compiledAccepts statement witness = true

structure Smz9WholeViewExperiment
    (Statement Witness SimulatorCoins VerifierTrace Distinguisher : Type*)
    (relation : CompiledSmz9RelationBinding Statement Witness)
    (refinement :
      RustLeanSmz9WholeViewRefinement Statement Witness SimulatorCoins VerifierTrace relation) where
  statement : Statement
  witness : Witness
  relationHolds : relation.semanticTarget statement witness
  realAcceptanceProbability : Distinguisher → ℚ
  simulatedAcceptanceProbability : Distinguisher → ℚ
  realProbabilityInRange :
    ∀ distinguisher,
      0 ≤ realAcceptanceProbability distinguisher ∧
        realAcceptanceProbability distinguisher ≤ 1
  simulatedProbabilityInRange :
    ∀ distinguisher,
      0 ≤ simulatedAcceptanceProbability distinguisher ∧
        simulatedAcceptanceProbability distinguisher ≤ 1

/-!
The Rust V8 verifier now implements this exact outer control flow: exact SMZ9
decode, canonical byte-for-byte re-encode, aggregate authentication-node
bound, honest-map audit, then the deterministic verifier trace result.  The
two Boolean arguments below isolate the algebraic audit and trace predicate;
the wrapper theorem is universal over both and every serialized byte string.
-/
def sourceInternalVerifierAccepts
    (honestMapAudit leanVerifierAccepts :
      SmallWoodSmz9ProofWire.ProofWire → Bool)
    (proofBytes : List Byte) : Bool :=
  match SmallWoodSmz9ProofWire.decodeProofExact proofBytes with
  | none => false
  | some proof =>
      decide (authenticationNodeCount proof ≤ maximumCompactAuthenticationNodes) &&
        honestMapAudit proof && leanVerifierAccepts proof

theorem source_internal_verifier_accepts_iff
    (honestMapAudit leanVerifierAccepts :
      SmallWoodSmz9ProofWire.ProofWire → Bool)
    (proofBytes : List Byte) :
    sourceInternalVerifierAccepts honestMapAudit leanVerifierAccepts proofBytes = true ↔
      ∃ proof,
        SmallWoodSmz9ProofWire.decodeProofExact proofBytes = some proof ∧
          authenticationNodeCount proof ≤ maximumCompactAuthenticationNodes ∧
          honestMapAudit proof = true ∧ leanVerifierAccepts proof = true := by
  unfold sourceInternalVerifierAccepts
  cases decoded : SmallWoodSmz9ProofWire.decodeProofExact proofBytes with
  | none => simp
  | some proof =>
      simp only [Bool.and_eq_true, decide_eq_true_eq]
      constructor
      · rintro ⟨⟨bound, audit⟩, accepts⟩
        exact ⟨proof, rfl, bound, audit, accepts⟩
      · rintro ⟨candidate, candidateDecoded, bound, audit, accepts⟩
        have same : candidate = proof :=
          (Option.some.inj candidateDecoded).symm
        subst candidate
        exact ⟨⟨bound, audit⟩, accepts⟩

theorem source_internal_verifier_acceptance_binds_canonical_serialized_bytes
    {honestMapAudit leanVerifierAccepts :
      SmallWoodSmz9ProofWire.ProofWire → Bool}
    {proofBytes : List Byte}
    (accepted :
      sourceInternalVerifierAccepts honestMapAudit leanVerifierAccepts proofBytes = true) :
    ∃ proof : SmallWoodSmz9ProofWire.ProofWire,
      SmallWoodSmz9ProofWire.ProofWire.Canonical proof ∧
        SmallWoodSmz9ProofWire.ProofWire.encode proof = proofBytes ∧
        authenticationNodeCount proof ≤ maximumCompactAuthenticationNodes ∧
        honestMapAudit proof = true ∧ leanVerifierAccepts proof = true := by
  rcases (source_internal_verifier_accepts_iff
      honestMapAudit leanVerifierAccepts proofBytes).mp accepted with
    ⟨proof, decoded, bound, audit, verifier⟩
  rcases SmallWoodSmz9ProofWire.decodeProofExact_sound decoded with
    ⟨canonical, bytesExact, _⟩
  exact ⟨proof, canonical, bytesExact.symm, bound, audit, verifier⟩

structure ExactExecutableSmz9TranscriptRefinement : Prop where
  evidenceIdExact :
    acceptedProofRefinementEvidenceId =
      "hegemon.smallwood.poseidon2-v8.smz9.accepted-proof-refinement.v1"
  wireModelExact :
    leanWireModelId = "HegemonCrypto.SmallWoodSmz9ProofWire.decodeProofExact"
  universalAcceptanceCharacterization :
    ∀ honestMapAudit leanVerifierAccepts proofBytes,
      sourceInternalVerifierAccepts honestMapAudit leanVerifierAccepts proofBytes = true ↔
        ∃ proof,
          SmallWoodSmz9ProofWire.decodeProofExact proofBytes = some proof ∧
            authenticationNodeCount proof ≤ maximumCompactAuthenticationNodes ∧
            honestMapAudit proof = true ∧ leanVerifierAccepts proof = true
  acceptedBytesCanonical :
    ∀ honestMapAudit leanVerifierAccepts proofBytes,
      sourceInternalVerifierAccepts honestMapAudit leanVerifierAccepts proofBytes = true →
        ∃ proof : SmallWoodSmz9ProofWire.ProofWire,
          SmallWoodSmz9ProofWire.ProofWire.Canonical proof ∧
            SmallWoodSmz9ProofWire.ProofWire.encode proof = proofBytes
  acceptedHonestMapAudit :
    ∀ honestMapAudit leanVerifierAccepts proofBytes,
      sourceInternalVerifierAccepts honestMapAudit leanVerifierAccepts proofBytes = true →
        ∃ proof, honestMapAudit proof = true

theorem checked_in_exact_executable_smz9_transcript_refinement :
    ExactExecutableSmz9TranscriptRefinement := by
  refine
    { evidenceIdExact := rfl
      wireModelExact := rfl
      universalAcceptanceCharacterization := ?_
      acceptedBytesCanonical := ?_
      acceptedHonestMapAudit := ?_ }
  · exact source_internal_verifier_accepts_iff
  · intro honestMapAudit leanVerifierAccepts proofBytes accepted
    rcases source_internal_verifier_acceptance_binds_canonical_serialized_bytes accepted with
      ⟨proof, canonical, bytesExact, _⟩
    exact ⟨proof, canonical, bytesExact⟩
  · intro honestMapAudit leanVerifierAccepts proofBytes accepted
    rcases (source_internal_verifier_accepts_iff
        honestMapAudit leanVerifierAccepts proofBytes).mp accepted with
      ⟨proof, _, _, audit, _⟩
    exact ⟨proof, audit⟩

inductive ConcreteSha512AdaptiveQromInstantiation : Prop
inductive AdaptiveRepeatedSmz9WholeViewHybrid : Prop

theorem adaptive_qrom_receipt_inputs_are_not_constructed_by_local_executable_evidence :
    ExactExecutableSmz9TranscriptRefinement ∧
      ¬ ConcreteSha512AdaptiveQromInstantiation ∧
      ¬ AdaptiveRepeatedSmz9WholeViewHybrid := by
  exact ⟨checked_in_exact_executable_smz9_transcript_refinement,
    (fun evidence => nomatch evidence), (fun evidence => nomatch evidence)⟩

structure Smz9AdaptiveQromWholeViewReduction
    {Statement Witness SimulatorCoins VerifierTrace Distinguisher : Type*}
    {relation : CompiledSmz9RelationBinding Statement Witness}
    {refinement :
      RustLeanSmz9WholeViewRefinement Statement Witness SimulatorCoins VerifierTrace relation}
    (experiment :
      Smz9WholeViewExperiment Statement Witness SimulatorCoins VerifierTrace
        Distinguisher relation refinement) where
  globalQuantumHashQueries : Nat
  globalPriorProofInteractions : Nat
  algebraicMapRefinement : Smz9HonestAlgebraicMapRefinement Goldilocks
  exactTranscriptRefinement : ExactExecutableSmz9TranscriptRefinement
  concreteSha512QromInstantiation : ConcreteSha512AdaptiveQromInstantiation
  adaptiveRepeatedProofHybrid : AdaptiveRepeatedSmz9WholeViewHybrid
  fieldSamplingAbortLoss : ℚ
  nonceAndOpeningAbortLoss : ℚ
  merkleProgrammingLoss : ℚ
  finalPiopProgrammingLoss : ℚ
  sha512InstantiationLoss : ℚ
  residualWholeViewLoss : ℚ
  totalLoss : ℚ
  allLossesNonnegative :
    0 ≤ fieldSamplingAbortLoss ∧ 0 ≤ nonceAndOpeningAbortLoss ∧
      0 ≤ merkleProgrammingLoss ∧ 0 ≤ finalPiopProgrammingLoss ∧
      0 ≤ sha512InstantiationLoss ∧ 0 ≤ residualWholeViewLoss
  totalLossExact :
    totalLoss = fieldSamplingAbortLoss + nonceAndOpeningAbortLoss +
      merkleProgrammingLoss + finalPiopProgrammingLoss +
      sha512InstantiationLoss + residualWholeViewLoss
  completeViewBound :
    ∀ distinguisher,
      |experiment.realAcceptanceProbability distinguisher -
          experiment.simulatedAcceptanceProbability distinguisher| ≤ totalLoss

structure Smz9AdaptiveQromWholeViewReleaseReceipt
    {Statement Witness SimulatorCoins VerifierTrace Distinguisher : Type*}
    {relation : CompiledSmz9RelationBinding Statement Witness}
    {refinement :
      RustLeanSmz9WholeViewRefinement Statement Witness SimulatorCoins VerifierTrace relation}
  (experiment :
      Smz9WholeViewExperiment Statement Witness SimulatorCoins VerifierTrace
        Distinguisher relation refinement) where
  reduction : Smz9AdaptiveQromWholeViewReduction experiment
  lossWithinTarget : reduction.totalLoss ≤ adaptiveQromTarget

theorem smz9_adaptive_qrom_whole_view_indistinguishability_given_release_receipt
    {Statement Witness SimulatorCoins VerifierTrace Distinguisher : Type*}
    {relation : CompiledSmz9RelationBinding Statement Witness}
    {refinement :
      RustLeanSmz9WholeViewRefinement Statement Witness SimulatorCoins VerifierTrace relation}
    (experiment :
      Smz9WholeViewExperiment Statement Witness SimulatorCoins VerifierTrace
        Distinguisher relation refinement)
    (receipt : Smz9AdaptiveQromWholeViewReleaseReceipt experiment) :
    SecurityAuthority.ScopedSecurityClaim .conditionalSupply
      (∀ distinguisher,
        |experiment.realAcceptanceProbability distinguisher -
            experiment.simulatedAcceptanceProbability distinguisher| ≤ adaptiveQromTarget) := by
  apply SecurityAuthority.ScopedSecurityClaim.ofConditionalSupply
  intro distinguisher
  exact (receipt.reduction.completeViewBound distinguisher).trans receipt.lossWithinTarget

theorem smz9_adaptive_qrom_whole_view_release_receipt_is_unavailable
    {Statement Witness SimulatorCoins VerifierTrace Distinguisher : Type*}
    {relation : CompiledSmz9RelationBinding Statement Witness}
    {refinement :
      RustLeanSmz9WholeViewRefinement Statement Witness SimulatorCoins VerifierTrace relation}
    (experiment :
      Smz9WholeViewExperiment Statement Witness SimulatorCoins VerifierTrace
        Distinguisher relation refinement) :
    ¬ Nonempty (Smz9AdaptiveQromWholeViewReleaseReceipt experiment) := by
  rintro ⟨receipt⟩
  exact nomatch receipt.reduction.concreteSha512QromInstantiation

end HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
