import HegemonCrypto.NativePrivateSpendQ58ChronologicalMasks
import HegemonCrypto.SmallWoodV8Smz9EagerPrivacy

/-!
Exact K64/open6 scalar algebra, instantiated at 26203 witness rows and ten
width-two masks of degrees 74/132. Conditional ideal-coordinate component.
No claim of Rust refinement, oracle independence, or complete ZK is made.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58Wpcs
open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open V8Smz9EagerPrivacy
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

abbrev W := Fin 26203 → Fin 6 → Goldilocks
abbrev Values := Fin 26203 → Fin 64 → Goldilocks
abbrev P := Fin 6 → Fin 10 → Goldilocks
abbrev Q := NativePrivateSpendQ58ChronologicalMasks.Q
abbrev D := NativePrivateSpendQ58ChronologicalMasks.D
abbrev Tails := NativePrivateSpendQ58LvcsJoint.Tails
abbrev TailView := NativePrivateSpendQ58LvcsJoint.Earlier × NativePrivateSpendQ58LvcsJoint.Later

/-- Scalar six-high-coefficient witness block. There is no 686-row map here. -/
def witnessBlock (points : Fin 6 → Goldilocks) (coins : Fin 6 → Goldilocks) :
    Fin 6 → Goldilocks := fun opening =>
  (witnessRandomnessPolynomial coins).eval (points opening)

theorem witness_block_injective (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points) :
    Function.Injective (witnessBlock points) := by
  intro left right same
  have bound (coins : Fin 6 → Goldilocks) :
      (witnessRandomnessPolynomial coins).degree < (70 : WithBot Nat) := by
    have h : (witnessRandomnessPolynomial coins).natDegree ≤ 69 := by
      simpa [packingFactor,
        Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor,
        piopOpeningCount] using witness_randomness_polynomial_degree_le admissible coins
    have hlt : (witnessRandomnessPolynomial coins).natDegree < 70 := by omega
    exact degree_le_natDegree.trans_lt (WithBot.coe_lt_coe.mpr hlt)
  have equal : witnessRandomnessPolynomial left = witnessRandomnessPolynomial right := by
    apply Polynomial.eq_of_degrees_lt_of_eval_index_eq
      (Finset.univ : Finset (Sum (Fin packingFactor) (Fin piopOpeningCount)))
      (smz9_witness_determination_point_injective admissible).injOn
    · convert bound left using 1;
        norm_num [packingFactor,
          Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor, piopOpeningCount]
    · convert bound right using 1;
        norm_num [packingFactor,
          Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor, piopOpeningCount]
    · intro index _
      cases index with
      | inl lane =>
          dsimp [smz9WitnessDeterminationPoint]
          rw [witness_randomness_polynomial_eval_packing admissible,
            witness_randomness_polynomial_eval_packing admissible]
      | inr opening => exact congrFun same opening
  funext coin
  have h := congrArg (fun p : Goldilocks[X] => p.coeff (packingFactor + coin.val)) equal
  rw [witness_randomness_polynomial_high_coeff admissible,
    witness_randomness_polynomial_high_coeff admissible] at h
  exact h

def witnessBlockEquiv (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points) :
    (Fin 6 → Goldilocks) ≃ (Fin 6 → Goldilocks) :=
  Equiv.ofBijective (witnessBlock points)
    ((Fintype.bijective_iff_injective_and_card _).2
      ⟨witness_block_injective points admissible, rfl⟩)

def witnessEquiv (values : Values) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points) : W ≃ W :=
  Equiv.piCongrRight fun row => (witnessBlockEquiv points admissible).trans
    (Equiv.addLeft (fun opening => (sourceWitnessBasePolynomial (values row)).eval (points opening)))

/-- The ten source width-two columns have delta59 (five degree74 masks),
then delta1 (five degree132 masks). -/
def delta (column : Fin 10) : Nat := if column.val < 5 then 59 else 1

def partialEffect (points : Fin 6 → Goldilocks) (coins : P) : P :=
  fun opening column => -(points opening ^ delta column) *
    ∑ coefficient : Fin 6, points opening ^ coefficient.val * coins coefficient column

theorem partial_effect_injective (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (nonzero : ∀ opening, points opening ≠ 0) :
    Function.Injective (partialEffect points) := by
  intro left right same
  funext coefficient column
  have rank := pcs_unstack_block_map_injective
    (points := points) (factor := fun opening => -(points opening ^ delta column))
    distinct (fun opening => neg_ne_zero.mpr (pow_ne_zero _ (nonzero opening)))
  have blocks : pcsUnstackBlockMap points (fun opening => -(points opening ^ delta column))
      (fun coefficient => left coefficient column) =
      pcsUnstackBlockMap points (fun opening => -(points opening ^ delta column))
      (fun coefficient => right coefficient column) := by
    funext opening
    exact congrFun (congrFun same opening) column
  exact congrFun (rank blocks) coefficient

def partialLinearEquiv (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (nonzero : ∀ opening, points opening ≠ 0) : P ≃ P :=
  Equiv.ofBijective (partialEffect points)
    ((Fintype.bijective_iff_injective_and_card _).2
      ⟨partial_effect_injective points distinct nonzero, rfl⟩)

/-- Literal source offsets: q[64..74] shifted to rows59..69, and
q[64..132] shifted to rows1..69. Linear Q stores only coefficients1..132. -/
def partialBase (points : Fin 6 → Goldilocks) (masks : Q) : P :=
  fun opening column =>
    if h : column.val < 5 then
      ∑ coefficient : Fin 11,
        masks.1 ⟨column.val, h⟩ ⟨64 + coefficient.val, by omega⟩ *
          points opening ^ (59 + coefficient.val)
    else
      ∑ coefficient : Fin 69,
        masks.2 ⟨column.val - 5, by omega⟩ ⟨63 + coefficient.val, by omega⟩ *
          points opening ^ (1 + coefficient.val)

def partialEquiv (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (nonzero : ∀ opening, points opening ≠ 0)
    (masks : Q) : P ≃ P :=
  (partialLinearEquiv points distinct nonzero).trans (Equiv.addLeft (partialBase points masks))

/-- Same PCS coin occurs in first and second columns; it is not resampled. -/
def twoColumns (point first second random : Goldilocks) (shift : Nat) : Goldilocks × Goldilocks :=
  (first + point^64 * random, second - point^shift * random)

theorem nonlinear_recombines (point first second random : Goldilocks) :
    (twoColumns point first second random 59).1 +
      point^5 * (twoColumns point first second random 59).2 = first + point^5 * second := by
  simp only [twoColumns]
  ring

theorem linear_recombines (point first second random : Goldilocks) :
    (twoColumns point first second random 1).1 +
      point^63 * (twoColumns point first second random 1).2 = first + point^63 * second := by
  simp only [twoColumns]
  ring

/-- Conditional on D,T from the earlier JOINT mask transport, recover exactly
Q=T-U(W,D), transform W, then the same PCS coins using that recovered Q. -/
def conditionedEquiv (values : Values) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (nonzero : ∀ opening, points opening ≠ 0)
    (model : NativePrivateSpendQ58ChronologicalMasks.Model) (d : D) (t : Q) :
    (W × P) ≃ (W × P) :=
  let ew := witnessEquiv values points admissible
  (Equiv.prodCongr ew (Equiv.refl P)).trans
    (NativePrivateSpendQ58ChronologicalMasks.fiberEquiv fun z =>
      partialEquiv points admissible.openingPointsInjective nonzero
        (t - model.piopUnmasked (ew.symm z) d))

theorem conditioned_joint_uniform (values : Values) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (nonzero : ∀ opening, points opening ≠ 0)
    (model : NativePrivateSpendQ58ChronologicalMasks.Model) (d : D) (t : Q) :
    pmfMap (uniformFintypePMF (W × P))
      (conditionedEquiv values points admissible nonzero model d t) =
      uniformFintypePMF (W × P) :=
  uniform_pmf_map_equiv (conditionedEquiv values points admissible nonzero model d t)

/-- Publicly indexed feedback is explicit. The source refinement must establish
that its hash input equals the heads reconstructed from Z/partials/D/T. -/
def remainingEquiv (values : Values) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (nonzero : ∀ opening, points opening ≠ 0)
    (model : NativePrivateSpendQ58ChronologicalMasks.Model) (d : D) (t : Q)
    (choose : W → P → NativePrivateSpendQ58LvcsJoint.Earlier →
      NativePrivateSpendQ58LvcsJoint.Targets) :
    ((W × P) × Tails) ≃ ((W × P) × TailView) :=
  let e := conditionedEquiv values points admissible nonzero model d t
  (Equiv.prodCongr e (Equiv.refl Tails)).trans
    (NativePrivateSpendQ58ChronologicalMasks.fiberEquiv fun output =>
      let old := e.symm output
      NativePrivateSpendQ58LvcsJoint.feedbackEquiv points admissible.openingPointsInjective
        (model.heads old.1 old.2 (t - model.piopUnmasked old.1 d))
        (choose output.1 output.2))

theorem remaining_joint_uniform (values : Values) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (nonzero : ∀ opening, points opening ≠ 0)
    (model : NativePrivateSpendQ58ChronologicalMasks.Model) (d : D) (t : Q)
    (choose : W → P → NativePrivateSpendQ58LvcsJoint.Earlier →
      NativePrivateSpendQ58LvcsJoint.Targets) :
    pmfMap (uniformFintypePMF ((W × P) × Tails))
      (remainingEquiv values points admissible nonzero model d t choose) =
      uniformFintypePMF ((W × P) × TailView) :=
  uniform_pmf_map_equiv (remainingEquiv values points admissible nonzero model d t choose)

theorem exact_counts :
    26203*6 = 157218 ∧ 10*6 = 60 ∧ 157218+60 = 157278 ∧
    26203+2*10 = 26223 ∧ 2*13112 = 26223+1 ∧
    6*26223 = 157338 ∧ 12*13112 = 157338+6 ∧
    157278+1035+8120+65850 = 232283 := by decide

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58Wpcs
