import Mca38VectorTransportR3
import Mathlib.FieldTheory.KummerPolynomial
import Mathlib.RingTheory.AdjoinRoot
import Mathlib.FieldTheory.Finite.Basic

/-! Explicit mathematical field F[X]/(X^5-7), its actual five-element power basis,
and unconditional instantiation of the source-label transport. No support count is assumed. -/
namespace HegemonCrypto.SmallWood.Mca38ConcreteExtension

open V8Smz9McaRecovery Mca38Closure Mca38VectorTransport Q38DecoderEvent Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

theorem seven_fifth_residue_ne_one :
    (7 : Goldilocks) ^ ((goldilocksModulus - 1) / 5) ≠ 1 := by
  have checked : (7 : ZMod 18446744069414584321) ^ 3689348813882916864 ≠ 1 := by
    reduce_mod_char
    decide
  exact checked

theorem seven_not_fifth_power (value : Goldilocks) : value ^ 5 ≠ 7 := by
  intro equality
  have nonzero : value ≠ 0 := by
    intro zero
    rw [zero] at equality
    have zero_ne_seven : (0 : Goldilocks) ≠ 7 := by
      change (0 : ZMod 18446744069414584321) ≠ 7
      decide
    exact zero_ne_seven (by simpa only [zero_pow (by decide : 5 ≠ 0)] using equality)
  have exponent : 5 * ((goldilocksModulus - 1) / 5) = goldilocksModulus - 1 := by decide
  have powered := congrArg (fun x : Goldilocks => x ^ ((goldilocksModulus - 1) / 5)) equality
  rw [← pow_mul, exponent, ZMod.pow_card_sub_one_eq_one nonzero] at powered
  exact seven_fifth_residue_ne_one powered.symm

def extensionPolynomial : Goldilocks[X] := X ^ 5 - C 7

theorem extensionPolynomial_degree : extensionPolynomial.natDegree = 5 :=
  Polynomial.natDegree_X_pow_sub_C

theorem extensionPolynomial_irreducible : Irreducible extensionPolynomial :=
  X_pow_sub_C_irreducible_of_prime (by norm_num : Nat.Prime 5) seven_not_fifth_power

instance extensionIrreducible : Fact (Irreducible extensionPolynomial) :=
  ⟨extensionPolynomial_irreducible⟩

abbrev Extension5 := AdjoinRoot extensionPolynomial

def basis5 : Module.Basis (Fin 5) Goldilocks Extension5 :=
  (AdjoinRoot.powerBasis extensionPolynomial_irreducible.ne_zero).basis.reindex
    (finCongr extensionPolynomial_degree)

instance extensionFintype : Fintype Extension5 := Module.fintypeOfFintype basis5

theorem extension_finrank : Module.finrank Goldilocks Extension5 = 5 := by
  rw [Module.finrank_eq_card_basis basis5, Fintype.card_fin]

theorem extension_card : Nat.card Extension5 = goldilocksModulus ^ 5 := by
  rw [Nat.card_eq_fintype_card, Module.card_fintype basis5, goldilocks_card, Fintype.card_fin]

def embeddedPoint (index : Position38) : Extension5 :=
  algebraMap Goldilocks Extension5 (V8Smz9DisjointCoset.evaluationPoint index)

theorem embeddedPoint_injective : Function.Injective embeddedPoint :=
  (algebraMap Goldilocks Extension5).injective.comp
    V8Smz9DisjointCoset.evaluation_point_injective

theorem coefficient_encode_bijective : Function.Bijective (encode basis5) :=
  (encode basis5).bijective

def encodedBadLabels (cutoff : Nat) (prior : Fin 5 → Position38 → Goldilocks)
    (direction : Position38 → Goldilocks) : Finset Extension5 :=
  (badSupportLabels V8Smz9DisjointCoset.evaluationPoint 405 cutoff prior direction).image
    (encode basis5)

theorem encodedBadLabels_card (cutoff : Nat) (prior : Fin 5 → Position38 → Goldilocks)
    (direction : Position38 → Goldilocks) :
    (encodedBadLabels cutoff prior direction).card =
      (badSupportLabels V8Smz9DisjointCoset.evaluationPoint 405 cutoff prior direction).card :=
by
  classical
  exact Finset.card_image_of_injective _ (encode basis5).injective

end
end HegemonCrypto.SmallWood.Mca38ConcreteExtension
