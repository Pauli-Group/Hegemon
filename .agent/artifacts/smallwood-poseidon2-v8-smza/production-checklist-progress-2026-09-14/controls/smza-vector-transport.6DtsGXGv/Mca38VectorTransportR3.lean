import Mca38FinitePartitionR4
import Mca38ScalarDescentR2
import Mathlib.LinearAlgebra.Basis.Defs

/-! Exact five-coordinate transport with an explicit supplied basis.
No concrete extension-field realization or support-count theorem is asserted. -/
namespace HegemonCrypto.SmallWood.Mca38VectorTransport

open V8Smz9McaRecovery Mca38ScalarDescent Mca38Closure Polynomial
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

variable {F K Position : Type*} [Field F] [Field K] [Algebra F K]

abbrev encode (basis : Module.Basis (Fin 5) F K) : (Fin 5 → F) ≃ₗ[F] K :=
  basis.equivFun.symm

def encodeWord (basis : Module.Basis (Fin 5) F K) (word : Fin 5 → Position → F) : Position → K :=
  fun index => encode basis (fun row => word row index)

def encodePolynomial (basis : Module.Basis (Fin 5) F K) (response : Fin 5 → F[X]) : K[X] :=
  ∑ row : Fin 5, (response row).map (algebraMap F K) * Polynomial.C (basis row)

theorem encode_injective (basis : Module.Basis (Fin 5) F K) :
    Function.Injective (encode basis) := (encode basis).injective

theorem encode_lineWord (basis : Module.Basis (Fin 5) F K)
    (prior : Fin 5 → Position → F) (direction : Position → F) (coefficient : Fin 5 → F)
    (index : Position) :
    encodeWord basis (lineWord prior direction coefficient) index =
      encodeWord basis prior index + encode basis coefficient * algebraMap F K (direction index) := by
  have coordinates : (fun row => prior row index + coefficient row * direction index) =
      (fun row => prior row index) + direction index • coefficient := by
    funext row
    simp only [Pi.add_apply, Pi.smul_apply, smul_eq_mul]
    rw [mul_comm]
  change encode basis (fun row => prior row index + coefficient row * direction index) = _
  rw [coordinates, map_add, map_smul, Algebra.smul_def]
  rw [mul_comm (algebraMap F K (direction index))]
  rfl

theorem encodePolynomial_degree (basis : Module.Basis (Fin 5) F K) (degree : Nat)
    (response : Fin 5 → F[X]) (bounded : ∀ row, (response row).natDegree ≤ degree) :
    (encodePolynomial basis response).natDegree ≤ degree := by
  unfold encodePolynomial
  apply Polynomial.natDegree_sum_le_of_forall_le
  intro row _
  exact (Polynomial.natDegree_mul_C_le _ _).trans
    (Polynomial.natDegree_map_le.trans (bounded row))

theorem encodePolynomial_eval (basis : Module.Basis (Fin 5) F K)
    (response : Fin 5 → F[X]) (point : F) :
    (encodePolynomial basis response).eval (algebraMap F K point) =
      encode basis (fun row => (response row).eval point) := by
  simp only [encodePolynomial, Polynomial.eval_finsetSum, Polynomial.eval_mul,
    Polynomial.eval_map_apply, Polynomial.eval_C, encode,
    Module.Basis.equivFun_symm_apply, Algebra.smul_def]

theorem vector_codeOn_iff (basis : Module.Basis (Fin 5) F K) (point : Position → F)
    (degree : Nat) (word : Fin 5 → Position → F) (support : Finset Position) :
    VectorCodeOn point degree word support ↔
      CodeOn (fun index => algebraMap F K (point index)) degree (encodeWord basis word) support := by
  constructor
  · intro coded
    choose response bounded agrees using coded
    refine ⟨encodePolynomial basis response, encodePolynomial_degree basis degree response bounded, ?_⟩
    intro index member
    rw [encodePolynomial_eval]
    apply congrArg (encode basis)
    funext row
    exact agrees row index member
  · rintro ⟨polynomial, bounded, agrees⟩
    intro row
    refine ⟨projectPolynomial degree (basis.coord row) polynomial,
      projectPolynomial_degree degree (basis.coord row) polynomial, ?_⟩
    intro index member
    rw [projectPolynomial_eval degree (basis.coord row) polynomial bounded, agrees index member]
    exact basis.coord_equivFun_symm row (fun row => word row index)

section FinitePosition
variable [Fintype Position]

def scalarAgreement (point : Position → K) (word : Position → K) (response : K[X]) :
    Finset Position := Finset.univ.filter fun index => response.eval (point index) = word index

theorem encoded_full_agreement_eq (basis : Module.Basis (Fin 5) F K) (point : Position → F)
    (word : Fin 5 → Position → F) (response : Fin 5 → F[X]) :
    scalarAgreement (fun index => algebraMap F K (point index)) (encodeWord basis word)
      (encodePolynomial basis response) = agreement point word response := by
  ext index
  simp only [scalarAgreement, Finset.mem_filter, Finset.mem_univ, true_and,
    encodePolynomial_eval, encodeWord, mem_agreement]
  constructor
  · intro equality
    exact fun row => congrFun ((encode basis).injective equality) row
  · intro equality
    exact congrArg (encode basis) (funext equality)

def scalarBadSupport (point : Position → K) (degree cutoff : Nat)
    (prior direction : Position → K) (label : K) : Prop :=
  ∃ support : Finset Position, cutoff ≤ support.card ∧
    CodeOn point degree (fun index => prior index + label * direction index) support ∧
    ¬ CodeOn point degree direction support

variable [Fintype F]

theorem badSupport_transport (basis : Module.Basis (Fin 5) F K) (point : Position → F)
    (degree cutoff : Nat) (prior : Fin 5 → Position → F) (direction : Position → F)
    (coefficient : Fin 5 → F)
    (member : coefficient ∈ badSupportLabels point degree cutoff prior direction) :
    scalarBadSupport (fun index => algebraMap F K (point index)) degree cutoff
      (encodeWord basis prior) (fun index => algebraMap F K (direction index))
      (encode basis coefficient) := by
  obtain ⟨support, large, bad, coded⟩ :=
    counted_label_has_arbitrary_bad_support point degree cutoff prior direction coefficient member
  refine ⟨support, large, ?_, (embedded_scalar_noncode_iff point degree direction support).mpr bad⟩
  have encoded := (vector_codeOn_iff basis point degree
    (lineWord prior direction coefficient) support).mp coded
  have lineEquality : encodeWord basis (lineWord prior direction coefficient) =
      (fun index => encodeWord basis prior index +
        encode basis coefficient * algebraMap F K (direction index)) := by
    funext index
    exact encode_lineWord basis prior direction coefficient index
  rw [lineEquality] at encoded
  exact encoded

theorem encoded_label_image_card (basis : Module.Basis (Fin 5) F K) (point : Position → F)
    (degree cutoff : Nat) (prior : Fin 5 → Position → F) (direction : Position → F) :
    ((badSupportLabels point degree cutoff prior direction).image (encode basis)).card =
      (badSupportLabels point degree cutoff prior direction).card :=
  Finset.card_image_of_injective _ (encode basis).injective

theorem encoded_label_image_bad (basis : Module.Basis (Fin 5) F K) (point : Position → F)
    (degree cutoff : Nat) (prior : Fin 5 → Position → F) (direction : Position → F)
    (label : K)
    (member : label ∈ (badSupportLabels point degree cutoff prior direction).image (encode basis)) :
    scalarBadSupport (fun index => algebraMap F K (point index)) degree cutoff
      (encodeWord basis prior) (fun index => algebraMap F K (direction index)) label := by
  obtain ⟨coefficient, sourceMember, rfl⟩ := Finset.mem_image.mp member
  exact badSupport_transport basis point degree cutoff prior direction coefficient sourceMember

end FinitePosition
end
end HegemonCrypto.SmallWood.Mca38VectorTransport


