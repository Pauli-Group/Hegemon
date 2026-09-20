import Q38WholeViewCmsSemantics

/-!
The response/phase Walsh transform used by the checked whole-view CMS
semantics is an L2 isometry.  This closes the quantitative transport omitted
from the representation-only inverse laws: `phaseDecode` preserves both norm
and pairwise distance, so a disturbance proved in the native CMS basis may be
fed to the standard-database continuation without changing its constant.
-/
namespace HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9CoherentMerkleInstrument
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open scoped BigOperators Classical ComplexConjugate InnerProductSpace

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

abbrev DigestVector := EuclideanSpace ℂ DigestRegister

def digestFourierVector (state : DigestVector) : DigestVector :=
  WithLp.toLp 2 (digestResponseFourier fun response => state response)

def digestFourierInverseVector (state : DigestVector) : DigestVector :=
  WithLp.toLp 2 (digestResponseFourierInverse fun phase => state phase)

@[simp]
theorem digest_fourier_vector_apply
    (state : DigestVector) (phase : DigestRegister) :
    digestFourierVector state phase = digestResponseFourier state phase := by
  rfl

@[simp]
theorem digest_fourier_inverse_vector_apply
    (state : DigestVector) (response : DigestRegister) :
    digestFourierInverseVector state response =
      digestResponseFourierInverse state response := by
  rfl

theorem digest_fourier_inverse_vector_left (state : DigestVector) :
    digestFourierInverseVector (digestFourierVector state) = state := by
  ext response
  exact congrFun (digest_response_fourier_inverse_left state) response

theorem digest_fourier_inverse_vector_right (state : DigestVector) :
    digestFourierVector (digestFourierInverseVector state) = state := by
  ext phase
  exact congrFun (digest_response_fourier_inverse_right state) phase

/-- The displayed inverse kernel in `Q38WholeViewCmsSemantics` is literally
the Hilbert adjoint of the forward Walsh transform. -/
theorem digest_fourier_adjoint
    (left right : DigestVector) :
    ⟪digestFourierVector left, right⟫_ℂ =
      ⟪left, digestFourierInverseVector right⟫_ℂ := by
  simp only [PiLp.inner_apply, RCLike.inner_apply',
    digest_fourier_vector_apply, digest_fourier_inverse_vector_apply]
  unfold digestResponseFourier digestResponseFourierInverse
  calc
    (∑ phase : DigestRegister,
        star (inverseSqrtOutputCard (Output := DigestRegister) *
          ∑ response : DigestRegister,
            digestCharacter phase response * left response) *
          right phase) =
      ∑ phase : DigestRegister, ∑ response : DigestRegister,
        star (inverseSqrtOutputCard (Output := DigestRegister) *
          digestCharacter phase response) *
          star (left response) * right phase := by
        apply Finset.sum_congr rfl
        intro phase _
        simp_rw [star_mul, star_sum, Finset.sum_mul]
        apply Finset.sum_congr rfl
        intro response _
        rw [star_mul]
        ring
    _ = ∑ response : DigestRegister, ∑ phase : DigestRegister,
        star (left response) *
          (inverseSqrtOutputCard (Output := DigestRegister) *
            digestCharacter phase (-response) * right phase) := by
        rw [Finset.sum_comm]
        apply Finset.sum_congr rfl
        intro response _
        apply Finset.sum_congr rfl
        intro phase _
        rw [digest_fourier_inverse_kernel_is_conjugate]
        ring
    _ = ∑ response : DigestRegister,
        star (left response) *
          (inverseSqrtOutputCard (Output := DigestRegister) *
            ∑ phase : DigestRegister,
              digestCharacter phase (-response) * right phase) := by
        apply Finset.sum_congr rfl
        intro response _
        simp_rw [Finset.mul_sum]
        ring

/-- Parseval for the concrete 512-bit Walsh transform. -/
theorem digest_fourier_vector_norm
    (state : DigestVector) :
    ‖digestFourierVector state‖ = ‖state‖ := by
  have innerEquality := digest_fourier_adjoint state
    (digestFourierVector state)
  rw [digest_fourier_inverse_vector_left] at innerEquality
  have squareEquality :=
    congrArg (RCLike.re : ℂ → ℝ) innerEquality
  rw [← norm_sq_eq_re_inner, ← norm_sq_eq_re_inner] at squareEquality
  nlinarith [norm_nonneg (digestFourierVector state), norm_nonneg state]

theorem digest_fourier_sum_normSq
    (state : DigestRegister → ℂ) :
    (∑ phase : DigestRegister,
      Complex.normSq (digestResponseFourier state phase)) =
      ∑ response : DigestRegister, Complex.normSq (state response) := by
  let vector : DigestVector := WithLp.toLp 2 state
  have preserved := congrArg (fun value : ℝ => value ^ 2)
    (digest_fourier_vector_norm vector)
  rw [EuclideanSpace.norm_sq_eq, EuclideanSpace.norm_sq_eq] at preserved
  simpa only [vector, digestFourierVector, Complex.sq_norm] using preserved

theorem digest_fourier_inverse_sum_normSq
    (state : DigestRegister → ℂ) :
    (∑ response : DigestRegister,
      Complex.normSq (digestResponseFourierInverse state response)) =
      ∑ phase : DigestRegister, Complex.normSq (state phase) := by
  have forward := digest_fourier_sum_normSq
    (digestResponseFourierInverse state)
  simpa only [digest_response_fourier_inverse_right] using forward.symm

variable {Input Work : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]

/-- Applying the response DFT independently in every
input/work/database fiber preserves the complete CMS squared norm. -/
theorem response_fourier_state_norm_squared
    (state : ResponseCmsState Input Work) :
    normSquared (responseFourierState state) = normSquared state := by
  let reindex :
      ((Input × Work × Database Input DigestRegister) ×
          DigestRegister) ≃
        HegemonCrypto.CmsCompressedOracle.Basis
          Input DigestRegister DigestRegister Work :=
    { toFun := fun pair =>
        { input := pair.1.1
          phase := pair.2
          workspace := pair.1.2.1
          database := pair.1.2.2 }
      invFun := fun basis =>
        ((basis.input, basis.workspace, basis.database), basis.phase)
      left_inv := by intro pair; cases pair; rfl
      right_inv := by intro basis; cases basis; rfl }
  unfold normSquared
  rw [← reindex.sum_comp
      (fun basis => Complex.normSq (responseFourierState state basis))]
  rw [← reindex.sum_comp
      (fun basis => Complex.normSq (state basis))]
  calc
    (∑ pair : (Input × Work × Database Input DigestRegister) ×
        DigestRegister,
      Complex.normSq (responseFourierState state (reindex pair))) =
        ∑ rest : Input × Work × Database Input DigestRegister,
          ∑ phase : DigestRegister,
            Complex.normSq
              (responseFourierState state (reindex (rest, phase))) :=
      Fintype.sum_prod_type
        (fun pair : (Input × Work × Database Input DigestRegister) ×
          DigestRegister =>
            Complex.normSq (responseFourierState state (reindex pair)))
    _ = ∑ rest : Input × Work × Database Input DigestRegister,
          ∑ response : DigestRegister,
            Complex.normSq (state (reindex (rest, response))) := by
      apply Finset.sum_congr rfl
      intro rest _
      simpa [reindex, responseFourierState] using
        digest_fourier_sum_normSq
          (fun response => state
            { input := rest.1
              phase := response
              workspace := rest.2.1
              database := rest.2.2 })
    _ = ∑ pair : (Input × Work × Database Input DigestRegister) ×
        DigestRegister, Complex.normSq (state (reindex pair)) :=
      (Fintype.sum_prod_type
        (fun pair : (Input × Work × Database Input DigestRegister) ×
          DigestRegister => Complex.normSq (state (reindex pair)))).symm

theorem response_fourier_inverse_state_norm_squared
    (state : ResponseCmsState Input Work) :
    normSquared (responseFourierInverseState state) = normSquared state := by
  calc
    normSquared (responseFourierInverseState state) =
        normSquared
          (responseFourierState (responseFourierInverseState state)) :=
      (response_fourier_state_norm_squared _).symm
    _ = normSquared state := by rw [response_fourier_inverse_right]

theorem decompress_at_sub
    (selected : Input) (left right : ResponseCmsState Input Work) :
    decompressAt selected (left - right) =
      decompressAt selected left - decompressAt selected right := by
  funext target
  simp only [Pi.sub_apply]
  rw [decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel,
    decompress_at_eq_sum_kernel]
  simp only [Pi.sub_apply, sub_mul, Finset.sum_sub_distrib]

theorem decompress_list_sub
    (inputs : List Input) (left right : ResponseCmsState Input Work) :
    decompressList inputs (left - right) =
      decompressList inputs left - decompressList inputs right := by
  induction inputs with
  | nil => rfl
  | cons selected remaining ih =>
      simp only [decompress_list_cons, decompress_at_sub, ih]

theorem global_decompress_sub
    (left right : ResponseCmsState Input Work) :
    globalDecompress (left - right) =
      globalDecompress left - globalDecompress right := by
  unfold globalDecompress
  exact decompress_list_sub _ left right

theorem response_fourier_inverse_state_sub
    (left right : ResponseCmsState Input Work) :
    responseFourierInverseState (left - right) =
      responseFourierInverseState left -
        responseFourierInverseState right := by
  funext target
  unfold responseFourierInverseState digestResponseFourierInverse
  simp only [Pi.sub_apply, mul_sub, Finset.sum_sub_distrib]

theorem phase_decode_sub
    (left right : ResponseCmsState Input Work) :
    phaseDecode (left - right) = phaseDecode left - phaseDecode right := by
  unfold phaseDecode
  rw [global_decompress_sub, response_fourier_inverse_state_sub]

/-- `phaseDecode` is an exact isometry for the native CMS squared norm. -/
theorem phase_decode_norm_squared
    (state : ResponseCmsState Input Work) :
    normSquared (phaseDecode state) = normSquared state := by
  unfold phaseDecode
  rw [response_fourier_inverse_state_norm_squared]
  exact decompress_list_preserves_norm_squared _ state

/-- Pairwise form consumed by the adaptive whole-view hybrid. -/
theorem phase_decode_difference_norm_squared
    (left right : ResponseCmsState Input Work) :
    normSquared (phaseDecode left - phaseDecode right) =
      normSquared (left - right) := by
  rw [← phase_decode_sub, phase_decode_norm_squared]

end
end HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
