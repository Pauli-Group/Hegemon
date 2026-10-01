import Q38FreshSwapFiber

namespace HegemonCrypto.SmallWood.V8SmzaFreshSwapFiber
open HegemonCrypto.CmsCompressedOracleUnitary
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 1000000

variable {Output : Type} [Fintype Output] [DecidableEq Output] [AddCommGroup Output]

/-- The same explicit fiber decompression as a block-diagonal isometry. -/
def jointDecompression : Joint (Output := Output) ≃ₗᵢ[ℂ] Joint (Output := Output) :=
  let reorder := LinearIsometryEquiv.piLpCongrLeft 2 ℂ ℂ
    ((Equiv.prodComm (Option Output) Output).trans (Equiv.sigmaEquivProd Output (Option Output)).symm)
  let curry := LinearIsometryEquiv.piLpCurry ℂ 2 (fun (_ : Output) (_ : Option Output) => ℂ)
  reorder.trans (curry.trans ((LinearIsometryEquiv.piLpCongrRight 2
    (fun _ : Output => decompressFiber (Output := Output))).trans (curry.symm.trans reorder.symm)))

omit [AddCommGroup Output] in
theorem joint_decompression_eq (state : Joint (Output := Output)) :
    jointDecompression state = decompressJoint state := by
  rfl

def compressedExchangeIsometry : Joint (Output := Output) ≃ₗᵢ[ℂ] Joint (Output := Output) :=
  jointDecompression.trans (exchange.trans jointDecompression)

omit [AddCommGroup Output] in
theorem compressed_exchange_is_actual_isometry (state : Joint (Output := Output)) :
    compressedExchangeIsometry state = compressedExchange state := by
  change jointDecompression (exchange (jointDecompression state)) =
    decompressJoint (exchange (decompressJoint state))
  rw [joint_decompression_eq, joint_decompression_eq]

omit [AddCommGroup Output] in
theorem compressed_exchange_preserves_norm (state : Joint (Output := Output)) :
    ‖compressedExchange state‖ = ‖state‖ := by
  rw [← compressed_exchange_is_actual_isometry]
  exact compressedExchangeIsometry.norm_map state

end
end HegemonCrypto.SmallWood.V8SmzaFreshSwapFiber
