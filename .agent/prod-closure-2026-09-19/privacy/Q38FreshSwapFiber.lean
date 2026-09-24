import HegemonCrypto.CmsCompressedOracleUnitary

/-! Concrete compressed-oracle resampling on one database/label fiber.
The raw operation exchanges the recorded oracle answer with the fresh label.
Conjugating by the existing CMS decompression fixes an absent database
coordinate tensor a uniform fresh label exactly. -/
namespace HegemonCrypto.SmallWood.V8SmzaFreshSwapFiber
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsCompressedOracleUnitary
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 1000000

variable {Output : Type} [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
abbrev Joint := EuclideanSpace ℂ (Option Output × Output)

def rawExchange : (Option Output × Output) ≃ (Option Output × Output) where
  toFun pair := match pair.1 with
    | none => (none, pair.2)
    | some answer => (some pair.2, answer)
  invFun pair := match pair.1 with
    | none => (none, pair.2)
    | some answer => (some pair.2, answer)
  left_inv pair := by rcases pair with ⟨slot, label⟩; cases slot <;> rfl
  right_inv pair := by rcases pair with ⟨slot, label⟩; cases slot <;> rfl

def exchange : Joint (Output := Output) ≃ₗᵢ[ℂ] Joint (Output := Output) :=
  LinearIsometryEquiv.piLpCongrLeft 2 ℂ ℂ rawExchange

def tensorUniform (state : FiberState Output) : Joint (Output := Output) :=
  WithLp.toLp 2 (fun pair => state pair.1 * inverseSqrtOutputCard (Output := Output))

def decompressJoint (state : Joint (Output := Output)) : Joint (Output := Output) :=
  WithLp.toLp 2 (fun pair =>
    decompressFiber (WithLp.toLp 2 (fun slot => state (slot, pair.2))) pair.1)

omit [AddCommGroup Output] in
theorem joint_decompression_tensor (state : FiberState Output) :
    decompressJoint (tensorUniform state) = tensorUniform (decompressFiber state) := by
  have sectionEq (label : Output) :
      (WithLp.toLp 2 (fun slot => tensorUniform state (slot, label)) : FiberState Output) =
        inverseSqrtOutputCard (Output := Output) • state := by
    ext slot
    exact mul_comm _ _
  ext pair
  change decompressFiber (WithLp.toLp 2 (fun slot => tensorUniform state (slot, pair.2))) pair.1 = _
  rw [sectionEq, map_smul]
  exact mul_comm _ _

theorem exchange_uniform_tensor :
    exchange (tensorUniform (uniformKet (Output := Output))) = tensorUniform (uniformKet (Output := Output)) := by
  ext pair
  rcases pair with ⟨slot, label⟩
  cases slot with
  | none => rfl
  | some answer =>
    change uniformKet (Output := Output) (some label) * inverseSqrtOutputCard =
      uniformKet (Output := Output) (some answer) * inverseSqrtOutputCard
    rw [uniform_ket_apply_some, uniform_ket_apply_some]

def compressedExchange (state : Joint (Output := Output)) : Joint (Output := Output) :=
  decompressJoint (exchange (decompressJoint state))

/-- Actual oracle/fresh-label exchange fixes the empty compressed fiber;
this is an operator identity, not a supplied freshness-security premise. -/
theorem compressed_exchange_fixes_absent :
    compressedExchange (tensorUniform (absentKet (Output := Output))) =
      tensorUniform (absentKet (Output := Output)) := by
  unfold compressedExchange
  rw [joint_decompression_tensor, decompress_absent_ket, exchange_uniform_tensor,
    joint_decompression_tensor, decompress_uniform_ket]

end
end HegemonCrypto.SmallWood.V8SmzaFreshSwapFiber
