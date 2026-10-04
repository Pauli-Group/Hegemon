import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle

/-!
# Full-vector retention versus the physical digest denominator

The counter domain is nonempty because every consumed vector has a selected
physical counter. Constant vectors inject the 512-bit output alphabet into
the full-vector alphabet. Thus the known-cell loss for a full-vector read is
no larger than the physical-digest loss; no counter or statement multiplier
is introduced.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05VectorRetention

open V8Smz9CoherentVectorMerkle V8Smz9RawCounterCompiler V8Smz9HiddenLeafQrom

noncomputable section
set_option autoImplicit false
set_option exponentiation.threshold 1024

variable {Counter : Type*} [Fintype Counter] [DecidableEq Counter]

theorem vector_output_cardinality_ge_digest (counter : Counter) :
    2^512 ≤ Fintype.card (VectorOutput Counter) := by
  have injection : Function.Injective
      (fun value : DigestRegister => fun _ : Counter => value) := by
    intro left right equal
    exact congrFun equal counter
  simpa only [digest_register_cardinality] using
    (Fintype.card_le_of_injective _ injection)

theorem vector_retention_loss_le_digest (counter : Counter) (claims : Nat) :
    ((2 * claims : Nat) : ℝ) / Fintype.card (VectorOutput Counter) ≤
      (2 * (claims : ℝ)) / (2 : ℝ)^512 := by
  have denominator : (2 : ℝ)^512 ≤
      (Fintype.card (VectorOutput Counter) : ℝ) := by
    exact_mod_cast vector_output_cardinality_ge_digest counter
  have bound := div_le_div_of_nonneg_left
    (show 0 ≤ (2 * (claims : ℝ)) by positivity)
    (show (0 : ℝ) < 2^512 by positivity) denominator
  simpa only [Nat.cast_mul, Nat.cast_ofNat] using bound

end
end HegemonCrypto.SmallWood.SmzaRp05VectorRetention
