import HegemonCrypto.NativeLaunchRecordedOracleGraph
import Mathlib.Data.Fintype.EquivFin

/-! Finite classical equivalence for the actual full64-byte encoding.
Uniformity below means normalized counting of finite events. No randomness
assumption, adversarial execution transport or QROM conclusion is asserted. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
set_option maxRecDepth 5000
set_option exponentiation.threshold 1024
namespace HegemonCrypto.NativeLaunchOracleOutputEquivalence
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Word)
open NativeLaunchFppHistoryBinding (Digest)
open NativeLaunchRecordedMerkleExtraction (Output)
open NativeLaunchRecordedOracleGraph (toOutput toOutput_injective)
noncomputable section
open Classical

theorem digest_cardinality : Fintype.card Digest = 2^512 := by
  norm_num [Digest, Word, Fintype.card_fun]

theorem output_cardinality : Fintype.card Output = 2^512 :=
  SmallWood.V8Smz9CoherentMerkleGeometry.raw_digest_cardinality

theorem equal_cardinality : Fintype.card Digest = Fintype.card Output :=
  digest_cardinality.trans output_cardinality.symm

theorem toOutput_bijective : Function.Bijective toOutput :=
  (Fintype.bijective_iff_injective_and_card toOutput).mpr
    ⟨toOutput_injective, equal_cardinality⟩

def outputEquiv : Digest ≃ Output := Equiv.ofBijective toOutput toOutput_bijective

theorem output_equiv_apply (value : Digest) : outputEquiv value = toOutput value := rfl

def fromOutput : Output → Digest := outputEquiv.symm

theorem from_to_output (value : Digest) : fromOutput (toOutput value) = value :=
  outputEquiv.symm_apply_apply value

theorem to_from_output (value : Output) : toOutput (fromOutput value) = value :=
  outputEquiv.apply_symm_apply value

theorem full_support : Finset.univ.image toOutput = (Finset.univ : Finset Output) := by
  ext value
  simp only [Finset.mem_image, Finset.mem_univ, true_and, iff_true]
  exact toOutput_bijective.2 value

/-- The exact inverse image of an event, represented constructively as a finite
image under the classical inverse. No uniform-law premise is supplied. -/
def pullback (event : Finset Output) : Finset Digest := event.image fromOutput

theorem mem_pullback (event : Finset Output) (value : Digest) :
    value ∈ pullback event ↔ toOutput value ∈ event := by
  constructor
  · intro member
    obtain ⟨output, inside, same⟩ := Finset.mem_image.mp member
    rw [← same, to_from_output]
    exact inside
  · intro inside
    exact Finset.mem_image.mpr ⟨toOutput value, inside, from_to_output value⟩

theorem pullback_cardinality (event : Finset Output) : (pullback event).card = event.card :=
  Finset.card_image_of_injective event outputEquiv.symm.injective

/-- Uniform event mass is cardinality divided by the complete finite support. -/
def uniformDigestMass (event : Finset Digest) : ℚ := event.card / (Fintype.card Digest : ℚ)
def uniformOutputMass (event : Finset Output) : ℚ := event.card / (Fintype.card Output : ℚ)

theorem uniform_event_transport (event : Finset Output) :
    uniformDigestMass (pullback event) = uniformOutputMass event := by
  unfold uniformDigestMass uniformOutputMass
  rw [pullback_cardinality, equal_cardinality]

theorem uniform_output_singleton (value : Output) :
    uniformDigestMass (pullback {value}) = (1 : ℚ) / 2^512 := by
  rw [uniform_event_transport]
  simp only [uniformOutputMass, Finset.card_singleton, output_cardinality,
    Nat.cast_one, Nat.cast_pow, Nat.cast_ofNat]

end
end HegemonCrypto.NativeLaunchOracleOutputEquivalence
