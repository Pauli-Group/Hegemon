import HegemonCrypto.NativePrivateSpendQ58CurrentSuccessfulFiber
import HegemonCrypto.NativePrivateSpendQ58CurrentQualifiedRecovery

/-! Current fixed-prefix raw q58 bad-event density. This is the actual80-field,
14-block partial sampler; failures remain in the denominator. It supplies the
finite algebra-density input to a current event-instability proof, not the
missing causal decoder-change or accepted-invalid event inclusion. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRawDensity

open HegemonCrypto.CmsClassicalDatabase
open V8Smz9McaRecovery V8Smz9McaDecoder V8Smz9RobustQueryMismatch
open V8Smz9RuntimeRandomness V8Smz9CappedRawSampler V8Smz9RawCounterCompiler
open V8Smz9CoherentMerkleInstrument V8Smz9CoherentVectorMerkle
open NativePrivateSpendQ58CurrentRecovery
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical
noncomputable section
set_option autoImplicit false

/-- Every fixed source/response view outside the universal matrix event has
current sampleLoss density under the actual capped raw sampler. Neither an
equal-fiber assumption nor acceptance/source agreement is supplied. -/
theorem nonexceptional_raw_q58_bad_and_success_density
    (point : NativePrivateSpendQ58CurrentRecovery.Position → Goldilocks) (injective : Function.Injective point)
    (view : SourceResponseView Goldilocks)
    (notBad : ¬ HegemonCrypto.SmallWood.NativeHtlcUniversalMatrix.BadMatrix point 13172 360448 view.data view.masks view.coefficients) :
    outputEventProbability
      (fun raw : Fin (digestCallCap 80) → RawByteBlock =>
        ∃ query,
          NativePrivateSpendQ58CurrentSuccessfulFiber.rawDecoder raw = some query ∧
          query ∈ decoderFailureEvent point 13172 58 view.data view.masks
            view.response view.coefficients) ≤
      NativePrivateSpendQ58CurrentLedger.sampleLoss := by
  calc
    _ ≤ FiniteEvents.probability
        (decoderFailureEvent point 13172 58 view.data view.masks
          view.response view.coefficients) :=
      NativePrivateSpendQ58CurrentSuccessfulFiber.raw_bad_and_success_probability_le _
    _ ≤ _ :=
      NativePrivateSpendQ58CurrentQualifiedRecovery.nonexceptional_sample_output_density
        point injective view notBad

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRawDensity
