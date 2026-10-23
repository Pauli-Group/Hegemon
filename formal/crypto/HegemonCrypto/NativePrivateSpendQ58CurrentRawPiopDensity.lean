import HegemonCrypto.NativePrivateSpendQ58CurrentPiopEvents
import SmzaRp04RawRoleSampling

/-! Current raw PIOP challenge success-and-bad density.
The matrix sampler's generic width-parametric raw decoder is reused at the
actual width1344594. The opening decoder is new and filters exactly the
current six-field admissibility predicate. No historical Opening or relation
label is reinterpreted. Failed raw sampling and rejected current tuples stay
in the raw sample-space denominator. These are finite per-label bounds, not
physical chronology, ordinary-verifier inclusion or G3 qualification. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRawPiopDensity

open scoped Classical
open HegemonCrypto.CmsClassicalDatabase (outputEventProbability)
open V8Smz9PiopSoundness (Candidate Matrix ClaimedTranscript)
open V8Smz9RuntimeRandomness (idealFieldCoinEquivGoldilocks)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9CappedRawSampler (FieldOutput sourceFieldSize RawByteBlock)
open HegemonCrypto.SmallWoodPowerBatching
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp04RawRoleSampling
  (SuccessfulFiber rawFieldSample rawPiopMatrixOutput matrixFieldEquiv
   totalEquivDecoder total_equiv_decoder_fibers_equal
   singleton_decoder_fibers_equal raw_field_then_partial_decoder_bad_le
   selectedRawBlocks selected_raw_blocks_event_probability)
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Opening)
end E
namespace C
export NativePrivateSpendQ58CurrentChronologicalRequest (currentOpeningAdmissible)
end C
namespace P
export NativePrivateSpendQ58CurrentPiopEvents
  (currentMatrixEvent current_matrix_probability currentOpeningEvent
   current_opening_probability conservativeCurrentDenominator)
end P
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- Uniform ideal six-field coordinates, with no old opening subtype. -/
def currentOpeningFieldEquiv :
    FieldOutput sourceFieldSize 6 ≃ (Fin 6 → Goldilocks) :=
  Equiv.piCongrRight fun _ => idealFieldCoinEquivGoldilocks

/-- Literal current opening guard. All other tuples reject. -/
def currentOpeningDecoder (coins : FieldOutput sourceFieldSize 6) : Option E.Opening :=
  if valid : C.currentOpeningAdmissible (currentOpeningFieldEquiv coins) then
    some ⟨currentOpeningFieldEquiv coins, valid⟩ else none

theorem current_opening_decoder_eq_some_iff
    (coins : FieldOutput sourceFieldSize 6) (opening : E.Opening) :
    currentOpeningDecoder coins = some opening ↔
      coins = currentOpeningFieldEquiv.symm opening.val := by
  constructor
  · intro decoded
    unfold currentOpeningDecoder at decoded
    split at decoded
    · have same : currentOpeningFieldEquiv coins = opening.val :=
        congrArg Subtype.val (Option.some.inj decoded)
      exact currentOpeningFieldEquiv.injective
        (same.trans (currentOpeningFieldEquiv.apply_symm_apply opening.val).symm)
    · cases decoded
  · intro same
    subst coins
    have valid : C.currentOpeningAdmissible
        (currentOpeningFieldEquiv (currentOpeningFieldEquiv.symm opening.val)) := by
      rw [currentOpeningFieldEquiv.apply_symm_apply]
      exact opening.property
    unfold currentOpeningDecoder
    rw [dif_pos valid]
    apply congrArg some
    apply Subtype.ext
    exact currentOpeningFieldEquiv.apply_symm_apply opening.val

/-- Every accepted current opening has exactly one ideal tuple preimage. -/
def currentOpeningDecoderFiberEquiv (opening : E.Opening) :
    SuccessfulFiber currentOpeningDecoder opening ≃ PUnit where
  toFun _ := PUnit.unit
  invFun _ := ⟨currentOpeningFieldEquiv.symm opening.val,
    (current_opening_decoder_eq_some_iff _ opening).2 rfl⟩
  left_inv input := by
    apply Subtype.ext
    exact ((current_opening_decoder_eq_some_iff input.val opening).1 input.property).symm
  right_inv value := by cases value; rfl

theorem current_opening_decoder_fiber_card (opening : E.Opening) :
    Fintype.card (SuccessfulFiber currentOpeningDecoder opening) = 1 := by
  simpa using Fintype.card_congr (currentOpeningDecoderFiberEquiv.{1} opening)

theorem current_opening_decoder_fibers_equal (left right : E.Opening) :
    Fintype.card (SuccessfulFiber currentOpeningDecoder left) =
      Fintype.card (SuccessfulFiber currentOpeningDecoder right) := by
  rw [current_opening_decoder_fiber_card, current_opening_decoder_fiber_card]

/-- The current admissible-opening domain is nonempty by its actual lower
bound. This instance introduces no sampled-opening or acceptance hypothesis. -/
noncomputable local instance currentOpeningNonempty : Nonempty E.Opening :=
  Fintype.card_pos_iff.mp NativePrivateSpendQ58CurrentPiopEvents.current_opening_card_positive

def rawCurrentOpeningOutput
    (raw : Fin (digestCallCap 6) → RawByteBlock) : Option E.Opening :=
  (rawFieldSample (digestCallCap 6) 6 raw).bind currentOpeningDecoder

/-- Failed raw samples remain in the denominator; no success conditioning
or total binary-to-field uniformity claim is used. -/
theorem raw_current_piop_matrix_success_and_bad_le
    (candidate : Candidate 1344594)
    (invalid : ¬ PiopExtraction.FullySatisfied candidate.system) :
    outputEventProbability
      (fun raw : Fin (digestCallCap (5 * 1344594)) → RawByteBlock =>
        ∃ matrix, rawPiopMatrixOutput 1344594 raw = some matrix ∧
          matrix ∈ P.currentMatrixEvent candidate) ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 := by
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap (5 * 1344594)) (5 * 1344594)
    (totalEquivDecoder (matrixFieldEquiv 1344594))
    (total_equiv_decoder_fibers_equal (matrixFieldEquiv 1344594))
    (P.currentMatrixEvent candidate)
  calc
    _ ≤ V8Smz9RobustQueryMismatch.FiniteEvents.probability
        (P.currentMatrixEvent candidate) := by
      simpa only [rawPiopMatrixOutput] using sampled
    _ ≤ _ := P.current_matrix_probability candidate invalid

/-- New current restricted decoder, singleton fibers and the current domain
count give the actual raw opening success-and-bad bound. Only one six-field
nonce attempt is modeled; chronology and first-valid selection stay separate. -/
theorem raw_current_piop_opening_success_and_bad_le
    (candidate : Candidate 1344594) (matrix : Matrix 1344594)
    (response : ClaimedTranscript)
    (failure : ¬ PiopExtraction.AffineBatchAccepts candidate.system
      (V8Smz9PiopSoundness.maskSum candidate) matrix) :
    outputEventProbability
      (fun raw : Fin (digestCallCap 6) → RawByteBlock =>
        ∃ opening, rawCurrentOpeningOutput raw = some opening ∧
          opening ∈ P.currentOpeningEvent candidate matrix response) ≤
      (V8Smz9QromAccounting.fallingProduct 552 6 : Rat) /
        P.conservativeCurrentDenominator := by
  have sampled := raw_field_then_partial_decoder_bad_le (digestCallCap 6) 6
    currentOpeningDecoder current_opening_decoder_fibers_equal
    (P.currentOpeningEvent candidate matrix response)
  calc
    _ ≤ V8Smz9RobustQueryMismatch.FiniteEvents.probability
        (P.currentOpeningEvent candidate matrix response) := by
      simpa only [rawCurrentOpeningOutput] using sampled
    _ ≤ _ := P.current_opening_probability candidate matrix response failure

/-- Exact restriction from any larger finite vector preserves this raw
current matrix event probability. No independent-vector hypothesis enters. -/
theorem vector_current_piop_matrix_success_and_bad_le
    {Counter : Type} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap (5 * 1344594)) ↪ Counter)
    (candidate : Candidate 1344594)
    (invalid : ¬ PiopExtraction.FullySatisfied candidate.system) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ matrix, rawPiopMatrixOutput 1344594 (selectedRawBlocks select vector) = some matrix ∧
        matrix ∈ P.currentMatrixEvent candidate) ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 := by
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ matrix, rawPiopMatrixOutput 1344594 raw = some matrix ∧
      matrix ∈ P.currentMatrixEvent candidate)]
  exact raw_current_piop_matrix_success_and_bad_le candidate invalid

/-- The same exact vector restriction applies to the new current opening
decoder. Exhaustion and inadmissible current tuples remain failed outputs. -/
theorem vector_current_piop_opening_success_and_bad_le
    {Counter : Type} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap 6) ↪ Counter)
    (candidate : Candidate 1344594) (matrix : Matrix 1344594)
    (response : ClaimedTranscript)
    (failure : ¬ PiopExtraction.AffineBatchAccepts candidate.system
      (V8Smz9PiopSoundness.maskSum candidate) matrix) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ opening, rawCurrentOpeningOutput (selectedRawBlocks select vector) = some opening ∧
        opening ∈ P.currentOpeningEvent candidate matrix response) ≤
      (V8Smz9QromAccounting.fallingProduct 552 6 : Rat) /
        P.conservativeCurrentDenominator := by
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ opening, rawCurrentOpeningOutput raw = some opening ∧
      opening ∈ P.currentOpeningEvent candidate matrix response)]
  exact raw_current_piop_opening_success_and_bad_le candidate matrix response failure

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRawPiopDensity
