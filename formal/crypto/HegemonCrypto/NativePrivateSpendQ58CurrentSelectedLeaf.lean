import HegemonCrypto.NativePrivateSpendQ58CurrentPublicOpening
import HegemonCrypto.NativePrivateSpendQ58CurrentTranscriptInput

/-! Concrete current selected-leaf factorization. The twelve public combination
rows and128 public subset rows reconstruct ALL140 evaluations at each selected
DECS point. Five mask evaluations then follow from the PUBLIC DECS response.
Original64-byte tapes, indices, raw oracle and incoming registers are retained.
The statement is pointwise in source coins, including inverse transported coins;
there is no assumed simulator equality or abstract coverage/model certificate. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSelectedLeaf
open Polynomial
open HegemonCrypto.CanonicalBytes
open V8Smz9ZeroKnowledge V8Smz9EagerSimulator V8Smz9EagerPrivacy
open V8Smz9RuntimeDistribution V8Smz9PiopOpeningRecovery
open V8Smz9HonestOpeningSchedule V8Smz9HiddenLeafQrom
open V8Smz9MixedMaskCompiler
open NativePrivateSpendQ58CurrentLeafInput
open V8Smz9HonestWholeViewFinalInput (fieldWord)
open scoped Classical BigOperators
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0


abbrev PublicHeads := Fin 12 → Fin 13115 → Goldilocks
abbrev SelectedRows := Fin 58 → Fin 140 → Goldilocks
abbrev SelectedMasks := Fin 58 → Fin 5 → Goldilocks

def publicCombinationAt (heads : PublicHeads) (early : NativePrivateSpendQ58Compff01OpeningContinuation.Earlier)
    (point : Goldilocks) : Fin 12 → Goldilocks := fun combination =>
  (Lagrange.interpolate (Finset.univ : Finset (Fin 13173))
    (fun node => (node.val : Goldilocks))
    (Fin.append (early combination) (heads combination))).eval point

def publicSelectedRows (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (heads : PublicHeads) (early : NativePrivateSpendQ58Compff01OpeningContinuation.Earlier)
    (targets : Fin 58 → Goldilocks) (later : NativePrivateSpendQ58Compff01OpeningContinuation.Later) : SelectedRows := fun opening =>
  (rowObservationEquiv points (actual_selected_block_injective distinct)).symm
    (publicCombinationAt heads early (targets opening), later opening)

/-- Lagrange interpolation is a linear map. Thus the same public C-times-row
combination holds at the selected point, including all13173 source coordinates. -/
theorem source_combination_at (points : Fin 6 → Goldilocks) (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads)
    (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails) (point : Goldilocks) :
    publicCombinationAt (NativePrivateSpendQ58Compff01OpeningContinuation.combinationHeads points heads) (NativePrivateSpendQ58Compff01OpeningContinuation.earlier points tails) point =
      rowCombination points (fun row => (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails row).eval point) := by
  funext combination
  have combined :
      Fin.append (NativePrivateSpendQ58Compff01OpeningContinuation.earlier points tails combination) (NativePrivateSpendQ58Compff01OpeningContinuation.combinationHeads points heads combination) =
        ∑ row : Fin 140, smz9LvcsCombinationCoefficient points combination row •
          Fin.append (tails row) (heads row) := by
    funext node
    refine Fin.addCases (fun left => ?_) (fun right => ?_) node
    · simp only [Fin.append_left, Finset.sum_apply, Pi.smul_apply,
        NativePrivateSpendQ58Compff01OpeningContinuation.earlier, rowCombination, smul_eq_mul]
    · simp only [Fin.append_right, Finset.sum_apply, Pi.smul_apply,
        NativePrivateSpendQ58Compff01OpeningContinuation.combinationHeads, rowCombination, smul_eq_mul]
  unfold publicCombinationAt
  rw [combined, map_sum]
  simp only [map_smul, eval_finsetSum, eval_smul, NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial,
    rowCombination, smul_eq_mul]

theorem public_selected_rows_are_source (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads) (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails)
    (targets : Fin 58 → Goldilocks) :
    publicSelectedRows points distinct (NativePrivateSpendQ58Compff01OpeningContinuation.combinationHeads points heads)
      (NativePrivateSpendQ58Compff01OpeningContinuation.earlier points tails) targets (NativePrivateSpendQ58Compff01OpeningContinuation.fullSubset heads targets tails) =
      (fun opening row => (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails row).eval (targets opening)) := by
  funext opening
  unfold publicSelectedRows
  rw [source_combination_at]
  have subsets : NativePrivateSpendQ58Compff01OpeningContinuation.fullSubset heads targets tails opening =
      rowSubset (fun row => (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails row).eval (targets opening)) := by
    funext subset
    exact NativePrivateSpendQ58Compff01OpeningContinuation.full_subset_is_rotated_interpolation heads targets tails opening subset
  rw [subsets]
  exact (rowObservationEquiv points (actual_selected_block_injective distinct)).symm_apply_apply _

/-- Actual witness/PCS/PIOP public fields reconstruct the matrix used by the
selector. This is derived from packed validity, not assumed as a coverage field. -/
theorem current_public_rows_are_source (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (gamma : Fin 5 → NativePrivateSpendQ58CurrentPublicOpening.Gamma)
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData) (valid : NativePrivateSpendQ58CurrentPublicOpening.Satisfies relation data.values)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (outside : ∀ opening lane, points opening ≠ NativePrivateSpendQ58CurrentPublicOpening.packing lane)
    (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails) (targets : Fin 58 → Goldilocks) :
    publicSelectedRows points distinct
      (NativePrivateSpendQ58CurrentPublicOpening.publicHeads relation (NativePrivateSpendQ58CurrentPublicOpening.sourceFields relation gamma data points) points)
      (NativePrivateSpendQ58Compff01OpeningContinuation.earlier points tails) targets
      (NativePrivateSpendQ58Compff01OpeningContinuation.fullSubset (NativePrivateSpendQ58Compff01OpeningContinuation.stackedHeads (NativePrivateSpendQ58Compff01SourceColumns.sourceCurrentColumns data)) targets tails) =
      (fun opening row => (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial
        (NativePrivateSpendQ58Compff01OpeningContinuation.stackedHeads (NativePrivateSpendQ58Compff01SourceColumns.sourceCurrentColumns data)) tails row).eval (targets opening)) := by
  rw [NativePrivateSpendQ58CurrentPublicOpening.public_heads_are_current_matrix relation gamma data valid points outside]
  exact public_selected_rows_are_source points distinct _ tails targets

def publicSelectedMasks (response : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) (gamma : NativePrivateSpendQ58CurrentPublicOpening.DecsGamma)
    (rows : SelectedRows) (targets : Fin 58 → Goldilocks) : SelectedMasks :=
  fun opening repetition => NativePrivateSpendQ58CurrentPublicOpening.publicDecsMask response gamma (rows opening) (targets opening) repetition

theorem public_selected_masks_are_source (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads) (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails)
    (gamma : NativePrivateSpendQ58CurrentPublicOpening.DecsGamma) (masks : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) (targets : Fin 58 → Goldilocks) :
    publicSelectedMasks (NativePrivateSpendQ58CurrentPublicOpening.sourceDecsResponse heads tails gamma masks) gamma
      (publicSelectedRows points distinct (NativePrivateSpendQ58Compff01OpeningContinuation.combinationHeads points heads)
        (NativePrivateSpendQ58Compff01OpeningContinuation.earlier points tails) targets (NativePrivateSpendQ58Compff01OpeningContinuation.fullSubset heads targets tails)) targets =
      (fun opening repetition => (coefficientPolynomial (masks repetition)).eval (targets opening)) := by
  rw [public_selected_rows_are_source]
  funext opening repetition
  exact NativePrivateSpendQ58CurrentPublicOpening.public_decs_mask_is_source heads tails gamma masks (targets opening) repetition

/-- Literal current strict-leaf payload: count140,140 row words,count5,five
mask words. The tape and index are inserted by CurrentLeafInput.sourceLeafInput. -/
def leafPayloadWords (rows : Fin 140 → Goldilocks) (masks : Fin 5 → Goldilocks) :
    List V8Smz9HonestWholeViewFinalInput.RawWord :=
  [⟨140, by norm_num⟩] ++ (List.ofFn rows).map fieldWord ++
    [⟨5, by norm_num⟩] ++ (List.ofFn masks).map fieldWord

theorem leaf_payload_word_count (rows : Fin 140 → Goldilocks) (masks : Fin 5 → Goldilocks) :
    (leafPayloadWords rows masks).length = 147 := by
  simp only [leafPayloadWords, List.length_append, List.length_cons, List.length_nil,
    List.length_map, List.length_ofFn]

def leafPayload (rows : Fin 140 → Goldilocks) (masks : Fin 5 → Goldilocks) : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte :=
  let bytes := V8Smz9RawCounterCompiler.typedWordPayload (leafPayloadWords rows masks)
  fun index => bytes.get ⟨index.val, by
    rw [V8Smz9RawCounterCompiler.typed_word_payload_length, leaf_payload_word_count]
    exact index.isLt⟩

def sourceSelectedLeaves (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads) (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails) (masks : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse)
    (targets : Fin 58 → Goldilocks) (indices : Fin 58 → V8Smz9HiddenPatch.LeafIndex)
    (tapes : Fin 58 → LeafTape) : Fin 58 → CurrentLeafInput := fun opening =>
  sourceLeafInput statement salt
    (leafPayload (fun row => (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails row).eval (targets opening))
      (fun repetition => (coefficientPolynomial (masks repetition)).eval (targets opening)))
    (indices opening) (tapes opening)

def publicSelectedLeaves (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (response : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) (gamma : NativePrivateSpendQ58CurrentPublicOpening.DecsGamma)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (heads : PublicHeads) (early : NativePrivateSpendQ58Compff01OpeningContinuation.Earlier) (later : NativePrivateSpendQ58Compff01OpeningContinuation.Later)
    (targets : Fin 58 → Goldilocks) (indices : Fin 58 → V8Smz9HiddenPatch.LeafIndex)
    (tapes : Fin 58 → LeafTape) : Fin 58 → CurrentLeafInput :=
  let rows := publicSelectedRows points distinct heads early targets later
  let masks := publicSelectedMasks response gamma rows targets
  fun opening => sourceLeafInput statement salt (leafPayload (rows opening) (masks opening))
    (indices opening) (tapes opening)

/-- The actual58 physical leaf addresses are IDENTICAL, with original tapes.
Any persistent-oracle selected-write/Merkle/public-strategy continuation therefore
has the same inputs and registers pointwise, not merely a fresh execution law. -/
theorem public_selected_leaf_addresses_are_source (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads) (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails)
    (gamma : NativePrivateSpendQ58CurrentPublicOpening.DecsGamma) (masks : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) (targets : Fin 58 → Goldilocks)
    (indices : Fin 58 → V8Smz9HiddenPatch.LeafIndex) (tapes : Fin 58 → LeafTape) :
    publicSelectedLeaves statement salt (NativePrivateSpendQ58CurrentPublicOpening.sourceDecsResponse heads tails gamma masks) gamma
      points distinct (NativePrivateSpendQ58Compff01OpeningContinuation.combinationHeads points heads) (NativePrivateSpendQ58Compff01OpeningContinuation.earlier points tails)
      (NativePrivateSpendQ58Compff01OpeningContinuation.fullSubset heads targets tails) targets indices tapes =
      sourceSelectedLeaves statement salt heads tails masks targets indices tapes := by
  unfold publicSelectedLeaves
  rw [public_selected_rows_are_source]
  have maskEquality : publicSelectedMasks (NativePrivateSpendQ58CurrentPublicOpening.sourceDecsResponse heads tails gamma masks) gamma
      (fun opening row => (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails row).eval (targets opening)) targets =
      (fun opening repetition => (coefficientPolynomial (masks repetition)).eval (targets opening)) := by
    funext opening repetition
    exact NativePrivateSpendQ58CurrentPublicOpening.public_decs_mask_is_source heads tails gamma masks (targets opening) repetition
  dsimp only
  rw [maskEquality]
  rfl

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSelectedLeaf
