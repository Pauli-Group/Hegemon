import HegemonCrypto.NativePrivateSpendQ58CurrentMatrixDynamicMass

/-! Exact current DECS coefficient allocation. The native gamma rows consume
140*row+column, whereas the generic matrixEquiv1405 consumes 5*column+row.
This successor uses a proved transposition of the actual 700 accepted coins.
The uniform counting theorem is unchanged; the decoder is current. Failed
raw sampling stays in the original sample space. SOURCE ONLY, kernel pending.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixRawOrder
open scoped Classical
open HegemonCrypto.CmsClassicalDatabase
open V8Smz9RuntimeFieldLayout V8Smz9RuntimeDistribution V8Smz9RuntimeRandomness
open V8Smz9CappedRawSampler V8Smz9CoherentMerkleInstrument
open V8Smz9RawCounterCompiler V8Smz9CoherentVectorMerkle
open SmzaRp04RawRoleSampling
namespace M
export NativePrivateSpendQ58CurrentMatrixDynamicMass
  (Coefficients Position matrixBad matrixLoss current_matrix_output_density traceLabel)
end M
namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport (currentPoint)
end L
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- Explicit inverse, not an equivalence inferred from equal cardinalities. -/
def transpose : (Fin 5 → Fin 140 → Goldilocks) ≃ M.Coefficients where
  toFun values column row := values row column
  invFun values row column := values column row
  left_inv _ := rfl
  right_inv _ := rfl

def fieldEquiv : FieldOutput sourceFieldSize 700 ≃ M.Coefficients :=
  (Equiv.piCongrRight fun _ => idealFieldCoinEquivGoldilocks).trans
    ((matrixEquiv 5 140 Goldilocks).trans transpose)

/-- Literal row-major coordinate used by current gammaRows. -/
theorem field_equiv_current_coordinate
    (coins : FieldOutput sourceFieldSize 700) (column : Fin 140) (row : Fin 5) :
    fieldEquiv coins column row =
      idealFieldCoinEquivGoldilocks (coins (finProdFinEquiv (row, column))) := rfl

theorem current_coordinate_value (column : Fin 140) (row : Fin 5) :
    (finProdFinEquiv (row, column)).val = 140*row.val+column.val := by
  change column.val+140*row.val=140*row.val+column.val
  omega

def rawOutput (raw : Fin (digestCallCap 700) → RawByteBlock) : Option M.Coefficients :=
  (rawFieldSample (digestCallCap 700) 700 raw).bind (totalEquivDecoder fieldEquiv)

def vectorOutput {Counter : Type} (select : Fin (digestCallCap 700) ↪ Counter)
    (vector : VectorOutput Counter) : Option M.Coefficients :=
  rawOutput (selectedRawBlocks select vector)

/-- The corrected raw decoder has the same equal fibers. It is not the
historical column-major decoder applied to the same bytes. -/
theorem current_raw_bad_and_success
    (injective : Function.Injective L.currentPoint)
    (data : Nat → M.Position → Goldilocks) (masks : Fin 5 → M.Position → Goldilocks) :
    outputEventProbability (fun raw : Fin (digestCallCap 700) → RawByteBlock =>
      ∃ coefficients, rawOutput raw = some coefficients ∧
        M.matrixBad data masks coefficients) ≤ M.matrixLoss := by
  let bad := Finset.univ.filter (M.matrixBad data masks)
  have sampled := raw_field_then_partial_decoder_bad_le (digestCallCap 700) 700
    (totalEquivDecoder fieldEquiv) (total_equiv_decoder_fibers_equal fieldEquiv) bad
  change outputEventProbability (fun raw =>
    ∃ coefficients, rawOutput raw = some coefficients ∧ coefficients ∈ bad) ≤
      V8Smz9RobustQueryMismatch.FiniteEvents.probability bad at sampled
  have membership : (fun raw : Fin (digestCallCap 700) → RawByteBlock =>
      ∃ coefficients, rawOutput raw = some coefficients ∧ coefficients ∈ bad) =
      (fun raw => ∃ coefficients, rawOutput raw = some coefficients ∧
        M.matrixBad data masks coefficients) := by
    funext raw
    simp only [bad, Finset.mem_filter, Finset.mem_univ, true_and]
  rw [membership] at sampled
  apply sampled.trans
  calc
    _ = outputEventProbability (fun coefficients => coefficients ∈ bad) :=
      (SmzaRp04RoleBadCells.output_event_probability_membership bad).symm
    _ = outputEventProbability (M.matrixBad data masks) := by
      have eventEquality :
          (fun coefficients : M.Coefficients => coefficients ∈ bad) = M.matrixBad data masks := by
        funext coefficients
        apply propext
        simp only [bad, Finset.mem_filter, Finset.mem_univ, true_and]
      exact congrArg (fun event : M.Coefficients → Prop => outputEventProbability event) eventEquality
    _ ≤ M.matrixLoss := M.current_matrix_output_density injective data masks

theorem current_vector_bad_and_success
    {Counter : Type} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap 700) ↪ Counter)
    (injective : Function.Injective L.currentPoint)
    (data : Nat → M.Position → Goldilocks) (masks : Fin 5 → M.Position → Goldilocks) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ coefficients, vectorOutput select vector = some coefficients ∧
        M.matrixBad data masks coefficients) ≤ M.matrixLoss := by
  change outputEventProbability (fun vector : VectorOutput Counter =>
    (fun raw => ∃ coefficients, rawOutput raw = some coefficients ∧
      M.matrixBad data masks coefficients) (selectedRawBlocks select vector)) ≤ _
  exact (selected_raw_blocks_event_probability select
    (fun raw => ∃ coefficients, rawOutput raw = some coefficients ∧
      M.matrixBad data masks coefficients)).trans_le
    (current_raw_bad_and_success injective data masks)

/-- Current base-vector event, using the corrected native coordinate order. -/
def vectorBad {Key Counter : Type}
    (bytes : Key → NativePrivateSpendQ58CurrentFullStageEnvelope.RawInput)
    (select : Fin (digestCallCap 700) ↪ Counter)
    (trace : NativePrivateSpendQ58CurrentFullStageEnvelope.Trace)
    (key : Key) (vector : VectorOutput Counter) : Prop :=
  (∃ query, NativePrivateSpendQ58CurrentRoleClassifier.parseCurrentStageQuery (bytes key) = some query ∧
    query.role = .decsMatrix ∧ query.counter = 0) ∧
  ∃ coefficients, vectorOutput select vector = some coefficients ∧
    M.matrixBad (NativePrivateSpendQ58CurrentSourceCandidate.labelData (M.traceLabel trace))
      (NativePrivateSpendQ58CurrentSourceCandidate.labelMasks (M.traceLabel trace)) coefficients

private theorem outputEventProbability_mono
    (Output : Type) [Fintype Output] (a b : Output → Prop)
    (inclusion : ∀ output, a output → b output) :
    outputEventProbability a ≤ outputEventProbability b := by
  classical
  have subset : Finset.univ.filter a ⊆ Finset.univ.filter b := by
    intro output member
    exact Finset.mem_filter.mpr
      ⟨Finset.mem_univ output, inclusion output (Finset.mem_filter.mp member).2⟩
  have cardBound : (Finset.univ.filter a).card ≤ (Finset.univ.filter b).card :=
    Finset.card_le_card subset
  have castBound : ((Finset.univ.filter a).card : Rat) ≤ (Finset.univ.filter b).card :=
    (Nat.cast_le (α := Rat)).mpr cardBound
  unfold outputEventProbability
  exact div_le_div_of_nonneg_right castBound (Nat.cast_nonneg (Fintype.card Output))

theorem current_vector_event_density {Key Counter : Type}
    [Fintype Counter] [DecidableEq Counter]
    (bytes : Key → NativePrivateSpendQ58CurrentFullStageEnvelope.RawInput)
    (select : Fin (digestCallCap 700) ↪ Counter)
    (injective : Function.Injective L.currentPoint)
    (trace : NativePrivateSpendQ58CurrentFullStageEnvelope.Trace) (key : Key) :
    outputEventProbability (vectorBad bytes select trace key) ≤ M.matrixLoss := by
  apply le_trans _ (current_vector_bad_and_success select injective
    (NativePrivateSpendQ58CurrentSourceCandidate.labelData (M.traceLabel trace))
    (NativePrivateSpendQ58CurrentSourceCandidate.labelMasks (M.traceLabel trace)))
  exact outputEventProbability_mono (VectorOutput Counter)
    (vectorBad bytes select trace key)
    (fun vector => ∃ coefficients,
      vectorOutput select vector = some coefficients ∧ M.matrixBad
        (NativePrivateSpendQ58CurrentSourceCandidate.labelData (M.traceLabel trace))
        (NativePrivateSpendQ58CurrentSourceCandidate.labelMasks (M.traceLabel trace)) coefficients)
    (fun _ member => member.2)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixRawOrder
