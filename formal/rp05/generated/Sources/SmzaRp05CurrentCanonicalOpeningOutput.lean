import SmzaRp05CurrentExecutedOpeningOutput
import SmzaRp05CurrentRawSampleReadback
import SmzaRp05ConditionedExecution

/-! The canonical first-success opening decoder is supplied by the same
executed current-profile scan, including every earlier rejected nonce. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentCanonicalOpeningOutput

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05CurrentExecutedOpeningOutput
open SmzaRp05CurrentOpeningProgram (openingCounterInput openingFieldInputs
  openingFieldCap decodeOpeningWords)
open SmzaRp05ExecutablePcsClosureOpening (DecodedAt)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05ExecutableChallengeStage (scan)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp04RawRoleSampling
open SmzaRp05ConditionedExecution (firstSome firstSome_append_selected canonicalOpeningNonceOrder)
open V8Smz9CoherentMerkleGeometry (RawDigest)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9AdaptiveFiniteAccounting.Historical (piopOpenings)
open V8Smz9PiopSoundness (Opening)

set_option autoImplicit false
noncomputable section

private theorem ofFn_fin_val_eq_range_map {α : Type*} {n : Nat} (f : Nat → α) :
    List.ofFn (fun index : Fin n => f index.val) = (List.range n).map f := by
  rw [List.ofFn_eq_pmap]
  simp only [List.pmap_eq_map]

/-- Both successful and rejected opening decodes are exactly the raw-role
decoder output. A rejection is not silently replaced by a successful nonce. -/
theorem executed_opening_decode_is_raw_output
    (oracle : Oracle) (digest : RawDigest) (nonce : Nat) (result : Option Opening)
    (readback : DecodedAt oracle digest nonce result) :
    actualPiopOpeningOutput (Equiv.refl (Fin (digestCallCap piopOpenings)))
      (currentOpeningVector oracle digest nonce) = result := by
  obtain ⟨words, scanEq, decoded⟩ := readback
  let keys : Fin (digestCallCap piopOpenings) → V8SmzaOracleParser.RawInput :=
    fun counter => openingCounterInput digest nonce counter.val
  have inputs : openingFieldInputs digest nonce = List.ofFn keys := by
    have cap : openingFieldCap = digestCallCap piopOpenings := by decide
    rw [openingFieldInputs, cap]
    exact (ofFn_fin_val_eq_range_map (n := digestCallCap piopOpenings)
      (openingCounterInput digest nonce)).symm
  have sampleEq : scan oracle 6 [] (openingFieldInputs digest nonce) =
      (rawFieldSample (digestCallCap piopOpenings) piopOpenings
        (currentOpeningRawBlocks oracle digest nonce)).map List.ofFn := by
    rw [inputs]
    exact SmzaRp05CurrentRawSampleReadback.source_scan_eq_raw_field_sample 6 keys oracle
  cases sampled : rawFieldSample (digestCallCap piopOpenings) piopOpenings
      (currentOpeningRawBlocks oracle digest nonce) with
  | none =>
      rw [sampled] at sampleEq
      rw [sampleEq] at scanEq
      cases scanEq
  | some fields =>
      have wordsEq : words = List.ofFn fields := by
        rw [sampleEq, sampled, Option.map_some] at scanEq
        exact (Option.some.inj scanEq).symm
      have decodedFields : openingDecoder fields = result := by
        rw [wordsEq] at decoded
        have hlen : (List.ofFn fields).length = 6 := by
          simp only [List.length_ofFn, actual_piop_opening_count_is_six]
        change (if (List.ofFn fields).length = 6 then
          openingDecoder (fun index : Fin piopOpenings =>
            (List.ofFn fields).getD index.val
              (⟨0, by decide⟩ : V8Smz9WholeViewObservation.FieldWord))
          else none) = result at decoded
        rw [if_pos hlen] at decoded
        have same : (fun index : Fin piopOpenings =>
            (List.ofFn fields).getD index.val
              (⟨0, by decide⟩ : V8Smz9WholeViewObservation.FieldWord)) = fields := by
          funext index
          simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn,
            index.isLt, dif_pos, Option.getD_some]
        rw [same] at decoded
        exact decoded
      have selectedEq : selectedRawBlocks
          (Equiv.refl (Fin (digestCallCap piopOpenings)))
          (currentOpeningVector oracle digest nonce) = currentOpeningRawBlocks oracle digest nonce := by
        funext counter
        change rawDigestBits.symm
          (rawDigestBits (oracle (openingCounterInput digest nonce counter.val))) = _
        exact rawDigestBits.symm_apply_apply _
      change (rawFieldSample (digestCallCap piopOpenings) piopOpenings
        (selectedRawBlocks (Equiv.refl (Fin (digestCallCap piopOpenings)))
          (currentOpeningVector oracle digest nonce))).bind openingDecoder = result
      rw [selectedEq, sampled]
      exact decodedFields

private theorem firstSome_map {Index Other Value : Type*}
    (read : Other → Option Value) (mapIndex : Index → Other) (items : List Index) :
    firstSome read (items.map mapIndex) = firstSome (fun index => read (mapIndex index)) items := by
  induction items with
  | nil => rfl
  | cons head tail ih =>
      simp only [List.map_cons, firstSome]
      cases read (mapIndex head) <;> simp only [ih]

/-- Acceptance supplies the entire canonical first-success raw opening
scan, not just a freely selected successful nonce. -/
theorem execution_stages_canonical_raw_opening
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (stages : ExecutionStages ns dsl statement pending binding statementBinding
      nonce wire oracle transcript)
    (openingClean : stages.openingPending = false) :
    firstSome (fun attempt : Fin 16 =>
      actualPiopOpeningOutput (Equiv.refl (Fin (digestCallCap piopOpenings)))
        (currentOpeningVector oracle wire.hPiop attempt.val))
      canonicalOpeningNonceOrder = some stages.opening := by
  obtain ⟨before, after, order, prior, _, selected⟩ :=
    execution_stages_current_raw_opening ns dsl statement pending binding
      statementBinding nonce wire oracle transcript stages openingClean
  let read := fun attempt : Nat =>
    actualPiopOpeningOutput (Equiv.refl (Fin (digestCallCap piopOpenings)))
      (currentOpeningVector oracle wire.hPiop attempt)
  have allPrior : ∀ attempt ∈ before, read attempt = none := by
    intro attempt member
    exact executed_opening_decode_is_raw_output oracle wire.hPiop attempt none
      (prior attempt member)
  have scanResult : firstSome read (List.range 16) = some stages.opening := by
    rw [order]
    exact firstSome_append_selected read before after nonce.val stages.opening allPrior selected
  have mappedOrder : canonicalOpeningNonceOrder.map Fin.val = List.range 16 := by
    change (List.ofFn (id : Fin 16 → Fin 16)).map Fin.val = _
    rw [List.map_ofFn]
    exact (ofFn_fin_val_eq_range_map (n := 16) id).trans (List.map_id _)
  rw [← mappedOrder, firstSome_map] at scanResult
  exact scanResult

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentCanonicalOpeningOutput
