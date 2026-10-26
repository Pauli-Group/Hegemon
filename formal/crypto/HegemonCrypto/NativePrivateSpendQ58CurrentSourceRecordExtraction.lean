import HegemonCrypto.NativePrivateSpendQ58CurrentActualTraceLabel

/-! Source filtration preserves the actual current least-valid-preimage
extractor. A valid source grammar input is proved unrecognized by the current
challenge parser, so filtration removes no candidate at any depth. This is a
deterministic grammar fact, with no collision or security assumption. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceRecordExtraction
open scoped Classical
open SmzaRp05FilteredDecoderInstability (RawRecords)
open V8Smz9CoherentMerkleGeometry (candidateInputs selectedInput extract)
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (Stage RawDigest rawNext)
end F
namespace AL
export NativePrivateSpendQ58CurrentActualTraceLabel
  (sourceRecords current_source_valid_input_is_unparsed)
end AL
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

theorem current_source_candidates_survive_filtration
    (records : RawRecords) (stage : F.Stage) (target : F.RawDigest) :
    candidateInputs F.rawNext (AL.sourceRecords records) stage target =
      candidateInputs F.rawNext records stage target := by
  unfold candidateInputs AL.sourceRecords
  congr 1
  ext pair
  simp only [Finset.mem_filter]
  constructor
  · rintro ⟨⟨recorded, _unparsed⟩, output, valid⟩
    exact ⟨recorded, output, valid⟩
  · rintro ⟨recorded, output, valid⟩
    exact ⟨⟨recorded, AL.current_source_valid_input_is_unparsed stage pair.1 valid⟩, output, valid⟩

theorem current_source_extract_survives_filtration
    (records : RawRecords) (fuel : Nat) (stage : F.Stage) (target : F.RawDigest) :
    extract F.rawNext (AL.sourceRecords records) fuel stage target =
      extract F.rawNext records fuel stage target := by
  have selection (stage : F.Stage) (target : F.RawDigest) :
      selectedInput F.rawNext (AL.sourceRecords records) stage target =
        selectedInput F.rawNext records stage target := by
    unfold selectedInput
    rw [current_source_candidates_survive_filtration]
  induction fuel generalizing stage target with
  | zero => rfl
  | succ fuel ih =>
    simp only [extract, selection]
    cases selected : selectedInput F.rawNext records stage target with
    | none => rfl
    | some input =>
      dsimp only
      cases parsed : F.rawNext stage input with
      | none => rfl
      | some edges =>
        apply congrArg (V8Smz9CoherentMerkleGeometry.ExtractionTrace.record input)
        apply List.map_congr_left
        intro edge _member
        exact ih edge.1 edge.2

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceRecordExtraction
