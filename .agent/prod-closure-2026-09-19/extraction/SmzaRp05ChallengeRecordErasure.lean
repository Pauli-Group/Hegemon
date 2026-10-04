import SmzaChallengeStageTargets
import SmzaRp05FilteredDecoderInstability
import SmzaRp05ChallengeRoleSeparation

/-!
# Erasure of Fiat--Shamir challenge records from RP05 VC extraction

Recognized challenge-query frames are physical random-oracle inputs, but they
are not VC frames.  The current online VC decoder therefore rejects them at
every stage.  Since `candidateInputs` already requires `next stage input` to
be present, these records can be erased before extraction, independently of
their output and independently of which queried other-role keys were fixed by
role conditioning.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ChallengeRecordErasure

open scoped Classical
open HegemonCrypto.CanonicalBytes
open V8Smz9CoherentMerkleGeometry V8SmzaOnlineParser
open SmzaChallengeStageTargets SmzaRp05LeafNamespace
open SmzaRp05FilteredReadback SmzaRp05FilteredDecoderInstability
open SmzaRp04StatementRecordFilter

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

abbrev Next := Stage → RawInput → Option (List (Stage × RawDigest))

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

theorem parse_stage_query_global_next_none
    (ns : Namespace) (input : RawInput) (query : StageQuery)
    (parsed : parseStageQuery input = some query) (stage : Stage) :
    globalOnlineNext ns stage input = none := by
  simp [globalOnlineNext,
    parse_stage_query_global_payload_none ns input query parsed]

def eraseChallengeRecords (records : RawRecords) : RawRecords :=
  records.filter fun record => (parseStageQuery record.1).isNone

theorem eraseChallengeRecords_eq_parse_none (records : RawRecords) :
    eraseChallengeRecords records =
      records.filter fun record => parseStageQuery record.1 = none := by
  ext record
  cases parsed : parseStageQuery record.1 <;> simp [eraseChallengeRecords, parsed]

/-- Generic candidate equality after erasing records whose inputs are inert
for every decoder stage. -/
theorem candidate_inputs_filter_inert
    (next : Next) (records : RawRecords) (keep : RawInput → Prop)
    (inert : ∀ input, ¬ keep input → ∀ stage, next stage input = none)
    (stage : Stage) (target : RawDigest) :
    candidateInputs next (records.filter fun record => keep record.1) stage target =
      candidateInputs next records stage target := by
  ext input
  constructor
  · intro member
    obtain ⟨record, selected, same⟩ := Finset.mem_image.mp member
    obtain ⟨recorded, outputEq, decoded⟩ := Finset.mem_filter.mp selected
    exact Finset.mem_image.mpr ⟨record,
      Finset.mem_filter.mpr ⟨(Finset.mem_filter.mp recorded).1, outputEq, decoded⟩,
      same⟩
  · intro member
    obtain ⟨record, selected, same⟩ := Finset.mem_image.mp member
    obtain ⟨recorded, outputEq, decoded⟩ := Finset.mem_filter.mp selected
    have retained : keep record.1 := by
      by_contra rejected
      rw [inert record.1 rejected stage] at decoded
      contradiction
    exact Finset.mem_image.mpr ⟨record,
      Finset.mem_filter.mpr
        ⟨Finset.mem_filter.mpr ⟨recorded, retained⟩, outputEq, decoded⟩,
      same⟩

theorem extract_eq_of_candidate_inputs
    (next : Next) (left right : RawRecords)
    (same : ∀ stage target,
      candidateInputs next left stage target = candidateInputs next right stage target)
    (fuel : Nat) (stage : Stage) (target : RawDigest) :
    extract next left fuel stage target = extract next right fuel stage target := by
  induction fuel generalizing stage target with
  | zero => rfl
  | succ fuel induction =>
      have selected : selectedInput next left stage target =
          selectedInput next right stage target := by
        simp only [selectedInput, same]
      simp [extract, selected, induction]

theorem extract_filter_inert
    (next : Next) (records : RawRecords) (keep : RawInput → Prop)
    (inert : ∀ input, ¬ keep input → ∀ stage, next stage input = none)
    (fuel : Nat) (stage : Stage) (target : RawDigest) :
    extract next (records.filter fun record => keep record.1) fuel stage target =
      extract next records fuel stage target := by
  apply extract_eq_of_candidate_inputs
  exact candidate_inputs_filter_inert next records keep inert

theorem global_extract_erase_challenge
    (ns : Namespace) (records : RawRecords)
    (fuel : Nat) (stage : Stage) (target : RawDigest) :
    extract (globalOnlineNext ns) (eraseChallengeRecords records)
        fuel stage target =
      extract (globalOnlineNext ns) records fuel stage target := by
  rw [eraseChallengeRecords_eq_parse_none]
  convert (extract_filter_inert (globalOnlineNext ns) records
    (fun input => parseStageQuery input = none)
    (by
      intro input notNone decoderStage
      cases parsed : parseStageQuery input with
      | none => simp [parsed] at notNone
      | some query =>
          exact parse_stage_query_global_next_none ns input query parsed decoderStage)
    fuel stage target) using 1; congr 1; ext record; simp

/-- Erasure commutes with an arbitrary input-only view for extraction.  This
is the form used by both the nonleaf outer view and every one-statement inner
view. -/
theorem global_extract_filtered_erase_challenge
    (ns : Namespace) (records : RawRecords) (view : RawInput → Prop)
    (fuel : Nat) (stage : Stage) (target : RawDigest) :
    extract (globalOnlineNext ns)
        ((eraseChallengeRecords records).filter fun record => view record.1)
        fuel stage target =
      extract (globalOnlineNext ns)
        (records.filter fun record => view record.1) fuel stage target := by
  rw [eraseChallengeRecords_eq_parse_none]
  rw [show (records.filter (fun record => parseStageQuery record.1 = none)).filter
        (fun record => view record.1) =
      (records.filter fun record => view record.1).filter
        (fun record => parseStageQuery record.1 = none) by
    ext record
    simp [and_left_comm, and_comm]]
  convert (extract_filter_inert (globalOnlineNext ns)
    (records.filter fun record => view record.1)
    (fun input => parseStageQuery input = none)
    (by
      intro input notNone decoderStage
      cases parsed : parseStageQuery input with
      | none => simp [parsed] at notNone
      | some query =>
          exact parse_stage_query_global_next_none ns input query parsed decoderStage)
    fuel stage target) using 1; congr 1; ext record; simp

/-- Any family of queried challenge-role records may be adjoined to or
removed from a relation without changing a filtered decoder. -/
theorem global_extract_union_challenge_records
    (ns : Namespace) (active fixed : RawRecords)
    (fixedChallenge : ∀ record ∈ fixed, (parseStageQuery record.1).isSome)
    (view : RawInput → Prop) (fuel : Nat) (stage : Stage) (target : RawDigest) :
    extract (globalOnlineNext ns)
        ((active ∪ fixed).filter fun record => view record.1) fuel stage target =
      extract (globalOnlineNext ns)
        (active.filter fun record => view record.1) fuel stage target := by
  apply extract_eq_of_candidate_inputs
  intro selectedStage selectedTarget
  ext input
  simp only [candidateInputs, Finset.mem_image, Finset.mem_filter]
  constructor
  · rintro ⟨record, ⟨⟨recorded, retained⟩, outputEq, decoded⟩, sameInput⟩
    rcases Finset.mem_union.mp recorded with activeRecord | fixedRecord
    · exact ⟨record, ⟨⟨activeRecord, retained⟩, outputEq, decoded⟩, sameInput⟩
    · obtain ⟨query, parsed⟩ := Option.isSome_iff_exists.mp
        (fixedChallenge record fixedRecord)
      have none := parse_stage_query_global_next_none ns record.1 query parsed
        selectedStage
      rw [none] at decoded
      contradiction
  · rintro ⟨record, ⟨⟨recorded, retained⟩, outputEq, decoded⟩, sameInput⟩
    exact ⟨record,
      ⟨⟨Finset.mem_union_left fixed recorded, retained⟩, outputEq, decoded⟩,
      sameInput⟩

end
end HegemonCrypto.SmallWood.SmzaRp05ChallengeRecordErasure
