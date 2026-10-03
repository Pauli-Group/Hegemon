import SmzaRp05SupplyClosureOutputs
import SmzaRp05SupplyClosureHistoryJoin

/-! Construct the opening log from accepted packed output witnesses and
the concrete ordered append stream. The opening-log equality is proved,
not supplied as a history or ledger premise. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoryJoin
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree

set_option autoImplicit false

/-- The source loop's successful Option-valued appends, in stream order. -/
def appendDigestStream (before : FrontierState) : List Digest → Option FrontierState
  | [] => some before
  | commitment :: rest =>
      match SmzaRp05NativeFrontierModel.append before commitment with
      | none => none
      | some after => appendDigestStream after rest

theorem successful_append_extends_replay
    {before after : FrontierState} {log : List Digest}
    (prior : NativeReplay before log) (commitment : Digest)
    (appended : SmzaRp05NativeFrontierModel.append before commitment = some after) :
    NativeReplay after (log ++ [commitment]) := by
  unfold SmzaRp05NativeFrontierModel.append at appended
  split at appended
  next capacity =>
    cases Option.some.inj appended
    exact .push prior commitment capacity
  next full => contradiction

theorem successful_stream_extends_replay
    {before after : FrontierState} {log : List Digest}
    (prior : NativeReplay before log) (stream : List Digest)
    (appended : appendDigestStream before stream = some after) :
    NativeReplay after (log ++ stream) := by
  induction stream generalizing before log with
  | nil =>
      have equal : before = after := Option.some.inj appended
      subst after
      simpa using prior
  | cons commitment rest ih =>
      simp only [appendDigestStream] at appended
      cases step : SmzaRp05NativeFrontierModel.append before commitment with
      | none => simp [step] at appended
      | some middle =>
          rw [step] at appended
          have next := successful_append_extends_replay prior commitment step
          have result := ih next appended
          simpa [List.append_assoc] using result

theorem accepted_output_append_extends_opening_log
    {before after : FrontierState} (openings : List V8NoteOpening)
    (prior : NativeReplay before (openings.map exactV8NoteCommitment))
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (appended : appendDigestStream before (outputCommitments publicWords) = some after) :
    NativeReplay after
      ((openings ++ outputOpenings publicWords packed).map exactV8NoteCommitment) := by
  rw [List.map_append, accepted_output_stream accepted]
  exact successful_stream_extends_replay prior _ appended

abbrev AcceptedOutputRecord := List Nat × List Nat

def extractedOutputLog (records : List AcceptedOutputRecord) : List V8NoteOpening :=
  records.flatMap (fun record => outputOpenings record.1 record.2)

def publicOutputStream (records : List AcceptedOutputRecord) : List Digest :=
  records.flatMap (fun record => outputCommitments record.1)

theorem accepted_records_output_stream (records : List AcceptedOutputRecord)
    (accepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2) :
    (extractedOutputLog records).map exactV8NoteCommitment = publicOutputStream records := by
  induction records with
  | nil => rfl
  | cons record rest ih =>
      have first := accepted_output_stream (accepted record (by simp))
      have later := ih (fun value member => accepted value (by simp [member]))
      simpa only [extractedOutputLog, publicOutputStream, List.flatMap_cons,
        List.map_append, first] using congrArg
          (fun tail : List Digest => outputCommitments record.1 ++ tail) later

/-- The source checks the typed coinbase note hash before passing its
optional trailing commitment to verify_attach. This projection preserves
that exact transaction-output-then-coinbase order. -/
def blockOpeningStream (records : List AcceptedOutputRecord)
    (coinbase : Option V8NoteOpening) : List V8NoteOpening :=
  extractedOutputLog records ++ coinbase.toList

def blockCommitmentStream (records : List AcceptedOutputRecord)
    (coinbase : Option V8NoteOpening) : List Digest :=
  publicOutputStream records ++ (coinbase.map exactV8NoteCommitment).toList

theorem accepted_block_output_stream (records : List AcceptedOutputRecord)
    (accepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2)
    (coinbase : Option V8NoteOpening) :
    (blockOpeningStream records coinbase).map exactV8NoteCommitment =
      blockCommitmentStream records coinbase := by
  unfold blockOpeningStream blockCommitmentStream
  rw [List.map_append, accepted_records_output_stream records accepted]
  cases coinbase <;> rfl

theorem accepted_block_append_extends_opening_log
    {before after : FrontierState} (openings : List V8NoteOpening)
    (prior : NativeReplay before (openings.map exactV8NoteCommitment))
    (records : List AcceptedOutputRecord)
    (accepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2)
    (coinbase : Option V8NoteOpening)
    (appended : appendDigestStream before (blockCommitmentStream records coinbase) =
      some after) :
    NativeReplay after
      ((openings ++ blockOpeningStream records coinbase).map exactV8NoteCommitment) := by
  rw [List.map_append, accepted_block_output_stream records accepted coinbase]
  exact successful_stream_extends_replay prior _ appended

/-- The actual commitment append sequence from empty note genesis yields
an opening log whose members are the extracted accepted outputs. -/
theorem accepted_records_replay_from_genesis
    (records : List AcceptedOutputRecord)
    (accepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2)
    {after : FrontierState}
    (appended : appendDigestStream newEmpty (publicOutputStream records) = some after) :
    NativeReplay after ((extractedOutputLog records).map exactV8NoteCommitment) := by
  rw [accepted_records_output_stream records accepted]
  exact successful_stream_extends_replay NativeReplay.start _ appended

/-- Retained anchors now obtain their producer-opening prefix from accepted
outputs and concrete successful replay, with no same-log-equality premise. -/
theorem accepted_records_anchor_has_opening_prefix
    (records : List AcceptedOutputRecord)
    (accepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2)
    {after : FrontierState}
    (appended : appendDigestStream newEmpty (publicOutputStream records) = some after)
    (anchor : Digest) (admitted : anchor ∈ after.history) :
    ∃ count, count ≤ (extractedOutputLog records).length ∧
      anchor = (fromLog merkleDepth 0 ((extractedOutputLog records).take count)).root :=
  replay_anchor_has_opening_prefix (extractedOutputLog records)
    (accepted_records_replay_from_genesis records accepted appended) anchor admitted

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory
