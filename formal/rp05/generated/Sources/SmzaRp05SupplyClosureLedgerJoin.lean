import SmzaRp05SupplyClosureInputNative
import SmzaRp05SupplyClosureHistoricalInputs
import SmzaRp05BalanceCertificateInstance
import SmzaRp05AuthorizationClosureCrossTransaction
import SmzaRp05CurrentBalanceCanonicality

/-! Source-level joins into the existing native ledger endpoint. The
historical prefix is an accepted-output prefix; positive inputs must refer
to actual appended openings. Native balance and the slot sum are derived,
never supplied as a conservation or input-realization premise. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureLedgerJoin

open scoped BigOperators Classical
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs (outputOpenings activeOutputSlots)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureCanonicalPaths
open HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open SmzaFiniteLedgerSupply (nativeValue wealth)
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureCrossTransaction
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureIdentity
open HegemonCrypto.SmallWood.SmzaRp05CurrentBalanceCanonicality

set_option autoImplicit false

theorem opening_at_prefix (log : List V8NoteOpening) (count position : Nat)
    (occupied : position < (log.take count).length) :
    openingAt (log.take count) position = openingAt log position := by
  have takeLength : (log.take count).length ≤ log.length := by
    simp only [List.length_take]
    exact Nat.min_le_right _ _
  have bound : position < log.length :=
    lt_of_lt_of_le occupied takeLength
  simp only [openingAt, if_pos occupied, if_pos bound,
    List.getD_eq_getElem _ _ occupied, List.getD_eq_getElem _ _ bound,
    List.getElem_take]

/-- A positive native contribution cannot come from the known-empty leaf,
including a stale anchor whose formerly empty position is occupied today. -/
theorem positive_historical_input_is_created
    (statement : V8PublicStatement) (packed : List Nat) (input : Fin 2)
    (log : List V8NoteOpening) (count : Nat)
    (positive : 0 < inputSlotNative statement packed input)
    (same : exactV8NoteWords (projectNote packed (noteCall input)) =
      exactV8NoteWords (openingAt (log.take count) (projectPosition packed input.val))) :
    projectPosition packed input.val < (log.take count).length ∧
      inputSlotNative statement packed input =
        nativeValue (openingAt log (projectPosition packed input.val)) := by
  have active := positive_input_slot_active statement packed input positive
  have value := SmzaFiniteLedgerSupply.note_words_preserve_native same
  have occupied : projectPosition packed input.val < (log.take count).length := by
    by_contra empty
    rw [opening_at_unoccupied _ _ (Nat.le_of_not_lt empty)] at value
    have zero : nativeValue knownEmptyOpening = 0 := by
      simp [nativeValue, known_empty_is_zero_native.1]
    rw [zero] at value
    rw [active_input_slot_native statement packed input active, value] at positive
    omega
  refine ⟨occupied, ?_⟩
  rw [active_input_slot_native statement packed input active, value,
    opening_at_prefix log count _ occupied]

/-- The two-slot typed total is bounded by the concrete live-position sum
once each positive slot is shown to be present. This interface is used only
after the source history/spent-nullifier collision split, never as a new
global freshness axiom. -/
theorem typed_two_input_live_sum
    (statement : V8PublicStatement) (packed : List Nat)
    (live : Finset Nat) (registry : Nat → V8NoteOpening)
    (present : ∀ input : Fin 2, 0 < inputSlotNative statement packed input →
      projectPosition packed input.val ∈ live ∧
        inputSlotNative statement packed input ≤ nativeValue (registry (projectPosition packed input.val)))
    (distinct : 0 < inputSlotNative statement packed 0 →
      0 < inputSlotNative statement packed 1 →
        projectPosition packed 0 ≠ projectPosition packed 1) :
    inputNative statement packed ≤ wealth registry live := by
  rw [input_native_two_slots]
  exact two_input_available live (fun position => nativeValue (registry position))
    (projectPosition packed 0) (projectPosition packed 1)
    (inputSlotNative statement packed 0) (inputSlotNative statement packed 1)
    (present 0) (present 1) distinct

/-- The existing current-program balance theorem connects the exact typed
slot sum to the actual appended accepted output openings plus the fee. -/
private theorem accepted_output_stream_native_generic
    (statement : V8PublicStatement) (packed : List Nat)
    {primitives : V8SemanticPrimitives}
    (canonical : CanonicalPublicStatement primitives statement) :
    ((outputOpenings (encodePublicStatement statement) packed).map nativeValue).sum =
      outputNative statement packed := by
  have flag0 := encoded_output_flag_for statement canonical (output := 0) (by decide)
  have flag1 := encoded_output_flag_for statement canonical (output := 1) (by decide)
  rw [output_native_two_slots]
  simp only [outputOpenings, activeOutputSlots, List.filter_cons, List.filter_nil]
  simp only [flag0, flag1]
  split_ifs <;> simp_all [SmzaRp05SupplyClosureOutputFrame.noteCall]

theorem accepted_source_native_balance
    (statement : V8PublicStatement) (packed : List Nat)
    {primitives : V8SemanticPrimitives}
    (canonical : CanonicalPublicStatement primitives statement)
    (accepted : program.AcceptsPacked (encodePublicStatement statement) packed) :
    inputSlotNative statement packed 0 + inputSlotNative statement packed 1 =
      ((SmzaRp05SupplyClosureOutputs.outputOpenings
        (encodePublicStatement statement) packed).map nativeValue).sum + statement.fee := by
  rw [← input_native_two_slots,
    accepted_output_stream_native_generic statement packed canonical]
  exact accepted_transfer_balance ⟨primitives, canonical⟩ accepted

private theorem positive_input_slot_public_active_generic
    (statement : V8PublicStatement) (packed : List Nat)
    {primitives : V8SemanticPrimitives}
    (canonical : CanonicalPublicStatement primitives statement)
    (input : Fin 2) (positive : 0 < inputSlotNative statement packed input) :
    (encodePublicStatement statement).getD input.val 0 = 1 := by
  rw [encoded_input_flag_for statement canonical input.isLt]
  exact positive_input_slot_active statement packed input positive

def HistoricalInputCollision (statement : V8PublicStatement) (packed : List Nat)
    (log : List V8NoteOpening) : Prop :=
  ∃ input : Fin 2, ∃ path,
    PathAt (fromLog merkleDepth 0 log) (projectPosition packed input.val)
      (openingAt log (projectPosition packed input.val)) path ∧
    Nonempty (CanonicalRp05PathCollision
      (exactV8NoteWords (projectNote packed (noteCall input)))
      (exactV8NoteWords (openingAt log (projectPosition packed input.val)))
      (inputPath statement packed input) path)

def PositiveSpentMatch (statement : V8PublicStatement) (packed : List Nat)
    (spent : Finset Nat) : Prop :=
  ∃ input : Fin 2, 0 < inputSlotNative statement packed input ∧
    projectPosition packed input.val ∈ spent

/-- This is the deterministic supply side of the final failure split.
History and same-transaction uniqueness are proved from source equations.
The remaining alternative names an actual positive spent-position match;
the authorization reduction must turn that match and the native nullifier
guard into its concrete framed collision, not assume it cannot occur. -/
theorem accepted_history_available_or_collision_or_spent_match
    (statement : V8PublicStatement) (packed : List Nat)
    {primitives : V8SemanticPrimitives}
    (canonicalStatement : CanonicalPublicStatement primitives statement)
    (accepted : program.AcceptsPacked (encodePublicStatement statement) packed)
    (log : List V8NoteOpening) (count : Nat)
    (canonicalLog : ∀ opening ∈ log, ExactWords 18 (exactV8NoteWords opening))
    (anchor : publicAnchor (encodePublicStatement statement) =
      (fromLog merkleDepth 0 (log.take count)).root)
    (spent : Finset Nat)
    (duplicateGuard : (encodePublicStatement statement).getD 0 0 = 1 →
      (encodePublicStatement statement).getD 1 0 = 1 →
      publicNullifier (encodePublicStatement statement) 0 ≠
        publicNullifier (encodePublicStatement statement) 1) :
    inputNative statement packed ≤
      wealth (openingAt log) (Finset.range log.length \ spent) ∨
    HistoricalInputCollision statement packed (log.take count) ∨
    PositiveSpentMatch statement packed spent := by
  classical
  by_cases collision : HistoricalInputCollision statement packed (log.take count)
  · exact Or.inr (Or.inl collision)
  by_cases reused : PositiveSpentMatch statement packed spent
  · exact Or.inr (Or.inr reused)
  have canonicalPrefix : ∀ opening ∈ log.take count,
      ExactWords 18 (exactV8NoteWords opening) :=
    fun opening member => canonicalLog opening (List.mem_of_mem_take member)
  have same : ∀ input : Fin 2, 0 < inputSlotNative statement packed input →
      exactV8NoteWords (projectNote packed (noteCall input)) =
        exactV8NoteWords (openingAt (log.take count) (projectPosition packed input.val)) := by
    intro input positive
    have active := positive_input_slot_public_active_generic
      statement packed canonicalStatement input positive
    rcases accepted_at_history_words_or_collision accepted statement input active
      (log.take count) canonicalPrefix anchor with equal | ⟨path, history, found⟩
    · exact equal
    · exact False.elim (collision ⟨input, path, history, found⟩)
  left
  apply typed_two_input_live_sum statement packed
  · intro input positive
    obtain ⟨occupied, value⟩ := positive_historical_input_is_created
      statement packed input log count positive (same input positive)
    refine ⟨Finset.mem_sdiff.mpr ⟨Finset.mem_range.mpr ?_, ?_⟩, Nat.le_of_eq value⟩
    · exact lt_of_lt_of_le occupied (by
        have takeLength : (log.take count).length ≤ log.length := by
          simp only [List.length_take]
          exact Nat.min_le_right _ _
        exact takeLength)
    · intro spentMember
      exact reused ⟨input, positive, spentMember⟩
  · intro leftPositive rightPositive
    have leftActive := positive_input_slot_public_active_generic
      statement packed canonicalStatement 0 leftPositive
    have rightActive := positive_input_slot_public_active_generic
      statement packed canonicalStatement 1 rightPositive
    apply accepted_two_input_positions_distinct accepted statement leftActive rightActive
      (duplicateGuard leftActive rightActive) (log.take count) canonicalPrefix anchor
    intro input path history found
    exact collision ⟨input, path, history, found⟩

/-- The log and the common retained prefix are constructed from successful
replay of accepted output commitments, before the spent-match reduction. -/
theorem accepted_replay_available_or_collision_or_spent_match
    (records : List AcceptedOutputRecord)
    (recordsAccepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2)
    {native : FrontierState}
    (appended : appendDigestStream newEmpty (publicOutputStream records) = some native)
    (statement : V8PublicStatement) (packed : List Nat)
    {primitives : V8SemanticPrimitives}
    (canonical : CanonicalPublicStatement primitives statement)
    (accepted : program.AcceptsPacked (encodePublicStatement statement) packed)
    (admitted : publicAnchor (encodePublicStatement statement) ∈ native.history)
    (spent : Finset Nat)
    (duplicateGuard : (encodePublicStatement statement).getD 0 0 = 1 →
      (encodePublicStatement statement).getD 1 0 = 1 →
      publicNullifier (encodePublicStatement statement) 0 ≠
        publicNullifier (encodePublicStatement statement) 1) :
    inputNative statement packed ≤ wealth (openingAt (extractedOutputLog records))
      (Finset.range (extractedOutputLog records).length \ spent) ∨
    (∃ count, count ≤ (extractedOutputLog records).length ∧
      HistoricalInputCollision statement packed ((extractedOutputLog records).take count)) ∨
    PositiveSpentMatch statement packed spent := by
  obtain ⟨count, bound, anchor⟩ := accepted_records_anchor_has_opening_prefix
    records recordsAccepted appended _ admitted
  rcases accepted_history_available_or_collision_or_spent_match
    statement packed canonical accepted (extractedOutputLog records) count
    (accepted_output_log_canonical records recordsAccepted) anchor spent duplicateGuard with
    available | collision | reused
  · exact Or.inl available
  · exact Or.inr (Or.inl ⟨count, bound, collision⟩)
  · exact Or.inr (Or.inr reused)

/-- A positive prior spend carries the concrete accepted source and its
historical output replay. No note-origin equality or freshness is a field.
Zero/empty inputs are intentionally excluded from the native-value ledger:
their positions may subsequently receive newly appended positive notes. -/
structure PositiveSourceSpend (primitives : V8SemanticPrimitives) where
  statement : V8PublicStatement
  packed : List Nat
  input : Fin 2
  records : List AcceptedOutputRecord
  native : FrontierState
  canonical : CanonicalPublicStatement primitives statement
  accepted : program.AcceptsPacked (encodePublicStatement statement) packed
  positive : 0 < inputSlotNative statement packed input
  recordsAccepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2
  appended : appendDigestStream newEmpty (publicOutputStream records) = some native
  admitted : publicAnchor (encodePublicStatement statement) ∈ native.history

def PositiveSourceSpend.position {primitives : V8SemanticPrimitives}
    (spend : PositiveSourceSpend primitives) : Nat :=
  projectPosition spend.packed spend.input.val

def positiveSpentPositions {primitives : V8SemanticPrimitives}
    (past : List (PositiveSourceSpend primitives)) : Finset Nat :=
  (past.map PositiveSourceSpend.position).toFinset

def SourceSpendPathCollision {primitives : V8SemanticPrimitives}
    (spend : PositiveSourceSpend primitives) : Prop :=
  ∃ count, count ≤ (extractedOutputLog spend.records).length ∧
    HistoricalInputCollision spend.statement spend.packed
      ((extractedOutputLog spend.records).take count)

theorem opening_at_appended_prefix (priorLog suffix : List V8NoteOpening) (position : Nat)
    (occupied : position < priorLog.length) :
    openingAt priorLog position = openingAt (priorLog ++ suffix) position := by
  have fullBound : position < (priorLog ++ suffix).length := by simp; omega
  simp only [openingAt, if_pos occupied, if_pos fullBound]
  rw [List.getD_append _ _ _ _ occupied]

theorem source_spend_words_or_collision {primitives : V8SemanticPrimitives}
    (spend : PositiveSourceSpend primitives)
    (records : List AcceptedOutputRecord) (recordPrefix : spend.records.IsPrefix records) :
    exactV8NoteWords (projectNote spend.packed (noteCall spend.input)) =
      exactV8NoteWords (openingAt (extractedOutputLog records) spend.position) ∨
    SourceSpendPathCollision spend := by
  obtain ⟨count, countBound, equal | ⟨path, history, collision⟩⟩ :=
    accepted_replay_input_words_or_collision spend.records spend.recordsAccepted spend.appended
      spend.accepted spend.statement spend.input
      (positive_input_slot_public_active_generic spend.statement spend.packed
        spend.canonical spend.input spend.positive) spend.admitted
  · have created := positive_historical_input_is_created spend.statement spend.packed
      spend.input (extractedOutputLog spend.records) count spend.positive equal
    have occupied : spend.position < (extractedOutputLog spend.records).length :=
      lt_of_lt_of_le created.1 (by
        have takeLength : ((extractedOutputLog spend.records).take count).length ≤
            (extractedOutputLog spend.records).length := by
          simp only [List.length_take]
          exact Nat.min_le_right _ _
        exact takeLength)
    rw [opening_at_prefix _ count _ created.1] at equal
    rcases recordPrefix with ⟨suffix, rfl⟩
    rw [show extractedOutputLog (spend.records ++ suffix) =
        extractedOutputLog spend.records ++ extractedOutputLog suffix by
          simp [extractedOutputLog, List.flatMap_append]]
    exact Or.inl (equal.trans (congrArg exactV8NoteWords
      (opening_at_appended_prefix _ _ spend.position occupied)))
  · exact Or.inr ⟨count, countBound, spend.input, path, history, collision⟩

/-- Explicit failure alternatives retained by the source-level supply join. -/
def SourceSupplyCollision {primitives : V8SemanticPrimitives}
    (statement : V8PublicStatement) (packed : List Nat)
    (records : List AcceptedOutputRecord) (past : List (PositiveSourceSpend primitives)) : Prop :=
  (∃ count, count ≤ (extractedOutputLog records).length ∧
    HistoricalInputCollision statement packed ((extractedOutputLog records).take count)) ∨
  (∃ spend ∈ past, SourceSpendPathCollision spend) ∨
  (∃ input : Fin 2, ∃ spend ∈ past,
    FramedAuthorizationCollision (selectedMessage packed input)
      (selectedMessage spend.packed spend.input))

/-- Source guards and the exact framed authorization reduction discharge
the positive spent-position alternative. Freshness is now a conclusion,
not a caller-supplied global no-reuse predicate. -/
theorem accepted_source_inputs_available_or_collision
    (records : List AcceptedOutputRecord)
    (recordsAccepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2)
    {native : FrontierState}
    (appended : appendDigestStream newEmpty (publicOutputStream records) = some native)
    (statement : V8PublicStatement) (packed : List Nat)
    {primitives : V8SemanticPrimitives}
    (canonical : CanonicalPublicStatement primitives statement)
    (accepted : program.AcceptsPacked (encodePublicStatement statement) packed)
    (admitted : publicAnchor (encodePublicStatement statement) ∈ native.history)
    (past : List (PositiveSourceSpend primitives))
    (pastPrefixes : ∀ spend ∈ past, spend.records.IsPrefix records)
    (duplicateGuard : (encodePublicStatement statement).getD 0 0 = 1 →
      (encodePublicStatement statement).getD 1 0 = 1 →
      publicNullifier (encodePublicStatement statement) 0 ≠
        publicNullifier (encodePublicStatement statement) 1)
    (spentGuard : ∀ spend ∈ past, ∀ input : Fin 2,
      (encodePublicStatement statement).getD input.val 0 = 1 →
      publicNullifier (encodePublicStatement statement) input ≠
        publicNullifier (encodePublicStatement spend.statement) spend.input) :
    inputNative statement packed ≤ wealth (openingAt (extractedOutputLog records))
      (Finset.range (extractedOutputLog records).length \ positiveSpentPositions past) ∨
    SourceSupplyCollision statement packed records past := by
  classical
  rcases accepted_replay_available_or_collision_or_spent_match records recordsAccepted
    appended statement packed canonical accepted admitted (positiveSpentPositions past)
    duplicateGuard with available | collision | reused
  · exact Or.inl available
  · exact Or.inr (Or.inl collision)
  · obtain ⟨input, positive, spentMember⟩ := reused
    obtain ⟨old, oldMember, positionEq⟩ := List.mem_map.mp
      (List.mem_toFinset.mp spentMember)
    let current : PositiveSourceSpend primitives :=
      { statement := statement, packed := packed, input := input,
        records := records, native := native, canonical := canonical,
        accepted := accepted, positive := positive,
        recordsAccepted := recordsAccepted, appended := appended, admitted := admitted }
    rcases source_spend_words_or_collision current records
        (show current.records.IsPrefix records from ⟨[], by simp [current]⟩) with
      currentWords | currentCollision
    · rcases source_spend_words_or_collision old records (pastPrefixes old oldMember) with
        oldWords | oldCollision
      · have samePosition : projectPosition packed input.val =
            projectPosition old.packed old.input.val := positionEq.symm
        have sameWords : exactV8NoteWords (projectNote packed (noteCall input)) =
            exactV8NoteWords (projectNote old.packed (noteCall old.input)) := by
          change exactV8NoteWords (projectNote packed (noteCall input)) =
            exactV8NoteWords (openingAt (extractedOutputLog records)
              (projectPosition packed input.val)) at currentWords
          rw [samePosition] at currentWords
          exact currentWords.trans oldWords.symm
        have active := positive_input_slot_public_active_generic statement packed canonical input positive
        have oldActive := positive_input_slot_public_active_generic old.statement old.packed
          old.canonical old.input old.positive
        have owners := same_accepted_note_owner_words accepted old.accepted input old.input sameWords
        have rho : ∀ limb : Fin 4,
            spongeSourceWord packed (SmzaRp05NullifierBinding.inputNoteFirstCall input) (6 + limb.val) =
              spongeSourceWord old.packed
                (SmzaRp05NullifierBinding.inputNoteFirstCall old.input) (6 + limb.val) := by
          intro limb
          exact equal_projected_note_words_coordinate _ _ sameWords (6 + limb.val) (by omega)
        rcases accepted_same_note_position_public_nullifier_or_authorization_collision
          accepted old.accepted input old.input active oldActive owners samePosition rho with
          sameNullifier | authCollision
        · have publicEqual : publicNullifier (encodePublicStatement statement) input =
              publicNullifier (encodePublicStatement old.statement) old.input := by
            apply List.map_congr_left
            intro limb member
            exact sameNullifier ⟨limb, List.mem_range.mp member⟩
          exact False.elim (spentGuard old oldMember input active publicEqual)
        · exact Or.inr (Or.inr (Or.inr ⟨input, old, oldMember, authCollision⟩))
      · exact Or.inr (Or.inr (Or.inl ⟨old, oldMember, oldCollision⟩))
    · exact Or.inr (Or.inl currentCollision)

/-- Construct the existing accepted transfer branch from actual replay,
public nullifier guards, and current relation acceptance, or return an
explicit canonical path/framed-authorization collision. -/
theorem accepted_source_transfer_step_or_collision
    (records : List AcceptedOutputRecord)
    (recordsAccepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2)
    {native : FrontierState}
    (appended : appendDigestStream newEmpty (publicOutputStream records) = some native)
    (statement : V8PublicStatement) (packed : List Nat)
    {primitives : V8SemanticPrimitives}
    (canonical : CanonicalPublicStatement primitives statement)
    (accepted : program.AcceptsPacked (encodePublicStatement statement) packed)
    (admitted : publicAnchor (encodePublicStatement statement) ∈ native.history)
    (past : List (PositiveSourceSpend primitives))
    (pastPrefixes : ∀ spend ∈ past, spend.records.IsPrefix records)
    (duplicateGuard : (encodePublicStatement statement).getD 0 0 = 1 →
      (encodePublicStatement statement).getD 1 0 = 1 →
      publicNullifier (encodePublicStatement statement) 0 ≠
        publicNullifier (encodePublicStatement statement) 1)
    (spentGuard : ∀ spend ∈ past, ∀ input : Fin 2,
      (encodePublicStatement statement).getD input.val 0 = 1 →
      publicNullifier (encodePublicStatement statement) input ≠
        publicNullifier (encodePublicStatement spend.statement) spend.input)
    (feeEscrow : Nat) (issuedHeights : Finset Nat) :
    let before : SupplyState :=
      { circulating := wealth (openingAt (extractedOutputLog records))
          (Finset.range (extractedOutputLog records).length \ positiveSpentPositions past),
        feeEscrow := feeEscrow, issuedHeights := issuedHeights }
    (AcceptedStep program before (.transfer statement packed)
      { circulating := before.circulating - inputNative statement packed + outputNative statement packed,
        feeEscrow := feeEscrow + statement.fee, issuedHeights := issuedHeights } ∧
      (before.circulating - inputNative statement packed + outputNative statement packed) +
        (feeEscrow + statement.fee) = potential before) ∨
    SourceSupplyCollision statement packed records past := by
  rcases accepted_source_inputs_available_or_collision records recordsAccepted appended
    statement packed canonical accepted admitted past pastPrefixes duplicateGuard spentGuard with
    available | collision
  · refine Or.inl ⟨.transfer _ statement packed ⟨primitives, canonical⟩ accepted available, ?_⟩
    have balance := accepted_transfer_balance ⟨primitives, canonical⟩ accepted
    dsimp only [potential]
    omega
  · exact Or.inr collision

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureLedgerJoin
