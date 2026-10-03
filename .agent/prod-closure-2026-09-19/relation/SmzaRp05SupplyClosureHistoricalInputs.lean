import SmzaRp05SupplyClosureCanonicalPaths
import SmzaRp05SupplyClosureDistinctInputs

/-! Compose accepted current proof paths with the opening history actually
constructed by replaying accepted public output commitments. Neither a
same-side premise nor a canonical-path premise is exposed to the caller. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDecodedPath
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosurePositionJoin
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureCanonicalPaths
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoryJoin
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)

set_option autoImplicit false

def inputPath (statement : V8PublicStatement) (packed : List Nat) (input : Fin 2) :=
  decodedPath (projectPosition packed input.val)
    (SmzaRp05BalanceCore.projectInput statement packed input.val).siblings merkleDepth

def publicAnchor (publicWords : List Nat) : Digest :=
  (List.range 7).map (fun limb => publicWords.getD (47 + limb) 0)

theorem accepted_at_history_words_or_collision
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2)
    (active : publicWords.getD input.val 0 = 1)
    (log : List V8NoteOpening)
    (canonical : ∀ opening ∈ log, ExactWords 18 (exactV8NoteWords opening))
    (anchor : publicAnchor publicWords = (fromLog merkleDepth 0 log).root) :
    exactV8NoteWords (projectNote packed (noteCall input)) =
      exactV8NoteWords (openingAt log (projectPosition packed input.val)) ∨
    ∃ historicalPath,
      PathAt (fromLog merkleDepth 0 log) (projectPosition packed input.val)
        (openingAt log (projectPosition packed input.val)) historicalPath ∧
      Nonempty (CanonicalRp05PathCollision
        (exactV8NoteWords (projectNote packed (noteCall input)))
        (exactV8NoteWords (openingAt log (projectPosition packed input.val)))
        (inputPath statement packed input) historicalPath) := by
  have inTree := SmzaRp05AcceptedInputShape.accepted_position_bounded
    SmzaRp05CurrentNullifierCertificates.directionCertificate accepted statement input
  change projectPosition packed input.val < 2 ^ 32 at inTree
  obtain ⟨path, history⟩ := path_from_log merkleDepth 0
    (projectPosition packed input.val) log (Nat.zero_le _) (by simpa [merkleDepth] using inTree)
  have acceptedOpens := current_active_input_opens_public_anchor accepted statement input active
  have sides := accepted_same_position_sides accepted statement input log _ path history
  have rightOpens := path_at_opens history
  have leftOpens : OpensAt rp05PathHash (fromLog merkleDepth 0 log).root
      (pathSides path) (exactV8NoteWords (projectNote packed (noteCall input)))
      (inputPath statement packed input) := by
    exact ⟨sides, acceptedOpens.2.trans anchor⟩
  rcases accepted_rp05_canonical_notes_or_collision _ _ _ _ _ _ leftOpens rightOpens
      (accepted_path_canonical accepted statement input)
      (historical_path_canonical log canonical _ path history) with equal | collision
  · exact Or.inl equal
  · exact Or.inr ⟨path, history, ⟨collision⟩⟩

/-- The retained prefix and its format evidence both come from successful
public-output replay, rather than a supplied semantic history certificate. -/
theorem accepted_replay_input_words_or_collision
    (records : List AcceptedOutputRecord)
    (recordsAccepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2)
    {native : FrontierState}
    (appended : appendDigestStream newEmpty (publicOutputStream records) = some native)
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2)
    (active : publicWords.getD input.val 0 = 1)
    (admitted : publicAnchor publicWords ∈ native.history) :
    ∃ count, count ≤ (extractedOutputLog records).length ∧
      (exactV8NoteWords (projectNote packed (noteCall input)) =
        exactV8NoteWords (openingAt ((extractedOutputLog records).take count)
          (projectPosition packed input.val)) ∨
      ∃ historicalPath,
        PathAt (fromLog merkleDepth 0 ((extractedOutputLog records).take count))
          (projectPosition packed input.val)
          (openingAt ((extractedOutputLog records).take count)
            (projectPosition packed input.val)) historicalPath ∧
        Nonempty (CanonicalRp05PathCollision
          (exactV8NoteWords (projectNote packed (noteCall input)))
          (exactV8NoteWords (openingAt ((extractedOutputLog records).take count)
            (projectPosition packed input.val)))
          (inputPath statement packed input) historicalPath)) := by
  obtain ⟨count, bound, root⟩ := accepted_records_anchor_has_opening_prefix
    records recordsAccepted appended (publicAnchor publicWords) admitted
  refine ⟨count, bound, accepted_at_history_words_or_collision
    accepted statement input active _ ?_ root⟩
  intro opening member
  exact accepted_output_log_canonical records recordsAccepted opening
    (List.mem_of_mem_take member)

/-- At a fixed admitted history, exclusion of the concrete extracted path
collision forces equal notes at equal positions. The native full-digest
duplicate guard then forces the two active positions to be distinct. -/
theorem accepted_two_input_positions_distinct
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement)
    (leftActive : publicWords.getD 0 0 = 1)
    (rightActive : publicWords.getD 1 0 = 1)
    (guard : publicNullifier publicWords 0 ≠ publicNullifier publicWords 1)
    (log : List V8NoteOpening)
    (canonical : ∀ opening ∈ log, ExactWords 18 (exactV8NoteWords opening))
    (anchor : publicAnchor publicWords = (fromLog merkleDepth 0 log).root)
    (noCollision : ∀ input : Fin 2, ∀ historicalPath,
      PathAt (fromLog merkleDepth 0 log) (projectPosition packed input.val)
        (openingAt log (projectPosition packed input.val)) historicalPath →
      ¬ Nonempty (CanonicalRp05PathCollision
        (exactV8NoteWords (projectNote packed (noteCall input)))
        (exactV8NoteWords (openingAt log (projectPosition packed input.val)))
        (inputPath statement packed input) historicalPath)) :
    projectPosition packed 0 ≠ projectPosition packed 1 := by
  have words : ∀ input : Fin 2, publicWords.getD input.val 0 = 1 →
      exactV8NoteWords (projectNote packed (noteCall input)) =
      exactV8NoteWords (openingAt log (projectPosition packed input.val)) := by
    intro input active
    rcases accepted_at_history_words_or_collision accepted statement input active
      log canonical anchor with equal | ⟨path, history, collision⟩
    · exact equal
    · exact False.elim (noCollision input path history collision)
  apply native_duplicate_guard_distinct_positions accepted leftActive rightActive guard
  intro samePosition
  have left := words 0 leftActive
  have right := words 1 rightActive
  simp only [Fin.val_zero, Fin.val_one, noteCall] at left right
  rw [samePosition] at left
  exact left.trans right.symm

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs
