import SmzaRp05ActualAcceptedAuthorizationEndpoint
import SmzaRp05CurrentAcceptedRelationWitness
import SmzaRp05FinalSupplySoundness
import SmzaRp05HistoricalTree
import SmzaRp05LedgerMerkleBinding
import SmzaRp05SupplyClosureHistoryJoin
import SmzaRp05SupplyClosureHistoricalInputs
import SmzaRp05SupplyClosureInputNative
import SmzaRp05SupplyClosureLedgerJoin

/-! Same-run input slot positions are derived from the designated accepted
source and the exact replayed pre-block openings. Equal positive positions
either expose the concrete accepted-path collision or contradict the parser's
active-nullifier distinctness check. In the no-collision case, the input
native sum is realized over the finite set of positive source positions, with
the position map proved injective before summing. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRelationWitness
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
open HegemonCrypto.SmallWood.SmzaRp05CurrentBalanceCanonicality
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureLedgerJoin
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoryJoin
open HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open SmzaQ38Recovery (packedFromRows)
open SmzaFiniteLedgerSupply (nativeValue)
open scoped BigOperators Classical

-- These projections have already-checked exact component lemmas below; their
-- expanded source syntax is needlessly expensive during generic finite sums.
attribute [local irreducible] inputNative inputSlotNative

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

-- Keep the packed witness opaque while finite input-position identities are
-- checked; unfolding it traverses the full source row encoding.
attribute [local irreducible] SmzaQ38Recovery.packedFromRows

noncomputable def designatedInputPacked {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed) : List Nat :=
  packedFromRows run.source.data

noncomputable def designatedInputPosition {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed) (input : Fin 2) : Nat :=
  projectPosition (designatedInputPacked run) input.val

noncomputable def positiveDesignatedInputSlots {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed) : Finset (Fin 2) :=
  Finset.univ.filter fun input =>
    0 < inputSlotNative typed (designatedInputPacked run) input

noncomputable def positiveDesignatedInputPositions {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed) : Finset Nat :=
  (positiveDesignatedInputSlots run).image (designatedInputPosition run)

/-- The collision carrier is the actual path emitted by comparing this
designated input's accepted path with the path opened at the retained prefix. -/
noncomputable def CurrentInputPathCollision {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed)
    (openings : List V8NoteOpening) (input : Fin 2) : Prop :=
  ∃ count, count ≤ openings.length ∧
    ∃ path, PathAt (fromLog merkleDepth 0 (openings.take count))
      (designatedInputPosition run input)
      (openingAt (openings.take count) (designatedInputPosition run input)) path ∧
    Nonempty (CanonicalRp05PathCollision
      (exactV8NoteWords (projectNote (designatedInputPacked run) (noteCall input)))
      (exactV8NoteWords (openingAt (openings.take count)
        (designatedInputPosition run input)))
      (inputPath typed (designatedInputPacked run) input) path)

private theorem encoded_public_nullifier_word_for_current
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement rustV8SemanticPrimitives statement)
    (input : Fin 2) (limb : Fin 7) :
    (encodePublicStatement statement).getD
        (4 + 7 * input.val + limb.val) 0 =
      (digestAt statement.nullifiers input.val).getD limb.val 0 := by
  obtain ⟨inputLength, outputLength, nullifierFlatLength, _, _, _, _⟩ :=
    admitted_public_lengths_for statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags
  have prefixLength : publicPrefix.length = 4 := by
    simp [publicPrefix, inputLength, outputLength]
  have encoded : encodePublicStatement statement = publicPrefix ++
      (statement.nullifiers.flatten ++ (statement.commitments.flatten ++
        statement.ciphertextCommitments.flatten ++
          [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
          statement.merkleRoot ++ statement.balanceAssets ++
          encodeCompatibility statement.compatibility ++
          [statement.version, statement.cryptoSuite] ++
          encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  have offset : 4 + 7 * input.val + limb.val - 4 =
      7 * input.val + limb.val := by omega
  rw [offset, List.getD_append _ _ _ _
    (by rw [nullifierFlatLength]; have := input.isLt; have := limb.isLt; omega)]
  have canonicalProof := canonical
  obtain ⟨_, _, _, _, nullifierCount, nullifierWords, _⟩ := canonicalProof
  obtain ⟨first, second, chunks⟩ := List.length_eq_two.mp nullifierCount
  have firstLength : first.length = 7 :=
    (nullifierWords first (by simp [chunks])).1
  fin_cases input
  · simpa [chunks, digestAt] using
      List.getD_append first second 0 limb.val (by have := limb.isLt; omega)
  · simpa [chunks, digestAt, firstLength] using
      List.getD_append_right first second 0 (7 + limb.val) (by omega)

private theorem encoded_public_nullifier_eq_digest_for_current
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement rustV8SemanticPrimitives statement)
    (input : Fin 2) :
    publicNullifier (encodePublicStatement statement) input =
      digestAt statement.nullifiers input.val := by
  have canonicalProof := canonical
  obtain ⟨_, _, _, _, nullifierCount, nullifierWords, _⟩ := canonicalProof
  have inputBound : input.val < statement.nullifiers.length := by
    rw [nullifierCount]
    exact input.isLt
  have found : statement.nullifiers[input.val]? =
      some (digestAt statement.nullifiers input.val) := by
    simp [digestAt, List.getD, inputBound]
  have digestLength :
      (digestAt statement.nullifiers input.val).length = 7 :=
    (nullifierWords _ (List.mem_of_getElem? found)).1
  apply List.ext_getElem (by simp [publicNullifier, digestLength])
  intro limb leftBound rightBound
  have limbBound : limb < 7 := by simpa [publicNullifier] using leftBound
  simp only [publicNullifier, List.getElem_map, List.getElem_range]
  have wordReadback := encoded_public_nullifier_word_for_current
    statement canonical input ⟨limb, limbBound⟩
  have normalizedWordReadback :
      (encodePublicStatement statement).getD
          (4 + input.val * 7 + limb) 0 =
        (digestAt statement.nullifiers input.val).getD limb 0 := by
    simpa only [Nat.mul_comm] using wordReadback
  rw [normalizedWordReadback]
  exact List.getD_eq_getElem _ _ rightBound

private theorem designated_public_nullifiers_distinct
    {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed)
    (leftActive : flagAt typed.inputFlags 0 = 1)
    (rightActive : flagAt typed.inputFlags 1 = 1) :
    publicNullifier (encodePublicStatement typed) 0 ≠
      publicNullifier (encodePublicStatement typed) 1 := by
  have parserChecks : CurrentRustPublicChecks typed :=
    ((parse_current_public_statement_iff preamble typed).mp run.parsed).2
  have canonical : CanonicalPublicStatement rustV8SemanticPrimitives typed :=
    parse_output_is_canonical preamble typed run.parsed
  have digestDistinct := parserChecks.distinctActiveNullifiers leftActive rightActive
  have nullifierReadback (input : Fin 2) :
      publicNullifier (encodePublicStatement typed) input =
        digestAt typed.nullifiers input.val :=
    encoded_public_nullifier_eq_digest_for_current typed canonical input
  intro equal
  apply digestDistinct
  calc
    digestAt typed.nullifiers 0 =
        publicNullifier (encodePublicStatement typed) 0 :=
      (nullifierReadback 0).symm
    _ = publicNullifier (encodePublicStatement typed) 1 := equal
    _ = digestAt typed.nullifiers 1 := nullifierReadback 1

/-- A positive designated input is tied to the same retained opening prefix
used by native replay, unless the exact canonical accepted-path collision is
returned. -/
theorem positive_input_snapshot_binding_or_collision
    {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed)
    {parent : FrontierState} (openings : List V8NoteOpening)
    (canonicalOpenings : ∀ opening ∈ openings,
      ExactWords 18 (exactV8NoteWords opening))
    (replay : NativeReplay parent (openings.map exactV8NoteCommitment))
    (admitted : publicAnchor (encodePublicStatement typed) ∈ parent.history)
    (input : Fin 2)
    (positive : 0 < inputSlotNative typed (designatedInputPacked run) input) :
    (designatedInputPosition run input < openings.length ∧
      exactV8NoteWords
        (projectNote (designatedInputPacked run) (noteCall input)) =
        exactV8NoteWords (openingAt openings (designatedInputPosition run input))) ∨
      CurrentInputPathCollision run openings input := by
  obtain ⟨count, countBound, anchor⟩ := replay_anchor_has_opening_prefix
    openings replay (publicAnchor (encodePublicStatement typed)) admitted
  have accepted := current_full_rows_yield_typed_accepted_witness
    preamble typed run.parsed run.source.data run.fullySatisfied
  have active : (encodePublicStatement typed).getD input.val 0 = 1 := by
    rw [encoded_input_flag_for typed accepted.1 input.isLt]
    exact positive_input_slot_active typed (designatedInputPacked run) input positive
  rcases accepted_at_history_words_or_collision accepted.2 typed input active
      (openings.take count)
      (fun opening member =>
        canonicalOpenings opening (List.mem_of_mem_take member)) anchor with
    same | collision
  · obtain ⟨occupied, _value⟩ := positive_historical_input_is_created
      typed (designatedInputPacked run) input openings count positive same
    have takeLength : (openings.take count).length ≤ openings.length := by
      simp only [List.length_take]
      exact Nat.min_le_right _ _
    have fullSame :
        exactV8NoteWords
          (projectNote (designatedInputPacked run) (noteCall input)) =
          exactV8NoteWords (openingAt openings (designatedInputPosition run input)) := by
      calc
        _ = exactV8NoteWords
            (openingAt (openings.take count) (designatedInputPosition run input)) := same
        _ = exactV8NoteWords (openingAt openings (designatedInputPosition run input)) :=
          congrArg exactV8NoteWords
            (opening_at_prefix openings count _ occupied)
    exact Or.inl ⟨lt_of_lt_of_le occupied takeLength, fullSame⟩
  · exact Or.inr ⟨count, countBound, collision⟩

/-- Two positive slots cannot use one retained source position in an accepted
designated run. If either authenticated source binding is exceptional, its
exact path-collision evidence is returned instead. The nullifier guard comes
from the successful current parser, not from a caller premise. -/
theorem current_positive_input_positions_distinct_or_path_collision
    {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed)
    {parent : FrontierState} (openings : List V8NoteOpening)
    (canonicalOpenings : ∀ opening ∈ openings,
      ExactWords 18 (exactV8NoteWords opening))
    (replay : NativeReplay parent (openings.map exactV8NoteCommitment))
    (admitted : publicAnchor (encodePublicStatement typed) ∈ parent.history)
    (leftPositive : 0 < inputSlotNative typed (designatedInputPacked run) 0)
    (rightPositive : 0 < inputSlotNative typed (designatedInputPacked run) 1) :
    designatedInputPosition run 0 ≠ designatedInputPosition run 1 ∨
      CurrentInputPathCollision run openings 0 ∨
      CurrentInputPathCollision run openings 1 := by
  rcases positive_input_snapshot_binding_or_collision run openings
      canonicalOpenings replay admitted 0 leftPositive with
    leftBinding | leftCollision
  · rcases positive_input_snapshot_binding_or_collision run openings
        canonicalOpenings replay admitted 1 rightPositive with
      rightBinding | rightCollision
    · have sameNoteOfEqualPosition : designatedInputPosition run 0 =
          designatedInputPosition run 1 →
          exactV8NoteWords (projectNote (designatedInputPacked run) (noteCall 0)) =
          exactV8NoteWords (projectNote (designatedInputPacked run) (noteCall 1)) := by
        intro samePosition
        calc
          _ = exactV8NoteWords (openingAt openings
              (designatedInputPosition run 0)) := leftBinding.2
          _ = exactV8NoteWords (openingAt openings
              (designatedInputPosition run 1)) := by
            exact congrArg (fun position =>
              exactV8NoteWords (openingAt openings position)) samePosition
          _ = _ := rightBinding.2.symm
      have accepted := current_full_rows_yield_typed_accepted_witness
        preamble typed run.parsed run.source.data run.fullySatisfied
      have leftActive : flagAt typed.inputFlags 0 = 1 :=
        positive_input_slot_active typed (designatedInputPacked run) 0 leftPositive
      have rightActive : flagAt typed.inputFlags 1 = 1 :=
        positive_input_slot_active typed (designatedInputPacked run) 1 rightPositive
      have guard := designated_public_nullifiers_distinct run leftActive rightActive
      have distinct := native_duplicate_guard_distinct_positions accepted.2
        (by rw [encoded_input_flag_for typed accepted.1 (by decide), leftActive])
        (by rw [encoded_input_flag_for typed accepted.1 (by decide), rightActive])
        guard sameNoteOfEqualPosition
      exact Or.inl (by simpa [designatedInputPosition, designatedInputPacked] using distinct)
    · exact Or.inr (Or.inr rightCollision)
  · exact Or.inr (Or.inl leftCollision)

private theorem designated_input_slot_value
    {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed)
    {parent : FrontierState} (openings : List V8NoteOpening)
    (canonicalOpenings : ∀ opening ∈ openings,
      ExactWords 18 (exactV8NoteWords opening))
    (replay : NativeReplay parent (openings.map exactV8NoteCommitment))
    (admitted : publicAnchor (encodePublicStatement typed) ∈ parent.history)
    (noCollision : ∀ input : Fin 2,
      0 < inputSlotNative typed (designatedInputPacked run) input →
      ¬ CurrentInputPathCollision run openings input)
    (input : Fin 2) :
    inputSlotNative typed (designatedInputPacked run) input =
      if 0 < inputSlotNative typed (designatedInputPacked run) input
      then nativeValue (openingAt openings (designatedInputPosition run input))
      else 0 := by
  by_cases positive : 0 < inputSlotNative typed (designatedInputPacked run) input
  · have binding := positive_input_snapshot_binding_or_collision run openings
      canonicalOpenings replay admitted input positive
    rcases binding with ⟨_positionBound, same⟩ | collision
    · have active := positive_input_slot_active typed
        (designatedInputPacked run) input positive
      calc
        inputSlotNative typed (designatedInputPacked run) input =
            nativeValue (projectNote (designatedInputPacked run) (noteCall input)) :=
          active_input_slot_native typed (designatedInputPacked run) input active
        _ = nativeValue (openingAt openings (designatedInputPosition run input)) :=
          SmzaFiniteLedgerSupply.note_words_preserve_native same
        _ = if 0 < inputSlotNative typed
            (designatedInputPacked run) input then
              nativeValue (openingAt openings (designatedInputPosition run input))
            else 0 := by simp [positive]
    · exact False.elim (noCollision input positive collision)
  · have zero : inputSlotNative typed (designatedInputPacked run) input = 0 := by omega
    simp [zero]

/-- Exact native input realization over distinct positive source positions.
Inactive input slots are zero, and only the positive-slot image is summed;
the proved injectivity prevents a repeated source position from being counted
once per slot. -/
private theorem sum_positive_fin_two (f : Fin 2 → Nat) :
    (∑ input ∈ Finset.univ.filter (fun input => 0 < f input), f input) =
      f 0 + f 1 := by
  classical
  simp only [Finset.sum_filter, Fin.sum_univ_two]
  split_ifs <;> omega

private theorem input_native_sum_of_slot_positions
    (statement : V8PublicStatement) (packed : List Nat)
    (openings : List V8NoteOpening)
    (slotValue : ∀ input : Fin 2,
      inputSlotNative statement packed input =
        if 0 < inputSlotNative statement packed input then
          nativeValue (openingAt openings (projectPosition packed input.val)) else 0)
    (positivePositionsDistinct :
      ∀ (_ : 0 < inputSlotNative statement packed 0)
        (_ : 0 < inputSlotNative statement packed 1),
        projectPosition packed 0 ≠ projectPosition packed 1) :
    (∑ position ∈
        ((Finset.univ.filter (fun input : Fin 2 =>
            0 < inputSlotNative statement packed input)).image
          (fun input => projectPosition packed input.val)),
        nativeValue (openingAt openings position)) =
      ∑ input ∈ Finset.univ.filter (fun input : Fin 2 =>
        0 < inputSlotNative statement packed input),
        inputSlotNative statement packed input := by
  classical
  let positiveSlots : Finset (Fin 2) := Finset.univ.filter fun input =>
    0 < inputSlotNative statement packed input
  let positivePositions : Finset Nat :=
    positiveSlots.image (fun input => projectPosition packed input.val)
  have injectiveOn : Set.InjOn (fun input : Fin 2 => projectPosition packed input.val)
      positiveSlots := by
    intro left leftMember right rightMember equal
    have leftPositive := (Finset.mem_filter.mp leftMember).2
    have rightPositive := (Finset.mem_filter.mp rightMember).2
    fin_cases left <;> fin_cases right
    · rfl
    · exact (positivePositionsDistinct leftPositive rightPositive equal).elim
    · exact (positivePositionsDistinct rightPositive leftPositive equal.symm).elim
    · rfl
  have sourceSlotSum :
      (∑ input ∈ positiveSlots,
        nativeValue (openingAt openings (projectPosition packed input.val))) =
      ∑ input ∈ positiveSlots, inputSlotNative statement packed input := by
    apply Finset.sum_congr rfl
    intro input member
    have positive := (Finset.mem_filter.mp member).2
    have value := slotValue input
    simp only [if_pos positive] at value
    exact value.symm
  have imageSum :
      (∑ position ∈ positivePositions,
        nativeValue (openingAt openings position)) =
      ∑ input ∈ positiveSlots,
        nativeValue (openingAt openings (projectPosition packed input.val)) := by
    dsimp only [positivePositions]
    exact Finset.sum_image
      (f := fun position => nativeValue (openingAt openings position))
      (s := positiveSlots)
      (g := fun input : Fin 2 => projectPosition packed input.val)
      injectiveOn
  exact imageSum.trans sourceSlotSum

theorem input_native_eq_positive_source_position_sum
    {preamble : Statement} {typed : V8PublicStatement}
    (run : DesignatedCurrentWitness preamble typed)
    {parent : FrontierState} (openings : List V8NoteOpening)
    (canonicalOpenings : ∀ opening ∈ openings,
      ExactWords 18 (exactV8NoteWords opening))
    (replay : NativeReplay parent (openings.map exactV8NoteCommitment))
    (admitted : publicAnchor (encodePublicStatement typed) ∈ parent.history)
    (noCollision : ∀ input : Fin 2,
      0 < inputSlotNative typed (designatedInputPacked run) input →
      ¬ CurrentInputPathCollision run openings input) :
    inputNative typed (designatedInputPacked run) =
      ∑ position ∈ positiveDesignatedInputPositions run,
        nativeValue (openingAt openings position) := by
  classical
  have slotValue : ∀ input : Fin 2,
      inputSlotNative typed (designatedInputPacked run) input =
        if 0 < inputSlotNative typed (designatedInputPacked run) input then
          nativeValue (openingAt openings (projectPosition
            (designatedInputPacked run) input.val)) else 0 := by
    intro input
    simpa only [designatedInputPosition] using
      designated_input_slot_value run openings canonicalOpenings replay
        admitted noCollision input
  have positivePositionsDistinct
      (leftPositive : 0 < inputSlotNative typed (designatedInputPacked run) 0)
      (rightPositive : 0 < inputSlotNative typed (designatedInputPacked run) 1) :
      projectPosition (designatedInputPacked run) 0 ≠
        projectPosition (designatedInputPacked run) 1 := by
    rcases current_positive_input_positions_distinct_or_path_collision run openings
        canonicalOpenings replay admitted leftPositive rightPositive with
      positions | leftCollision | rightCollision
    · exact positions
    · exact False.elim (noCollision 0 leftPositive leftCollision)
    · exact False.elim (noCollision 1 rightPositive rightCollision)
  change inputNative typed (designatedInputPacked run) =
    ∑ position ∈
      ((Finset.univ.filter (fun input : Fin 2 =>
          0 < inputSlotNative typed (designatedInputPacked run) input)).image
        (fun input => projectPosition (designatedInputPacked run) input.val)),
      nativeValue (openingAt openings position)
  calc
    inputNative typed (designatedInputPacked run) =
        inputSlotNative typed (designatedInputPacked run) 0 +
          inputSlotNative typed (designatedInputPacked run) 1 :=
      input_native_two_slots typed (designatedInputPacked run)
    _ = ∑ input ∈ Finset.univ.filter (fun input : Fin 2 =>
        0 < inputSlotNative typed (designatedInputPacked run) input),
        inputSlotNative typed (designatedInputPacked run) input :=
      (sum_positive_fin_two
        (fun input => inputSlotNative typed (designatedInputPacked run) input)).symm
    _ = ∑ position ∈
        ((Finset.univ.filter (fun input : Fin 2 =>
            0 < inputSlotNative typed (designatedInputPacked run) input)).image
          (fun input => projectPosition (designatedInputPacked run) input.val)),
        nativeValue (openingAt openings position) :=
      (input_native_sum_of_slot_positions typed
        (designatedInputPacked run) openings slotValue positivePositionsDistinct).symm

end HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness
