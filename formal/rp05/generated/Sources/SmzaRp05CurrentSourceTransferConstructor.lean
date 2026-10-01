import SmzaRp05CurrentSourceLedgerPrefix
import SmzaRp05CurrentSourceLedgerTransitions
import SmzaRp05CurrentInputSlotUniqueness
import SmzaRp05CurrentFiniteLedgerHistory
import SmzaRp05CurrentOutputLedgerPositions
import SmzaRp05FinalSupplySoundness
import SmzaRp05SupplyClosureHistoricalInputs
import SmzaRp05CurrentPublicStatementTransport

/-! # Source-shaped finite-ledger transfer constructor

This module turns the exact designated current run and its appended output
stream into the finite-ledger `Transfer` action. The later constructor proof
uses the replay-produced prefix carrier and the source's per-input binding
outcomes; it does not add a private balance-availability gate.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceTransferConstructor

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
  (CurrentSourceLedgerPrefix stagedOpenings_length_le openingAt_stagedPrefix)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
open HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness
open HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteLedgerHistory
open HegemonCrypto.SmallWood.SmzaRp05CurrentOutputLedgerPositions
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs
  (outputOpenings)
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
  (openingAt)
open SmzaFiniteLedgerSupply
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
  (inputSlotNative input_native_two_slots active_input_slot_native
    positive_input_slot_active)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (projectPosition projectNote)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs (publicAnchor)
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
  (rustV8SemanticPrimitives)
open SmzaQ38Recovery (packedFromRows)
open HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness (inputNative outputNative)

set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 0

noncomputable section

attribute [local irreducible]
  packedFromRows
  SmzaRp05GeneratedCertificates.currentDsl
  SmzaRp05RelationRefinement.candidate
  SmzaRp05Components.program
  rustV8SemanticPrimitives
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
  exactV8NoteWords
  exactV8NoteCommitment
  nativeValue
  inputValueForAsset
  outputValueForAsset
  HegemonCrypto.SmallWood.SmzaRp05BalanceCore.projectTypedWitness

/-- The fixed registry extends the parent snapshot to the replay's staged
frontier before assigning this transfer's appended output positions. -/
def currentSourceRegistry (ledgerPrefix : CurrentSourceLedgerPrefix)
    (added future : List V8NoteOpening) : Nat → V8NoteOpening :=
  fun id => openingAt (ledgerPrefix.stagedOpenings ++ added ++ future) id

/-- Construct the exact transfer view from the designated decoded rows.
Inputs are the positive active source positions; outputs are the fresh global
positions assigned to the actual flattened output-opening stream. Both
opening functions are views into the same global registry. -/
def currentSourceTransfer {preamble : SmzaRp05StatementNamespace.Statement}
    {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed)
    (future : List V8NoteOpening) : Transfer :=
  let added := outputOpenings (encodePublicStatement typed) (designatedInputPacked run)
  let registry := currentSourceRegistry ledgerPrefix added future
  {
    statement := typed
    packedWitness := designatedInputPacked run
    inputs := positiveDesignatedInputPositions run
    outputs := appendedOutputIds ledgerPrefix.stagedOpenings added
    inputOpening := registry
    outputOpening := registry
  }

/-- One source-resolved binding per positive input position, in the exact
named ledger-history carrier used by accepted replay. This is intentionally
per slot, not an aggregate native-availability assumption. -/
def CurrentSuccessfulInputBindings
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed)
    (_admitted : publicAnchor (encodePublicStatement typed) ∈
      ledgerPrefix.snapshot.parent.history) : Prop :=
  ∀ input : Fin 2,
    (positive : 0 < inputSlotNative typed (designatedInputPacked run) input) →
      CurrentInputLedgerBinding ledgerPrefix run input

private theorem designated_packed_eq_source_packed
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) :
    designatedInputPacked run = sourcePacked run := by
  change packedFromRows run.source.data = packedFromRows run.source.data
  rfl

private theorem designated_position_eq_source_position
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2) :
    designatedInputPosition run input =
      projectPosition (sourcePacked run) input.val := by
  change projectPosition (packedFromRows run.source.data) input.val =
    projectPosition (packedFromRows run.source.data) input.val
  rfl

attribute [local irreducible]
  designatedInputPacked designatedInputPosition inputNative outputNative inputSlotNative projectNote
  currentWitness
  HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness.typedWitness

private theorem opening_at_prefix_offset
    (prior added future : List V8NoteOpening) (position : Nat)
    (occupied : position < prior.length) :
    openingAt prior position = openingAt (prior ++ added ++ future) position := by
  have registryEq : prior ++ added ++ future = prior ++ (added ++ future) := by
    simp only [List.append_assoc]
  have fullBound : position < (prior ++ (added ++ future)).length := by
    simp only [List.length_append]
    omega
  rw [registryEq]
  simp only [openingAt, if_pos occupied, if_pos fullBound]
  rw [List.getD_append _ _ _ _ occupied]

private theorem sum_positive_fin_two_local (f : Fin 2 → Nat) :
    (∑ input ∈ Finset.univ.filter (fun input => 0 < f input), f input) =
      f 0 + f 1 := by
  classical
  simp only [Finset.sum_filter, Fin.sum_univ_two]
  split_ifs <;> omega

private theorem sum_positive_fin_two_values (f g : Fin 2 → Nat)
    (h : ∀ input, 0 < f input → f input = g input) :
    f 0 + f 1 =
      (∑ input ∈ Finset.univ.filter (fun input => 0 < f input), g input) := by
  classical
  calc
    f 0 + f 1 =
        ∑ input ∈ Finset.univ.filter (fun input => 0 < f input), f input :=
      (sum_positive_fin_two_local f).symm
    _ = ∑ input ∈ Finset.univ.filter (fun input => 0 < f input), g input := by
      apply Finset.sum_congr rfl
      intro input member
      have positive : 0 < f input := (Finset.mem_filter.mp member).2
      exact h input positive

private theorem fin_two_injective_of_distinct (g : Fin 2 → Nat)
    (distinct : g 0 ≠ g 1) : Function.Injective g := by
  intro a b equal
  fin_cases a <;> fin_cases b
  · rfl
  · exact (distinct equal).elim
  · exact (distinct equal.symm).elim
  · rfl

private theorem fin_two_injOn_of_inactive (f g : Fin 2 → Nat)
    (inactive : ¬ 0 < f 0 ∨ ¬ 0 < f 1) :
    Set.InjOn g (Finset.univ.filter (fun i => 0 < f i)) := by
  intro a aMember b bMember _equal
  have aPositive := (Finset.mem_filter.mp aMember).2
  have bPositive := (Finset.mem_filter.mp bMember).2
  rcases inactive with inactive | inactive
  · fin_cases a <;> fin_cases b
    · rfl
    · exact (inactive aPositive).elim
    · exact (inactive bPositive).elim
    · rfl
  · fin_cases a <;> fin_cases b
    · rfl
    · exact (inactive bPositive).elim
    · exact (inactive aPositive).elim
    · rfl

private theorem transfer_step_of_fields
    {program : Hegemon.Transaction.Poseidon2V8RelationProgram.RelationProgramComponents}
    {primitives : V8SemanticPrimitives}
    (registry : Nat → V8NoteOpening) (state : Ledger) (tx : Transfer)
    (canonical : CanonicalPublicStatement primitives tx.statement)
    (accepted : program.AcceptsPacked (encodePublicStatement tx.statement) tx.packed)
    (historical : tx.inputs ⊆ state.live ∪ state.spent)
    (fresh : Disjoint tx.inputs state.spent)
    (inputFrames : ∀ id ∈ tx.inputs,
      exactV8NoteCommitment (tx.inputOpening id) = exactV8NoteCommitment (registry id))
    (outputFrames : ∀ id ∈ tx.outputs,
      exactV8NoteCommitment (tx.outputOpening id) = exactV8NoteCommitment (registry id))
    (inputRealization : (∑ id ∈ tx.inputs, nativeValue (tx.inputOpening id)) =
      inputValueForAsset (currentWitness tx) nativeAssetId)
    (outputRealization : (∑ id ∈ tx.outputs, nativeValue (tx.outputOpening id)) =
      outputValueForAsset (currentWitness tx) nativeAssetId) :
    CurrentProtocolStep (program := program) (primitives := primitives)
      registry state (.transfer tx) (applyTransfer state tx) := by
  exact CurrentProtocolStep.transfer (program := program) (primitives := primitives)
    (registry := registry) state tx canonical accepted historical fresh
    inputFrames outputFrames inputRealization outputRealization

private theorem typed_input_native_identity
    (statement : V8PublicStatement) (packed : List Nat) :
    inputNative statement packed =
      inputValueForAsset
        (SmzaRp05BalanceCore.projectTypedWitness statement packed) nativeAssetId := by
  unfold inputNative HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness.typedWitness
  rfl

private theorem typed_output_native_identity
    (statement : V8PublicStatement) (packed : List Nat) :
    outputNative statement packed =
      outputValueForAsset
        (SmzaRp05BalanceCore.projectTypedWitness statement packed) nativeAssetId := by
  unfold outputNative HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness.typedWitness
  rfl

private theorem canonical_public_statement_transport
    {primitives : V8SemanticPrimitives}
    {source target : V8PublicStatement}
    (statementEq : source = target)
    (canonical : CanonicalPublicStatement primitives source) :
    CanonicalPublicStatement primitives target := by
  cases statementEq
  exact canonical

private theorem accepted_packed_transport
    {program : Hegemon.Transaction.Poseidon2V8RelationProgram.RelationProgramComponents}
    {sourceStatement targetStatement : V8PublicStatement}
    {sourcePacked targetPacked : List Nat}
    (statementEq : sourceStatement = targetStatement)
    (packedEq : sourcePacked = targetPacked)
    (accepted : program.AcceptsPacked
      (encodePublicStatement sourceStatement) sourcePacked) :
    program.AcceptsPacked (encodePublicStatement targetStatement) targetPacked := by
  cases statementEq
  cases packedEq
  exact accepted

private theorem transfer_witness_transport
    (tx : Transfer) (statement : V8PublicStatement) (packed : List Nat)
    (statementEq : tx.statement = statement) (packedEq : tx.packed = packed) :
    currentWitness tx =
      SmzaRp05BalanceCore.projectTypedWitness statement packed := by
  unfold currentWitness
  rw [statementEq, packedEq]

private theorem transfer_input_native_transport
    (tx : Transfer) (statement : V8PublicStatement) (packed : List Nat)
    (statementEq : tx.statement = statement) (packedEq : tx.packed = packed) :
    inputNative statement packed =
      inputValueForAsset (currentWitness tx) nativeAssetId := by
  rw [transfer_witness_transport tx statement packed statementEq packedEq]
  exact typed_input_native_identity statement packed

private theorem transfer_output_native_transport
    (tx : Transfer) (statement : V8PublicStatement) (packed : List Nat)
    (statementEq : tx.statement = statement) (packedEq : tx.packed = packed) :
    outputNative statement packed =
      outputValueForAsset (currentWitness tx) nativeAssetId := by
  rw [transfer_witness_transport tx statement packed statementEq packedEq]
  exact typed_output_native_identity statement packed

/-- Successful per-input history bindings produce the concrete current
finite-ledger transfer step. If source-level duplicate-position resolution
returns its explicit canonical path-collision arm, that charged evidence is
returned instead; the caller routes it outside the ledger-step branch. -/
private theorem current_source_transfer_step_of_successful_bindings_core
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed)
    (future : List V8NoteOpening)
    (added : List V8NoteOpening)
    (registry : Nat → V8NoteOpening)
    (tx : Transfer)
    (addedEq : added = outputOpenings (encodePublicStatement typed)
      (designatedInputPacked run))
    (registryEq : registry = currentSourceRegistry ledgerPrefix added future)
    (txInputs : tx.inputs = positiveDesignatedInputPositions run)
    (txOutputs : tx.outputs = appendedOutputIds ledgerPrefix.stagedOpenings added)
    (txStatement : tx.statement = typed)
    (txPacked : tx.packed = designatedInputPacked run)
    (txInputOpening : tx.inputOpening = registry)
    (txOutputOpening : tx.outputOpening = registry)
    (admitted : publicAnchor (encodePublicStatement typed) ∈
      ledgerPrefix.snapshot.parent.history)
    (bindings : CurrentSuccessfulInputBindings ledgerPrefix run admitted) :
    CurrentProtocolStep (program := HegemonCrypto.SmallWood.SmzaRp05Components.program)
      (primitives := rustV8SemanticPrimitives)
      registry ledgerPrefix.ledger (.transfer tx) (applyTransfer ledgerPrefix.ledger tx) ∨
    (∃ _leftPositive : 0 < inputSlotNative typed (designatedInputPacked run) 0,
      ∃ _rightPositive : 0 < inputSlotNative typed (designatedInputPacked run) 1,
        HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
            run ledgerPrefix.snapshot.openings 0 ∨
          HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
            run ledgerPrefix.snapshot.openings 1) := by
  classical
  have accepted :
      CanonicalPublicStatement rustV8SemanticPrimitives typed ∧
        HegemonCrypto.SmallWood.SmzaRp05Components.program.AcceptsPacked
          (encodePublicStatement typed) (sourcePacked run) :=
    HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions.source_run_accepted
      (preamble := preamble) (typed := typed) run
  have canonical :
      CanonicalPublicStatement rustV8SemanticPrimitives typed := accepted.1
  have acceptedPacked :
      HegemonCrypto.SmallWood.SmzaRp05Components.program.AcceptsPacked
        (encodePublicStatement typed) (designatedInputPacked run) := by
    exact accepted_packed_transport
      (program := HegemonCrypto.SmallWood.SmzaRp05Components.program)
      (sourceStatement := typed) (targetStatement := typed)
      (sourcePacked := sourcePacked run)
      (targetPacked := designatedInputPacked run)
      rfl (designated_packed_eq_source_packed run).symm accepted.2
  have inputValueBySlots :
      (inputNative typed (designatedInputPacked run)) =
        ∑ input ∈ positiveDesignatedInputSlots run,
          nativeValue (openingAt ledgerPrefix.snapshot.openings
            (designatedInputPosition run input)) := by
    as_aux_lemma =>
      have slotValue (input : Fin 2)
          (positive : 0 < inputSlotNative typed (designatedInputPacked run) input) :
          inputSlotNative typed (designatedInputPacked run) input =
            nativeValue (openingAt ledgerPrefix.snapshot.openings
              (designatedInputPosition run input)) := by
        have binding := bindings input positive
        have active := positive_input_slot_active typed
          (designatedInputPacked run) input positive
        have noteWords : exactV8NoteWords
            (projectNote (designatedInputPacked run)
              (HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate.noteCall input)) =
            exactV8NoteWords (openingAt ledgerPrefix.snapshot.openings
              (designatedInputPosition run input)) := by
          rw [designated_packed_eq_source_packed run,
            designated_position_eq_source_position run input]
          exact binding.2.1
        exact (active_input_slot_native typed (designatedInputPacked run) input active).trans
          (SmzaFiniteLedgerSupply.note_words_preserve_native noteWords)
      calc
        inputNative typed (designatedInputPacked run) =
            inputSlotNative typed (designatedInputPacked run) 0 +
              inputSlotNative typed (designatedInputPacked run) 1 :=
          input_native_two_slots typed (designatedInputPacked run)
        _ = ∑ input ∈ positiveDesignatedInputSlots run,
            nativeValue (openingAt ledgerPrefix.snapshot.openings
              (designatedInputPosition run input)) := by
          simpa only [positiveDesignatedInputSlots] using
            sum_positive_fin_two_values
              (fun input => inputSlotNative typed (designatedInputPacked run) input)
              (fun input => nativeValue (openingAt ledgerPrefix.snapshot.openings
                (designatedInputPosition run input))) slotValue
  have injectiveOrCollision :
      Set.InjOn (designatedInputPosition run) (positiveDesignatedInputSlots run) ∨
      (∃ _leftPositive : 0 < inputSlotNative typed (designatedInputPacked run) 0,
        ∃ _rightPositive : 0 < inputSlotNative typed (designatedInputPacked run) 1,
          HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
              run ledgerPrefix.snapshot.openings 0 ∨
            HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
              run ledgerPrefix.snapshot.openings 1) := by
    as_aux_lemma =>
      by_cases leftPositive :
          0 < inputSlotNative typed (designatedInputPacked run) 0
      · by_cases rightPositive :
            0 < inputSlotNative typed (designatedInputPacked run) 1
        · cases current_positive_input_positions_distinct_or_path_collision
              run ledgerPrefix.snapshot.openings ledgerPrefix.snapshot.canonical
              ledgerPrefix.snapshot.replay admitted leftPositive rightPositive with
            | inl distinct =>
                left
                exact fun _ _ _ _ equal =>
                  fin_two_injective_of_distinct (designatedInputPosition run) distinct equal
            | inr failures =>
                cases failures with
                | inl leftCollision =>
                    right
                    exact ⟨leftPositive, rightPositive, Or.inl leftCollision⟩
                | inr rightCollision =>
                    right
                    exact ⟨leftPositive, rightPositive, Or.inr rightCollision⟩
        · left
          exact fin_two_injOn_of_inactive
            (fun input => inputSlotNative typed (designatedInputPacked run) input)
            (designatedInputPosition run) (Or.inr rightPositive)
      · by_cases rightPositive :
            0 < inputSlotNative typed (designatedInputPacked run) 1
        · left
          exact fin_two_injOn_of_inactive
            (fun input => inputSlotNative typed (designatedInputPacked run) input)
            (designatedInputPosition run) (Or.inl leftPositive)
        · left
          exact fin_two_injOn_of_inactive
            (fun input => inputSlotNative typed (designatedInputPacked run) input)
            (designatedInputPosition run) (Or.inl leftPositive)
  rcases injectiveOrCollision with injectiveOn | slotCollision
  · have inputImageSum :
        (∑ position ∈ positiveDesignatedInputPositions run,
          nativeValue (openingAt ledgerPrefix.snapshot.openings position)) =
          inputNative typed (designatedInputPacked run) := by
      as_aux_lemma =>
        calc
          (∑ position ∈ positiveDesignatedInputPositions run,
            nativeValue (openingAt ledgerPrefix.snapshot.openings position)) =
              ∑ input ∈ positiveDesignatedInputSlots run,
                nativeValue (openingAt ledgerPrefix.snapshot.openings
                  (designatedInputPosition run input)) := by
            unfold positiveDesignatedInputPositions
            exact Finset.sum_image
              (f := fun position =>
                nativeValue (openingAt ledgerPrefix.snapshot.openings position))
              (s := positiveDesignatedInputSlots run)
              (g := designatedInputPosition run) injectiveOn
          _ = inputNative typed (designatedInputPacked run) := inputValueBySlots.symm
    have inputToRegistry :
        (∑ position ∈ positiveDesignatedInputPositions run,
          nativeValue (openingAt ledgerPrefix.snapshot.openings position)) =
          ∑ position ∈ positiveDesignatedInputPositions run,
            nativeValue (registry position) := by
      as_aux_lemma =>
        apply Finset.sum_congr rfl
        intro position member
        have member' : position ∈
            (positiveDesignatedInputSlots run).image (designatedInputPosition run) := by
          simpa only [positiveDesignatedInputPositions] using member
        rcases Finset.mem_image.mp member' with ⟨input, slotMember, positionEq⟩
        have positive := (Finset.mem_filter.mp slotMember).2
        have binding := bindings input positive
        have inputBound : designatedInputPosition run input <
            ledgerPrefix.snapshot.openings.length := by
          rw [designated_position_eq_source_position run input]
          exact binding.1
        have stagedBound : designatedInputPosition run input <
            ledgerPrefix.stagedOpenings.length :=
          lt_of_lt_of_le inputBound (stagedOpenings_length_le ledgerPrefix)
        rw [← positionEq]
        change nativeValue (openingAt ledgerPrefix.snapshot.openings
            (designatedInputPosition run input)) =
          nativeValue (registry (designatedInputPosition run input))
        rw [registryEq]
        unfold currentSourceRegistry
        exact congrArg nativeValue
          ((openingAt_stagedPrefix ledgerPrefix (designatedInputPosition run input) inputBound).trans
            (opening_at_prefix_offset ledgerPrefix.stagedOpenings added future
              (designatedInputPosition run input) stagedBound))
    have historical : tx.inputs ⊆ ledgerPrefix.ledger.live ∪ ledgerPrefix.ledger.spent := by
      as_aux_lemma =>
        intro position member
        have member' : position ∈ positiveDesignatedInputPositions run := by
          rw [txInputs] at member
          exact member
        have imageMember : position ∈
            (positiveDesignatedInputSlots run).image (designatedInputPosition run) := by
          simpa only [positiveDesignatedInputPositions] using member'
        rcases Finset.mem_image.mp imageMember
          with ⟨input, slotMember, positionEq⟩
        have positive := (Finset.mem_filter.mp slotMember).2
        have binding := bindings input positive
        have inRange : designatedInputPosition run input ∈
            Finset.range ledgerPrefix.stagedOpenings.length := by
          apply Finset.mem_range.mpr
          have bound : designatedInputPosition run input < ledgerPrefix.snapshot.openings.length := by
            rw [designated_position_eq_source_position run input]
            exact binding.1
          exact lt_of_lt_of_le bound (stagedOpenings_length_le ledgerPrefix)
        have inLiveOrSpent : designatedInputPosition run input ∈
            ledgerPrefix.ledger.live ∪ ledgerPrefix.ledger.spent := by
          rw [ledgerPrefix.liveCoverage]
          by_cases inSpent : designatedInputPosition run input ∈ ledgerPrefix.ledger.spent
          · exact Finset.mem_union_right _ inSpent
          · exact Finset.mem_union_left _ (Finset.mem_sdiff.mpr ⟨inRange, inSpent⟩)
        exact positionEq ▸ inLiveOrSpent
    have fresh : Disjoint tx.inputs ledgerPrefix.ledger.spent := by
      as_aux_lemma =>
        rw [Finset.disjoint_left]
        intro position positionInput positionSpent
        have member' : position ∈ positiveDesignatedInputPositions run := by
          rw [txInputs] at positionInput
          exact positionInput
        have imageMember : position ∈
            (positiveDesignatedInputSlots run).image (designatedInputPosition run) := by
          simpa only [positiveDesignatedInputPositions] using member'
        rcases Finset.mem_image.mp imageMember
          with ⟨input, slotMember, positionEq⟩
        have positive := (Finset.mem_filter.mp slotMember).2
        have binding := bindings input positive
        have notSpent : designatedInputPosition run input ∉ ledgerPrefix.ledger.spent := by
          rw [designated_position_eq_source_position run input]
          exact binding.2.2
        exact notSpent (positionEq.symm ▸ positionSpent)
    have inputFrames : ∀ id ∈ tx.inputs,
        exactV8NoteCommitment (tx.inputOpening id) =
          exactV8NoteCommitment (registry id) := by
      as_aux_lemma =>
        intro id _
        rw [txInputOpening]
    have outputFrames : ∀ id ∈ tx.outputs,
        exactV8NoteCommitment (tx.outputOpening id) =
          exactV8NoteCommitment (registry id) := by
      as_aux_lemma =>
        intro id _
        rw [txOutputOpening]
    have inputRealization :
        (∑ id ∈ tx.inputs, nativeValue (tx.inputOpening id)) =
          inputValueForAsset (currentWitness tx) nativeAssetId := by
      as_aux_lemma =>
        calc
          (∑ id ∈ tx.inputs, nativeValue (tx.inputOpening id)) =
              ∑ id ∈ positiveDesignatedInputPositions run,
                nativeValue (registry id) := by
            rw [txInputs, txInputOpening]
          _ = inputNative typed (designatedInputPacked run) :=
            inputToRegistry.symm.trans inputImageSum
          _ = inputValueForAsset (currentWitness tx) nativeAssetId := by
            exact transfer_input_native_transport tx typed
              (designatedInputPacked run) txStatement txPacked
    have outputRealization :
        (∑ id ∈ tx.outputs, nativeValue (tx.outputOpening id)) =
          outputValueForAsset (currentWitness tx) nativeAssetId := by
      as_aux_lemma =>
        calc
          (∑ id ∈ tx.outputs, nativeValue (tx.outputOpening id)) =
              (added.map nativeValue).sum := by
            rw [txOutputs, txOutputOpening, registryEq]
            unfold currentSourceRegistry
            exact appended_output_native_sum ledgerPrefix.stagedOpenings added future
          _ = outputNative typed (designatedInputPacked run) := by
            rw [addedEq]
            exact current_accepted_output_stream_native typed
              (designatedInputPacked run) canonical
          _ = outputValueForAsset (currentWitness tx) nativeAssetId := by
            exact transfer_output_native_transport tx typed
              (designatedInputPacked run) txStatement txPacked
    have canonicalForTx : CanonicalPublicStatement rustV8SemanticPrimitives tx.statement :=
      canonical_public_statement_transport txStatement.symm canonical
    have acceptedForTx : HegemonCrypto.SmallWood.SmzaRp05Components.program.AcceptsPacked
        (encodePublicStatement tx.statement) tx.packed :=
      accepted_packed_transport txStatement.symm txPacked.symm acceptedPacked
    exact Or.inl (transfer_step_of_fields
      (program := HegemonCrypto.SmallWood.SmzaRp05Components.program)
      (primitives := rustV8SemanticPrimitives) registry
      ledgerPrefix.ledger tx canonicalForTx acceptedForTx
      historical fresh inputFrames outputFrames inputRealization outputRealization)
  · exact Or.inr slotCollision

private theorem currentSourceTransfer_inputs_eq
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed) (future : List V8NoteOpening) :
    (currentSourceTransfer ledgerPrefix run future).inputs =
      positiveDesignatedInputPositions run := by
  rfl

private theorem currentSourceTransfer_outputs_eq
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed) (future : List V8NoteOpening) :
    (currentSourceTransfer ledgerPrefix run future).outputs =
      appendedOutputIds ledgerPrefix.stagedOpenings
        (outputOpenings (encodePublicStatement typed) (designatedInputPacked run)) := by
  rfl

private theorem currentSourceTransfer_statement_eq
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed) (future : List V8NoteOpening) :
    (currentSourceTransfer ledgerPrefix run future).statement = typed := by
  rfl

private theorem transfer_packed_projection (tx : Transfer) :
    tx.packed = tx.packedWitness := by
  rfl

attribute [local irreducible] Transfer.packed

private theorem currentSourceTransfer_packed_eq
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed) (future : List V8NoteOpening) :
    (currentSourceTransfer ledgerPrefix run future).packed =
      designatedInputPacked run := by
  calc
    (currentSourceTransfer ledgerPrefix run future).packed =
        (currentSourceTransfer ledgerPrefix run future).packedWitness :=
      transfer_packed_projection (currentSourceTransfer ledgerPrefix run future)
    _ = designatedInputPacked run := by rfl

private theorem currentSourceTransfer_inputOpening_eq
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed) (future : List V8NoteOpening) :
    (currentSourceTransfer ledgerPrefix run future).inputOpening =
      currentSourceRegistry ledgerPrefix
        (outputOpenings (encodePublicStatement typed) (designatedInputPacked run)) future := by
  rfl

private theorem currentSourceTransfer_outputOpening_eq
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed) (future : List V8NoteOpening) :
    (currentSourceTransfer ledgerPrefix run future).outputOpening =
      currentSourceRegistry ledgerPrefix
        (outputOpenings (encodePublicStatement typed) (designatedInputPacked run)) future := by
  rfl

/-- Public wrapper: the source-facing statement and exact constructor are
unchanged; only its private proof core consumes the constructor identities. -/
theorem current_source_transfer_step_of_successful_bindings
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed)
    (future : List V8NoteOpening)
    (admitted : publicAnchor (encodePublicStatement typed) ∈
      ledgerPrefix.snapshot.parent.history)
    (bindings : CurrentSuccessfulInputBindings ledgerPrefix run admitted) :
    CurrentProtocolStep (program := HegemonCrypto.SmallWood.SmzaRp05Components.program)
      (primitives := rustV8SemanticPrimitives)
      (currentSourceRegistry ledgerPrefix
        (outputOpenings (encodePublicStatement typed) (designatedInputPacked run)) future)
      ledgerPrefix.ledger (.transfer (currentSourceTransfer ledgerPrefix run future))
      (applyTransfer ledgerPrefix.ledger
        (currentSourceTransfer ledgerPrefix run future)) ∨
    (∃ _leftPositive : 0 < inputSlotNative typed (designatedInputPacked run) 0,
      ∃ _rightPositive : 0 < inputSlotNative typed (designatedInputPacked run) 1,
        HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
            run ledgerPrefix.snapshot.openings 0 ∨
          HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
            run ledgerPrefix.snapshot.openings 1) := by
  classical
  have coreResult := current_source_transfer_step_of_successful_bindings_core
    (preamble := preamble) (typed := typed)
    ledgerPrefix run future
    (outputOpenings (encodePublicStatement typed) (designatedInputPacked run))
    (currentSourceRegistry ledgerPrefix
      (outputOpenings (encodePublicStatement typed) (designatedInputPacked run)) future)
    (currentSourceTransfer ledgerPrefix run future)
    rfl rfl
    (currentSourceTransfer_inputs_eq ledgerPrefix run future)
    (currentSourceTransfer_outputs_eq ledgerPrefix run future)
    (currentSourceTransfer_statement_eq ledgerPrefix run future)
    (currentSourceTransfer_packed_eq ledgerPrefix run future)
    (currentSourceTransfer_inputOpening_eq ledgerPrefix run future)
    (currentSourceTransfer_outputOpening_eq ledgerPrefix run future)
    admitted bindings
  exact coreResult

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceTransferConstructor
