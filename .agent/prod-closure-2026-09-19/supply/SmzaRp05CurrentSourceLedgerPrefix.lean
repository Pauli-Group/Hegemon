import SmzaRp05ActualAcceptedAuthorizationEndpoint
import SmzaRp05NativeFrontierModel
import SmzaRp05HistoricalTree
import SmzaRp05SupplyClosureInputNative
import SmzaRp05SupplyClosureDistinctInputs
import SmzaRp05CurrentPublicStatementTransport
import SmzaRp05SupplyClosureHistoricalInputs
import FiniteLedgerSupplyR8

/-! # Current source ledger prefix carrier

This module contains the small shared data boundary for the current
source-shaped finite ledger replay.  The prefix equations are proof fields
which the recursive replay constructs from its empty initial state and each
validated source transition; they are not admission inputs or runtime gates.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open SmzaFiniteLedgerSupply
open SmzaQ38Recovery (packedFromRows)
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false

noncomputable section

abbrev CurrentSourceRun (preamble : Statement) (typed : V8PublicStatement) :=
  DesignatedCurrentWitness preamble typed

def sourcePacked {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) : List Nat :=
  packedFromRows run.source.data

attribute [local irreducible] sourcePacked packedFromRows

structure CurrentNativeSnapshot where
  parent : FrontierState
  openings : List V8NoteOpening
  canonical : ∀ opening ∈ openings, ExactWords 18 (exactV8NoteWords opening)
  replay : NativeReplay parent (openings.map exactV8NoteCommitment)

structure CurrentSourceSpend where
  preamble : Statement
  typed : V8PublicStatement
  run : CurrentSourceRun preamble typed
  input : Fin 2
  positive : 0 < inputSlotNative typed (sourcePacked run) input
  snapshot : CurrentNativeSnapshot
  admitted : publicAnchor (encodePublicStatement typed) ∈ snapshot.parent.history

def CurrentSourceSpend.position (spend : CurrentSourceSpend) : Nat :=
  projectPosition (sourcePacked spend.run) spend.input.val

def CurrentSourceSpend.nullifier (spend : CurrentSourceSpend) : Digest :=
  publicNullifier (encodePublicStatement spend.typed) spend.input

attribute [local irreducible]
  CurrentSourceSpend.position
  CurrentSourceSpend.nullifier

theorem CurrentSourceSpend.position_eq (spend : CurrentSourceSpend) :
    spend.position = projectPosition (sourcePacked spend.run) spend.input.val := by
  unfold CurrentSourceSpend.position
  rfl

def sourceSpendsOfRun {preamble : Statement} {typed : V8PublicStatement}
    (snapshot : CurrentNativeSnapshot) (run : CurrentSourceRun preamble typed)
    (admitted : publicAnchor (encodePublicStatement typed) ∈ snapshot.parent.history) :
    List CurrentSourceSpend :=
  (List.finRange 2).filterMap fun input =>
    if positive : 0 < inputSlotNative typed (sourcePacked run) input then
      some ⟨preamble, typed, run, input, positive, snapshot, admitted⟩
    else none

def sourceRunNullifiers {preamble : Statement} {typed : V8PublicStatement}
    (_run : CurrentSourceRun preamble typed) : List Digest :=
  (List.finRange 2).filterMap fun input =>
    if (encodePublicStatement typed).getD input.val 0 = 1 then
      some (publicNullifier (encodePublicStatement typed) input)
    else none

def sourceNullifiersFresh (spent : List Digest) {preamble : Statement}
    {typed : V8PublicStatement} (run : CurrentSourceRun preamble typed) : Bool :=
  (sourceRunNullifiers run).Nodup &&
    (sourceRunNullifiers run).all (fun value => spent.contains value = false)

/-! The fields below express invariants of the recursive source replay.  In
particular, no transition constructor accepts these facts from an external
caller: the genesis constructor establishes the empty case, and the replay
induction proves each update preserves them. -/
structure CurrentSourceLedgerPrefix where
  snapshot : CurrentNativeSnapshot
  /-- Ledger registry after any earlier transactions staged by the current
  block.  It may extend the parent's native snapshot with already accepted
  outputs; those outputs are live in the finite ledger but are not admitted
  as inputs against the parent anchor until a later block. -/
  stagedOpenings : List V8NoteOpening
  stagedPrefix : snapshot.openings.IsPrefix stagedOpenings
  ledger : Ledger
  priorSpends : List CurrentSourceSpend
  spentNullifiers : List Digest
  liveCoverage : ledger.live = Finset.range stagedOpenings.length \ ledger.spent
  /-- Every previously spent position is in the concrete staged opening
  registry.  This is a replay invariant, not an admission test. -/
  spentInStagedRange : ledger.spent ⊆ Finset.range stagedOpenings.length
  spentExact : ledger.spent =
    (priorSpends.map CurrentSourceSpend.position).toFinset
  priorPrefix : ∀ spend ∈ priorSpends,
    spend.snapshot.openings.IsPrefix snapshot.openings
  priorRegistered : ∀ spend ∈ priorSpends,
    spend.nullifier ∈ spentNullifiers

def initialCurrentSourceLedgerPrefix : CurrentSourceLedgerPrefix where
  snapshot := {
    parent := newEmpty
    openings := []
    canonical := by simp
    replay := NativeReplay.start
  }
  stagedOpenings := []
  stagedPrefix := ⟨[], by simp⟩
  ledger := { live := ∅, spent := ∅, feeEscrow := 0, issuedHeights := ∅ }
  priorSpends := []
  spentNullifiers := []
  liveCoverage := by simp
  spentInStagedRange := by simp
  spentExact := by simp
  priorPrefix := by simp
  priorRegistered := by simp

theorem stagedOpenings_length_le (ledgerPrefix : CurrentSourceLedgerPrefix) :
    ledgerPrefix.snapshot.openings.length ≤ ledgerPrefix.stagedOpenings.length := by
  obtain ⟨suffix, suffixEq⟩ := ledgerPrefix.stagedPrefix
  rw [← suffixEq]
  simp only [List.length_append]
  omega

theorem openingAt_stagedPrefix (ledgerPrefix : CurrentSourceLedgerPrefix)
    (position : Nat) (occupied : position < ledgerPrefix.snapshot.openings.length) :
    openingAt ledgerPrefix.snapshot.openings position =
      openingAt ledgerPrefix.stagedOpenings position := by
  obtain ⟨suffix, suffixEq⟩ := ledgerPrefix.stagedPrefix
  have stagedEq : ledgerPrefix.stagedOpenings =
      ledgerPrefix.snapshot.openings ++ suffix := suffixEq.symm
  have fullBound : position < (ledgerPrefix.snapshot.openings ++ suffix).length := by
    simp only [List.length_append]
    omega
  rw [stagedEq]
  simp only [openingAt, if_pos occupied, if_pos fullBound]
  rw [List.getD_append _ _ _ _ occupied]

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
