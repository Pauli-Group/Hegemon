import HegemonCrypto.SmallWoodV8Smz9SemanticBalance
import LifetimeIssuanceR2
import Hegemon.Consensus.AcceptedSmallWoodBlockComposition
import Mathlib.Algebra.BigOperators.Group.Finset.Basic
import Mathlib.Data.Real.Basic

set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 2000000

open scoped BigOperators
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open Hegemon.Consensus

namespace SmzaFiniteLedgerSupply
noncomputable section
attribute [local instance] Classical.propDecidable

def nativeValue (note : V8NoteOpening) : Nat :=
  if note.assetId = nativeAssetId then note.value else 0

def wealth (registry : Nat → V8NoteOpening) (ids : Finset Nat) : Nat :=
  ∑ id ∈ ids, nativeValue (registry id)

structure Ledger where
  live : Finset Nat
  spent : Finset Nat
  feeEscrow : Nat
  issuedHeights : Finset Nat

def potential (registry : Nat → V8NoteOpening) (state : Ledger) : Nat :=
  wealth registry state.live + state.feeEscrow

def allowance (state : Ledger) : Nat :=
  ∑ height ∈ state.issuedHeights, blockSubsidy height

structure Transfer where
  statement : V8PublicStatement
  packedWitness : List Nat
  inputs : Finset Nat
  outputs : Finset Nat
  inputOpening : Nat → V8NoteOpening
  outputOpening : Nat → V8NoteOpening

def Transfer.packed (tx : Transfer) : List Nat := tx.packedWitness
def Transfer.witness (tx : Transfer) : V8Witness :=
  projectTypedWitness tx.statement tx.packed

-- Exact packed-candidate failure event, not a successful extraction certificate.
-- The q38 inverse must supply packedWitness in a separate specialization; this
-- generic endpoint never silently instantiates the old q20 inverse.
def extractionFailure (tx : Transfer) : Prop :=
  ¬ hgv8rp03ProgramComponents.AcceptsPacked
      (encodePublicStatement tx.statement) tx.packed

-- A concrete collision in two complete note-word preimages of the actual
-- fixed-domain V8 sponge. No global/universal injectivity axiom is used.
def noteCollision (left right : V8NoteOpening) : Prop :=
  exactV8NoteWords left ≠ exactV8NoteWords right ∧
    exactV8NoteCommitment left = exactV8NoteCommitment right

def transferCollision (registry : Nat → V8NoteOpening) (tx : Transfer) : Prop :=
  (∃ id ∈ tx.inputs, noteCollision (tx.inputOpening id) (registry id)) ∨
  (∃ id ∈ tx.outputs, noteCollision (tx.outputOpening id) (registry id))

def applyTransfer (state : Ledger) (tx : Transfer) : Ledger :=
  { live := (state.live \ tx.inputs) ∪ (tx.outputs \ (state.spent ∪ tx.inputs))
    spent := state.spent ∪ tx.inputs
    feeEscrow := state.feeEscrow + tx.statement.fee
    issuedHeights := state.issuedHeights }

def applyCoinbase (state : Ledger) (height : Nat) (outputs : Finset Nat) : Ledger :=
  { live := state.live ∪ (outputs \ state.spent)
    spent := state.spent
    feeEscrow := 0
    issuedHeights := insert height state.issuedHeights }

def burnEscrow (state : Ledger) : Ledger := { state with feeEscrow := 0 }

inductive Action where
  | transfer (tx : Transfer)
  | coinbase (height paid : Nat) (outputs : Finset Nat)
      (opening : Nat → V8NoteOpening)
  | noCoinbase

def badExtraction : Action → Prop
  | .transfer tx => extractionFailure tx
  | _ => False

def badCollision (registry : Nat → V8NoteOpening) : Action → Prop
  | .transfer tx => transferCollision registry tx
  | .coinbase _ _ outputs opening =>
      ∃ id ∈ outputs, noteCollision (opening id) (registry id)
  | .noCoinbase => False

-- Mathematical protocol transition rules. Identity references are authenticated
-- registry positions; the separate membership/nullifier linkage reduction is
-- not silently assumed to follow from note collision resistance.
inductive ProtocolStep (registry : Nat → V8NoteOpening) :
    Ledger → Action → Ledger → Prop where
  | transfer (state : Ledger) (tx : Transfer)
      (canonical : CanonicalPublicStatement exactV8SemanticPrimitives tx.statement)
      (historical : tx.inputs ⊆ state.live ∪ state.spent)
      (fresh : Disjoint tx.inputs state.spent)
      (inputFrames : ∀ id ∈ tx.inputs,
        exactV8NoteCommitment (tx.inputOpening id) = exactV8NoteCommitment (registry id))
      (outputFrames : ∀ id ∈ tx.outputs,
        exactV8NoteCommitment (tx.outputOpening id) = exactV8NoteCommitment (registry id))
      (inputRealization : (∑ id ∈ tx.inputs, nativeValue (tx.inputOpening id)) =
        inputValueForAsset tx.witness nativeAssetId)
      (outputRealization : (∑ id ∈ tx.outputs, nativeValue (tx.outputOpening id)) =
        outputValueForAsset tx.witness nativeAssetId) :
      ProtocolStep registry state (.transfer tx) (applyTransfer state tx)
  | coinbase (state : Ledger) (height paid : Nat) (outputs : Finset Nat)
      (opening : Nat → V8NoteOpening)
      (once : height ∉ state.issuedHeights)
      (positive : 0 < height)
      (payment : nativeCoinbaseAmount height state.feeEscrow = some paid)
      (frames : ∀ id ∈ outputs,
        exactV8NoteCommitment (opening id) = exactV8NoteCommitment (registry id))
      (realization : (∑ id ∈ outputs, nativeValue (opening id)) = paid) :
      ProtocolStep registry state (.coinbase height paid outputs opening)
        (applyCoinbase state height outputs)
  | noCoinbase (state : Ledger) :
      ProtocolStep registry state .noCoinbase (burnEscrow state)

inductive Execution (registry : Nat → V8NoteOpening) :
    Ledger → List Action → Ledger → Prop where
  | nil (state : Ledger) : Execution registry state [] state
  | cons {before middle after : Ledger} {action : Action} {actions : List Action}
      (step : ProtocolStep registry before action middle)
      (rest : Execution registry middle actions after) :
      Execution registry before (action :: actions) after

theorem note_words_preserve_native {left right : V8NoteOpening}
    (same : exactV8NoteWords left = exactV8NoteWords right) :
    nativeValue left = nativeValue right := by
  have fields := List.cons.inj same
  have asset := List.cons.inj fields.2
  simp only [nativeValue, fields.1, asset.1]

theorem binding_sum {registry opening : Nat → V8NoteOpening} {ids : Finset Nat}
    (frames : ∀ id ∈ ids,
      exactV8NoteCommitment (opening id) = exactV8NoteCommitment (registry id))
    (noCollision : ¬ ∃ id ∈ ids, noteCollision (opening id) (registry id)) :
    wealth registry ids = ∑ id ∈ ids, nativeValue (opening id) := by
  apply Finset.sum_congr rfl
  intro id member
  have equalWords : exactV8NoteWords (opening id) = exactV8NoteWords (registry id) := by
    by_contra different
    exact noCollision ⟨id, member, different, frames id member⟩
  exact (note_words_preserve_native equalWords).symm

theorem extracted_native_balance (tx : Transfer)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives tx.statement)
    (success : ¬ extractionFailure tx) :
    inputValueForAsset tx.witness nativeAssetId =
      outputValueForAsset tx.witness nativeAssetId + tx.statement.fee := by
  have satisfied : hgv8rp03ProgramComponents.AcceptsPacked
      (encodePublicStatement tx.statement) tx.packed := Classical.not_not.mp success
  have domain : CanonicalPublicPackedDomain tx.statement
      (encodePublicStatement tx.statement) tx.packed :=
    ⟨rfl, canonical, satisfied⟩
  have balance := admitted_packed_project_typed_witness_balance domain 0 (by decide)
  have native := (admitted_native_slot_iff domain (slot := 0) (by decide)).mpr rfl
  rw [native] at balance
  have paddingNe : nativeAssetId ≠ balancePaddingAssetId := by
    rw [balance_padding_asset_id_eq]
    decide
  simpa only [paddingNe, false_or, if_pos rfl, ite_true, Transfer.witness] using balance

theorem wealth_union_le (registry : Nat → V8NoteOpening) (a b : Finset Nat) :
    wealth registry (a ∪ b) ≤ wealth registry a + wealth registry b := by
  have eqn := Finset.sum_union_inter (s₁ := a) (s₂ := b)
      (f := fun id => nativeValue (registry id))
  unfold wealth
  omega

theorem wealth_mono (registry : Nat → V8NoteOpening) {a b : Finset Nat}
    (subset : a ⊆ b) : wealth registry a ≤ wealth registry b := by
  exact Finset.sum_le_sum_of_subset_of_nonneg subset (by intros; exact Nat.zero_le _)

theorem historical_membership_and_freshness_give_available
    (state : Ledger) (inputs : Finset Nat)
    (historical : inputs ⊆ state.live ∪ state.spent)
    (fresh : Disjoint inputs state.spent) : inputs ⊆ state.live := by
  intro id member
  rcases Finset.mem_union.mp (historical member) with live | spent
  · exact live
  · exact False.elim ((Finset.disjoint_left.mp fresh) member spent)

theorem step_supply_invariant {registry : Nat → V8NoteOpening}
    {before after : Ledger} {action : Action} {initial : Nat}
    (step : ProtocolStep registry before action after)
    (noExtraction : ¬ badExtraction action)
    (noCollision : ¬ badCollision registry action)
    (prior : potential registry before ≤ initial + allowance before) :
    potential registry after ≤ initial + allowance after := by
  cases step with
  | transfer tx canonical historical fresh inFrames outFrames inReal outReal =>
    have available := historical_membership_and_freshness_give_available
      before tx.inputs historical fresh
    have noIn : ¬ ∃ id ∈ tx.inputs, noteCollision (tx.inputOpening id) (registry id) :=
      fun h => noCollision (Or.inl h)
    have noOut : ¬ ∃ id ∈ tx.outputs, noteCollision (tx.outputOpening id) (registry id) :=
      fun h => noCollision (Or.inr h)
    have ins := (binding_sum inFrames noIn).trans inReal
    have outs := (binding_sum outFrames noOut).trans outReal
    have balance := extracted_native_balance tx canonical noExtraction
    rw [← ins, ← outs] at balance
    have removed := Finset.sum_sdiff (f := fun id => nativeValue (registry id)) available
    have added := wealth_union_le registry (before.live \ tx.inputs)
      (tx.outputs \ (before.spent ∪ tx.inputs))
    have outputBound := wealth_mono registry
      (Finset.sdiff_subset : tx.outputs \ (before.spent ∪ tx.inputs) ⊆ tx.outputs)
    change wealth registry (before.live \ tx.inputs) + wealth registry tx.inputs =
      wealth registry before.live at removed
    simp only [potential, allowance, applyTransfer] at *
    omega
  | coinbase height paid outputs opening once positive payment frames realization =>
    have outputValue := (binding_sum frames noCollision).trans realization
    have added := wealth_union_le registry before.live (outputs \ before.spent)
    have outputBound := wealth_mono registry
      (Finset.sdiff_subset : outputs \ before.spent ⊆ outputs)
    have paidEq : paid = blockSubsidy height + before.feeEscrow := by
      unfold nativeCoinbaseAmount checkedU64Add at payment
      dsimp only at payment
      split at payment
      · exact (Option.some.inj payment).symm
      · contradiction
    have budget : allowance (applyCoinbase before height outputs) =
        blockSubsidy height + allowance before := by
      simp [allowance, applyCoinbase, Finset.sum_insert, once]
    rw [budget]
    simp only [potential, applyCoinbase, Nat.add_zero] at *
    omega
  | noCoinbase =>
    simp only [potential, burnEscrow, allowance, Nat.add_zero] at *
    omega

theorem execution_supply_invariant {registry : Nat → V8NoteOpening}
    {before after : Ledger} {actions : List Action} {initial : Nat}
    (run : Execution registry before actions after)
    (good : ∀ action ∈ actions, ¬ badExtraction action ∧ ¬ badCollision registry action)
    (prior : potential registry before ≤ initial + allowance before) :
    potential registry after ≤ initial + allowance after := by
  induction run with
  | nil => exact prior
  | cons step rest ih =>
    apply ih
    · intro action member
      exact good action (List.mem_cons_of_mem _ member)
    · exact step_supply_invariant step (good _ (by simp)).1 (good _ (by simp)).2 prior

theorem spent_monotone {registry : Nat → V8NoteOpening}
    {before after : Ledger} {action : Action}
    (step : ProtocolStep registry before action after) :
    before.spent ⊆ after.spent := by
  cases step <;> simp [applyTransfer, applyCoinbase, burnEscrow]

theorem live_spent_disjoint {registry : Nat → V8NoteOpening}
    {before after : Ledger} {action : Action}
    (step : ProtocolStep registry before action after)
    (prior : Disjoint before.live before.spent) :
    Disjoint after.live after.spent := by
  cases step <;>
    simp_all [applyTransfer, applyCoinbase, burnEscrow, Finset.disjoint_left] <;> aesop

theorem execution_spent_monotone {registry : Nat → V8NoteOpening}
    {before after : Ledger} {actions : List Action}
    (run : Execution registry before actions after) : before.spent ⊆ after.spent := by
  induction run with
  | nil => exact fun _ member => member
  | cons step rest ih => exact fun _ member => ih ((spent_monotone step) member)

theorem spent_identity_cannot_be_selected_again
    {registry : Nat → V8NoteOpening} {before after : Ledger} {actions : List Action}
    (run : Execution registry before actions after) (inputs : Finset Nat)
    (fresh : Disjoint inputs after.spent) {id : Nat} (spent : id ∈ before.spent) :
    id ∉ inputs := by
  intro selected
  exact (Finset.disjoint_left.mp fresh) selected ((execution_spent_monotone run) spent)

-- Finite adversarial experiment: weights may describe classical outputs of a
-- quantum execution. No quantum oracle assumption is hidden in this measure.
def mass {Ω : Type} [Fintype Ω] (weight : Ω → ℝ) (event : Ω → Prop) : ℝ :=
  ∑ outcome, if event outcome then weight outcome else 0

theorem mass_union_le {Ω : Type} [Fintype Ω] (weight : Ω → ℝ)
    (nonnegative : ∀ outcome, 0 ≤ weight outcome) (left right : Ω → Prop) :
    mass weight (fun outcome => left outcome ∨ right outcome) ≤
      mass weight left + mass weight right := by
  unfold mass
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro outcome _
  by_cases l : left outcome <;> by_cases r : right outcome <;>
    simp [l, r, nonnegative outcome]

theorem finite_supply_failure_reduction {Ω : Type} [Fintype Ω]
    (registry : Ω → Nat → V8NoteOpening)
    (before after : Ω → Ledger) (actions : Ω → List Action)
    (weight : Ω → ℝ) (nonnegative : ∀ outcome, 0 ≤ weight outcome)
    (initial : Nat) (extractionBudget collisionBudget : ℝ)
    (runs : ∀ outcome, Execution (registry outcome) (before outcome)
      (actions outcome) (after outcome))
    (genesis : ∀ outcome, potential (registry outcome) (before outcome) ≤
      initial + allowance (before outcome))
    (extractionBound : mass weight (fun outcome =>
      ∃ action ∈ actions outcome, badExtraction action) ≤ extractionBudget)
    (collisionBound : mass weight (fun outcome =>
      ∃ action ∈ actions outcome, badCollision (registry outcome) action) ≤ collisionBudget) :
    mass weight (fun outcome =>
      initial + allowance (after outcome) <
        wealth (registry outcome) (after outcome).live) ≤
      extractionBudget + collisionBudget := by
  let ext := fun outcome => ∃ action ∈ actions outcome, badExtraction action
  let coll := fun outcome => ∃ action ∈ actions outcome, badCollision (registry outcome) action
  have inclusion : ∀ outcome,
      initial + allowance (after outcome) < wealth (registry outcome) (after outcome).live →
      ext outcome ∨ coll outcome := by
    intro outcome violation
    by_contra noBad
    have good : ∀ action ∈ actions outcome,
        ¬ badExtraction action ∧ ¬ badCollision (registry outcome) action := by
      intro action member
      exact ⟨fun h => noBad (Or.inl ⟨action, member, h⟩),
        fun h => noBad (Or.inr ⟨action, member, h⟩)⟩
    have bound := execution_supply_invariant (runs outcome) good (genesis outcome)
    unfold potential at bound
    omega
  have monotone : mass weight (fun outcome =>
      initial + allowance (after outcome) < wealth (registry outcome) (after outcome).live) ≤
      mass weight (fun outcome => ext outcome ∨ coll outcome) := by
    apply Finset.sum_le_sum
    intro outcome _
    by_cases bad : initial + allowance (after outcome) <
        wealth (registry outcome) (after outcome).live
    · simp [bad, inclusion outcome bad]
    · simp [bad]
      split <;> simp [nonnegative outcome]
  exact monotone.trans ((mass_union_le weight nonnegative ext coll).trans
    (add_le_add extractionBound collisionBound))

theorem deterministic_lifetime_cap {registry : Nat → V8NoteOpening}
    {before after : Ledger} {actions : List Action} {initial : Nat}
    (run : Execution registry before actions after)
    (good : ∀ action ∈ actions, ¬ badExtraction action ∧ ¬ badCollision registry action)
    (genesis : potential registry before ≤ initial + allowance before) :
    wealth registry after.live ≤ initial + maxMonetarySupply := by
  have conserved := execution_supply_invariant run good genesis
  have cap := Hegemon.Consensus.blockSubsidy_finset_sum_le after.issuedHeights
  change allowance after ≤ maxMonetarySupply at cap
  unfold potential at conserved
  omega

/-- Full finite authenticated-ledger cap reduction. The two budgets are separate
    explicit primitive-game obligations, not an assumed no-inflation event.
    Calling them concrete security guarantees still requires proving the q38
    extraction and canonical note-sponge collision bounds. -/
theorem finite_ledger_native_cap_probability {Ω : Type} [Fintype Ω]
    (registry : Ω → Nat → V8NoteOpening)
    (before after : Ω → Ledger) (actions : Ω → List Action)
    (weight : Ω → ℝ) (nonnegative : ∀ outcome, 0 ≤ weight outcome)
    (_normalized : mass weight (fun _ => True) = 1)
    (initial : Nat) (extractionBudget collisionBudget : ℝ)
    (runs : ∀ outcome, Execution (registry outcome) (before outcome)
      (actions outcome) (after outcome))
    (genesis : ∀ outcome, potential (registry outcome) (before outcome) ≤
      initial + allowance (before outcome))
    (extractionBound : mass weight (fun outcome =>
      ∃ action ∈ actions outcome, badExtraction action) ≤ extractionBudget)
    (collisionBound : mass weight (fun outcome =>
      ∃ action ∈ actions outcome, badCollision (registry outcome) action) ≤ collisionBudget) :
    mass weight (fun outcome =>
      initial + maxMonetarySupply < wealth (registry outcome) (after outcome).live) ≤
      extractionBudget + collisionBudget := by
  have reduced := finite_supply_failure_reduction registry before after actions weight
    nonnegative initial extractionBudget collisionBudget runs genesis extractionBound collisionBound
  apply le_trans _ reduced
  apply Finset.sum_le_sum
  intro outcome _
  have cap := Hegemon.Consensus.blockSubsidy_finset_sum_le (after outcome).issuedHeights
  change allowance (after outcome) ≤ maxMonetarySupply at cap
  by_cases excess : initial + maxMonetarySupply <
      wealth (registry outcome) (after outcome).live
  · have excessSchedule : initial + allowance (after outcome) <
        wealth (registry outcome) (after outcome).live := by omega
    simp [excess, excessSchedule]
  · simp [excess]
    split <;> simp [nonnegative outcome]


end
end SmzaFiniteLedgerSupply
