import Mathlib.Data.Finset.Card
import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

/-! UNCOMPILED typed-ledger data law. Nat identifiers stand for exact source
key/digest/intent encodings under the UNPROVED typed-owner/certificate bridge.
This does not assert a collision reduction or implementation-level authorization. -/
namespace HegemonCrypto.NativePrivateSpendApprovalHistory
open scoped Classical
noncomputable section
set_option autoImplicit false

abbrev Signer := Fin 3
structure Context where
  policy : Signer → Nat
  key : Nat
  intent : List Nat
  deriving DecidableEq

inductive Owner where
  | ordinary : Nat → Owner
  | valueLock : (Signer → Nat) → Nat → Owner
  | accumulator : Context → Finset Signer → Owner
  | locked : Nat → Owner
  deriving DecidableEq

structure Note where
  id : Nat
  nullifier : Nat
  value : Nat
  owner : Owner
  deriving DecidableEq

structure Receipt where
  context : Context
  previous : Finset Signer
  signer : Signer
  credential : Nat
  fundingId : Nat
  outputId : Nat
  deriving DecidableEq

structure Ledger where
  live : List Note
  created : Finset Nat
  spent : Finset Nat
  approvals : List Receipt

/-- No initial positive accumulator is assumed. Start at the empty note ledger. -/
def empty : Ledger := ⟨[], ∅, ∅, []⟩

/-- Actual finite membership/consumption and creation checks. Note equality
includes owner/value/nullifier; no membership claim is asserted by the caller. -/
def IOValid (state : Ledger) (inputs outputs : List Note) : Prop :=
  (∀ note ∈ inputs, note ∈ state.live) ∧
  (inputs.map Note.id).Nodup ∧ (inputs.map Note.nullifier).Nodup ∧
  (∀ note ∈ inputs, note.nullifier ∉ state.spent) ∧
  (outputs.map Note.id).Nodup ∧ (∀ note ∈ outputs, note.id ∉ state.created)

def applyIO (state : Ledger) (inputs outputs : List Note) (receipt : Option Receipt) : Ledger :=
  { live := outputs ++ state.live.filter (fun note => note.id ∉ inputs.map Note.id)
    created := state.created ∪ (outputs.map Note.id).toFinset
    spent := state.spent ∪ (inputs.map Note.nullifier).toFinset
    approvals := state.approvals ++ receipt.toList }

/-- Chain starts at no approvals. Each extension records an authenticated,
fresh signer on the SAME policy/key/intent and the exact previous flag set. -/
inductive Chain (authority : Nat → Nat) (history : List Receipt) (context : Context) :
    Finset Signer → Prop where
  | empty : Chain authority history context ∅
  | add (flags : Finset Signer) (receipt : Receipt)
      (prior : Chain authority history context flags)
      (recorded : receipt ∈ history)
      (same : receipt.context = context) (previous : receipt.previous = flags)
      (fresh : receipt.signer ∉ flags)
      (authenticated : authority receipt.credential = context.policy receipt.signer) :
      Chain authority history context (insert receipt.signer flags)

theorem chain_mono (authority : Nat → Nat) (before after : List Receipt)
    (included : ∀ receipt ∈ before, receipt ∈ after) (context : Context)
    (flags : Finset Signer) (chain : Chain authority before context flags) :
    Chain authority after context flags := by
  induction chain with
  | empty => exact .empty
  | add flags receipt prior recorded same previous fresh authenticated ih =>
    exact .add flags receipt ih (included receipt recorded) same previous fresh authenticated

/-- Invariant only concerns ZERO-value accumulator notes. A positive mint with
an accidentally accumulator-shaped owner cannot seed this zero-value chain. -/
def Good (authority : Nat → Nat) (state : Ledger) : Prop :=
  ∀ note ∈ state.live, ∀ context flags,
    note.value = 0 → note.owner = .accumulator context flags →
      flags.Nonempty ∧ Chain authority state.approvals context flags

inductive OrdinaryRoute where
  | ordinary | lock | claim | refund
  deriving DecidableEq

/-- These are typed output constructors, not semantic-equality assumptions. -/
def NonAccumulator (owner : Owner) : Prop :=
  match owner with
  | .ordinary _ | .locked _ => True
  | _ => False

/-- Finite typed transition clauses. Source cryptographic checks must establish
this typed interpretation or yield an explicit owner/hash-bad event. -/
inductive Step (authority : Nat → Nat) : Ledger → Ledger → Prop where
  | mint (state : Ledger) (outputs : List Note)
      (io : IOValid state [] outputs) (positive : ∀ note ∈ outputs, 0 < note.value) :
      Step authority state (applyIO state [] outputs none)
  | transfer (state : Ledger) (route : OrdinaryRoute) (inputs outputs : List Note)
      (io : IOValid state inputs outputs)
      (owners : ∀ note ∈ outputs, NonAccumulator note.owner) :
      Step authority state (applyIO state inputs outputs none)
  | approval (state : Ledger) (context : Context) (flags : Finset Signer)
      (prior : Option Note) (funding output change : Note) (signer : Signer) (credential : Nat)
      (base : match prior with
        | none => flags = ∅
        | some note => note.value = 0 ∧ note.owner = .accumulator context flags ∧ flags.Nonempty)
      (io : IOValid state (prior.toList ++ [funding]) [output, change])
      (fresh : signer ∉ flags)
      (policyDistinct : Function.Injective context.policy)
      (policyNonzero : ∀ index, context.policy index ≠ 0)
      (fundingOwner : funding.owner = .ordinary (context.policy signer))
      (authenticated : authority credential = context.policy signer)
      (outputValue : output.value = 0)
      (outputOwner : output.owner = .accumulator context (insert signer flags))
      (changeOwner : ∃ tag, change.owner = .ordinary tag) :
      Step authority state (applyIO state (prior.toList ++ [funding]) [output, change]
        (some ⟨context, flags, signer, credential, funding.id, output.id⟩))
  | final (state : Ledger) (context : Context) (flags : Finset Signer)
      (value accumulator : Note) (outputs : List Note)
      (io : IOValid state [value, accumulator] outputs)
      (valueOwner : value.owner = .valueLock context.policy context.key)
      (accumulatorValue : accumulator.value = 0)
      (accumulatorOwner : accumulator.owner = .accumulator context flags)
      (threshold : 2 ≤ flags.card)
      (owners : ∀ note ∈ outputs, NonAccumulator note.owner) :
      Step authority state (applyIO state [value, accumulator] outputs none)

/-- Generic list preservation only; the semantic proof below supplies new-note
facts separately for each concrete constructor. -/
theorem good_apply (authority : Nat → Nat) (state : Ledger) (inputs outputs : List Note)
    (receipt : Option Receipt) (old : Good authority state)
    (new : ∀ note ∈ outputs, ∀ context flags, note.value = 0 →
      note.owner = .accumulator context flags → flags.Nonempty ∧
        Chain authority (state.approvals ++ receipt.toList) context flags) :
    Good authority (applyIO state inputs outputs receipt) := by
  intro note member context flags zero owner
  rcases List.mem_append.mp member with created | retained
  · exact new note created context flags zero owner
  · have prior := old note (List.mem_filter.mp retained).1 context flags zero owner
    exact ⟨prior.1, chain_mono authority _ _
      (fun r hr => List.mem_append_left _ hr) context flags prior.2⟩

theorem step_preserves_good (authority : Nat → Nat) (before after : Ledger)
    (old : Good authority before) (step : Step authority before after) : Good authority after := by
  cases step with
  | mint outputs io positive =>
    apply good_apply authority before [] outputs none old
    intro note member context flags zero owner
    have h := positive note member
    omega
  | transfer route inputs outputs io owners =>
    apply good_apply authority before inputs outputs none old
    intro note member context flags zero owner
    have h := owners note member
    simp [owner, NonAccumulator] at h
  | final context flags value accumulator outputs io vo av ao threshold owners =>
    apply good_apply authority before [value, accumulator] outputs none old
    intro note member other bits zero owner
    have h := owners note member
    simp [owner, NonAccumulator] at h
  | approval context flags prior funding output change signer credential base io fresh
      distinct nonzero fundingOwner authenticated outputValue outputOwner changeOwner =>
    have previous : Chain authority before.approvals context flags := by
      cases prior with
      | none => simp only at base; subst flags; exact .empty
      | some note =>
        have member : note ∈ before.live := io.1 note (by simp)
        exact (old note member context flags base.1 base.2.1).2
    let receipt : Receipt := ⟨context, flags, signer, credential, funding.id, output.id⟩
    have extended : Chain authority (before.approvals ++ [receipt]) context (insert signer flags) :=
      .add flags receipt (chain_mono authority _ _ (fun r hr => List.mem_append_left _ hr)
        context flags previous) (by simp) rfl rfl fresh authenticated
    apply good_apply authority before _ _ (some receipt) old
    intro note member other bits zero owner
    have alternatives : note = output ∨ note = change := by
      rcases List.mem_cons.mp member with first | tail
      · exact Or.inl first
      · exact Or.inr (List.mem_singleton.mp tail)
    rcases alternatives with rfl | rfl
    · have same : context = other ∧ insert signer flags = bits :=
        Owner.accumulator.inj (outputOwner.symm.trans owner)
      rcases same with ⟨rfl, rfl⟩
      exact ⟨Finset.insert_nonempty _ _, extended⟩
    · obtain ⟨tag, htag⟩ := changeOwner
      simp [htag] at owner

inductive Reachable (authority : Nat → Nat) : Ledger → Prop where
  | empty : Reachable authority NativePrivateSpendApprovalHistory.empty
  | step {before after : Ledger} : Reachable authority before →
      Step authority before after → Reachable authority after

theorem reachable_good (authority : Nat → Nat) (state : Ledger)
    (reachable : Reachable authority state) : Good authority state := by
  induction reachable with
  | empty => simp [Good, empty]
  | step prior step ih => exact step_preserves_good authority _ _ ih step

/-- Final provenance is obtained from the SAME prior live accumulator, without
assuming that its positive count already has authenticated approval origins. -/
theorem final_accumulator_provenance (authority : Nat → Nat) (state : Ledger)
    (reachable : Reachable authority state) (context : Context) (flags : Finset Signer)
    (accumulator : Note) (member : accumulator ∈ state.live)
    (zero : accumulator.value = 0) (owner : accumulator.owner = .accumulator context flags)
    (threshold : 2 ≤ flags.card) :
    2 ≤ flags.card ∧ Chain authority state.approvals context flags :=
  ⟨threshold, (reachable_good authority state reachable accumulator member context flags zero owner).2⟩

end
end HegemonCrypto.NativePrivateSpendApprovalHistory
