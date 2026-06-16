import Hegemon.Transaction.SpendAuthorization

namespace Hegemon
namespace Transaction
namespace SmallWoodSpendAuthorization

open Hegemon.Transaction.SpendAuthorization

def goldilocksModulus : Nat := 18446744069414584321

def goldilocksAdd (left right : Nat) : Nat :=
  (left + right) % goldilocksModulus

structure ActiveAuthLinkSurface where
  active : Bool
  previousAuth0 : Nat
  previousAuth1 : Nat
  previousAuth2 : Nat
  previousAuth3 : Nat
  derivedAuth0 : Nat
  derivedAuth1 : Nat
  derivedAuth2 : Nat
  derivedAuth3 : Nat
  commitmentAuth0 : Nat
  commitmentAuth1 : Nat
  commitmentAuth2 : Nat
  commitmentAuth3 : Nat
deriving DecidableEq, Repr

def activeAuthLinkAccepted (surface : ActiveAuthLinkSurface) : Bool :=
  if surface.active then
    natEq surface.commitmentAuth0
        (goldilocksAdd surface.previousAuth0 surface.derivedAuth0)
      && natEq surface.commitmentAuth1
        (goldilocksAdd surface.previousAuth1 surface.derivedAuth1)
      && natEq surface.commitmentAuth2
        (goldilocksAdd surface.previousAuth2 surface.derivedAuth2)
      && natEq surface.commitmentAuth3
        (goldilocksAdd surface.previousAuth3 surface.derivedAuth3)
  else
    true

def ActiveAuthLinkFacts (surface : ActiveAuthLinkSurface) : Prop :=
  surface.commitmentAuth0 =
      goldilocksAdd surface.previousAuth0 surface.derivedAuth0
    ∧ surface.commitmentAuth1 =
      goldilocksAdd surface.previousAuth1 surface.derivedAuth1
    ∧ surface.commitmentAuth2 =
      goldilocksAdd surface.previousAuth2 surface.derivedAuth2
    ∧ surface.commitmentAuth3 =
      goldilocksAdd surface.previousAuth3 surface.derivedAuth3

theorem natEq_false_of_ne {left right : Nat} (mismatch : left ≠ right) :
    natEq left right = false := by
  unfold natEq
  split
  · contradiction
  · rfl

theorem active_auth_link_constraints_imply_pk_auth_eq_derived
    {surface : ActiveAuthLinkSurface}
    (accepted : activeAuthLinkAccepted surface = true)
    (active : surface.active = true) :
    ActiveAuthLinkFacts surface := by
  unfold activeAuthLinkAccepted at accepted
  rw [active] at accepted
  simp at accepted
  exact
    ⟨natEq_true_eq accepted.left.left.left,
      natEq_true_eq accepted.left.left.right,
      natEq_true_eq accepted.left.right,
      natEq_true_eq accepted.right⟩

theorem active_auth_link_constraints_imply_goldilocks_auth_link
    {surface : ActiveAuthLinkSurface}
    (accepted : activeAuthLinkAccepted surface = true)
    (active : surface.active = true) :
    ActiveAuthLinkFacts surface :=
  active_auth_link_constraints_imply_pk_auth_eq_derived accepted active

theorem active_auth_link_wrong_secret_rejects
    {surface : ActiveAuthLinkSurface}
    (active : surface.active = true)
    (mismatch :
      surface.commitmentAuth0 ≠
        goldilocksAdd surface.previousAuth0 surface.derivedAuth0) :
    activeAuthLinkAccepted surface = false := by
  unfold activeAuthLinkAccepted
  rw [active]
  simp [natEq_false_of_ne mismatch]

theorem active_auth_link_mismatched_active_limbs_reject
    {surface : ActiveAuthLinkSurface}
    (active : surface.active = true)
    (mismatch : ¬ ActiveAuthLinkFacts surface) :
    activeAuthLinkAccepted surface = false := by
  cases accepted : activeAuthLinkAccepted surface
  · rfl
  · have facts :=
      active_auth_link_constraints_imply_goldilocks_auth_link accepted active
    exact False.elim (mismatch facts)

theorem inactive_auth_link_accepts_without_constraint
    {surface : ActiveAuthLinkSurface}
    (inactive : surface.active = false) :
    activeAuthLinkAccepted surface = true := by
  unfold activeAuthLinkAccepted
  rw [inactive]
  simp

theorem active_auth_link_wraparound_accepts :
    activeAuthLinkAccepted
      { active := true,
        previousAuth0 := goldilocksModulus - 1,
        previousAuth1 := goldilocksModulus - 2,
        previousAuth2 := 7,
        previousAuth3 := 11,
        derivedAuth0 := 1,
        derivedAuth1 := 7,
        derivedAuth2 := goldilocksModulus - 7,
        derivedAuth3 := 13,
        commitmentAuth0 := 0,
        commitmentAuth1 := 5,
        commitmentAuth2 := 0,
        commitmentAuth3 := 24 } = true := by
  decide

theorem inactive_auth_link_allows_mismatched_limbs :
    activeAuthLinkAccepted
      { active := false,
        previousAuth0 := 1,
        previousAuth1 := 2,
        previousAuth2 := 3,
        previousAuth3 := 4,
        derivedAuth0 := 5,
        derivedAuth1 := 6,
        derivedAuth2 := 7,
        derivedAuth3 := 8,
        commitmentAuth0 := 99,
        commitmentAuth1 := 98,
        commitmentAuth2 := 97,
        commitmentAuth3 := 96 } = true := by
  simp [activeAuthLinkAccepted]

structure ActiveInputSpendBoundarySurface where
  activeFlag : Nat
  noteOpeningCommitment : Nat
  commitmentRowCommitment : Nat
  publicNullifier : Nat
  nullifierRow : Nat
  publicMerkleRoot : Nat
  merkleRootRow : Nat
  nullifierPosition : Nat
  merklePosition : Nat
  merklePathAccepted : Bool
deriving DecidableEq, Repr

def activeInputSpendBoundaryAccepted
    (surface : ActiveInputSpendBoundarySurface) : Bool :=
  if surface.activeFlag = 1 then
    natEq surface.commitmentRowCommitment surface.noteOpeningCommitment
      && natEq surface.nullifierRow surface.publicNullifier
      && natEq surface.merkleRootRow surface.publicMerkleRoot
      && natEq surface.merklePosition surface.nullifierPosition
      && surface.merklePathAccepted
  else if surface.activeFlag = 0 then
    natEq surface.publicNullifier 0
      && natEq surface.nullifierRow 0
  else
    false

structure ActiveInputSpendBoundaryFacts
    (surface : ActiveInputSpendBoundarySurface) : Prop where
  activeFlagBoolean : surface.activeFlag = 0 ∨ surface.activeFlag = 1
  commitmentRowsBindNoteOpening :
    surface.activeFlag = 1 ->
      surface.commitmentRowCommitment = surface.noteOpeningCommitment
  nullifierRowsBindPublicNullifier :
    surface.activeFlag = 1 ->
      surface.nullifierRow = surface.publicNullifier
  merkleRowsBindPublicRoot :
    surface.activeFlag = 1 ->
      surface.merkleRootRow = surface.publicMerkleRoot
  merkleRowsBindNullifierPosition :
    surface.activeFlag = 1 ->
      surface.merklePosition = surface.nullifierPosition
  merklePathAccepted :
    surface.activeFlag = 1 ->
      surface.merklePathAccepted = true
  inactivePublicNullifierZero :
    surface.activeFlag = 0 ->
      surface.publicNullifier = 0
  inactiveNullifierRowZero :
    surface.activeFlag = 0 ->
      surface.nullifierRow = 0

theorem active_input_commitment_rows_bind_note_opening
    {surface : ActiveInputSpendBoundarySurface}
    (accepted : activeInputSpendBoundaryAccepted surface = true)
    (active : surface.activeFlag = 1) :
    surface.commitmentRowCommitment = surface.noteOpeningCommitment := by
  unfold activeInputSpendBoundaryAccepted at accepted
  rw [active] at accepted
  simp at accepted
  exact natEq_true_eq accepted.left.left.left.left

theorem active_input_nullifier_rows_bind_public_nullifier
    {surface : ActiveInputSpendBoundarySurface}
    (accepted : activeInputSpendBoundaryAccepted surface = true)
    (active : surface.activeFlag = 1) :
    surface.nullifierRow = surface.publicNullifier := by
  unfold activeInputSpendBoundaryAccepted at accepted
  rw [active] at accepted
  simp at accepted
  exact natEq_true_eq accepted.left.left.left.right

theorem active_input_merkle_rows_bind_public_root
    {surface : ActiveInputSpendBoundarySurface}
    (accepted : activeInputSpendBoundaryAccepted surface = true)
    (active : surface.activeFlag = 1) :
    surface.merkleRootRow = surface.publicMerkleRoot
      ∧ surface.merklePosition = surface.nullifierPosition
      ∧ surface.merklePathAccepted = true := by
  unfold activeInputSpendBoundaryAccepted at accepted
  rw [active] at accepted
  simp at accepted
  exact
    ⟨natEq_true_eq accepted.left.left.right,
      natEq_true_eq accepted.left.right,
      accepted.right⟩

theorem inactive_input_nullifier_rows_zero
    {surface : ActiveInputSpendBoundarySurface}
    (accepted : activeInputSpendBoundaryAccepted surface = true)
    (inactive : surface.activeFlag = 0) :
    surface.publicNullifier = 0 ∧ surface.nullifierRow = 0 := by
  unfold activeInputSpendBoundaryAccepted at accepted
  rw [inactive] at accepted
  simp at accepted
  exact
    ⟨natEq_true_eq accepted.left,
      natEq_true_eq accepted.right⟩

theorem accepted_smallwood_spend_constraints_imply_active_input_spend_boundary
    {surface : ActiveInputSpendBoundarySurface}
    (accepted : activeInputSpendBoundaryAccepted surface = true) :
    ActiveInputSpendBoundaryFacts surface := by
  by_cases inactive : surface.activeFlag = 0
  · have zeroFacts :=
      inactive_input_nullifier_rows_zero accepted inactive
    refine {
      activeFlagBoolean := Or.inl inactive,
      commitmentRowsBindNoteOpening := ?_,
      nullifierRowsBindPublicNullifier := ?_,
      merkleRowsBindPublicRoot := ?_,
      merkleRowsBindNullifierPosition := ?_,
      merklePathAccepted := ?_,
      inactivePublicNullifierZero := ?_,
      inactiveNullifierRowZero := ?_
    }
    · intro active
      rw [inactive] at active
      cases active
    · intro active
      rw [inactive] at active
      cases active
    · intro active
      rw [inactive] at active
      cases active
    · intro active
      rw [inactive] at active
      cases active
    · intro active
      rw [inactive] at active
      cases active
    · intro _
      exact zeroFacts.left
    · intro _
      exact zeroFacts.right
  · by_cases active : surface.activeFlag = 1
    · have merkleFacts :=
        active_input_merkle_rows_bind_public_root accepted active
      refine {
        activeFlagBoolean := Or.inr active,
        commitmentRowsBindNoteOpening := ?_,
        nullifierRowsBindPublicNullifier := ?_,
        merkleRowsBindPublicRoot := ?_,
        merkleRowsBindNullifierPosition := ?_,
        merklePathAccepted := ?_,
        inactivePublicNullifierZero := ?_,
        inactiveNullifierRowZero := ?_
      }
      · intro _
        exact
          active_input_commitment_rows_bind_note_opening
            accepted
            active
      · intro _
        exact
          active_input_nullifier_rows_bind_public_nullifier
            accepted
            active
      · intro _
        exact merkleFacts.left
      · intro _
        exact merkleFacts.right.left
      · intro _
        exact merkleFacts.right.right
      · intro inactiveNow
        rw [active] at inactiveNow
        cases inactiveNow
      · intro inactiveNow
        rw [active] at inactiveNow
        cases inactiveNow
    · unfold activeInputSpendBoundaryAccepted at accepted
      simp [inactive, active] at accepted

def sampleActiveSpendBoundarySurface : ActiveInputSpendBoundarySurface :=
  {
    activeFlag := 1,
    noteOpeningCommitment := 55,
    commitmentRowCommitment := 55,
    publicNullifier := 77,
    nullifierRow := 77,
    publicMerkleRoot := 99,
    merkleRootRow := 99,
    nullifierPosition := 3,
    merklePosition := 3,
    merklePathAccepted := true
  }

theorem sample_active_spend_boundary_accepts :
    activeInputSpendBoundaryAccepted sampleActiveSpendBoundarySurface = true := by
  decide

def sampleInactiveSpendBoundarySurface : ActiveInputSpendBoundarySurface :=
  {
    activeFlag := 0,
    noteOpeningCommitment := 55,
    commitmentRowCommitment := 56,
    publicNullifier := 0,
    nullifierRow := 0,
    publicMerkleRoot := 99,
    merkleRootRow := 100,
    nullifierPosition := 3,
    merklePosition := 4,
    merklePathAccepted := false
  }

theorem sample_inactive_spend_boundary_accepts :
    activeInputSpendBoundaryAccepted sampleInactiveSpendBoundarySurface = true := by
  decide

end SmallWoodSpendAuthorization
end Transaction
end Hegemon
