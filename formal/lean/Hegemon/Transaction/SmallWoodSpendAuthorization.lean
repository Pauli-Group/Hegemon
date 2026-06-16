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

end SmallWoodSpendAuthorization
end Transaction
end Hegemon
