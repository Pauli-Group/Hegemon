import Hegemon.Transaction.SpendAuthorization

namespace Hegemon
namespace Transaction
namespace SmallWoodSpendAuthorization

open Hegemon.Transaction.SpendAuthorization

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
        (surface.previousAuth0 + surface.derivedAuth0)
      && natEq surface.commitmentAuth1
        (surface.previousAuth1 + surface.derivedAuth1)
      && natEq surface.commitmentAuth2
        (surface.previousAuth2 + surface.derivedAuth2)
      && natEq surface.commitmentAuth3
        (surface.previousAuth3 + surface.derivedAuth3)
  else
    true

def ActiveAuthLinkFacts (surface : ActiveAuthLinkSurface) : Prop :=
  surface.commitmentAuth0 = surface.previousAuth0 + surface.derivedAuth0
    ∧ surface.commitmentAuth1 = surface.previousAuth1 + surface.derivedAuth1
    ∧ surface.commitmentAuth2 = surface.previousAuth2 + surface.derivedAuth2
    ∧ surface.commitmentAuth3 = surface.previousAuth3 + surface.derivedAuth3

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

theorem active_auth_link_wrong_secret_rejects
    {surface : ActiveAuthLinkSurface}
    (active : surface.active = true)
    (mismatch :
      surface.commitmentAuth0 ≠ surface.previousAuth0 + surface.derivedAuth0) :
    activeAuthLinkAccepted surface = false := by
  unfold activeAuthLinkAccepted
  rw [active]
  simp [natEq_false_of_ne mismatch]

theorem inactive_auth_link_accepts_without_constraint
    {surface : ActiveAuthLinkSurface}
    (inactive : surface.active = false) :
    activeAuthLinkAccepted surface = true := by
  unfold activeAuthLinkAccepted
  rw [inactive]
  simp

end SmallWoodSpendAuthorization
end Transaction
end Hegemon
