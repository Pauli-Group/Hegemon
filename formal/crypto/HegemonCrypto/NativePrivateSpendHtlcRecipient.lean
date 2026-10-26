import HegemonCrypto.NativePrivateSpendSelectedNullifier

namespace HegemonCrypto.NativePrivateSpendHtlcRecipient
open NativePrivateSpendSelectedNullifier NativePrivateSpendG1SourceComposition
open NativePrivateSpendCurrentSourceCallContract NativePrivateSpendRoleBridge
open NativePrivateSpendSymbolicBridge NativePrivateSpendSpongeBridge
open NativePrivateSpendArithmeticTopology NativePrivateSpendPackedLowering
open NativePrivateSpendLocalSemantics NativeLaunchConstraintAdapterBridge
noncomputable section
variable [Fact (Nat.Prime modulus)]

def outputRecipient (w : Nat → Word K) (i : Fin 7) := w (629+i.val)
def outputAddress (w : Nat → Word K) (i : Fin 4) := w (595+i.val)

theorem selected_gate (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (selector a b : Word K)
    (checked : GateData g selector a b) (selected : natural z selector = 1) :
    read z a = read z b := by
  have hs : read z selector = 1 := by
    rw [← natural_cast z selector, selected, Nat.cast_one]
  have h := gate_equation g layout z sem selector a b checked
  rw [hs, one_mul] at h
  exact sub_eq_zero.mp h

/-- Source-only gate/call interpretation for input0 and output0. w is the
same compiler-bound input-slot lookup used by SourceBinding, not wire IDs. -/
structure RecipientChecked (g : Graph K) (r : Roles) (v : RouteRoles)
    (w : Nat → Word K) where
  who : DigestWords
  single : SpongeChecked g (0x48534b4156320001 : K)
    (List.ofFn (key w (0 : Fin 2)) ++ [.constant 0,.constant 0]) who
  claimAuthority : ∀ i, GateData g (v.modes 4) (who i) (r.claimAuthority i)
  refundAuthority : ∀ i, GateData g (v.modes 5) (who i) (r.refundAuthority i)
  claimRecipient : ∀ i, GateData g (v.modes 4) (outputRecipient w i) (r.claimAuthority i)
  refundRecipient : ∀ i, GateData g (v.modes 5) (outputRecipient w i) (r.refundAuthority i)
  claimAddress : ∀ i, GateData g (v.modes 4) (outputAddress w i) (r.claimRecipient i)
  refundAddress : ∀ i, GateData g (v.modes 5) (outputAddress w i) (r.refundRecipient i)

def SelectedRecipient (z : Nat → K) (w : Nat → Word K) (who authority : DigestWords)
    (address : Fin 4 → Word K) : Prop :=
  (∀ i, read z (who i) = read z (authority i)) ∧
  (∀ i, read z (outputRecipient w i) = read z (authority i)) ∧
  (∀ i, read z (outputAddress w i) = read z (address i))

theorem recipient_consequences (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (r : Roles) (v : RouteRoles)
    (w : Nat → Word K) (c : RecipientChecked g r v w) :
    SpongeEquation z (0x48534b4156320001 : K)
      (List.ofFn (key w (0 : Fin 2)) ++ [.constant 0,.constant 0]) c.who ∧
    (natural z (v.modes 4)=1 → SelectedRecipient z w c.who r.claimAuthority r.claimRecipient) ∧
    (natural z (v.modes 5)=1 → SelectedRecipient z w c.who r.refundAuthority r.refundRecipient) := by
  refine ⟨source_sponge g layout z sem _ _ _ c.single, ?_, ?_⟩
  · intro selected
    exact ⟨fun i => selected_gate g layout z sem _ _ _ (c.claimAuthority i) selected,
      fun i => selected_gate g layout z sem _ _ _ (c.claimRecipient i) selected,
      fun i => selected_gate g layout z sem _ _ _ (c.claimAddress i) selected⟩
  · intro selected
    exact ⟨fun i => selected_gate g layout z sem _ _ _ (c.refundAuthority i) selected,
      fun i => selected_gate g layout z sem _ _ _ (c.refundRecipient i) selected,
      fun i => selected_gate g layout z sem _ _ _ (c.refundAddress i) selected⟩

/-- Connected to the same G1 binding; recipient clauses add no output Law. -/
theorem g1_with_recipients (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (r : Roles) (v : RouteRoles) (values : Fin 5 → Word K)
    (binding : SourceBinding g pub r v values) (w : Nat → Word K)
    (c : RecipientChecked g r v w) :
    MainSourceConsequences z pub r v values ∧
    (natural z (v.modes 4)=1 → SelectedRecipient z w c.who r.claimAuthority r.claimRecipient) ∧
    (natural z (v.modes 5)=1 → SelectedRecipient z w c.who r.refundAuthority r.refundRecipient) :=
  ⟨main_source_consequences g layout z sem pub r v values binding,
    (recipient_consequences g layout z sem r v w c).2⟩
end
end HegemonCrypto.NativePrivateSpendHtlcRecipient
