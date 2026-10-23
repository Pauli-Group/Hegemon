import HegemonCrypto.NativePrivateSpendCurrentSourceCallContract
import HegemonCrypto.NativePrivateSpendCsrCertificate

namespace HegemonCrypto.NativePrivateSpendG1SourceComposition
open NativePrivateSpendCurrentSourceCallContract NativePrivateSpendRoleBridge
open NativePrivateSpendSymbolicBridge NativePrivateSpendSpongeBridge
open NativePrivateSpendPackedLowering NativePrivateSpendArithmeticTopology
open NativePrivateSpendCsrCertificate NativePrivateSpendLocalSemantics
open NativeLaunchConstraintAdapterBridge
noncomputable section
variable [Fact (Nat.Prime modulus)]

def publicWords : Fin 77 → Word K := fun i => .wire i.val

/-- Current source/compiler interpretation data. Every arithmetic/hash binding
is a graph operation/frame certificate, never a desired semantic-output law. -/
structure SourceBinding (g : Graph K) (pub : Fin 77 → K)
    (r : Roles) (v : RouteRoles) (values : Fin 5 → Word K) where
  public77 : g.publicBindings = NativePrivateSpendCsrCertificate.public77 pub
  calls : CurrentCallMatch g r v
  balance : BalanceData g values
  fee : values 4 = .wire 24
  intent : IntentData g (v.modes 2) publicWords r.intent
  lock : LockData g (v.modes 3) (.wire 16) r.timeout
  refund : RefundData g (v.modes 5) (.wire 16) r.timeout
  payout : GateData g v.unlocked (values 2) (values 0)

structure MainSourceConsequences (z : Nat → K) (pub : Fin 77 → K)
    (r : Roles) (v : RouteRoles) (values : Fin 5 → Word K) : Prop where
  public77 : ∀ i : Fin 77, z i.val = pub i
  hashes : RoleEquations z r
  routes : RouteEquations z r v
  balance : natural z (values 0) + natural z (values 1) =
    natural z (values 2) + natural z (values 3) + (pub 24).val
  finalIntent : natural z (v.modes 2) = 1 →
    (fun i => read z (r.intent i)) = intentProjection pub
  unlockPayout : natural z (v.modes 4) = 1 ∨ natural z (v.modes 5) = 1 →
    natural z (values 2) = natural z (values 0)
  lockSafe : natural z (v.modes 3) = 1 → ∀ parent,
    natural z (.wire 16) ≤ parent ∧ parent ≤ natural z (.wire 16) + 12 →
    parent + 1 < natural z r.timeout
  refundMature : natural z (v.modes 5) = 1 → ∀ parent,
    natural z (.wire 16) ≤ parent → natural z r.timeout ≤ parent

theorem main_source_consequences (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (r : Roles) (v : RouteRoles) (values : Fin 5 → Word K)
    (binding : SourceBinding g pub r v values) : MainSourceConsequences z pub r v values := by
  have pubEq := certified_public77 g layout z sem pub binding.public77
  have joined := current_source_semantic_join g layout z sem r v binding.calls
  have selectors := selector_equations_from_topology g layout z sem v.modes
    binding.calls.routes.selector
  have conservation := integer_balance_from_topology g layout z sem values binding.balance
  refine {
    public77 := pubEq
    hashes := joined.1
    routes := joined.2
    balance := ?_
    finalIntent := ?_
    unlockPayout := ?_
    lockSafe := ?_
    refundMature := ?_ }
  · have feeValue : natural z (values 4) = (pub (24 : Fin 77)).val := by
      rw [binding.fee]
      change (z 24).val = (pub (24 : Fin 77)).val
      exact congrArg ZMod.val (pubEq (24 : Fin 77))
    simpa only [feeValue] using conservation
  · intro selected
    have h := exact_intent_from_topology g layout z sem (v.modes 2)
      publicWords r.intent binding.intent selected
    have publicFunction : (fun i => read z (publicWords i)) = pub := by
      funext i
      exact pubEq i
    simpa only [publicFunction] using h
  · intro selected
    have bound (i : Fin 5) : natural z (values i) < valueBound :=
      range_natural_bound g layout z sem _ 56 (binding.balance.ranges i) (by norm_num [modulus])
    apply unlocked_full_payout _ selectors selected _ _ (bound 0) (bound 2)
    have gate := gate_equation g layout z sem _ _ _ binding.payout
    rw [joined.2.unlocked] at gate
    simpa only [natural_cast] using gate
  · intro selected parent window
    exact lock_safe_from_topology g layout z sem _ _ _ binding.lock selected parent window
  · intro selected parent notFuture
    exact refund_mature_from_topology g layout z sem _ _ _ binding.refund selected parent notFuture

/-- Concrete current note-hash call plus its actual public commitment gate.
This reuses the kernel call theorem, not an old graph acceptance theorem. -/
structure OutputNoteCall (g : Graph K) (slot : Fin 2) where
  note : Fin 18 → Word K
  digest : DigestWords
  call : SpongeChecked g (1 : K) (List.ofFn note) digest
  publicGate : ∀ lane : Fin 7,
    GateData g (.constant 1) (digest lane) (.wire (39 + 7*slot.val + lane.val))

theorem output_note_commitment (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (publicBinding : g.publicBindings = NativePrivateSpendCsrCertificate.public77 pub)
    (slot : Fin 2) (checked : OutputNoteCall g slot) (lane : Fin 7) :
    pub ⟨39 + 7*slot.val + lane.val, by omega⟩ =
      (spongeNaturals z (1 : K) (List.ofFn checked.note) |>.getD lane.val 0 : K) := by
  have hash := source_sponge g layout z sem _ _ _ checked.call lane
  have gate := gate_equation g layout z sem _ _ _ (checked.publicGate lane)
  have equal : read z (checked.digest lane) = z (39 + 7*slot.val + lane.val) := by
    simpa only [NativeLaunchConstraintAdapterBridge.read, one_mul, sub_eq_zero] using gate
  have publicLane := certified_public77 g layout z sem pub publicBinding
    ⟨39 + 7*slot.val + lane.val, by omega⟩
  exact publicLane.symm.trans (equal.symm.trans hash)

/-- Nullifier sponge meaning on the EXACT selected-key/position/rho Word frame.
Selection, occupancy, dummy branch and public routing need their own topology. -/
structure RealNullifierCall (g : Graph K) where
  selectedKey : Fin 5 → Word K
  position : Word K
  rho : Fin 4 → Word K
  digest : DigestWords
  call : SpongeChecked g (0x484e554c56320001 : K)
    (List.ofFn selectedKey ++ [.constant 0,.constant 0,position] ++ List.ofFn rho) digest

theorem real_nullifier_meaning (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (checked : RealNullifierCall g) :
    SpongeEquation z (0x484e554c56320001 : K)
      (List.ofFn checked.selectedKey ++ [.constant 0,.constant 0,checked.position] ++
        List.ofFn checked.rho) checked.digest :=
  source_sponge g layout z sem _ _ _ checked.call
end
end HegemonCrypto.NativePrivateSpendG1SourceComposition
