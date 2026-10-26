import HegemonCrypto.NativePrivateSpendRoleBridge

/-! Current-source join under the explicitly retained PR205 source/compiler
interpretation boundary. All binding fields are topology, not desired hash laws.
No accepted-proof or production conclusion is asserted by this module. -/
namespace HegemonCrypto.NativePrivateSpendCurrentSourceCallContract
open NativePrivateSpendSymbolicBridge NativePrivateSpendSpongeBridge NativePrivateSpendRoleBridge
open NativePrivateSpendPackedLowering NativePrivateSpendArithmeticTopology
open NativePrivateSpendLocalSemantics NativeLaunchConstraintAdapterBridge
noncomputable section
variable [Fact (Nat.Prime modulus)]

def currentSegmentStarts : List Nat := [10700,25561,42610,52327,62044,72338]
def currentNextNodes : List Nat := [25552,25553,25554]

/-- Direct StructuralSemantics path: a new literal-CSR theorem is unnecessary
when the existing source/compiler binding supplies this original premise. -/
theorem source_sponge (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (domain : K)
    (message : List (Word K)) (role : DigestWords)
    (checked : SpongeChecked g domain message role) : SpongeEquation z domain message role := by
  intro lane
  have h := checked_blocks_match g layout z sem message checked.chain
    (stateNaturals z checked.input) (stateNaturals_matches z checked.input)
  have hi : lane.val < 16 := by omega
  have value := h.lane lane.val hi
  change stateValue z checked.output lane.val =
    (runBlocks (fun i => (messageValue z message i).val) message.length 0
      (blockCount message.length) (stateNaturals z checked.input) |>.getD lane.val 0 : K) at value
  rw [checked.frame] at value
  change stateValue z checked.output lane.val =
    (spongeNaturals z domain message |>.getD lane.val 0 : K) at value
  have lhs : stateValue z checked.output lane.val =
      NativeLaunchConstraintAdapterBridge.read z (checked.output ⟨lane.val,hi⟩) := by
    change NativeLaunchConstraintAdapterBridge.read z (words checked.output lane.val) = _
    unfold words
    rw [dif_pos hi]
  rw [checked.roleWords lane]
  exact lhs.symm.trans value

theorem source_compress (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (domain : K)
    (left right role : DigestWords) (checked : CompressChecked g domain left right role) :
    CompressEquation z domain left right role := by
  intro lane
  have h := checked_permutation_refines_kernel g layout z sem checked.input checked.output
    checked.permutation (stateNaturals z checked.input) (stateNaturals_length z checked.input)
    (stateNaturals_matches z checked.input)
  have hi : lane.val < 16 := by omega
  have value := h.lane lane.val hi
  change stateValue z checked.output lane.val =
    (Hegemon.Transaction.Poseidon2Width16Kernel.permutation
      (stateNaturals z checked.input) |>.getD lane.val 0 : K) at value
  rw [checked.inputFrame] at value
  have lhs : stateValue z checked.output lane.val =
      NativeLaunchConstraintAdapterBridge.read z (checked.output ⟨lane.val,hi⟩) := by
    change NativeLaunchConstraintAdapterBridge.read z (words checked.output lane.val) = _
    unfold words
    rw [dif_pos hi]
  have permutation := lhs.symm.trans value
  exact (add_sound g layout z sem (checked.outputAdds lane)).trans
    (congrArg (fun x : K => x + read z (left lane)) permutation)

theorem source_role_equations (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (r : Roles) (checked : CallsChecked g r) :
    RoleEquations z r := by
  exact {
    nextAdd := fun i => add_sound g layout z sem (checked.nextAdd i)
    count := three_sum_sound g layout z sem _ _ checked.count
    nextCount := three_sum_sound g layout z sem _ _ checked.nextCount
    policy := source_sponge g layout z sem _ _ _ checked.policy
    intent := source_sponge g layout z sem _ _ _ checked.intent
    accumulatorInner := source_sponge g layout z sem _ _ _ checked.accumulatorInner
    accumulator := source_compress g layout z sem _ _ _ _ checked.accumulator
    nextAccumulatorInner := source_sponge g layout z sem _ _ _ checked.nextAccumulatorInner
    nextAccumulator := source_compress g layout z sem _ _ _ _ checked.nextAccumulator
    valueInner := source_compress g layout z sem _ _ _ _ checked.valueInner
    valueOwner := source_compress g layout z sem _ _ _ _ checked.valueOwner
    htlcPolicy := source_sponge g layout z sem _ _ _ checked.htlcPolicy
    htlcOwner := source_compress g layout z sem _ _ _ _ checked.htlcOwner }

/-- Actual owner-routing Word roles. Normal-owner hash meaning remains a
separate omitted-call obligation; these locators must not be called hashes yet. -/
structure RouteRoles where
  modes : Fin 6 → Word K
  input0Owner : DigestWords
  input1Owner : DigestWords
  output0Owner : DigestWords
  output1Owner : DigestWords
  normal0Owner : DigestWords
  normal1Owner : DigestWords
  normalPrefix : Word K
  normal : Word K
  unlocked : Word K
  occupied0 : Word K
  approvalOccupied : Word K

abbrev Gates (g : Graph K) (selector : Word K) (left right : DigestWords) :=
  ∀ lane : Fin 7, GateData g selector (left lane) (right lane)

/-- Exact gates present in private_spend/circuit.rs. This is finite compiler
binding data, not branch validity or a wished-for equality about z. -/
structure RouteChecked (g : Graph K) (r : Roles) (v : RouteRoles) where
  selector : SelectorData g v.modes
  normalFirst : SubData g (.constant 1) (v.modes 1) v.normalPrefix
  normalLast : SubData g v.normalPrefix (v.modes 3) v.normal
  unlockedAdd : AddData g (v.modes 4) (v.modes 5) v.unlocked
  approvalActive : MulData g (v.modes 1) v.occupied0 v.approvalOccupied
  normalOutput0 : Gates g v.normal v.output0Owner v.normal0Owner
  normalOutput1 : Gates g (.constant 1) v.output1Owner v.normal1Owner
  approvalInput : Gates g v.approvalOccupied v.input0Owner r.accumulator
  approvalOutput : Gates g (v.modes 1) v.output0Owner r.nextAccumulator
  finalValue : Gates g (v.modes 2) v.input0Owner r.valueOwner
  finalAccumulator : Gates g (v.modes 2) v.input1Owner r.accumulator
  lockOutput : Gates g (v.modes 3) v.output0Owner r.htlcOwner
  unlockedInput : Gates g v.unlocked v.input0Owner r.htlcOwner

/-- Gate equations for ordinary/approval/final/lock/claim/refund, sharing the
same role hashes and arbitrary satisfying assignment. This is not all six
transaction validity predicates (CM/NF/Merkle/SHA/history remain separate). -/
structure RouteEquations (z : Nat → K) (r : Roles) (v : RouteRoles) : Prop where
  uniqueMode : ∃! i : Fin 6, natural z (v.modes i) = 1
  normal : read z v.normal = 1 - read z (v.modes 1) - read z (v.modes 3)
  unlocked : read z v.unlocked = read z (v.modes 4) + read z (v.modes 5)
  approvalActive : read z v.approvalOccupied = read z (v.modes 1) * read z v.occupied0
  normalOutput0 : ∀ lane, read z v.normal * (read z (v.output0Owner lane) - read z (v.normal0Owner lane)) = 0
  normalOutput1 : ∀ lane, read z (v.output1Owner lane) = read z (v.normal1Owner lane)
  approvalInput : ∀ lane, read z v.approvalOccupied * (read z (v.input0Owner lane) - read z (r.accumulator lane)) = 0
  approvalOutput : ∀ lane, read z (v.modes 1) * (read z (v.output0Owner lane) - read z (r.nextAccumulator lane)) = 0
  finalValue : ∀ lane, read z (v.modes 2) * (read z (v.input0Owner lane) - read z (r.valueOwner lane)) = 0
  finalAccumulator : ∀ lane, read z (v.modes 2) * (read z (v.input1Owner lane) - read z (r.accumulator lane)) = 0
  lockOutput : ∀ lane, read z (v.modes 3) * (read z (v.output0Owner lane) - read z (r.htlcOwner lane)) = 0
  claimRefundInput : ∀ lane, (read z (v.modes 4) + read z (v.modes 5)) * (read z (v.input0Owner lane) - read z (r.htlcOwner lane)) = 0

theorem source_route_equations (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (r : Roles) (v : RouteRoles)
    (checked : RouteChecked g r v) : RouteEquations z r v := by
  have normalFirst := sub_sound g layout z sem checked.normalFirst
  have normalLast := sub_sound g layout z sem checked.normalLast
  have unlocked := add_sound g layout z sem checked.unlockedAdd
  refine {
    uniqueMode := unique_mode_from_topology g layout z sem v.modes checked.selector
    normal := ?_, unlocked := unlocked
    approvalActive := mul_sound g layout z sem checked.approvalActive
    normalOutput0 := fun i => gate_equation g layout z sem _ _ _ (checked.normalOutput0 i)
    normalOutput1 := ?_
    approvalInput := fun i => gate_equation g layout z sem _ _ _ (checked.approvalInput i)
    approvalOutput := fun i => gate_equation g layout z sem _ _ _ (checked.approvalOutput i)
    finalValue := fun i => gate_equation g layout z sem _ _ _ (checked.finalValue i)
    finalAccumulator := fun i => gate_equation g layout z sem _ _ _ (checked.finalAccumulator i)
    lockOutput := fun i => gate_equation g layout z sem _ _ _ (checked.lockOutput i)
    claimRefundInput := ?_ }
  · rw [normalLast, normalFirst]
    rfl
  · intro i
    have h := gate_equation g layout z sem _ _ _ (checked.normalOutput1 i)
    simpa only [NativeLaunchConstraintAdapterBridge.read, one_mul, sub_eq_zero] using h
  · intro i
    have h := gate_equation g layout z sem _ _ _ (checked.unlockedInput i)
    simpa only [unlocked] using h

/-- Explicit current compiler/source binding contract. Its construction must
use current descriptors/source; no axiom or assumed compiler success is added. -/
structure CurrentCallMatch (g : Graph K) (r : Roles) (v : RouteRoles) where
  calls : CallsChecked g r
  routes : RouteChecked g r v

theorem current_source_semantic_join (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (r : Roles) (v : RouteRoles)
    (binding : CurrentCallMatch g r v) : RoleEquations z r ∧ RouteEquations z r v :=
  ⟨source_role_equations g layout z sem r binding.calls,
   source_route_equations g layout z sem r v binding.routes⟩
end
end HegemonCrypto.NativePrivateSpendCurrentSourceCallContract
