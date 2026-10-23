import HegemonCrypto.NativePrivateSpendCompffPrimitiveGames
import SmzaRoleDomainConditioning

/-! Exact current owner-role evaluators and conditional same-execution games.

This is a NEW current-model component, not an RP205 endpoint successor.
Ordinary owners include the successor ORDINARY_OWNER_DOMAIN wrapper sponge;
the ordinary/value claw therefore differs from the historical SingleKey/raw
compression claw. Value, accumulator and HTLC owners use COMPFF01.

The role-game union invokes the existing PR205 generic finite-state theorem.
It neither constructs accepted-failure coverage nor supplies any cryptographic
game bound. Nullifier, Merkle, note, transcript and proof-system failure events
remain separate obligations. Source/compiler interpretation remains trusted.
This module grants no release authority.
-/
namespace HegemonCrypto.NativePrivateSpendCurrentRoleGames

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.NativePrivateSpendCompffPrimitiveGames
namespace Union
export HegemonCrypto.SmallWood.SmzaRoleDomainConditioning
  (eventProjection finiteNormSquared same_execution_event_union_bound)
end Union
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false

abbrev Key := CanonicalSingleKey
abbrev Tags := Fin 3 → CanonicalDigest
abbrev Intent := Fin 54 → Fin fieldModulus
abbrev ApprovalBits := Fin 3 → Fin 2
abbrev Bytes32Words := Fin 8 → Fin (2^32)
abbrev Recipient := Fin 4 → Fin fieldModulus

def ordinaryOwnerDomain : Nat := 0x50534f574e520001
def policyDomain : Nat := 0x48415038504f4c01
def intentDomain : Nat := 0x5053494e544e0001
def accumulatorDomain : Nat := 0x5053414343550001
def htlcPolicyDomain : Nat := 0x505348504f4c0001

def words {n : Nat} (input : Fin n → Fin fieldModulus) : List Nat :=
  List.ofFn fun i => (input i).val

def byteWords (input : Bytes32Words) : List Nat :=
  List.ofFn fun i => (input i).val

def zeroDigest : Digest := List.replicate 7 0

/-- Native circuit `who = hash(SINGLE,key7); new_owner = ordinary(who)`. -/
def ordinaryOwner (key : Key) : Digest :=
  poseidon2V8Sponge ordinaryOwnerDomain (singleKeyEvaluator key)

def policyMessage (tags : Tags) : List Nat :=
  [2, 3] ++ (List.ofFn fun signer => canonicalDigestWords (tags signer)).flatten ++
    List.replicate 21 0

def policyDigest (tags : Tags) : Digest :=
  poseidon2V8Sponge policyDomain (policyMessage tags)

structure ValueOwnerInput where
  key : Key
  tags : Tags

def valueInner (tags : Tags) : Digest :=
  CurrentCompression.compress14 nativeValueLockDomain (policyDigest tags) zeroDigest

def valueOwner (input : ValueOwnerInput) : Digest :=
  CurrentCompression.compress14
    HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry.currentAuthorizationBindingDomain
    (canonicalSingleKeyWords input.key) (valueInner input.tags)

structure AccumulatorOwnerInput where
  key : Key
  tags : Tags
  intent : Intent
  approved : ApprovalBits

def approvalWords (bits : ApprovalBits) : List Nat :=
  List.ofFn fun i => (bits i).val

def approvalCount (bits : ApprovalBits) : Nat := (approvalWords bits).sum

def accumulatorMessage (input : AccumulatorOwnerInput) : List Nat :=
  policyDigest input.tags ++ poseidon2V8Sponge intentDomain (words input.intent) ++
    [2, 3, approvalCount input.approved] ++ approvalWords input.approved ++
    List.replicate 3 0

def accumulatorOwner (input : AccumulatorOwnerInput) : Digest :=
  CurrentCompression.compress14
    HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry.currentAuthorizationBindingDomain
    (canonicalSingleKeyWords input.key)
    (poseidon2V8Sponge accumulatorDomain (accumulatorMessage input))

structure HtlcOwnerInput where
  chain : Bytes32Words
  hashlock : Bytes32Words
  claimAuthority : CanonicalDigest
  refundAuthority : CanonicalDigest
  claimRecipient : Recipient
  refundRecipient : Recipient
  timeout : Fin (2^48)
  key : Key

def htlcMessage (input : HtlcOwnerInput) : List Nat :=
  byteWords input.chain ++ byteWords input.hashlock ++
    canonicalDigestWords input.claimAuthority ++ canonicalDigestWords input.refundAuthority ++
    words input.claimRecipient ++ words input.refundRecipient ++ [input.timeout.val]

def htlcOwner (input : HtlcOwnerInput) : Digest :=
  CurrentCompression.compress14 nativeHtlcOwnerDomain
    (canonicalSingleKeyWords input.key) (poseidon2V8Sponge htlcPolicyDomain (htlcMessage input))

def ordinaryCollision (pair : Key × Key) : Prop :=
  pair.1 ≠ pair.2 ∧ ordinaryOwner pair.1 = ordinaryOwner pair.2

/-- A collision at the successor wrapper sponge on two unequal effective
SingleKey digests, separate from the retained SingleKey game. -/
def ordinaryWrapperCollision (pair : Digest × Digest) : Prop :=
  pair.1 ≠ pair.2 ∧
    poseidon2V8Sponge ordinaryOwnerDomain pair.1 =
      poseidon2V8Sponge ordinaryOwnerDomain pair.2

theorem ordinary_collision_covered (pair : Key × Key)
    (collision : ordinaryCollision pair) :
    singleKeyCollision pair ∨
      ordinaryWrapperCollision (singleKeyEvaluator pair.1, singleKeyEvaluator pair.2) := by
  rcases collision with ⟨different, sameOwner⟩
  by_cases sameAuthority : singleKeyEvaluator pair.1 = singleKeyEvaluator pair.2
  · exact Or.inl ⟨different, sameAuthority⟩
  · exact Or.inr ⟨sameAuthority, sameOwner⟩

def valueCollision (pair : ValueOwnerInput × ValueOwnerInput) : Prop :=
  pair.1 ≠ pair.2 ∧ valueOwner pair.1 = valueOwner pair.2

def accumulatorCollision (pair : AccumulatorOwnerInput × AccumulatorOwnerInput) : Prop :=
  pair.1 ≠ pair.2 ∧ accumulatorOwner pair.1 = accumulatorOwner pair.2

def htlcCollision (pair : HtlcOwnerInput × HtlcOwnerInput) : Prop :=
  pair.1 ≠ pair.2 ∧ htlcOwner pair.1 = htlcOwner pair.2

/-- Current owner-role claws use the actual wrapper and full owner composers. -/
def ordinaryValueClaw (pair : Key × ValueOwnerInput) : Prop :=
  ordinaryOwner pair.1 = valueOwner pair.2
theorem ordinary_value_claw_exact (pair : Key × ValueOwnerInput) :
    ordinaryValueClaw pair ↔
      poseidon2V8Sponge ordinaryOwnerDomain
        (poseidon2V8Sponge
          HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry.currentSourceSingleKeyDomain
          (canonicalSingleKeyWords pair.1)) =
        CurrentCompression.compress14
          HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry.currentAuthorizationBindingDomain
          (canonicalSingleKeyWords pair.2.key) (valueInner pair.2.tags) := Iff.rfl

def ordinaryAccumulatorClaw (pair : Key × AccumulatorOwnerInput) : Prop :=
  ordinaryOwner pair.1 = accumulatorOwner pair.2
def ordinaryHtlcClaw (pair : Key × HtlcOwnerInput) : Prop :=
  ordinaryOwner pair.1 = htlcOwner pair.2
def valueAccumulatorClaw (pair : ValueOwnerInput × AccumulatorOwnerInput) : Prop :=
  valueOwner pair.1 = accumulatorOwner pair.2
def valueHtlcClaw (pair : ValueOwnerInput × HtlcOwnerInput) : Prop :=
  valueOwner pair.1 = htlcOwner pair.2
def accumulatorHtlcClaw (pair : AccumulatorOwnerInput × HtlcOwnerInput) : Prop :=
  accumulatorOwner pair.1 = htlcOwner pair.2

structure RoleGameOutputs where
  ordinary : Key × Key
  value : ValueOwnerInput × ValueOwnerInput
  accumulator : AccumulatorOwnerInput × AccumulatorOwnerInput
  htlc : HtlcOwnerInput × HtlcOwnerInput
  ordinaryValue : Key × ValueOwnerInput
  ordinaryAccumulator : Key × AccumulatorOwnerInput
  ordinaryHtlc : Key × HtlcOwnerInput
  valueAccumulator : ValueOwnerInput × AccumulatorOwnerInput
  valueHtlc : ValueOwnerInput × HtlcOwnerInput
  accumulatorHtlc : AccumulatorOwnerInput × HtlcOwnerInput

/-- Four owner collisions and six distinct-role claws, on one output readout. -/
def roleGameWin (index : Fin 10) (out : RoleGameOutputs) : Prop :=
  match index.val with
  | 0 => ordinaryCollision out.ordinary
  | 1 => valueCollision out.value
  | 2 => accumulatorCollision out.accumulator
  | 3 => htlcCollision out.htlc
  | 4 => ordinaryValueClaw out.ordinaryValue
  | 5 => ordinaryAccumulatorClaw out.ordinaryAccumulator
  | 6 => ordinaryHtlcClaw out.ordinaryHtlc
  | 7 => valueAccumulatorClaw out.valueAccumulator
  | 8 => valueHtlcClaw out.valueHtlc
  | _ => accumulatorHtlcClaw out.accumulatorHtlc

/-- The existing generic PR205 union theorem, instantiated once. -/
theorem same_execution_role_games_le_sum
    {Basis : Type*} [Fintype Basis]
    (outputs : Basis → RoleGameOutputs) (state : Basis → ℂ) :
    Union.finiteNormSquared
        (Union.eventProjection (fun basis => ∃ index, roleGameWin index (outputs basis)) state) ≤
      ∑ index : Fin 10,
        Union.finiteNormSquared
          (Union.eventProjection (fun basis => roleGameWin index (outputs basis)) state) := by
  exact Union.same_execution_event_union_bound
    (fun index basis => roleGameWin index (outputs basis)) state

/-- Conditional closure only: same-state failure coverage AND all ten actual
current role-game bounds must be supplied. No old claw advantage is relabeled. -/
theorem failure_le_assumed_role_game_bounds
    {Basis : Type*} [Fintype Basis]
    (outputs : Basis → RoleGameOutputs) (state : Basis → ℂ) (failure : Basis → Prop)
    (coverage : ∀ basis, failure basis → ∃ index, roleGameWin index (outputs basis))
    (bounds : Fin 10 → ℝ)
    (games : ∀ index : Fin 10,
      Union.finiteNormSquared
        (Union.eventProjection (fun basis => roleGameWin index (outputs basis)) state) ≤ bounds index) :
    Union.finiteNormSquared (Union.eventProjection failure state) ≤ ∑ index, bounds index := by
  have monotone : Union.finiteNormSquared (Union.eventProjection failure state) ≤
      Union.finiteNormSquared
        (Union.eventProjection (fun basis => ∃ index, roleGameWin index (outputs basis)) state) := by
    unfold Union.finiteNormSquared Union.eventProjection
    apply Finset.sum_le_sum
    intro basis _
    by_cases bad : failure basis
    · simp only [if_pos bad, if_pos (coverage basis bad)]
      exact le_rfl
    · simp only [if_neg bad, Complex.normSq_zero]
      exact Complex.normSq_nonneg _
  exact monotone.trans
    ((same_execution_role_games_le_sum outputs state).trans
      (Finset.sum_le_sum fun index _ => games index))

end
end HegemonCrypto.NativePrivateSpendCurrentRoleGames
