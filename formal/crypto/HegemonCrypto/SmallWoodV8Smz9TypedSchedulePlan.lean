import HegemonCrypto.SmallWoodV8Smz9TypedScheduleSources

/-! Fixed source call order. Every role is executed, including inactive slots.
Only the two source input slots and two output slots are selected. -/

namespace HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
set_option Elab.async false
set_option maxHeartbeats 600000
set_option maxRecDepth 10000

inductive Role where
  | transactionPrf
  | inputNote (input block : Nat)
  | inputMerkle (input level : Nat)
  | inputNullifier (input : Nat)
  | outputNote (output block : Nat)
  | actionIntent (block : Nat)
  | policy (block : Nat)
  | currentAccumulator (block : Nat)
  | nextAccumulator (block : Nat)
  | valueLock (block : Nat)
  | stableConfigChunk (chunk : Nat)
  | stableConfigNode (node : Nat)
  | stableLeaf (after : Bool)
  | stablePath (after : Bool) (level : Nat)
  | issuerCommitment
  | issuerAuthorization
  | padding
deriving DecidableEq, Repr

inductive Plan where
  | sponge (role : Role) (domain : Nat) (inputs : List Nat)
      (blocks block : Nat) (previous : Option Nat)
  | compress (role : Role) (domain : Nat) (left right : List Nat)
  | padding
deriving Repr

def Plan.role : Plan → Role
  | .sponge role _ _ _ _ _ => role
  | .compress role _ _ _ => role
  | .padding => .padding

def finalDigest (earlier : Nat → State) (call : Nat) : List Nat :=
  (stateWords (earlier call)).take 7

def previousSponge (call block : Nat) : Option Nat := if block = 0 then none else some (call-1)

def orient (position level : Nat) (current sibling : List Nat) : List Nat × List Nat :=
  if ((position >>> level) &&& 1) = 0 then (current,sibling) else (sibling,current)

theorem orient_is_source_bit (position level : Nat) (current sibling : List Nat) :
    orient position level current sibling =
      if (position / 2^level) % 2 = 0 then (current,sibling) else (sibling,current) := by
  simp only [orient, Nat.shiftRight_eq_div_pow, Nat.and_one_is_mod]

theorem stable_asset_mask_exact (asset : Nat) : asset &&& 15 = asset % 16 := by
  exact Nat.and_two_pow_sub_one_eq_mod asset 4

def sourceInputPlan (statement : V8PublicStatement) (witness : V8Witness)
    (earlier : Nat → State) (call input first : Nat) : Plan :=
  let offset := call-first
  if offset < 3 then
    .sponge (.inputNote input offset) 1 (sourceNoteWords (inputAt witness input).note)
      3 offset (previousSponge call offset)
  else if offset < 35 then
    let level := offset-3
    let operands := orient (inputAt witness input).position level
      (finalDigest earlier (call-1)) (fixedWords 7 ((inputAt witness input).siblings.getD level []))
    .compress (.inputMerkle input level) 4 operands.1 operands.2
  else
    .sponge (.inputNullifier input) 2
      (sourceNullifierWords statement witness (wordAtState (earlier 0) 0) input) 1 0 none

def sourceCallPlan (statement : V8PublicStatement) (witness : V8Witness)
    (call : Nat) (earlier : Nat → State) : Plan :=
  if call = 0 then
    .sponge .transactionPrf 2 (globalSpendKey statement witness) 1 0 none
  else if call < 37 then sourceInputPlan statement witness earlier call 0 1
  else if call < 73 then sourceInputPlan statement witness earlier call 1 37
  else if call < 79 then
    let output := (call-73)/3
    let block := (call-73)%3
    .sponge (.outputNote output block) 1 (sourceNoteWords (outputAt witness output).note)
      3 block (previousSponge call block)
  else if call < 94 then
    let block := call-79
    .sponge (.actionIntent block) poseidon2V8ActionIntentDomain (exactV8ActionIntentProjection statement)
      15 block (previousSponge call block)
  else if call < 98 then
    let block := call-94
    .sponge (.policy block) 7 (sourcePolicyWords witness.authorization)
      4 block (previousSponge call block)
  else if call < 101 then
    let block := call-98
    .sponge (.currentAccumulator block) 6 (sourceAccumulatorWords witness.authorization.current)
      3 block (previousSponge call block)
  else if call < 104 then
    let block := call-101
    .sponge (.nextAccumulator block) 6 (sourceAccumulatorWords (effectiveNext witness.authorization))
      3 block (previousSponge call block)
  else if call < 106 then
    let block := call-104
    .sponge (.valueLock block) 8 (sourceValueLockWords witness.authorization.current)
      2 block (previousSponge call block)
  else if call < 110 then
    let chunk := call-106
    .compress (.stableConfigChunk chunk) (stablecoinV8ConfigChunkDomains.getD chunk 0)
      (fixedWords 7 ((stableConfigWords witness).drop (chunk*14)))
      (fixedWords 7 ((stableConfigWords witness).drop (chunk*14+7)))
  else if call = 110 then
    .compress (.stableConfigNode 0) stablecoinV8DomainConfigNode0
      (finalDigest earlier 106) (finalDigest earlier 107)
  else if call = 111 then
    .compress (.stableConfigNode 1) stablecoinV8DomainConfigNode1
      (finalDigest earlier 108) (finalDigest earlier 109)
  else if call = 112 then
    .compress (.stableConfigNode 2) stablecoinV8DomainConfigRoot
      (finalDigest earlier 110) (finalDigest earlier 111)
  else if call < 115 then
    let after := call = 114
    .compress (.stableLeaf after) stablecoinV8DomainStateLeaf
      (finalDigest earlier 112) (stableLeafRight statement witness after)
  else if call < 123 then
    let level := (call-115)/2
    let after := (call-115)%2 = 1
    let current := if level = 0 then 113+(call-115)%2 else call-2
    let operands := orient (statement.stablecoin.assetId &&& 15) level
      (finalDigest earlier current) (stableSibling witness level)
    .compress (.stablePath after level) (stablecoinV8DomainStateNode0+level) operands.1 operands.2
  else if call = 123 then
    .compress .issuerCommitment stablecoinV8DomainIssuerCommitment (stableSecret witness)
      [statement.stablecoin.assetId, statement.stablecoin.policyVersion, 0, 0, 0, 0, 0]
  else if call = 124 then
    .compress .issuerAuthorization stablecoinV8DomainIssuerAuthorization
      (stableSecret witness) (fixedWords 7 statement.stablecoin.actionIntent)
  else .padding

def preparePlan (earlier : Nat → State) : Plan → State
  | .sponge _ domain inputs blocks block previous =>
      spongeFrame domain inputs blocks
        (match previous with | none => zeroState | some call => earlier call) block
  | .compress _ domain left right => compressFrame domain left right
  | .padding => zeroState

def builtFinals (statement : V8PublicStatement) (witness : V8Witness) : Nat → Nat → State
  | 0 => fun _ => zeroState
  | n+1 =>
      let earlier := builtFinals statement witness n
      let final := runState (preparePlan earlier (sourceCallPlan statement witness n earlier))
      fun call => if call = n then final else earlier call

def scheduledInitial (statement : V8PublicStatement) (witness : V8Witness) (call : Nat) : State :=
  let earlier := builtFinals statement witness call
  preparePlan earlier (sourceCallPlan statement witness call earlier)

def scheduledFinal (statement : V8PublicStatement) (witness : V8Witness) (call : Nat) : State :=
  runState (scheduledInitial statement witness call)

def typedLiveInitialStates (statement : V8PublicStatement) (witness : V8Witness) :
    HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization.LiveInitialStates :=
  fun call => scheduledInitial statement witness call.val

theorem built_finals_readback (statement : V8PublicStatement) (witness : V8Witness)
    (count call : Nat) (before : call < count) :
    builtFinals statement witness count call = scheduledFinal statement witness call := by
  induction count with
  | zero => omega
  | succ n ih =>
    by_cases last : call = n
    · subst call
      simp only [builtFinals, if_true, scheduledFinal, scheduledInitial]
    · simp only [builtFinals, if_neg last]
      exact ih (by omega)

theorem every_call_has_actual_kernel_final (statement : V8PublicStatement) (witness : V8Witness)
    (call : Nat) :
    stateWords (scheduledFinal statement witness call) =
      Poseidon2Width16Kernel.permutation (stateWords (scheduledInitial statement witness call)) :=
  run_state_is_exact_primitive _

theorem live_schedule_readback (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (lane : Fin 16) :
    typedLiveInitialStates statement witness call lane = scheduledInitial statement witness call.val lane := rfl

theorem live_schedule_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (lane : Fin 16) :
    (typedLiveInitialStates statement witness call lane).val < Poseidon2Width16Kernel.fieldModulus :=
  (typedLiveInitialStates statement witness call lane).isLt

end HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule

