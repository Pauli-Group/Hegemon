import Hegemon.Bytes

namespace Hegemon
namespace Essence
namespace Core

abbrev Digest := Nat
abbrev AssetId := Nat
abbrev ChainId := Nat
abbrev MessageNonce := Nat
abbrev VerifierVersion := Nat

def nativeAsset : AssetId := 0
def u32Limit : Nat := 4294967296
def u64Limit : Nat := 18446744073709551616

def fitsU32 (value : Nat) : Prop := value < u32Limit
def fitsU64 (value : Nat) : Prop := value < u64Limit

structure AssetDelta where
  assetId : AssetId
  delta : Int
deriving DecidableEq, Repr

structure AssetBalance where
  assetId : AssetId
  amount : Nat
deriving DecidableEq, Repr

structure LedgerState where
  supply : Nat
  assetBalances : List AssetBalance
  spentNullifiers : List Digest
  commitments : List Digest
  bridgeReplayKeys : List Digest
deriving DecidableEq, Repr

structure SpendAuthorization where
  spendKey : Digest
  statementDigest : Digest
  keyOwnsInputs : Prop
  authorizationValid : Prop

structure NativeMintAuthorization where
  authority : Digest
  amount : Nat
  scheduleDigest : Digest
  scheduleAllowsMint : Prop
  amountBound : Prop

structure AssetAuthorization where
  authority : Digest
  assetId : AssetId
  delta : Int
  policyDigest : Digest
  policyAllowsDelta : Prop
  amountBound : Prop

structure BridgeReceipt where
  sourceChainId : ChainId
  sourceMessageNonce : MessageNonce
  sourceEventId : Digest
  verifierVersion : VerifierVersion
  assetId : AssetId
  amount : Nat
  destinationChainId : ChainId
  recipientCommitment : Digest
  finalityDepth : Nat
  replayKey : Digest
  messageHash : Digest
  payloadHash : Digest
deriving DecidableEq, Repr

structure BridgeAuthorization where
  receipt : BridgeReceipt
  verifierAccepted : Prop
  finalityProved : Prop
  sourceEventBound : Prop
  messageHashBound : Prop
  payloadHashBound : Prop
  destinationChainBound : Prop
  amountAssetDeltaBound : Prop

structure ProofStatementBinding where
  statementDigest : Digest
  publicInputsBound : Prop
  actionHashBound : Prop

structure Action where
  inputNullifiers : List Digest
  outputCommitments : List Digest
  outputCiphertextTags : List Digest
  nativeMint : Nat
  nativeBurn : Nat
  assetDeltas : List AssetDelta
  spendAuthorization : Option SpendAuthorization
  nativeMintAuthorization : Option NativeMintAuthorization
  assetAuthorization : Option AssetAuthorization
  bridgeAuthorization : Option BridgeAuthorization
  proofBinding : Option ProofStatementBinding

structure Block where
  actions : List Action

structure ObserverView where
  supplyBefore : Nat
  supplyAfter : Nat
  nullifierCount : Nat
  commitmentCount : Nat
  ciphertextCount : Nat
  bridgeReplayCount : Nat
  bridgeSourceChain : Option ChainId
  bridgeAsset : Option AssetId
  bridgeAmount : Option Nat
deriving DecidableEq, Repr

structure PrivateMaterial where
  spendSecrets : List Nat
  noteOpenings : List Nat
  witnessRandomness : List Nat
  proverRandomness : Nat
deriving DecidableEq, Repr

structure SpendAuthorizationData where
  spendKey : Digest
  statementDigest : Digest
deriving DecidableEq, Repr

structure NativeMintAuthorizationData where
  authority : Digest
  amount : Nat
  scheduleDigest : Digest
deriving DecidableEq, Repr

structure AssetAuthorizationData where
  authority : Digest
  assetId : AssetId
  delta : Int
  policyDigest : Digest
deriving DecidableEq, Repr

structure BridgeAuthorizationData where
  receipt : BridgeReceipt
deriving DecidableEq, Repr

structure ProofStatementBindingData where
  statementDigest : Digest
deriving DecidableEq, Repr

structure ActionPublicData where
  inputNullifiers : List Digest
  outputCommitments : List Digest
  outputCiphertextTags : List Digest
  nativeMint : Nat
  nativeBurn : Nat
  assetDeltas : List AssetDelta
  spendAuthorization : Option SpendAuthorizationData
  nativeMintAuthorization : Option NativeMintAuthorizationData
  assetAuthorization : Option AssetAuthorizationData
  bridgeAuthorization : Option BridgeAuthorizationData
  proofBinding : Option ProofStatementBindingData
deriving DecidableEq, Repr

structure LedgerPublicData where
  supply : Nat
  assetBalances : List AssetBalance
  spentNullifiers : List Digest
  commitments : List Digest
  bridgeReplayKeys : List Digest
deriving DecidableEq, Repr

inductive CanonicalTerm where
  | action (data : ActionPublicData)
  | ledger (data : LedgerPublicData)
  | block (actions : List ActionPublicData)
  | observer (view : ObserverView)
deriving DecidableEq, Repr

def spendAuthorizationData
    (authorization : SpendAuthorization) : SpendAuthorizationData :=
  { spendKey := authorization.spendKey
    statementDigest := authorization.statementDigest }

def nativeMintAuthorizationData
    (authorization : NativeMintAuthorization) : NativeMintAuthorizationData :=
  { authority := authorization.authority
    amount := authorization.amount
    scheduleDigest := authorization.scheduleDigest }

def assetAuthorizationData
    (authorization : AssetAuthorization) : AssetAuthorizationData :=
  { authority := authorization.authority
    assetId := authorization.assetId
    delta := authorization.delta
    policyDigest := authorization.policyDigest }

def bridgeAuthorizationData
    (authorization : BridgeAuthorization) : BridgeAuthorizationData :=
  { receipt := authorization.receipt }

def proofStatementBindingData
    (binding : ProofStatementBinding) : ProofStatementBindingData :=
  { statementDigest := binding.statementDigest }

def actionPublicData (action : Action) : ActionPublicData :=
  { inputNullifiers := action.inputNullifiers
    outputCommitments := action.outputCommitments
    outputCiphertextTags := action.outputCiphertextTags
    nativeMint := action.nativeMint
    nativeBurn := action.nativeBurn
    assetDeltas := action.assetDeltas
    spendAuthorization := action.spendAuthorization.map spendAuthorizationData
    nativeMintAuthorization :=
      action.nativeMintAuthorization.map nativeMintAuthorizationData
    assetAuthorization := action.assetAuthorization.map assetAuthorizationData
    bridgeAuthorization := action.bridgeAuthorization.map bridgeAuthorizationData
    proofBinding := action.proofBinding.map proofStatementBindingData }

def ledgerPublicData (state : LedgerState) : LedgerPublicData :=
  { supply := state.supply
    assetBalances := state.assetBalances
    spentNullifiers := state.spentNullifiers
    commitments := state.commitments
    bridgeReplayKeys := state.bridgeReplayKeys }

def actionCanonicalTerm (action : Action) : CanonicalTerm :=
  CanonicalTerm.action (actionPublicData action)

def ledgerCanonicalTerm (state : LedgerState) : CanonicalTerm :=
  CanonicalTerm.ledger (ledgerPublicData state)

def blockCanonicalTerm (block : Block) : CanonicalTerm :=
  CanonicalTerm.block (block.actions.map actionPublicData)

def observerCanonicalTerm (view : ObserverView) : CanonicalTerm :=
  CanonicalTerm.observer view

def decodeCanonicalActionTerm : CanonicalTerm -> Option ActionPublicData
  | CanonicalTerm.action data => some data
  | _ => none

def checkedSupply (parent mint burn : Nat) : Option Nat :=
  if burn <= parent + mint then
    some ((parent + mint) - burn)
  else
    none

def checkedApplyDelta (balance : Nat) (delta : Int) : Option Nat :=
  if delta < 0 then
    if delta.natAbs <= balance then
      some (balance - delta.natAbs)
    else
      none
  else
    some (balance + delta.natAbs)

def balanceOf (assetId : AssetId) : List AssetBalance -> Nat
  | [] => 0
  | balance :: rest =>
      if balance.assetId = assetId then
        balance.amount
      else
        balanceOf assetId rest

def assetBalanceIds (balances : List AssetBalance) : List AssetId :=
  balances.map fun balance => balance.assetId

def assetBalancesUnique (balances : List AssetBalance) : Prop :=
  (assetBalanceIds balances).Nodup

def nativeBalanceMatchesSupply (state : LedgerState) : Prop :=
  balanceOf nativeAsset state.assetBalances = state.supply

def assetDeltaFor (assetId : AssetId) : List AssetDelta -> Int
  | [] => 0
  | delta :: rest =>
      if delta.assetId = assetId then
        delta.delta + assetDeltaFor assetId rest
      else
        assetDeltaFor assetId rest

def bridgeReceiptFromAction (action : Action) : Option BridgeReceipt :=
  match action.bridgeAuthorization with
  | none => none
  | some authorization => some authorization.receipt

def bridgeReplayKeysFromAction (action : Action) : List Digest :=
  match bridgeReceiptFromAction action with
  | none => []
  | some receipt => [receipt.replayKey]

def bridgeSourceChainFromAction (action : Action) : Option ChainId :=
  match bridgeReceiptFromAction action with
  | none => none
  | some receipt => some receipt.sourceChainId

def bridgeAssetFromAction (action : Action) : Option AssetId :=
  match bridgeReceiptFromAction action with
  | none => none
  | some receipt => some receipt.assetId

def bridgeAmountFromAction (action : Action) : Option Nat :=
  match bridgeReceiptFromAction action with
  | none => none
  | some receipt => some receipt.amount

def actionProofBound (action : Action) : Prop :=
  ∃ binding,
    action.proofBinding = some binding
      ∧ binding.publicInputsBound
      ∧ binding.actionHashBound

def actionSpendAuthorized (action : Action) : Prop :=
  action.inputNullifiers = []
    ∨ ∃ authorization,
      action.spendAuthorization = some authorization
        ∧ authorization.keyOwnsInputs
        ∧ authorization.authorizationValid

def actionNoTheft (action : Action) : Prop :=
  actionProofBound action ∧ actionSpendAuthorized action

def actionNativeMintAuthorized (action : Action) : Prop :=
  action.nativeMint = 0
    ∨ ∃ authorization,
      action.nativeMintAuthorization = some authorization
        ∧ authorization.amount = action.nativeMint
        ∧ authorization.scheduleAllowsMint
        ∧ authorization.amountBound

def deltaMatchesAssetAuthorization
    (action : Action)
    (delta : AssetDelta) : Prop :=
  ∃ authorization,
    action.assetAuthorization = some authorization
      ∧ authorization.assetId = delta.assetId
      ∧ authorization.delta = delta.delta
      ∧ authorization.policyAllowsDelta
      ∧ authorization.amountBound

def deltaMatchesBridgeAuthorization
    (action : Action)
    (delta : AssetDelta) : Prop :=
  ∃ authorization,
    action.bridgeAuthorization = some authorization
      ∧ authorization.receipt.assetId = delta.assetId
      ∧ delta.delta = Int.ofNat authorization.receipt.amount
      ∧ authorization.amountAssetDeltaBound

def actionAssetIsolated (action : Action) : Prop :=
  ∀ delta, delta ∈ action.assetDeltas ->
    delta.assetId = nativeAsset
      ∨ delta.delta = 0
      ∨ deltaMatchesAssetAuthorization action delta
      ∨ deltaMatchesBridgeAuthorization action delta

def actionAssetConserved
    (before : LedgerState)
    (action : Action)
    (after : LedgerState) : Prop :=
  ∀ assetId,
    checkedApplyDelta
        (balanceOf assetId before.assetBalances)
        (assetDeltaFor assetId action.assetDeltas) =
      some (balanceOf assetId after.assetBalances)

def actionBridgeSafe (state : LedgerState) (action : Action) : Prop :=
  match action.bridgeAuthorization with
  | none => True
  | some authorization =>
      authorization.receipt.replayKey ∉ state.bridgeReplayKeys
        ∧ authorization.receipt.amount > 0
        ∧ authorization.receipt.assetId ≠ nativeAsset
        ∧ authorization.verifierAccepted
        ∧ authorization.finalityProved
        ∧ authorization.sourceEventBound
        ∧ authorization.messageHashBound
        ∧ authorization.payloadHashBound
        ∧ authorization.destinationChainBound
        ∧ authorization.amountAssetDeltaBound

def observerView
    (before : LedgerState)
    (action : Action)
    (after : LedgerState) : ObserverView :=
  { supplyBefore := before.supply
    supplyAfter := after.supply
    nullifierCount := action.inputNullifiers.length
    commitmentCount := action.outputCommitments.length
    ciphertextCount := action.outputCiphertextTags.length
    bridgeReplayCount := (bridgeReplayKeysFromAction action).length
    bridgeSourceChain := bridgeSourceChainFromAction action
    bridgeAsset := bridgeAssetFromAction action
    bridgeAmount := bridgeAmountFromAction action }

def observerViewWithPrivate
    (before : LedgerState)
    (action : Action)
    (after : LedgerState)
    (_privateMaterial : PrivateMaterial) : ObserverView :=
  observerView before action after

def bridgeReceiptWithinEncodingBounds (receipt : BridgeReceipt) : Prop :=
  fitsU64 receipt.sourceChainId
    ∧ fitsU64 receipt.sourceMessageNonce
    ∧ fitsU64 receipt.sourceEventId
    ∧ fitsU64 receipt.verifierVersion
    ∧ fitsU64 receipt.assetId
    ∧ fitsU64 receipt.amount
    ∧ fitsU64 receipt.destinationChainId
    ∧ fitsU64 receipt.recipientCommitment
    ∧ fitsU64 receipt.finalityDepth
    ∧ fitsU64 receipt.replayKey
    ∧ fitsU64 receipt.messageHash
    ∧ fitsU64 receipt.payloadHash

def assetDeltaWithinEncodingBounds (delta : AssetDelta) : Prop :=
  fitsU64 delta.assetId ∧ fitsU64 delta.delta.natAbs

def assetBalanceWithinEncodingBounds (balance : AssetBalance) : Prop :=
  fitsU64 balance.assetId ∧ fitsU64 balance.amount

def actionEncodingBounded (action : Action) : Prop :=
  fitsU32 action.inputNullifiers.length
    ∧ (∀ value, value ∈ action.inputNullifiers -> fitsU64 value)
    ∧ fitsU32 action.outputCommitments.length
    ∧ (∀ value, value ∈ action.outputCommitments -> fitsU64 value)
    ∧ fitsU32 action.outputCiphertextTags.length
    ∧ (∀ value, value ∈ action.outputCiphertextTags -> fitsU64 value)
    ∧ fitsU64 action.nativeMint
    ∧ fitsU64 action.nativeBurn
    ∧ fitsU32 action.assetDeltas.length
    ∧ (∀ delta, delta ∈ action.assetDeltas ->
        assetDeltaWithinEncodingBounds delta)
    ∧ (match action.spendAuthorization with
        | none => True
        | some authorization =>
            fitsU64 authorization.spendKey
              ∧ fitsU64 authorization.statementDigest)
    ∧ (match action.nativeMintAuthorization with
        | none => True
        | some authorization =>
            fitsU64 authorization.authority
              ∧ fitsU64 authorization.amount
              ∧ fitsU64 authorization.scheduleDigest)
    ∧ (match action.assetAuthorization with
        | none => True
        | some authorization =>
            fitsU64 authorization.authority
              ∧ fitsU64 authorization.assetId
              ∧ fitsU64 authorization.delta.natAbs
              ∧ fitsU64 authorization.policyDigest)
    ∧ (match action.bridgeAuthorization with
        | none => True
        | some authorization =>
            bridgeReceiptWithinEncodingBounds authorization.receipt)
    ∧ (match action.proofBinding with
        | none => True
        | some binding => fitsU64 binding.statementDigest)

def ledgerStateEncodingBounded (state : LedgerState) : Prop :=
  fitsU64 state.supply
    ∧ fitsU32 state.assetBalances.length
    ∧ (∀ balance, balance ∈ state.assetBalances ->
        assetBalanceWithinEncodingBounds balance)
    ∧ fitsU32 state.spentNullifiers.length
    ∧ (∀ value, value ∈ state.spentNullifiers -> fitsU64 value)
    ∧ fitsU32 state.commitments.length
    ∧ (∀ value, value ∈ state.commitments -> fitsU64 value)
    ∧ fitsU32 state.bridgeReplayKeys.length
    ∧ (∀ value, value ∈ state.bridgeReplayKeys -> fitsU64 value)

theorem append_nodup_of_fresh
    {values added : List Digest}
    (valuesNodup : values.Nodup)
    (addedNodup : added.Nodup)
    (fresh : ∀ value, value ∈ added -> value ∉ values) :
    (values ++ added).Nodup := by
  rw [List.nodup_append]
  exact
    ⟨valuesNodup,
      addedNodup,
      by
        intro left leftMem right rightMem same
        subst right
        exact fresh left rightMem leftMem⟩

theorem bridge_replay_keys_from_action_nodup
    (action : Action) :
    (bridgeReplayKeysFromAction action).Nodup := by
  cases h : action.bridgeAuthorization with
  | none =>
      simp [bridgeReplayKeysFromAction, bridgeReceiptFromAction, h]
  | some authorization =>
      simp [bridgeReplayKeysFromAction, bridgeReceiptFromAction, h]

theorem bridge_replay_keys_from_action_fresh
    {state : LedgerState}
    {action : Action}
    (safe : actionBridgeSafe state action) :
    ∀ key, key ∈ bridgeReplayKeysFromAction action ->
      key ∉ state.bridgeReplayKeys := by
  cases h : action.bridgeAuthorization with
  | none =>
      intro key keyMem
      simp [bridgeReplayKeysFromAction, bridgeReceiptFromAction, h] at keyMem
  | some authorization =>
      have safeFacts := safe
      simp [actionBridgeSafe, h] at safeFacts
      intro key keyMem
      have keyEq : key = authorization.receipt.replayKey := by
        simpa [bridgeReplayKeysFromAction, bridgeReceiptFromAction, h]
          using keyMem
      subst key
      exact safeFacts.1

structure Transition
    (before : LedgerState)
    (action : Action)
    (after : LedgerState) : Prop where
  supplyIntegrity :
    checkedSupply before.supply action.nativeMint action.nativeBurn =
      some after.supply
  nativeMintAuthorized :
    actionNativeMintAuthorized action
  priorNullifiersUnique :
    before.spentNullifiers.Nodup
  actionNullifiersUnique :
    action.inputNullifiers.Nodup
  inputNullifiersFresh :
    forall nf, nf ∈ action.inputNullifiers -> nf ∉ before.spentNullifiers
  nextNullifiers :
    after.spentNullifiers = before.spentNullifiers ++ action.inputNullifiers
  nextCommitments :
    after.commitments = before.commitments ++ action.outputCommitments
  ciphertextsMatchCommitments :
    action.outputCiphertextTags.length = action.outputCommitments.length
  assetConservation :
    actionAssetConserved before action after
  bridgeSafety :
    actionBridgeSafe before action
  priorBridgeReplayKeysUnique :
    before.bridgeReplayKeys.Nodup
  nextBridgeReplayKeys :
    after.bridgeReplayKeys =
      before.bridgeReplayKeys ++ bridgeReplayKeysFromAction action
  noTheft :
    actionNoTheft action
  assetIsolation :
    actionAssetIsolated action
  beforeEncodingBounded :
    ledgerStateEncodingBounded before
  actionEncodingBounded :
    actionEncodingBounded action
  afterEncodingBounded :
    ledgerStateEncodingBounded after
  beforeAssetBalancesUnique :
    assetBalancesUnique before.assetBalances
  afterAssetBalancesUnique :
    assetBalancesUnique after.assetBalances
  beforeNativeBalanceMatchesSupply :
    nativeBalanceMatchesSupply before
  afterNativeBalanceMatchesSupply :
    nativeBalanceMatchesSupply after

theorem transition_nullifiers_unique_derived
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    after.spentNullifiers.Nodup := by
  rw [transition.nextNullifiers]
  exact
    append_nodup_of_fresh
      transition.priorNullifiersUnique
      transition.actionNullifiersUnique
      transition.inputNullifiersFresh

theorem transition_bridge_replay_keys_unique_derived
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    after.bridgeReplayKeys.Nodup := by
  rw [transition.nextBridgeReplayKeys]
  exact
    append_nodup_of_fresh
      transition.priorBridgeReplayKeysUnique
      (bridge_replay_keys_from_action_nodup action)
      (bridge_replay_keys_from_action_fresh transition.bridgeSafety)

inductive ActionChainTransition :
    LedgerState -> List Action -> LedgerState -> Prop where
  | nil (state : LedgerState) :
      ActionChainTransition state [] state
  | cons
      {start middle final : LedgerState}
      {action : Action}
      {rest : List Action}
      (head : Transition start action middle)
      (tail : ActionChainTransition middle rest final) :
      ActionChainTransition start (action :: rest) final

structure BlockTransition
    (before : LedgerState)
    (block : Block)
    (after : LedgerState) : Prop where
  chain :
    ActionChainTransition before block.actions after

def expectedSupplyAfter : Nat -> List Action -> Option Nat
  | supply, [] => some supply
  | supply, action :: rest =>
      match checkedSupply supply action.nativeMint action.nativeBurn with
      | none => none
      | some nextSupply => expectedSupplyAfter nextSupply rest

def allActionsNoTheft : List Action -> Prop
  | [] => True
  | action :: rest => actionNoTheft action /\ allActionsNoTheft rest

def allActionsAssetIsolated : List Action -> Prop
  | [] => True
  | action :: rest => actionAssetIsolated action /\ allActionsAssetIsolated rest

def allActionsNativeMintAuthorized : List Action -> Prop
  | [] => True
  | action :: rest =>
      actionNativeMintAuthorized action /\ allActionsNativeMintAuthorized rest

def allActionsPerAssetConserved
    (before : LedgerState) : List Action -> LedgerState -> Prop
  | [], after => before.assetBalances = after.assetBalances
  | action :: _rest, after => actionAssetConserved before action after

theorem transition_no_counterfeiting
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    checkedSupply before.supply action.nativeMint action.nativeBurn =
        some after.supply
      /\ actionNativeMintAuthorized action := by
  exact ⟨transition.supplyIntegrity, transition.nativeMintAuthorized⟩

theorem transition_no_double_spend
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    before.spentNullifiers.Nodup
      /\ action.inputNullifiers.Nodup
      /\ (forall nf, nf ∈ action.inputNullifiers ->
            nf ∉ before.spentNullifiers)
      /\ after.spentNullifiers =
            before.spentNullifiers ++ action.inputNullifiers
      /\ after.spentNullifiers.Nodup := by
  exact
    ⟨transition.priorNullifiersUnique,
      transition.actionNullifiersUnique,
      transition.inputNullifiersFresh,
      transition.nextNullifiers,
      transition_nullifiers_unique_derived transition⟩

theorem transition_no_theft
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    actionNoTheft action := by
  exact transition.noTheft

theorem transition_asset_isolation
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    actionAssetIsolated action := by
  exact transition.assetIsolation

theorem transition_per_asset_conservation
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    actionAssetConserved before action after := by
  exact transition.assetConservation

theorem transition_bridge_safety
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    actionBridgeSafe before action
      /\ after.bridgeReplayKeys =
          before.bridgeReplayKeys ++ bridgeReplayKeysFromAction action
      /\ after.bridgeReplayKeys.Nodup := by
  exact
    ⟨transition.bridgeSafety,
      transition.nextBridgeReplayKeys,
      transition_bridge_replay_keys_unique_derived transition⟩

theorem transition_privacy_projection
    {before after : LedgerState}
    {action : Action}
    (_transition : Transition before action after)
    (left right : PrivateMaterial) :
    observerViewWithPrivate before action after left =
      observerViewWithPrivate before action after right := by
  rfl

theorem transition_encoding_no_truncation
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    ledgerStateEncodingBounded before
      /\ actionEncodingBounded action
      /\ ledgerStateEncodingBounded after := by
  exact
    ⟨transition.beforeEncodingBounded,
      transition.actionEncodingBounded,
      transition.afterEncodingBounded⟩

theorem transition_asset_balance_invariants
    {before after : LedgerState}
    {action : Action}
    (transition : Transition before action after) :
    assetBalancesUnique before.assetBalances
      /\ assetBalancesUnique after.assetBalances
      /\ nativeBalanceMatchesSupply before
      /\ nativeBalanceMatchesSupply after := by
  exact
    ⟨transition.beforeAssetBalancesUnique,
      transition.afterAssetBalancesUnique,
      transition.beforeNativeBalanceMatchesSupply,
      transition.afterNativeBalanceMatchesSupply⟩

theorem action_chain_supply_integrity
    {before after : LedgerState}
    {actions : List Action}
    (chain : ActionChainTransition before actions after) :
    expectedSupplyAfter before.supply actions = some after.supply := by
  induction chain with
  | nil state =>
      rfl
  | cons head tail ih =>
      unfold expectedSupplyAfter
      rw [head.supplyIntegrity]
      exact ih

theorem action_chain_nullifiers_unique
    {before after : LedgerState}
    {actions : List Action}
    (chain : ActionChainTransition before actions after)
    (initialUnique : before.spentNullifiers.Nodup) :
    after.spentNullifiers.Nodup := by
  induction chain with
  | nil state =>
      exact initialUnique
  | cons head tail ih =>
      exact ih (transition_nullifiers_unique_derived head)

theorem action_chain_no_theft
    {before after : LedgerState}
    {actions : List Action}
    (chain : ActionChainTransition before actions after) :
    allActionsNoTheft actions := by
  induction chain with
  | nil state =>
      trivial
  | cons head tail ih =>
      exact ⟨head.noTheft, ih⟩

theorem action_chain_asset_isolation
    {before after : LedgerState}
    {actions : List Action}
    (chain : ActionChainTransition before actions after) :
    allActionsAssetIsolated actions := by
  induction chain with
  | nil state =>
      trivial
  | cons head tail ih =>
      exact ⟨head.assetIsolation, ih⟩

theorem action_chain_native_mint_authorized
    {before after : LedgerState}
    {actions : List Action}
    (chain : ActionChainTransition before actions after) :
    allActionsNativeMintAuthorized actions := by
  induction chain with
  | nil state =>
      trivial
  | cons head tail ih =>
      exact ⟨head.nativeMintAuthorized, ih⟩

theorem block_transition_supply_integrity
    {before after : LedgerState}
    {block : Block}
    (transition : BlockTransition before block after) :
    expectedSupplyAfter before.supply block.actions = some after.supply := by
  exact action_chain_supply_integrity transition.chain

theorem block_transition_nullifiers_unique
    {before after : LedgerState}
    {block : Block}
    (transition : BlockTransition before block after)
    (initialUnique : before.spentNullifiers.Nodup) :
    after.spentNullifiers.Nodup := by
  exact action_chain_nullifiers_unique transition.chain initialUnique

theorem block_transition_no_theft
    {before after : LedgerState}
    {block : Block}
    (transition : BlockTransition before block after) :
    allActionsNoTheft block.actions := by
  exact action_chain_no_theft transition.chain

theorem block_transition_asset_isolation
    {before after : LedgerState}
    {block : Block}
    (transition : BlockTransition before block after) :
    allActionsAssetIsolated block.actions := by
  exact action_chain_asset_isolation transition.chain

theorem block_transition_native_mint_authorized
    {before after : LedgerState}
    {block : Block}
    (transition : BlockTransition before block after) :
    allActionsNativeMintAuthorized block.actions := by
  exact action_chain_native_mint_authorized transition.chain

def canonicalEncodingSource : String :=
  "formal/lean/Hegemon/Essence/Core.lean"

def concatMap {α β : Type} (f : α -> List β) : List α -> List β
  | [] => []
  | value :: rest => f value ++ concatMap f rest

def encodeAssetDelta (delta : AssetDelta) : List Byte :=
  u64le delta.assetId
    ++ (if delta.delta < 0 then [1] else [0])
    ++ u64le delta.delta.natAbs

def encodeAssetBalance (balance : AssetBalance) : List Byte :=
  u64le balance.assetId ++ u64le balance.amount

def encodeOptionalDigest : Option Digest -> List Byte
  | none => [0]
  | some digest => [1] ++ u64le digest

def encodeSpendAuthorizationData
    (authorization : SpendAuthorizationData) : List Byte :=
  u64le authorization.spendKey
    ++ u64le authorization.statementDigest

def encodeNativeMintAuthorizationData
    (authorization : NativeMintAuthorizationData) : List Byte :=
  u64le authorization.authority
    ++ u64le authorization.amount
    ++ u64le authorization.scheduleDigest

def encodeAssetAuthorizationData
    (authorization : AssetAuthorizationData) : List Byte :=
  u64le authorization.authority
    ++ u64le authorization.assetId
    ++ (if authorization.delta < 0 then [1] else [0])
    ++ u64le authorization.delta.natAbs
    ++ u64le authorization.policyDigest

def encodeBridgeReceipt (receipt : BridgeReceipt) : List Byte :=
  u64le receipt.sourceChainId
    ++ u64le receipt.sourceMessageNonce
    ++ u64le receipt.sourceEventId
    ++ u64le receipt.verifierVersion
    ++ u64le receipt.assetId
    ++ u64le receipt.amount
    ++ u64le receipt.destinationChainId
    ++ u64le receipt.recipientCommitment
    ++ u64le receipt.finalityDepth
    ++ u64le receipt.replayKey
    ++ u64le receipt.messageHash
    ++ u64le receipt.payloadHash

def encodeBridgeAuthorizationData
    (authorization : BridgeAuthorizationData) : List Byte :=
  encodeBridgeReceipt authorization.receipt

def encodeProofStatementBindingData
    (binding : ProofStatementBindingData) : List Byte :=
  u64le binding.statementDigest

def encodeOptional {α : Type} (encode : α -> List Byte) :
    Option α -> List Byte
  | none => [0]
  | some value => [1] ++ encode value

def encodeActionPublicData (action : ActionPublicData) : List Byte :=
  asciiBytes "hegemon-essence-action-v2"
    ++ u32le action.inputNullifiers.length
    ++ concatMap u64le action.inputNullifiers
    ++ u32le action.outputCommitments.length
    ++ concatMap u64le action.outputCommitments
    ++ u32le action.outputCiphertextTags.length
    ++ concatMap u64le action.outputCiphertextTags
    ++ u64le action.nativeMint
    ++ u64le action.nativeBurn
    ++ u32le action.assetDeltas.length
    ++ concatMap encodeAssetDelta action.assetDeltas
    ++ encodeOptional encodeSpendAuthorizationData action.spendAuthorization
    ++ encodeOptional encodeNativeMintAuthorizationData
        action.nativeMintAuthorization
    ++ encodeOptional encodeAssetAuthorizationData action.assetAuthorization
    ++ encodeOptional encodeBridgeAuthorizationData action.bridgeAuthorization
    ++ encodeOptional encodeProofStatementBindingData action.proofBinding

def encodeLedgerPublicData (state : LedgerPublicData) : List Byte :=
  asciiBytes "hegemon-essence-ledger-v2"
    ++ u64le state.supply
    ++ u32le state.assetBalances.length
    ++ concatMap encodeAssetBalance state.assetBalances
    ++ u32le state.spentNullifiers.length
    ++ concatMap u64le state.spentNullifiers
    ++ u32le state.commitments.length
    ++ concatMap u64le state.commitments
    ++ u32le state.bridgeReplayKeys.length
    ++ concatMap u64le state.bridgeReplayKeys

def encodeObserverView (view : ObserverView) : List Byte :=
  asciiBytes "hegemon-essence-observer-v2"
    ++ u64le view.supplyBefore
    ++ u64le view.supplyAfter
    ++ u64le view.nullifierCount
    ++ u64le view.commitmentCount
    ++ u64le view.ciphertextCount
    ++ u64le view.bridgeReplayCount
    ++ encodeOptionalDigest view.bridgeSourceChain
    ++ encodeOptionalDigest view.bridgeAsset
    ++ encodeOptionalDigest view.bridgeAmount

def encodeCanonicalTerm : CanonicalTerm -> List Byte
  | CanonicalTerm.action data => encodeActionPublicData data
  | CanonicalTerm.ledger data => encodeLedgerPublicData data
  | CanonicalTerm.block actions =>
      asciiBytes "hegemon-essence-block-v2"
        ++ u32le actions.length
        ++ concatMap encodeActionPublicData actions
  | CanonicalTerm.observer view => encodeObserverView view

def encodeAction (action : Action) : List Byte :=
  encodeCanonicalTerm (actionCanonicalTerm action)

def encodeLedgerState (state : LedgerState) : List Byte :=
  encodeCanonicalTerm (ledgerCanonicalTerm state)

def encodeBlock (block : Block) : List Byte :=
  encodeCanonicalTerm (blockCanonicalTerm block)

theorem canonical_encoding_source_is_core :
    canonicalEncodingSource =
      "formal/lean/Hegemon/Essence/Core.lean" := by
  rfl

theorem canonical_action_encoding_comes_from_core
    (action : Action) :
    encodeAction action =
      encodeCanonicalTerm (actionCanonicalTerm action) := by
  rfl

theorem canonical_action_term_roundtrip
    (action : Action) :
    decodeCanonicalActionTerm (actionCanonicalTerm action) =
      some (actionPublicData action) := by
  rfl

theorem canonical_action_term_injective
    {left right : Action}
    (same : actionCanonicalTerm left = actionCanonicalTerm right) :
    actionPublicData left = actionPublicData right := by
  unfold actionCanonicalTerm at same
  injection same

theorem canonical_action_term_non_malleable
    {term : CanonicalTerm}
    {data : ActionPublicData}
    (decoded : decodeCanonicalActionTerm term = some data) :
    term = CanonicalTerm.action data := by
  cases term with
  | action actionData =>
      simp [decodeCanonicalActionTerm] at decoded
      cases decoded
      rfl
  | ledger ledgerData =>
      simp [decodeCanonicalActionTerm] at decoded
  | block actions =>
      simp [decodeCanonicalActionTerm] at decoded
  | observer view =>
      simp [decodeCanonicalActionTerm] at decoded

structure ProductionPath where
  rawBytes : List Byte
  parsed : Action
  admitted : Action
  replayed : Action
  stored : Action
  storedBytes : List Byte
  reloaded : Action
  published : Action
  before : LedgerState
  after : LedgerState

inductive ProductionStage where
  | parser
  | admittedAction
  | replay
  | storage
  | publication
deriving DecidableEq, Repr

def productionStageOrder : List ProductionStage :=
  [ProductionStage.parser,
    ProductionStage.admittedAction,
    ProductionStage.replay,
    ProductionStage.storage,
    ProductionStage.publication]

structure ProductionPathRefinement (path : ProductionPath) : Prop where
  parserExactDecode :
    path.rawBytes = encodeAction path.parsed
  parsedToAdmitted :
    path.parsed = path.admitted
  admittedToReplayed :
    path.admitted = path.replayed
  replayedToStored :
    path.replayed = path.stored
  storageWritesCanonical :
    path.storedBytes = encodeAction path.stored
  storageReloadExact :
    path.reloaded = path.stored
  reloadedToPublished :
    path.reloaded = path.published
  publishedTransition :
    Transition path.before path.published path.after

inductive FailureStage where
  | parser
  | admission
  | replay
  | storage
  | publication
deriving DecidableEq, Repr

structure FailedProductionPath where
  rawBytes : List Byte
  stage : FailureStage
  before : LedgerState
  publishedAfter : Option LedgerState
deriving DecidableEq, Repr

structure FailedProductionPathRefinement
    (path : FailedProductionPath) : Prop where
  failClosed :
    path.publishedAfter = none

theorem production_path_refines_core_transition
    {path : ProductionPath}
    (refinement : ProductionPathRefinement path) :
    Transition path.before path.parsed path.after := by
  have parsedToPublished : path.parsed = path.published := by
    calc
      path.parsed = path.admitted := refinement.parsedToAdmitted
      _ = path.replayed := refinement.admittedToReplayed
      _ = path.stored := refinement.replayedToStored
      _ = path.reloaded := Eq.symm refinement.storageReloadExact
      _ = path.published := refinement.reloadedToPublished
  simpa [parsedToPublished] using refinement.publishedTransition

theorem production_path_refines_core_security
    {path : ProductionPath}
    (refinement : ProductionPathRefinement path) :
    checkedSupply path.before.supply path.parsed.nativeMint path.parsed.nativeBurn =
        some path.after.supply
      /\ actionNoTheft path.parsed
      /\ actionAssetIsolated path.parsed
      /\ actionAssetConserved path.before path.parsed path.after
      /\ actionBridgeSafe path.before path.parsed := by
  have transition := production_path_refines_core_transition refinement
  exact
    ⟨transition.supplyIntegrity,
      transition.noTheft,
      transition.assetIsolation,
      transition.assetConservation,
      transition.bridgeSafety⟩

theorem production_path_exact_bytes
    {path : ProductionPath}
    (refinement : ProductionPathRefinement path) :
    path.rawBytes = encodeAction path.parsed
      /\ path.storedBytes = encodeAction path.stored := by
  exact
    ⟨refinement.parserExactDecode,
      refinement.storageWritesCanonical⟩

theorem failed_production_path_publishes_no_state
    {path : FailedProductionPath}
    (refinement : FailedProductionPathRefinement path) :
    path.publishedAfter = none := by
  exact refinement.failClosed

structure NamedExternalAssumptions where
  mlKemSecurity : Prop
  mlDsaSecurity : Prop
  aeadSecurity : Prop
  hashSecurity : Prop
  starkPcsSoundness : Prop
  daRetention : Prop
  storageDurability : Prop
  localZeroKnowledge : Prop
  timingPrivacy : Prop
  topologyPrivacy : Prop
  minerOrderingPrivacy : Prop
  globalTrafficPrivacy : Prop

structure NamedExternalAssumptionProofs
    (assumptions : NamedExternalAssumptions) : Prop where
  mlKemSecurity :
    assumptions.mlKemSecurity
  mlDsaSecurity :
    assumptions.mlDsaSecurity
  aeadSecurity :
    assumptions.aeadSecurity
  hashSecurity :
    assumptions.hashSecurity
  starkPcsSoundness :
    assumptions.starkPcsSoundness
  daRetention :
    assumptions.daRetention
  storageDurability :
    assumptions.storageDurability
  localZeroKnowledge :
    assumptions.localZeroKnowledge
  timingPrivacy :
    assumptions.timingPrivacy
  topologyPrivacy :
    assumptions.topologyPrivacy
  minerOrderingPrivacy :
    assumptions.minerOrderingPrivacy
  globalTrafficPrivacy :
    assumptions.globalTrafficPrivacy

theorem external_assumption_boundary_is_named
    {assumptions : NamedExternalAssumptions}
    (proofs : NamedExternalAssumptionProofs assumptions) :
    assumptions.mlKemSecurity
      /\ assumptions.mlDsaSecurity
      /\ assumptions.aeadSecurity
      /\ assumptions.hashSecurity
      /\ assumptions.starkPcsSoundness
      /\ assumptions.daRetention
      /\ assumptions.storageDurability
      /\ assumptions.localZeroKnowledge
      /\ assumptions.timingPrivacy
      /\ assumptions.topologyPrivacy
      /\ assumptions.minerOrderingPrivacy
      /\ assumptions.globalTrafficPrivacy := by
  exact
    ⟨proofs.mlKemSecurity,
      proofs.mlDsaSecurity,
      proofs.aeadSecurity,
      proofs.hashSecurity,
      proofs.starkPcsSoundness,
      proofs.daRetention,
      proofs.storageDurability,
      proofs.localZeroKnowledge,
      proofs.timingPrivacy,
      proofs.topologyPrivacy,
      proofs.minerOrderingPrivacy,
      proofs.globalTrafficPrivacy⟩

theorem global_privacy_requires_system_model
    {assumptions : NamedExternalAssumptions}
    (proofs : NamedExternalAssumptionProofs assumptions) :
    assumptions.localZeroKnowledge
      /\ assumptions.timingPrivacy
      /\ assumptions.topologyPrivacy
      /\ assumptions.minerOrderingPrivacy
      /\ assumptions.globalTrafficPrivacy := by
  exact
    ⟨proofs.localZeroKnowledge,
      proofs.timingPrivacy,
      proofs.topologyPrivacy,
      proofs.minerOrderingPrivacy,
      proofs.globalTrafficPrivacy⟩

end Core
end Essence
end Hegemon
