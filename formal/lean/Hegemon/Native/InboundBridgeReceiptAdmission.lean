namespace Hegemon
namespace Native
namespace InboundBridgeReceiptAdmission

inductive InboundBridgeReceiptReject where
  | sourceChainMismatch
  | rulesHashMismatch
  | messageNonceMismatch
  | messageHashMismatch
  | tipBeforeMessage
  | confirmationsOverstated
  | underconfirmed
deriving DecidableEq, Repr

structure InboundBridgeReceiptInput where
  sourceChainMatches : Bool
  rulesHashMatches : Bool
  messageNonceMatches : Bool
  messageHashMatches : Bool
  checkpointHeight : Nat
  canonicalTipHeight : Nat
  confirmationsChecked : Nat
  minConfirmations : Nat
deriving DecidableEq, Repr

def heightConfirmations
    (input : InboundBridgeReceiptInput) : Option Nat :=
  if input.canonicalTipHeight < input.checkpointHeight then
    none
  else
    some (input.canonicalTipHeight - input.checkpointHeight + 1)

def evaluateInboundBridgeReceipt
    (input : InboundBridgeReceiptInput) :
      Except InboundBridgeReceiptReject Nat :=
  if input.sourceChainMatches = false then
    Except.error InboundBridgeReceiptReject.sourceChainMismatch
  else if input.rulesHashMatches = false then
    Except.error InboundBridgeReceiptReject.rulesHashMismatch
  else if input.messageNonceMatches = false then
    Except.error InboundBridgeReceiptReject.messageNonceMismatch
  else if input.messageHashMatches = false then
    Except.error InboundBridgeReceiptReject.messageHashMismatch
  else
    match heightConfirmations input with
    | none => Except.error InboundBridgeReceiptReject.tipBeforeMessage
    | some heightConfirmations =>
        if heightConfirmations < input.confirmationsChecked then
          Except.error InboundBridgeReceiptReject.confirmationsOverstated
        else if input.confirmationsChecked < input.minConfirmations then
          Except.error InboundBridgeReceiptReject.underconfirmed
        else
          Except.ok heightConfirmations

def inboundBridgeReceiptAccepts
    (input : InboundBridgeReceiptInput) : Bool :=
  match evaluateInboundBridgeReceipt input with
  | Except.ok _ => true
  | Except.error _ => false

def inboundBridgeReceiptRejection
    (input : InboundBridgeReceiptInput) :
      Option InboundBridgeReceiptReject :=
  match evaluateInboundBridgeReceipt input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def inboundBridgeReceiptHeightConfirmations
    (input : InboundBridgeReceiptInput) : Option Nat :=
  match evaluateInboundBridgeReceipt input with
  | Except.ok confirmations => some confirmations
  | Except.error _ => none

def inboundBridgeReceiptPreconditions
    (input : InboundBridgeReceiptInput) : Bool :=
  input.sourceChainMatches
    && input.rulesHashMatches
    && input.messageNonceMatches
    && input.messageHashMatches
    && match heightConfirmations input with
       | none => false
       | some heightConfirmations =>
           !(heightConfirmations < input.confirmationsChecked)
             && !(input.confirmationsChecked < input.minConfirmations)

theorem accepts_iff_inbound_bridge_receipt_preconditions
    {input : InboundBridgeReceiptInput} :
    inboundBridgeReceiptAccepts input = true ↔
      inboundBridgeReceiptPreconditions input = true := by
  cases input with
  | mk sourceChainMatches rulesHashMatches messageNonceMatches
      messageHashMatches checkpointHeight canonicalTipHeight
      confirmationsChecked minConfirmations =>
      simp [
        inboundBridgeReceiptAccepts,
        inboundBridgeReceiptPreconditions,
        evaluateInboundBridgeReceipt,
        heightConfirmations
      ]
      cases sourceChainMatches <;>
        cases rulesHashMatches <;>
        cases messageNonceMatches <;>
        cases messageHashMatches <;>
        simp
      · by_cases htip : canonicalTipHeight < checkpointHeight
        · simp [htip]
        · by_cases hover :
            canonicalTipHeight - checkpointHeight + 1 < confirmationsChecked
          · simp [htip, hover]
          · by_cases hunder : confirmationsChecked < minConfirmations
            · simp [htip, hover, hunder]
            · simp [htip, hover, hunder]

def valid : InboundBridgeReceiptInput :=
  {
    sourceChainMatches := true,
    rulesHashMatches := true,
    messageNonceMatches := true,
    messageHashMatches := true,
    checkpointHeight := 40,
    canonicalTipHeight := 44,
    confirmationsChecked := 5,
    minConfirmations := 3
  }

theorem valid_accepts :
    evaluateInboundBridgeReceipt valid = Except.ok 5 := by
  rfl

def sameHeightValid : InboundBridgeReceiptInput :=
  { valid with
    checkpointHeight := 44,
    canonicalTipHeight := 44,
    confirmationsChecked := 1,
    minConfirmations := 1 }

theorem same_height_valid_has_one_confirmation :
    evaluateInboundBridgeReceipt sameHeightValid = Except.ok 1 := by
  rfl

def sourceChainMismatch : InboundBridgeReceiptInput :=
  { valid with sourceChainMatches := false }

theorem source_chain_mismatch_rejects :
    evaluateInboundBridgeReceipt sourceChainMismatch =
      Except.error InboundBridgeReceiptReject.sourceChainMismatch := by
  rfl

def rulesHashMismatch : InboundBridgeReceiptInput :=
  { valid with rulesHashMatches := false }

theorem rules_hash_mismatch_rejects :
    evaluateInboundBridgeReceipt rulesHashMismatch =
      Except.error InboundBridgeReceiptReject.rulesHashMismatch := by
  rfl

def messageNonceMismatch : InboundBridgeReceiptInput :=
  { valid with messageNonceMatches := false }

theorem message_nonce_mismatch_rejects :
    evaluateInboundBridgeReceipt messageNonceMismatch =
      Except.error InboundBridgeReceiptReject.messageNonceMismatch := by
  rfl

def messageHashMismatch : InboundBridgeReceiptInput :=
  { valid with messageHashMatches := false }

theorem message_hash_mismatch_rejects :
    evaluateInboundBridgeReceipt messageHashMismatch =
      Except.error InboundBridgeReceiptReject.messageHashMismatch := by
  rfl

def tipBeforeMessage : InboundBridgeReceiptInput :=
  { valid with canonicalTipHeight := 39 }

theorem tip_before_message_rejects :
    evaluateInboundBridgeReceipt tipBeforeMessage =
      Except.error InboundBridgeReceiptReject.tipBeforeMessage := by
  rfl

def confirmationsOverstated : InboundBridgeReceiptInput :=
  { valid with
    checkpointHeight := 40,
    canonicalTipHeight := 44,
    confirmationsChecked := 6 }

theorem confirmations_overstated_rejects :
    evaluateInboundBridgeReceipt confirmationsOverstated =
      Except.error InboundBridgeReceiptReject.confirmationsOverstated := by
  rfl

def underconfirmed : InboundBridgeReceiptInput :=
  { valid with confirmationsChecked := 2, minConfirmations := 3 }

theorem underconfirmed_rejects :
    evaluateInboundBridgeReceipt underconfirmed =
      Except.error InboundBridgeReceiptReject.underconfirmed := by
  rfl

def source_chain_precedes_rules_input :
    InboundBridgeReceiptInput :=
  { valid with
    sourceChainMatches := false,
    rulesHashMatches := false }

theorem source_chain_precedes_rules :
    evaluateInboundBridgeReceipt source_chain_precedes_rules_input =
      Except.error InboundBridgeReceiptReject.sourceChainMismatch := by
  rfl

def rules_precede_nonce_input :
    InboundBridgeReceiptInput :=
  { valid with
    rulesHashMatches := false,
    messageNonceMatches := false }

theorem rules_precede_nonce :
    evaluateInboundBridgeReceipt rules_precede_nonce_input =
      Except.error InboundBridgeReceiptReject.rulesHashMismatch := by
  rfl

def nonce_precedes_message_hash_input :
    InboundBridgeReceiptInput :=
  { valid with
    messageNonceMatches := false,
    messageHashMatches := false }

theorem nonce_precedes_message_hash :
    evaluateInboundBridgeReceipt nonce_precedes_message_hash_input =
      Except.error InboundBridgeReceiptReject.messageNonceMismatch := by
  rfl

def message_hash_precedes_tip_input :
    InboundBridgeReceiptInput :=
  { valid with
    messageHashMatches := false,
    canonicalTipHeight := 39 }

theorem message_hash_precedes_tip :
    evaluateInboundBridgeReceipt message_hash_precedes_tip_input =
      Except.error InboundBridgeReceiptReject.messageHashMismatch := by
  rfl

def tip_precedes_overstated_input :
    InboundBridgeReceiptInput :=
  { valid with
    canonicalTipHeight := 39,
    confirmationsChecked := 6 }

theorem tip_precedes_overstated :
    evaluateInboundBridgeReceipt tip_precedes_overstated_input =
      Except.error InboundBridgeReceiptReject.tipBeforeMessage := by
  rfl

def overstated_precedes_underconfirmed_input :
    InboundBridgeReceiptInput :=
  { valid with
    checkpointHeight := 40,
    canonicalTipHeight := 44,
    confirmationsChecked := 6,
    minConfirmations := 7 }

theorem overstated_precedes_underconfirmed :
    evaluateInboundBridgeReceipt overstated_precedes_underconfirmed_input =
      Except.error InboundBridgeReceiptReject.confirmationsOverstated := by
  rfl

end InboundBridgeReceiptAdmission
end Native
end Hegemon
