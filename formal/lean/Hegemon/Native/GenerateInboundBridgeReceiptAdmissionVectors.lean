import Hegemon.Native.InboundBridgeReceiptAdmission

open Hegemon.Native.InboundBridgeReceiptAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natOptionJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def rejectionJson : Option InboundBridgeReceiptReject -> String
  | none => "null"
  | some InboundBridgeReceiptReject.sourceChainMismatch =>
      "\"source_chain_mismatch\""
  | some InboundBridgeReceiptReject.rulesHashMismatch =>
      "\"rules_hash_mismatch\""
  | some InboundBridgeReceiptReject.messageNonceMismatch =>
      "\"message_nonce_mismatch\""
  | some InboundBridgeReceiptReject.messageHashMismatch =>
      "\"message_hash_mismatch\""
  | some InboundBridgeReceiptReject.tipBeforeMessage =>
      "\"tip_before_message\""
  | some InboundBridgeReceiptReject.confirmationsOverflow =>
      "\"confirmations_overflow\""
  | some InboundBridgeReceiptReject.confirmationsOverstated =>
      "\"confirmations_overstated\""
  | some InboundBridgeReceiptReject.underconfirmed =>
      "\"underconfirmed\""
  | some InboundBridgeReceiptReject.workPolicyMismatch =>
      "\"work_policy_mismatch\""

def inboundBridgeReceiptCaseJson
    (name : String)
    (input : InboundBridgeReceiptInput) : String :=
  let result := evaluateInboundBridgeReceipt input
  let confirmations := inboundBridgeReceiptHeightConfirmations input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"source_chain_matches\": "
      ++ boolJson input.sourceChainMatches ++ ",\n"
    ++ "      \"rules_hash_matches\": "
      ++ boolJson input.rulesHashMatches ++ ",\n"
    ++ "      \"message_nonce_matches\": "
      ++ boolJson input.messageNonceMatches ++ ",\n"
    ++ "      \"message_hash_matches\": "
      ++ boolJson input.messageHashMatches ++ ",\n"
    ++ "      \"checkpoint_height\": "
      ++ toString input.checkpointHeight ++ ",\n"
    ++ "      \"canonical_tip_height\": "
      ++ toString input.canonicalTipHeight ++ ",\n"
    ++ "      \"canonical_tip_work\": "
      ++ "\"" ++ toString input.canonicalTipWork ++ "\",\n"
    ++ "      \"confirmations_checked\": "
      ++ toString input.confirmationsChecked ++ ",\n"
    ++ "      \"min_confirmations\": "
      ++ toString input.minConfirmations ++ ",\n"
    ++ "      \"min_work_checked\": "
      ++ "\"" ++ toString input.minWorkChecked ++ "\",\n"
    ++ "      \"min_tip_work\": "
      ++ "\"" ++ toString input.minTipWork ++ "\",\n"
    ++ "      \"expected_valid\": " ++ boolJson result.isOk ++ ",\n"
    ++ "      \"expected_height_confirmations\": "
      ++ natOptionJson confirmations ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (inboundBridgeReceiptRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"inbound_bridge_receipt_admission_cases\": [\n"
    ++ inboundBridgeReceiptCaseJson
      "valid-inbound-bridge-receipt" valid ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "same-height-has-one-confirmation" sameHeightValid ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "max-native-confirmation-count-accepted"
      maxNativeConfirmationsValid ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "source-chain-mismatch-rejected" sourceChainMismatch ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "rules-hash-mismatch-rejected" rulesHashMismatch ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "message-nonce-mismatch-rejected" messageNonceMismatch ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "message-hash-mismatch-rejected" messageHashMismatch ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "tip-before-message-rejected" tipBeforeMessage ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "confirmation-count-overflow-rejected" confirmationsOverflow ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "confirmations-overstated-rejected" confirmationsOverstated ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "underconfirmed-rejected" underconfirmed ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "tip-work-under-policy-rejected" tipWorkUnderPolicy ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "checked-work-under-policy-rejected" checkedWorkUnderPolicy ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "source-chain-precedes-rules" source_chain_precedes_rules_input ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "rules-precede-nonce" rules_precede_nonce_input ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "nonce-precedes-message-hash" nonce_precedes_message_hash_input ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "message-hash-precedes-tip" message_hash_precedes_tip_input ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "tip-precedes-overstated" tip_precedes_overstated_input ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "overflow-precedes-underconfirmed" overflow_precedes_underconfirmed_input ++ ",\n"
    ++ inboundBridgeReceiptCaseJson
      "overstated-precedes-underconfirmed"
      overstated_precedes_underconfirmed_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
