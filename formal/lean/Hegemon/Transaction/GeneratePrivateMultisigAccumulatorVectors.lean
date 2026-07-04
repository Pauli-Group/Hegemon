import Hegemon.Transaction.PrivateMultisigAccumulator

namespace Hegemon
namespace Transaction
namespace PrivateMultisigAccumulator

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def intentJson (intent : SpendIntent) : String :=
  "{"
    ++ "\"account_digest\": " ++ toString intent.accountDigest ++ ", "
    ++ "\"policy_root\": " ++ toString intent.policyRoot ++ ", "
    ++ "\"intent_digest\": " ++ toString intent.intentDigest
    ++ "}"

def policyJson (policy : PolicyWitness) : String :=
  "{"
    ++ "\"account_digest\": " ++ toString policy.accountDigest ++ ", "
    ++ "\"policy_root\": " ++ toString policy.policyRoot ++ ", "
    ++ "\"threshold\": " ++ toString policy.threshold ++ ", "
    ++ "\"signer_set_root\": " ++ toString policy.signerSetRoot ++ ", "
    ++ "\"signer_tags\": " ++ natListJson policy.signerTags
    ++ "}"

def accumulatorJson (accumulator : AccumulatorNote) : String :=
  "{"
    ++ "\"account_digest\": " ++ toString accumulator.accountDigest ++ ", "
    ++ "\"policy_root\": " ++ toString accumulator.policyRoot ++ ", "
    ++ "\"intent_digest\": " ++ toString accumulator.intentDigest ++ ", "
    ++ "\"approval_count\": " ++ toString accumulator.approvalCount ++ ", "
    ++ "\"approval_nullifiers\": "
    ++ natListJson accumulator.approvalNullifiers ++ ", "
    ++ "\"approval_signer_tags\": "
    ++ natListJson accumulator.approvalSignerTags ++ ", "
    ++ "\"approval_leaves\": "
    ++ natListJson accumulator.approvalLeaves ++ ", "
    ++ "\"state_digest\": " ++ toString accumulator.stateDigest
    ++ "}"

def capabilityJson (capability : SignerCapabilityNote) : String :=
  "{"
    ++ "\"policy_root\": " ++ toString capability.policyRoot ++ ", "
    ++ "\"signer_tag\": " ++ toString capability.signerTag ++ ", "
    ++ "\"signer_nullifier\": " ++ toString capability.signerNullifier ++ ", "
    ++ "\"capability_secret_commitment\": "
    ++ toString capability.capabilitySecretCommitment
    ++ "}"

def valueNoteJson (note : ValueNote) : String :=
  "{"
    ++ "\"account_digest\": " ++ toString note.accountDigest ++ ", "
    ++ "\"note_commitment\": " ++ toString note.noteCommitment ++ ", "
    ++ "\"value_lock_digest\": " ++ toString note.valueLockDigest ++ ", "
    ++ "\"public_nullifier\": " ++ toString note.publicNullifier
    ++ "}"

def approvalCaseJson (name : String) (step : ApprovalStep) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": \"approval\",\n"
    ++ "      \"policy\": " ++ policyJson step.policy ++ ",\n"
    ++ "      \"intent\": " ++ intentJson step.intent ++ ",\n"
    ++ "      \"prior_accumulator\": "
    ++ accumulatorJson step.priorAccumulator ++ ",\n"
    ++ "      \"signer_capability\": "
    ++ capabilityJson step.signerCapability ++ ",\n"
    ++ "      \"spend_derived_signer_tag\": "
    ++ toString step.spendDerivedSignerTag ++ ",\n"
    ++ "      \"next_accumulator\": "
    ++ accumulatorJson step.nextAccumulator ++ ",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson (approvalStepAccepted step) ++ "\n"
    ++ "    }"

def approvalStepJson (step : ApprovalStep) : String :=
  "{"
    ++ "\"policy\": " ++ policyJson step.policy ++ ", "
    ++ "\"intent\": " ++ intentJson step.intent ++ ", "
    ++ "\"prior_accumulator\": "
    ++ accumulatorJson step.priorAccumulator ++ ", "
    ++ "\"signer_capability\": "
    ++ capabilityJson step.signerCapability ++ ", "
    ++ "\"spend_derived_signer_tag\": "
    ++ toString step.spendDerivedSignerTag ++ ", "
    ++ "\"next_accumulator\": "
    ++ accumulatorJson step.nextAccumulator
    ++ "}"

def approvalTraceJson (trace : List ApprovalStep) : String :=
  "[" ++ String.intercalate ", " (trace.map approvalStepJson) ++ "]"

def finalCaseJson (name : String) (spend : FinalSpend) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": \"final\",\n"
    ++ "      \"policy\": " ++ policyJson spend.policy ++ ",\n"
    ++ "      \"intent\": " ++ intentJson spend.intent ++ ",\n"
    ++ "      \"value_note\": " ++ valueNoteJson spend.valueNote ++ ",\n"
    ++ "      \"accumulator\": "
    ++ accumulatorJson spend.accumulator ++ ",\n"
    ++ "      \"approval_trace\": "
    ++ approvalTraceJson spend.approvalTrace ++ ",\n"
    ++ "      \"output_commitment\": "
    ++ toString spend.outputCommitment ++ ",\n"
    ++ "      \"output_ciphertext_hash\": "
    ++ toString spend.outputCiphertextHash ++ ",\n"
    ++ "      \"balance_tag\": "
    ++ toString spend.balanceTag ++ ",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson (finalSpendAccepted spend) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"digest_modulus\": " ++ toString digestMod ++ ",\n"
    ++ "  \"privacy_model\": "
    ++ "\"stateful_shielded_accumulator_no_signatures_no_mpc\",\n"
    ++ "  \"private_fields\": ["
    ++ "\"signer_set_root\", \"threshold\", \"approval_count\", "
    ++ "\"approval_leaves\", \"policy_root\", \"approval_nullifiers\", "
    ++ "\"approval_signer_tags\", \"signer_tags\", \"spend_derived_signer_tag\", "
    ++ "\"value_lock_digest\""
    ++ "],\n"
    ++ "  \"public_shape_fields\": ["
    ++ "\"input_nullifier\", \"output_commitment\", "
    ++ "\"output_ciphertext_hash\", \"balance_tag\""
    ++ "],\n"
    ++ "  \"cases\": [\n"
    ++ approvalCaseJson "valid-approval-step" validApprovalStep ++ ",\n"
    ++ approvalCaseJson "duplicate-signer-rejected" duplicateSignerStep
    ++ ",\n"
    ++ approvalCaseJson "same-signer-fresh-nullifier-rejected"
      sameSignerFreshNullifierStep ++ ",\n"
    ++ approvalCaseJson "wrong-intent-rejected" wrongIntentStep ++ ",\n"
    ++ approvalCaseJson "wrong-policy-rejected" wrongPolicyStep ++ ",\n"
    ++ approvalCaseJson "outside-policy-signer-rejected"
      outsidePolicySignerStep ++ ",\n"
    ++ approvalCaseJson "forged-signer-tag-rejected"
      forgedSignerTagStep ++ ",\n"
    ++ approvalCaseJson "zero-threshold-policy-approval-rejected"
      zeroThresholdPolicyStep ++ ",\n"
    ++ approvalCaseJson
      "threshold-above-signer-count-policy-approval-rejected"
      thresholdAboveSignerCountPolicyStep ++ ",\n"
    ++ approvalCaseJson "duplicate-signer-policy-approval-rejected"
      duplicateSignerPolicyStep ++ ",\n"
    ++ approvalCaseJson "signer-set-root-drift-policy-approval-rejected"
      signerSetRootDriftPolicyStep ++ ",\n"
    ++ finalCaseJson
      "below-threshold-final-rejected"
      belowThresholdFinalSpend ++ ",\n"
    ++ finalCaseJson
      "exact-threshold-final-accepted"
      exactThresholdFinalSpend ++ ",\n"
    ++ finalCaseJson
      "same-signer-fresh-nullifier-final-rejected"
      sameSignerFreshNullifierFinalSpend ++ ",\n"
    ++ finalCaseJson
      "forged-threshold-final-without-approval-trace-rejected"
      forgedThresholdFinalSpend ++ ",\n"
    ++ finalCaseJson
      "final-intent-mismatch-rejected"
      finalIntentMismatchSpend ++ ",\n"
    ++ finalCaseJson
      "final-value-lock-mismatch-rejected"
      finalValueLockMismatchSpend ++ ",\n"
    ++ finalCaseJson
      "zero-threshold-final-rejected"
      zeroThresholdFinalSpend ++ ",\n"
    ++ finalCaseJson
      "duplicate-signer-policy-final-rejected"
      duplicateSignerPolicyFinalSpend ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

end PrivateMultisigAccumulator
end Transaction
end Hegemon

def main : IO Unit :=
  Hegemon.Transaction.PrivateMultisigAccumulator.main
