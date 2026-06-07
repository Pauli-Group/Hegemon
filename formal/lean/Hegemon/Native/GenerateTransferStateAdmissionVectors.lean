import Hegemon.Native.TransferStateAdmission

open Hegemon.Native.TransferStateAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def nullifierStateJson : TransferNullifierState -> String
  | TransferNullifierState.valid => "\"valid\""
  | TransferNullifierState.zero => "\"zero\""
  | TransferNullifierState.alreadySpent => "\"already_spent\""
  | TransferNullifierState.duplicate => "\"duplicate\""
  | TransferNullifierState.alreadyPending => "\"already_pending\""

def rejectionJson : Option TransferStateReject -> String
  | none => "null"
  | some TransferStateReject.unknownAnchor => "\"unknown_anchor\""
  | some TransferStateReject.nullifierZero => "\"nullifier_zero\""
  | some TransferStateReject.nullifierAlreadySpent =>
      "\"nullifier_already_spent\""
  | some TransferStateReject.duplicateNullifier => "\"duplicate_nullifier\""
  | some TransferStateReject.nullifierAlreadyPending =>
      "\"nullifier_already_pending\""
  | some TransferStateReject.commitmentZero => "\"commitment_zero\""
  | some TransferStateReject.sidecarCiphertextMissing =>
      "\"sidecar_ciphertext_missing\""
  | some TransferStateReject.sidecarCiphertextSizeMissing =>
      "\"sidecar_ciphertext_size_missing\""
  | some TransferStateReject.sidecarCiphertextSizeMismatch =>
      "\"sidecar_ciphertext_size_mismatch\""

def transferStateCaseJson (name : String) (input : TransferStateInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"anchor_known\": " ++ boolJson input.anchorKnown ++ ",\n"
    ++ "      \"nullifier_state\": "
      ++ nullifierStateJson input.nullifierState ++ ",\n"
    ++ "      \"commitments_nonzero\": " ++ boolJson input.commitmentsNonzero ++ ",\n"
    ++ "      \"sidecar_route\": " ++ boolJson input.sidecarRoute ++ ",\n"
    ++ "      \"sidecar_ciphertexts_available\": "
      ++ boolJson input.sidecarCiphertextsAvailable ++ ",\n"
    ++ "      \"sidecar_ciphertext_sizes_present\": "
      ++ boolJson input.sidecarCiphertextSizesPresent ++ ",\n"
    ++ "      \"sidecar_ciphertext_sizes_match\": "
      ++ boolJson input.sidecarCiphertextSizesMatch ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (transferStateAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (transferStateRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"transfer_state_admission_cases\": [\n"
    ++ transferStateCaseJson "valid-sidecar-transfer-state"
      validTransferState ++ ",\n"
    ++ transferStateCaseJson "valid-inline-transfer-state"
      { validTransferState with sidecarRoute := false } ++ ",\n"
    ++ transferStateCaseJson "unknown-anchor-rejected"
      { validTransferState with anchorKnown := false } ++ ",\n"
    ++ transferStateCaseJson "zero-nullifier-rejected"
      { validTransferState with
        nullifierState := TransferNullifierState.zero } ++ ",\n"
    ++ transferStateCaseJson "already-spent-nullifier-rejected"
      { validTransferState with
        nullifierState := TransferNullifierState.alreadySpent } ++ ",\n"
    ++ transferStateCaseJson "duplicate-nullifier-rejected"
      { validTransferState with
        nullifierState := TransferNullifierState.duplicate } ++ ",\n"
    ++ transferStateCaseJson "already-pending-nullifier-rejected"
      { validTransferState with
        nullifierState := TransferNullifierState.alreadyPending } ++ ",\n"
    ++ transferStateCaseJson "zero-commitment-rejected"
      { validTransferState with commitmentsNonzero := false } ++ ",\n"
    ++ transferStateCaseJson "sidecar-ciphertext-missing-rejected"
      { validTransferState with sidecarCiphertextsAvailable := false } ++ ",\n"
    ++ transferStateCaseJson "sidecar-ciphertext-size-missing-rejected"
      { validTransferState with sidecarCiphertextSizesPresent := false } ++ ",\n"
    ++ transferStateCaseJson "sidecar-ciphertext-size-mismatch-rejected"
      { validTransferState with sidecarCiphertextSizesMatch := false } ++ ",\n"
    ++ transferStateCaseJson "unknown-anchor-precedes-nullifier"
      { validTransferState with
        anchorKnown := false,
        nullifierState := TransferNullifierState.zero } ++ ",\n"
    ++ transferStateCaseJson "nullifier-precedes-zero-commitment"
      { validTransferState with
        nullifierState := TransferNullifierState.duplicate,
        commitmentsNonzero := false } ++ ",\n"
    ++ transferStateCaseJson "inline-ignores-sidecar-availability"
      { validTransferState with
        sidecarRoute := false,
        sidecarCiphertextsAvailable := false,
        sidecarCiphertextSizesPresent := false,
        sidecarCiphertextSizesMatch := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
