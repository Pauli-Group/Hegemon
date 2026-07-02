import Hegemon.Bytes
import Hegemon.Native.SidecarUploadAdmission

namespace Hegemon
namespace Native
namespace SidecarUploadRawJsonProjection

open Hegemon
open Hegemon.Native.SidecarUploadAdmission

inductive RawSidecarUploadKind where
  | ciphertexts
  | proofs
deriving DecidableEq, Repr

inductive RawSidecarUploadReject where
  | jsonDecodeRejected
  | uploadFieldMissing
  | ciphertextBytesRejected
  | proofBytesRejected
  | sidecar : SidecarUploadReject -> RawSidecarUploadReject
deriving DecidableEq, Repr

structure RawSidecarUploadInput where
  kind : RawSidecarUploadKind
  jsonDecodeAccepts : Bool
  uploadFieldPresent : Bool
  requestCount : RequestCountInput
  ciphertextItemPresent : Bool
  ciphertextBytesDecode : Bool
  proofItemPresent : Bool
  proofMetadata : ProofMetadataInput
  proofBytesDecode : Bool
  proofDecoded : ProofDecodedInput
deriving DecidableEq, Repr

structure RawSidecarUploadCase where
  rawJsonBytes : List Byte
  input : RawSidecarUploadInput
  expected : Option RawSidecarUploadReject
deriving DecidableEq, Repr

def evaluateRawSidecarUpload (input : RawSidecarUploadInput) :
    Option RawSidecarUploadReject :=
  if input.jsonDecodeAccepts = false then
    some RawSidecarUploadReject.jsonDecodeRejected
  else if input.uploadFieldPresent = false then
    some RawSidecarUploadReject.uploadFieldMissing
  else
    match input.kind with
    | RawSidecarUploadKind.ciphertexts =>
        match evaluateCiphertextRequest input.requestCount with
        | Except.error reject => some (RawSidecarUploadReject.sidecar reject)
        | Except.ok _ =>
            if input.ciphertextItemPresent = false then
              none
            else if input.ciphertextBytesDecode = false then
              some RawSidecarUploadReject.ciphertextBytesRejected
            else
              none
    | RawSidecarUploadKind.proofs =>
        match evaluateProofRequest input.requestCount with
        | Except.error reject => some (RawSidecarUploadReject.sidecar reject)
        | Except.ok _ =>
            if input.proofItemPresent = false then
              none
            else
              match evaluateProofMetadata input.proofMetadata with
              | Except.error reject => some (RawSidecarUploadReject.sidecar reject)
              | Except.ok _ =>
                  if input.proofBytesDecode = false then
                    some RawSidecarUploadReject.proofBytesRejected
                  else
                    match evaluateProofDecoded input.proofDecoded with
                    | Except.error reject => some (RawSidecarUploadReject.sidecar reject)
                    | Except.ok _ => none

def rawSidecarUploadCaseMatches (case : RawSidecarUploadCase) : Bool :=
  evaluateRawSidecarUpload case.input == case.expected

def validProofMetadataInput : ProofMetadataInput := {
  bindingHashPresent := true,
  bindingHashValid := true,
  proofPresent := true
}

def validProofDecodedInput : ProofDecodedInput := {
  proofBytes := 1,
  maxProofBytes := 530368,
  proofBindingHashMatchesKey := true
}

def repeatJsonItems (item : String) (count : Nat) : String :=
  match count with
  | 0 => ""
  | 1 => item
  | n + 1 => item ++ "," ++ repeatJsonItems item n

def validCiphertextUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{\"ciphertexts\":[\"0x010203\"]}",
  input := {
    kind := RawSidecarUploadKind.ciphertexts,
    jsonDecodeAccepts := true,
    uploadFieldPresent := true,
    requestCount := { itemCount := 1, maxItems := 1024 },
    ciphertextItemPresent := true,
    ciphertextBytesDecode := true,
    proofItemPresent := false,
    proofMetadata := validProofMetadataInput,
    proofBytesDecode := true,
    proofDecoded := validProofDecodedInput
  },
  expected := none
}

def malformedCiphertextUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{",
  input := { validCiphertextUpload.input with jsonDecodeAccepts := false },
  expected := some RawSidecarUploadReject.jsonDecodeRejected
}

def unknownCiphertextFieldUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{\"ciphertexts\":[],\"extra\":true}",
  input := { validCiphertextUpload.input with
    jsonDecodeAccepts := false,
    requestCount := { itemCount := 0, maxItems := 1024 },
    ciphertextItemPresent := false
  },
  expected := some RawSidecarUploadReject.jsonDecodeRejected
}

def missingCiphertextFieldUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{}",
  input := { validCiphertextUpload.input with
    uploadFieldPresent := false,
    requestCount := { itemCount := 0, maxItems := 1024 },
    ciphertextItemPresent := false
  },
  expected := some RawSidecarUploadReject.uploadFieldMissing
}

def nonArrayCiphertextFieldUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{\"ciphertexts\":\"0x01\"}",
  input := { validCiphertextUpload.input with jsonDecodeAccepts := false },
  expected := some RawSidecarUploadReject.jsonDecodeRejected
}

def invalidCiphertextBytesUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{\"ciphertexts\":[\"not bytes!\"]}",
  input := { validCiphertextUpload.input with ciphertextBytesDecode := false },
  expected := some RawSidecarUploadReject.ciphertextBytesRejected
}

def tooManyCiphertextsUpload : RawSidecarUploadCase := {
  rawJsonBytes :=
    asciiBytes ("{\"ciphertexts\":[" ++ repeatJsonItems "null" 1025 ++ "]}"),
  input := { validCiphertextUpload.input with
    requestCount := { itemCount := 1025, maxItems := 1024 },
    ciphertextItemPresent := false
  },
  expected := some (RawSidecarUploadReject.sidecar SidecarUploadReject.tooManyCiphertexts)
}

def validEmptyProofUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{\"proofs\":[]}",
  input := {
    kind := RawSidecarUploadKind.proofs,
    jsonDecodeAccepts := true,
    uploadFieldPresent := true,
    requestCount := { itemCount := 0, maxItems := 256 },
    ciphertextItemPresent := false,
    ciphertextBytesDecode := true,
    proofItemPresent := false,
    proofMetadata := validProofMetadataInput,
    proofBytesDecode := true,
    proofDecoded := validProofDecodedInput
  },
  expected := none
}

def missingProofsFieldUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{}",
  input := { validEmptyProofUpload.input with uploadFieldPresent := false },
  expected := some RawSidecarUploadReject.uploadFieldMissing
}

def nonArrayProofsFieldUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{\"proofs\":{}}",
  input := { validEmptyProofUpload.input with jsonDecodeAccepts := false },
  expected := some RawSidecarUploadReject.jsonDecodeRejected
}

def unknownProofItemFieldUpload : RawSidecarUploadCase := {
  rawJsonBytes :=
    asciiBytes
      ("{\"proofs\":[{\"binding_hash\":\""
        ++ "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ++ "\",\"proof\":\"0x01\",\"extra\":true}]}"),
  input := { validEmptyProofUpload.input with
    jsonDecodeAccepts := false,
    requestCount := { itemCount := 1, maxItems := 256 },
    proofItemPresent := true
  },
  expected := some RawSidecarUploadReject.jsonDecodeRejected
}

def tooManyProofsUpload : RawSidecarUploadCase := {
  rawJsonBytes :=
    asciiBytes ("{\"proofs\":[" ++ repeatJsonItems "{}" 257 ++ "]}"),
  input := { validEmptyProofUpload.input with
    requestCount := { itemCount := 257, maxItems := 256 }
  },
  expected := some (RawSidecarUploadReject.sidecar SidecarUploadReject.tooManyProofs)
}

def missingProofBindingHashUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{\"proofs\":[{\"proof\":\"0x01\"}]}",
  input := { validEmptyProofUpload.input with
    requestCount := { itemCount := 1, maxItems := 256 },
    proofItemPresent := true,
    proofMetadata := { validProofMetadataInput with
      bindingHashPresent := false,
      bindingHashValid := false
    }
  },
  expected := some (RawSidecarUploadReject.sidecar SidecarUploadReject.proofBindingHashMissing)
}

def invalidProofBindingHashUpload : RawSidecarUploadCase := {
  rawJsonBytes := asciiBytes "{\"proofs\":[{\"binding_hash\":\"not-hex\",\"proof\":\"0x01\"}]}",
  input := { missingProofBindingHashUpload.input with
    proofMetadata := { validProofMetadataInput with bindingHashValid := false }
  },
  expected := some (RawSidecarUploadReject.sidecar SidecarUploadReject.invalidBindingHash)
}

def missingProofBytesUpload : RawSidecarUploadCase := {
  rawJsonBytes :=
    asciiBytes
      ("{\"proofs\":[{\"binding_hash\":\""
        ++ "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ++ "\"}]}"),
  input := { missingProofBindingHashUpload.input with
    proofMetadata := { validProofMetadataInput with proofPresent := false }
  },
  expected := some (RawSidecarUploadReject.sidecar SidecarUploadReject.proofMissing)
}

def invalidProofBytesUpload : RawSidecarUploadCase := {
  rawJsonBytes :=
    asciiBytes
      ("{\"proofs\":[{\"binding_hash\":\""
        ++ "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ++ "\",\"proof\":\"not bytes!\"}]}"),
  input := { missingProofBindingHashUpload.input with
    proofMetadata := validProofMetadataInput,
    proofBytesDecode := false
  },
  expected := some RawSidecarUploadReject.proofBytesRejected
}

def emptyProofBytesUpload : RawSidecarUploadCase := {
  rawJsonBytes :=
    asciiBytes
      ("{\"proofs\":[{\"binding_hash\":\""
        ++ "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ++ "\",\"proof\":\"0x\"}]}"),
  input := { missingProofBindingHashUpload.input with
    proofMetadata := validProofMetadataInput,
    proofBytesDecode := true,
    proofDecoded := { validProofDecodedInput with proofBytes := 0 }
  },
  expected := some (RawSidecarUploadReject.sidecar SidecarUploadReject.proofEmpty)
}

theorem raw_sidecar_upload_case_matches_iff_expected_rejection
    {case : RawSidecarUploadCase} :
    rawSidecarUploadCaseMatches case = true ↔
      evaluateRawSidecarUpload case.input = case.expected := by
  cases case
  simp [rawSidecarUploadCaseMatches]

theorem valid_ciphertext_raw_upload_accepts :
    evaluateRawSidecarUpload validCiphertextUpload.input = none := by
  decide

theorem malformed_ciphertext_raw_upload_rejects :
    evaluateRawSidecarUpload malformedCiphertextUpload.input =
      some RawSidecarUploadReject.jsonDecodeRejected := by
  decide

theorem unknown_ciphertext_raw_field_rejects :
    evaluateRawSidecarUpload unknownCiphertextFieldUpload.input =
      some RawSidecarUploadReject.jsonDecodeRejected := by
  decide

theorem missing_ciphertext_raw_field_rejects :
    evaluateRawSidecarUpload missingCiphertextFieldUpload.input =
      some RawSidecarUploadReject.uploadFieldMissing := by
  decide

theorem non_array_ciphertext_raw_field_rejects :
    evaluateRawSidecarUpload nonArrayCiphertextFieldUpload.input =
      some RawSidecarUploadReject.jsonDecodeRejected := by
  decide

theorem invalid_ciphertext_raw_bytes_rejects :
    evaluateRawSidecarUpload invalidCiphertextBytesUpload.input =
      some RawSidecarUploadReject.ciphertextBytesRejected := by
  decide

theorem too_many_ciphertexts_raw_upload_rejects :
    evaluateRawSidecarUpload tooManyCiphertextsUpload.input =
      some (RawSidecarUploadReject.sidecar SidecarUploadReject.tooManyCiphertexts) := by
  decide

theorem valid_empty_proof_raw_upload_accepts :
    evaluateRawSidecarUpload validEmptyProofUpload.input = none := by
  decide

theorem missing_proofs_raw_field_rejects :
    evaluateRawSidecarUpload missingProofsFieldUpload.input =
      some RawSidecarUploadReject.uploadFieldMissing := by
  decide

theorem non_array_proofs_raw_field_rejects :
    evaluateRawSidecarUpload nonArrayProofsFieldUpload.input =
      some RawSidecarUploadReject.jsonDecodeRejected := by
  decide

theorem unknown_proof_item_raw_field_rejects :
    evaluateRawSidecarUpload unknownProofItemFieldUpload.input =
      some RawSidecarUploadReject.jsonDecodeRejected := by
  decide

theorem too_many_proofs_raw_upload_rejects :
    evaluateRawSidecarUpload tooManyProofsUpload.input =
      some (RawSidecarUploadReject.sidecar SidecarUploadReject.tooManyProofs) := by
  decide

theorem missing_proof_binding_hash_raw_upload_rejects :
    evaluateRawSidecarUpload missingProofBindingHashUpload.input =
      some (RawSidecarUploadReject.sidecar SidecarUploadReject.proofBindingHashMissing) := by
  decide

theorem invalid_proof_binding_hash_raw_upload_rejects :
    evaluateRawSidecarUpload invalidProofBindingHashUpload.input =
      some (RawSidecarUploadReject.sidecar SidecarUploadReject.invalidBindingHash) := by
  decide

theorem missing_proof_bytes_raw_upload_rejects :
    evaluateRawSidecarUpload missingProofBytesUpload.input =
      some (RawSidecarUploadReject.sidecar SidecarUploadReject.proofMissing) := by
  decide

theorem invalid_proof_raw_bytes_rejects :
    evaluateRawSidecarUpload invalidProofBytesUpload.input =
      some RawSidecarUploadReject.proofBytesRejected := by
  decide

theorem empty_proof_raw_bytes_rejects :
    evaluateRawSidecarUpload emptyProofBytesUpload.input =
      some (RawSidecarUploadReject.sidecar SidecarUploadReject.proofEmpty) := by
  decide

end SidecarUploadRawJsonProjection
end Native
end Hegemon
