import Hegemon.Consensus.Header

open Hegemon
open Hegemon.Consensus.Header

def optionHexJson : Option (List Byte) -> String
  | none => "null"
  | some bytes => "\"" ++ hexBytes bytes ++ "\""

def powSealJson : Option PowSeal -> String
  | none => "null"
  | some powSeal =>
      "{ \"nonce\": \"" ++ hexBytes powSeal.nonce
        ++ "\", \"pow_bits\": " ++ toString powSeal.powBits ++ " }"

def headerCaseJson (name : String) (header : BlockHeader) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"version\": " ++ toString header.version ++ ",\n"
    ++ "      \"height\": " ++ toString header.height ++ ",\n"
    ++ "      \"view\": " ++ toString header.view ++ ",\n"
    ++ "      \"timestamp_ms\": " ++ toString header.timestampMs ++ ",\n"
    ++ "      \"parent_hash\": \"" ++ hexBytes header.parentHash ++ "\",\n"
    ++ "      \"state_root\": \"" ++ hexBytes header.stateRoot ++ "\",\n"
    ++ "      \"kernel_root\": \"" ++ hexBytes header.kernelRoot ++ "\",\n"
    ++ "      \"nullifier_root\": \"" ++ hexBytes header.nullifierRoot ++ "\",\n"
    ++ "      \"proof_commitment\": \"" ++ hexBytes header.proofCommitment ++ "\",\n"
    ++ "      \"da_root\": \"" ++ hexBytes header.daRoot ++ "\",\n"
    ++ "      \"da_params\": { \"chunk_size\": " ++ toString header.daParams.chunkSize
    ++ ", \"sample_count\": " ++ toString header.daParams.sampleCount ++ " },\n"
    ++ "      \"version_commitment\": \"" ++ hexBytes header.versionCommitment ++ "\",\n"
    ++ "      \"tx_count\": " ++ toString header.txCount ++ ",\n"
    ++ "      \"fee_commitment\": \"" ++ hexBytes header.feeCommitment ++ "\",\n"
    ++ "      \"supply_digest\": \"" ++ toString header.supplyDigest ++ "\",\n"
    ++ "      \"validator_set_commitment\": \"" ++ hexBytes header.validatorSetCommitment ++ "\",\n"
    ++ "      \"signature_aggregate\": \"" ++ hexBytes header.signatureAggregate ++ "\",\n"
    ++ "      \"signature_bitmap\": " ++ optionHexJson header.signatureBitmap ++ ",\n"
    ++ "      \"pow\": " ++ powSealJson header.pow ++ ",\n"
    ++ "      \"expected_signing_preimage_len\": "
    ++ toString (signingPreimage header).length ++ ",\n"
    ++ "      \"expected_full_header_preimage_len\": "
    ++ toString (fullHeaderPreimage header).length ++ ",\n"
    ++ "      \"expected_signing_preimage\": \""
    ++ hexBytes (signingPreimage header) ++ "\",\n"
    ++ "      \"expected_full_header_preimage\": \""
    ++ hexBytes (fullHeaderPreimage header) ++ "\"\n"
    ++ "    }"

def alteredAuthPayloadHeader : BlockHeader := {
  sampleHeader with
  signatureAggregate := patternedBytes 8 211,
  signatureBitmap := some (patternedBytes 2 223),
  pow := none
}

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"header_preimage_cases\": [\n"
    ++ headerCaseJson "pow-header-preimage" sampleHeader ++ ",\n"
    ++ headerCaseJson "bft-header-preimage" bftHeader ++ ",\n"
    ++ headerCaseJson "unsigned-no-auth-preimage" unsignedHeader ++ ",\n"
    ++ headerCaseJson "signing-preimage-auth-payload-independent"
      alteredAuthPayloadHeader ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
