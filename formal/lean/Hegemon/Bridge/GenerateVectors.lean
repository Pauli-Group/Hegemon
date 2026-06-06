import Hegemon.Bridge.Encoding
import Hegemon.Bridge.Replay

open Hegemon
open Hegemon.Bridge

def sourceChainA : List Byte :=
  patternedBytes 32 0x23

def sourceChainB : List Byte :=
  patternedBytes 32 0xa0

def payloadHashA : List Byte :=
  patternedBytes 48 0x51

def payloadHashB : List Byte :=
  patternedBytes 48 0xc4

def messageCaseA : BridgeMessageV1 :=
  {
    sourceChainId := sourceChainA,
    destinationChainId := sourceChainA,
    appFamilyId := 5,
    messageNonce := 7313672856623994476953600,
    sourceHeight := 396475,
    payloadHash := payloadHashA,
    payload := asciiBytes "formal-core self loop"
  }

def messageCaseB : BridgeMessageV1 :=
  {
    sourceChainId := sourceChainA,
    destinationChainId := sourceChainB,
    appFamilyId := 5,
    messageNonce := 7313672856623994476953601,
    sourceHeight := 396476,
    payloadHash := payloadHashB,
    payload := asciiBytes "formal-core app payload 2"
  }

def keyA : ReplayKey :=
  patternedBytes 48 0x11

def keyB : ReplayKey :=
  patternedBytes 48 0x87

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def stageResult (state : ReplayState) (key : ReplayKey) : Bool :=
  match state.stage key with
  | some _ => true
  | none => false

def importResult (state : ReplayState) (key : ReplayKey) : Bool :=
  match state.importOne key with
  | some _ => true
  | none => false

def stageThenImportResult (state : ReplayState) (key : ReplayKey) : Bool :=
  match state.stage key with
  | some staged =>
      importResult staged key
  | none => false

def stageAfterImportResult (state : ReplayState) (key : ReplayKey) : Bool :=
  match state.importOne key with
  | some imported =>
      stageResult imported key
  | none => false

def bridgeCaseJson (name : String) (message : BridgeMessageV1) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"source_chain_id\": \"" ++ hexBytes message.sourceChainId ++ "\",\n"
    ++ "      \"destination_chain_id\": \"" ++ hexBytes message.destinationChainId ++ "\",\n"
    ++ "      \"app_family_id\": " ++ toString message.appFamilyId ++ ",\n"
    ++ "      \"message_nonce\": \"" ++ toString message.messageNonce ++ "\",\n"
    ++ "      \"source_height\": " ++ toString message.sourceHeight ++ ",\n"
    ++ "      \"payload_hash\": \"" ++ hexBytes message.payloadHash ++ "\",\n"
    ++ "      \"payload_hex\": \"" ++ hexBytes message.payload ++ "\",\n"
    ++ "      \"expected_encoded_hex\": \"" ++ hexBytes message.encode ++ "\"\n"
    ++ "    }"

def replayCaseJson (name : String) (state : ReplayState) (key : ReplayKey) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"initial_consumed\": [" ++ String.join (state.consumed.map fun item => "\"" ++ hexBytes item ++ "\"") ++ "],\n"
    ++ "      \"initial_pending\": [" ++ String.join (state.pending.map fun item => "\"" ++ hexBytes item ++ "\"") ++ "],\n"
    ++ "      \"key\": \"" ++ hexBytes key ++ "\",\n"
    ++ "      \"stage\": " ++ boolJson (stageResult state key) ++ ",\n"
    ++ "      \"stage_then_import\": " ++ boolJson (stageThenImportResult state key) ++ ",\n"
    ++ "      \"stage_after_import\": " ++ boolJson (stageAfterImportResult state key) ++ ",\n"
    ++ "      \"import\": " ++ boolJson (importResult state key) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_encoding_cases\": [\n"
    ++ bridgeCaseJson "lean-self-loop-encoding" messageCaseA ++ ",\n"
    ++ bridgeCaseJson "lean-cross-chain-encoding" messageCaseB ++ "\n"
    ++ "  ],\n"
    ++ "  \"replay_cases\": [\n"
    ++ replayCaseJson "empty-stage-import" ReplayState.empty keyA ++ ",\n"
    ++ replayCaseJson "pending-rejects-restage" { consumed := [], pending := [keyA] } keyA ++ ",\n"
    ++ replayCaseJson "consumed-rejects-restage" { consumed := [keyA], pending := [] } keyA ++ ",\n"
    ++ replayCaseJson "other-key-still-accepted" { consumed := [keyA], pending := [] } keyB ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
