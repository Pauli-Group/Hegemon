import Hegemon.Shielded.Nullifier

open Hegemon
open Hegemon.Shielded

def keyA : Nullifier :=
  patternedBytes 48 0x31

def keyB : Nullifier :=
  patternedBytes 48 0xb5

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def stageResult (state : NullifierState) (key : Nullifier) : Bool :=
  match state.stage key with
  | some _ => true
  | none => false

def importResult (state : NullifierState) (key : Nullifier) : Bool :=
  match state.importOne key with
  | some _ => true
  | none => false

def stageThenImportResult (state : NullifierState) (key : Nullifier) : Bool :=
  match state.stage key with
  | some staged =>
      importResult staged key
  | none => false

def stageAfterImportResult (state : NullifierState) (key : Nullifier) : Bool :=
  match state.importOne key with
  | some imported =>
      stageResult imported key
  | none => false

def quotedHexListJson (values : List Nullifier) : String :=
  String.join (values.map fun item => "\"" ++ hexBytes item ++ "\"")

def nullifierCaseJson (name : String) (state : NullifierState) (key : Nullifier) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"initial_spent\": [" ++ quotedHexListJson state.spent ++ "],\n"
    ++ "      \"initial_pending\": [" ++ quotedHexListJson state.pending ++ "],\n"
    ++ "      \"key\": \"" ++ hexBytes key ++ "\",\n"
    ++ "      \"stage\": " ++ boolJson (stageResult state key) ++ ",\n"
    ++ "      \"stage_then_import\": " ++ boolJson (stageThenImportResult state key) ++ ",\n"
    ++ "      \"stage_after_import\": " ++ boolJson (stageAfterImportResult state key) ++ ",\n"
    ++ "      \"import\": " ++ boolJson (importResult state key) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"nullifier_cases\": [\n"
    ++ nullifierCaseJson "empty-stage-import" NullifierState.empty keyA ++ ",\n"
    ++ nullifierCaseJson "zero-rejected" NullifierState.empty zeroNullifier ++ ",\n"
    ++ nullifierCaseJson "pending-rejects-restage" { spent := [], pending := [keyA] } keyA ++ ",\n"
    ++ nullifierCaseJson "spent-rejects-restage" { spent := [keyA], pending := [] } keyA ++ ",\n"
    ++ nullifierCaseJson "other-key-still-accepted" { spent := [keyA], pending := [] } keyB ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
