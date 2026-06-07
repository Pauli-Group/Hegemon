import Hegemon.Consensus.VersionPolicy

open Hegemon.Consensus

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def bindingJson (binding : VersionBinding) : String :=
  "{ \"circuit\": " ++ toString binding.circuit
    ++ ", \"crypto\": " ++ toString binding.crypto ++ " }"

def bindingListJson : List VersionBinding -> String
  | [] => "[]"
  | head :: tail =>
      "[" ++ tail.foldl
        (fun acc binding => acc ++ ", " ++ bindingJson binding)
        (bindingJson head) ++ "]"

def optionBindingJson : Option VersionBinding -> String
  | none => "null"
  | some binding => bindingJson binding

def eventJson (event : VersionEvent) : String :=
  "{ \"height\": " ++ toString event.height
    ++ ", \"versions\": " ++ bindingListJson event.versions ++ " }"

def eventListJson : List VersionEvent -> String
  | [] => "[]"
  | head :: tail =>
      "[" ++ tail.foldl
        (fun acc event => acc ++ ", " ++ eventJson event)
        (eventJson head) ++ "]"

def versionCaseJson
    (name : String)
    (schedule : VersionSchedule)
    (height : Nat)
    (txVersions : List VersionBinding) : String :=
  let firstUnsupported := firstUnsupportedVersion schedule height txVersions
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"height\": " ++ toString height ++ ",\n"
    ++ "      \"initial\": " ++ bindingListJson schedule.initial ++ ",\n"
    ++ "      \"activations\": " ++ eventListJson schedule.activations ++ ",\n"
    ++ "      \"retirements\": " ++ eventListJson schedule.retirements ++ ",\n"
    ++ "      \"tx_versions\": " ++ bindingListJson txVersions ++ ",\n"
    ++ "      \"expected_allowed\": "
    ++ bindingListJson (allowedVersionsAt schedule height) ++ ",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson (versionPolicyAccepts schedule height txVersions) ++ ",\n"
    ++ "      \"expected_first_unsupported\": "
    ++ optionBindingJson firstUnsupported ++ "\n"
    ++ "    }"

def duplicateInitialSchedule : VersionSchedule := {
  initial := [baseVersion, baseVersion],
  activations := [],
  retirements := []
}

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"version_policy_cases\": [\n"
    ++ versionCaseJson "initial-version-accepted"
      activationSchedule 0 [baseVersion] ++ ",\n"
    ++ versionCaseJson "unknown-initial-version-rejected"
      activationSchedule 0 [nextCryptoVersion] ++ ",\n"
    ++ versionCaseJson "pre-activation-version-rejected"
      activationSchedule 9 [nextCircuitVersion] ++ ",\n"
    ++ versionCaseJson "activation-boundary-accepted"
      activationSchedule 10 [baseVersion, nextCircuitVersion] ++ ",\n"
    ++ versionCaseJson "pre-retirement-version-accepted"
      retirementSchedule 19 [baseVersion, nextCircuitVersion] ++ ",\n"
    ++ versionCaseJson "retirement-boundary-rejected"
      retirementSchedule 20 [baseVersion] ++ ",\n"
    ++ versionCaseJson "same-height-retirement-wins"
      sameHeightSchedule 10 [nextCircuitVersion] ++ ",\n"
    ++ versionCaseJson "first-unsupported-preserves-transaction-order"
      activationSchedule 0 [baseVersion, nextCryptoVersion, nextCircuitVersion] ++ ",\n"
    ++ versionCaseJson "duplicate-initial-deduplicated"
      duplicateInitialSchedule 0 [baseVersion] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
