import Hegemon.Native.ActionPlanApplicationAdmission

open Hegemon.Native.ActionPlanApplicationAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListTailJson : List Nat -> String
  | [] => ""
  | head :: tail => ", " ++ toString head ++ natListTailJson tail

def natListJson : List Nat -> String
  | [] => "[]"
  | head :: tail => "[" ++ toString head ++ natListTailJson tail ++ "]"

def rejectionJson :
    Except ActionPlanApplicationReject ActionPlanApplicationOutput -> String
  | Except.ok _ => "null"
  | Except.error ActionPlanApplicationReject.planLengthMismatch =>
      "\"plan_length_mismatch\""
  | Except.error ActionPlanApplicationReject.plannedStartMismatch =>
      "\"planned_start_mismatch\""
  | Except.error ActionPlanApplicationReject.commitmentIndexOverflow =>
      "\"commitment_index_overflow\""

def natOrNull :
    Except ActionPlanApplicationReject ActionPlanApplicationOutput ->
    (ActionPlanApplicationOutput -> Nat) -> String
  | Except.ok output, selector => toString (selector output)
  | Except.error _, _ => "null"

def planApplicationCaseJson
    (name : String)
    (input : ActionPlanApplicationInput) : String :=
  let result := evaluateActionPlanApplication input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"leaf_start\": " ++ toString input.leafStart ++ ",\n"
    ++ "      \"action_commitment_counts\": "
      ++ natListJson input.actionCommitmentCounts ++ ",\n"
    ++ "      \"planned_starts\": "
      ++ natListJson input.plannedStarts ++ ",\n"
    ++ "      \"expected_next_leaf_count\": "
      ++ natOrNull result ActionPlanApplicationOutput.nextLeafCount ++ ",\n"
    ++ "      \"expected_applied_action_count\": "
      ++ natOrNull result ActionPlanApplicationOutput.appliedActionCount ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (match result with | Except.ok _ => true | Except.error _ => false)
      ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"action_plan_application_admission_cases\": [\n"
    ++ planApplicationCaseJson "valid-two-action-plan"
      validTwoActionPlan ++ ",\n"
    ++ planApplicationCaseJson "empty-plan"
      emptyPlan ++ ",\n"
    ++ planApplicationCaseJson "missing-planned-start-rejected"
      missingPlannedStart ++ ",\n"
    ++ planApplicationCaseJson "extra-planned-start-rejected"
      extraPlannedStart ++ ",\n"
    ++ planApplicationCaseJson "first-planned-start-mismatch-rejected"
      firstPlannedStartMismatch ++ ",\n"
    ++ planApplicationCaseJson "second-planned-start-mismatch-rejected"
      secondPlannedStartMismatch ++ ",\n"
    ++ planApplicationCaseJson "commitment-overflow-rejected"
      commitmentOverflow ++ ",\n"
    ++ planApplicationCaseJson "planned-start-precedes-overflow"
      planned_start_precedes_overflow_input ++ ",\n"
    ++ planApplicationCaseJson "zero-commitment-at-max-leaf"
      zeroCommitmentPlan ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
