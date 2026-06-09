import Hegemon.Native.WorkTemplateAdmission

open Hegemon.Native.WorkTemplateAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Except WorkTemplateReject Nat -> String
  | Except.ok _ => "null"
  | Except.error WorkTemplateReject.heightNotNext => "\"height_not_next\""
  | Except.error WorkTemplateReject.cumulativeWorkOverflow => "\"cumulative_work_overflow\""

def heightJson : Except WorkTemplateReject Nat -> String
  | Except.ok height => toString height
  | Except.error _ => "null"

def workTemplateCaseJson (name : String) (input : WorkTemplateInput) : String :=
  let result := evaluateWorkTemplate input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"best_height\": " ++ toString input.bestHeight ++ ",\n"
    ++ "      \"cumulative_work_advances\": " ++ boolJson input.cumulativeWorkAdvances ++ ",\n"
    ++ "      \"expected_height\": " ++ heightJson result ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (match result with | Except.ok _ => true | Except.error _ => false) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"work_template_admission_cases\": [\n"
    ++ workTemplateCaseJson "valid-work-template" valid ++ ",\n"
    ++ workTemplateCaseJson "height-overflow-rejected" heightOverflow ++ ",\n"
    ++ workTemplateCaseJson "cumulative-work-overflow-rejected" cumulativeWorkOverflow ++ ",\n"
    ++ workTemplateCaseJson "height-precedes-work-overflow"
      height_precedes_work_overflow_input ++ ",\n"
    ++ workTemplateCaseJson "max-predecessor-accepts-max-height"
      maxPredecessorAcceptsMaxHeight ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
