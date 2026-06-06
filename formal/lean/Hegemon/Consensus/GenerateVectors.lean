import Hegemon.Consensus.ForkChoice

open Hegemon
open Hegemon.Consensus

def lowHash : Hash32 :=
  patternedBytes 32 0x05

def midHash : Hash32 :=
  patternedBytes 32 0x40

def highHash : Hash32 :=
  patternedBytes 32 0xa0

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def forkChoiceCaseJson
    (name : String)
    (current candidate : ForkChoiceTip) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"current_work\": \"" ++ toString current.work ++ "\",\n"
    ++ "      \"current_height\": " ++ toString current.height ++ ",\n"
    ++ "      \"current_hash\": \"" ++ hexBytes current.hash ++ "\",\n"
    ++ "      \"candidate_work\": \"" ++ toString candidate.work ++ "\",\n"
    ++ "      \"candidate_height\": " ++ toString candidate.height ++ ",\n"
    ++ "      \"candidate_hash\": \"" ++ hexBytes candidate.hash ++ "\",\n"
    ++ "      \"select_candidate\": " ++ boolJson (betterThan candidate current) ++ "\n"
    ++ "    }"

def currentBase : ForkChoiceTip :=
  { work := 1000000, height := 20, hash := midHash }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"fork_choice_cases\": [\n"
    ++ forkChoiceCaseJson "higher-work-wins" currentBase { work := 1000001, height := 19, hash := highHash } ++ ",\n"
    ++ forkChoiceCaseJson "lower-work-loses" currentBase { work := 999999, height := 30, hash := lowHash } ++ ",\n"
    ++ forkChoiceCaseJson "equal-work-higher-height-wins" currentBase { work := 1000000, height := 21, hash := highHash } ++ ",\n"
    ++ forkChoiceCaseJson "equal-work-lower-height-loses" currentBase { work := 1000000, height := 19, hash := lowHash } ++ ",\n"
    ++ forkChoiceCaseJson "equal-work-height-lower-hash-wins" currentBase { work := 1000000, height := 20, hash := lowHash } ++ ",\n"
    ++ forkChoiceCaseJson "equal-work-height-higher-hash-loses" currentBase { work := 1000000, height := 20, hash := highHash } ++ ",\n"
    ++ forkChoiceCaseJson "same-tip-loses" currentBase currentBase ++ ",\n"
    ++ forkChoiceCaseJson "wide-work-higher-wins"
        { work := 1208925819614629174706176, height := 99, hash := highHash }
        { work := 1208925819614629174706177, height := 1, hash := lowHash } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
