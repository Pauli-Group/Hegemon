import Hegemon.Consensus.Asert

open Hegemon.Consensus.Asert

private def base : Input := ⟨19, 20000000, 439041101, 19, 20060000, 60000, 3600000⟩

private def cases : List (String × Input) :=
  [ ("activation_exact_interval", base)
  , ("activation_half_life_lag", { base with parentTimestamp := 23660000 })
  , ("minimum_target_underflow", { base with anchorBits := 16842752, parentHeight := 1000 })
  , ("maximum_target_saturation", { base with anchorBits := 545259519, parentTimestamp := 100000000 })
  , ("huge_positive_exponent", { base with parentTimestamp := maxU64 })
  , ("huge_negative_exponent", { base with parentHeight := maxU64-1 })
  , ("zero_spacing", { base with spacing := 0 })
  , ("zero_half_life", { base with halfLife := 0 })
  , ("genesis_anchor", { base with anchorHeight := 0 })
  , ("parent_before_anchor", { base with parentHeight := 18 })
  , ("no_next_height", { base with parentHeight := maxU64 })
  , ("zero_target", { base with anchorBits := 0 })
  , ("negative_compact", { base with anchorBits := 545259520 })
  , ("noncanonical_compact", { base with anchorBits := 33554433 })
  , ("i128_overflow", { base with parentHeight := maxU64-1, spacing := maxU64 })
  ] ++
  ([1800000, 3600000, 10800000].flatMap fun halfLife =>
    ([0, 1, 100, 1000, 59999, 60000, 60001, 1799999, 1800000,
       3599999, 3600000, 3600001, 7200000, 10800000].map fun offset =>
      ("elapsed_" ++ toString offset ++ "_half_" ++ toString halfLife,
       { base with halfLife := halfLife, parentTimestamp := base.anchorParentTimestamp + offset }))) ++
  ([1, 2, 10, 100, 10000].map fun heightDelta =>
    ("later_exact_schedule_" ++ toString heightDelta,
      { base with parentHeight := base.anchorHeight + heightDelta, parentTimestamp := base.anchorParentTimestamp + base.spacing * (heightDelta + 1) }))

private def rejectionLabel : Rejection → String
  | .invalidParameters => "invalid_parameters"
  | .invalidAnchor => "invalid_anchor"
  | .invalidCompactTarget => "invalid_compact_target"
  | .arithmeticOverflow => "arithmetic_overflow"

private def caseJson (named : String × Input) : String :=
  let (name, input) := named
  let result := nextBits input
  let bits := match result with | .ok value => toString value | .error _ => "null"
  let label := match result with | .ok _ => "accepted" | .error e => rejectionLabel e
  "{\"name\":\"" ++ name ++ "\",\"anchor_height\":" ++ toString input.anchorHeight
    ++ ",\"anchor_parent_timestamp_ms\":" ++ toString input.anchorParentTimestamp
    ++ ",\"anchor_bits\":" ++ toString input.anchorBits
    ++ ",\"parent_height\":" ++ toString input.parentHeight
    ++ ",\"parent_timestamp_ms\":" ++ toString input.parentTimestamp
    ++ ",\"spacing_ms\":" ++ toString input.spacing
    ++ ",\"half_life_ms\":" ++ toString input.halfLife
    ++ ",\"expected_bits\":" ++ bits ++ ",\"expected_result\":\"" ++ label ++ "\"}"

private def activationJson (activation height : Nat) : String :=
  "{\"activation\":" ++ toString activation ++ ",\"height\":" ++ toString height
    ++ ",\"valid\":" ++ (if activation ≥ 2 then "true" else "false")
    ++ ",\"active\":" ++ (if asertActive activation height then "true" else "false") ++ "}"

def main : IO Unit := do
  IO.println ("{\"schema_version\":1,\"model\":\"Hegemon.Consensus.Asert\","
    ++ "\"claim\":\"mathematical bounds and finite Rust conformance only; no general Rust refinement or release authority\","
    ++ "\"cases\":[" ++ String.intercalate "," (cases.map caseJson) ++ "],"
    ++ "\"activation_cases\":[" ++ String.intercalate ","
      ([0,1,2,20,1000].flatMap fun activation =>
        [0,1,2,19,20,21,999,1000,1001].map fun height => activationJson activation height)
    ++ "]}")
