import Hegemon.Network.PeerStoreCapacityAdmission

open Hegemon.Network.PeerStoreCapacityAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def entryIds (entries : List PeerStoreEntry) : List Nat :=
  entries.map (fun entry => entry.id)

def isPrefixIds (prefixIds allIds : List Nat) : Bool :=
  allIds.take prefixIds.length == prefixIds

def idsAbsentFrom (dropped retained : List Nat) : Bool :=
  dropped.all (fun id => !retained.contains id)

def capacityCaseJson
    (name : String)
    (maxEntries : Nat)
    (entries : List PeerStoreEntry) : String :=
  let entryIdsByRecency := entryIds entries
  let retainedIds := enforcePeerStoreEntryIds maxEntries entries
  let droppedIds := droppedPeerStoreEntryIds maxEntries entries
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"max_entries\": " ++ toString maxEntries ++ ",\n"
    ++ "      \"entry_ids_by_recency\": " ++ natListJson entryIdsByRecency ++ ",\n"
    ++ "      \"expected_retained_ids\": " ++ natListJson retainedIds ++ ",\n"
    ++ "      \"expected_dropped_ids\": " ++ natListJson droppedIds ++ ",\n"
    ++ "      \"expected_retained_count\": " ++ toString retainedIds.length ++ ",\n"
    ++ "      \"expected_dropped_count\": " ++ toString droppedIds.length ++ ",\n"
    ++ "      \"expected_changed\": "
      ++ boolJson (entries.length != retainedIds.length) ++ ",\n"
    ++ "      \"expected_count_within_max\": "
      ++ boolJson (retainedIds.length <= maxEntries) ++ ",\n"
    ++ "      \"expected_retained_is_recency_prefix\": "
      ++ boolJson (isPrefixIds retainedIds entryIdsByRecency) ++ ",\n"
    ++ "      \"expected_dropped_ids_absent\": "
      ++ boolJson (idsAbsentFrom droppedIds retainedIds) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"default_max_peer_store_entries\": "
      ++ toString defaultMaxPeerStoreEntries ++ ",\n"
    ++ "  \"capacity_cases\": [\n"
    ++ capacityCaseJson "below-limit-keeps-all" 4 belowLimitEntries ++ ",\n"
    ++ capacityCaseJson "exact-limit-keeps-all" 3 exactLimitEntries ++ ",\n"
    ++ capacityCaseJson "over-limit-keeps-recency-prefix" 3 overLimitEntries ++ ",\n"
    ++ capacityCaseJson "zero-limit-keeps-none" 0 overLimitEntries ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
