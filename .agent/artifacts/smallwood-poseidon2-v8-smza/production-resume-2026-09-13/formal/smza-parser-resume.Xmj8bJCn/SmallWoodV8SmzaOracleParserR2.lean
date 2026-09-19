import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleGeometry

/-!
Additive SMZA source-frame specialization. This uses the generic finite extractor,
not the old q20 `parseSource`. It parses all physical payload bytes, exact source
lengths, fixed q38 geometry, and the caller's complete source-owned PB02 context.
The accepted-proof verifier must supply that context; this module does not prove
Rust/Lean refinement, proof acceptance, extraction success, or a quantum bound.
-/
namespace HegemonCrypto.SmallWood.V8SmzaOracleParser

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical

set_option maxRecDepth 5000
set_option maxHeartbeats 1000000

abbrev RawInput := List Byte
abbrev RawDigest := Fin 64 → Byte

def profileDomain : List Byte :=
  [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,
   112,111,115,101,105,100,111,110,50,45,118,56,46,115,109,122,97,46,
   115,104,97,53,49,50,46,112,114,111,102,105,108,101,46,118,49]

def relationDigest : List Byte :=
  [126,80,235,160,125,132,67,58,83,166,200,94,210,179,239,236,
   190,255,16,60,164,2,187,147,24,49,225,89,142,108,154,184,
   250,19,140,155,47,12,185,210,27,242,191,4,75,80,212,208]

abbrev digestAt := V8Smz9CoherentMerkleGeometry.digestAt
abbrev wordAt := V8Smz9CoherentMerkleGeometry.wordAt

/-- The salt and PB02 bytes are fixed before extraction from the actual
accepted proof and independently reconstructed verifier input. Keeping them
as data is not an assumption that any proof or extraction accepts. -/
structure Context where
  salt : List Byte
  binding : List Byte
deriving DecidableEq

def Context.Canonical (context : Context) : Prop :=
  context.salt.length = 32 ∧ context.binding.length = 1104 ∧
  context.binding.take 24 =
    [72,71,86,56,80,66,48,50,2,0,8,0,7,0,1,0,10,0,2,9,5,0,1,0] ∧
  (context.binding.drop 28).take 8 = [120,0,7,0,83,77,90,65] ∧
  (context.binding.drop 36).take 48 = relationDigest ∧
  context.binding.drop 1100 = [0,0,0,0] ∧
  (∀ i : Fin 127, wordAt (context.binding.drop 84) i.val < goldilocksModulus)

instance (context : Context) : Decidable context.Canonical := by
  unfold Context.Canonical
  infer_instance

inductive Kind where
  | leaf | node | root | fpp | piop | decs
deriving DecidableEq

def roleName : Kind → List Byte
  | .leaf => V8Smz9WholeViewObservation.strictZkMerkleLeafDomain
  | .node => merkleNodeDomain
  | .root => merkleRootDomain
  | .fpp => piopInputDomain
  | .piop => piopTranscriptDomain
  | .decs => decsOpeningDomain

def decodeRole (role : List Byte) : Option Kind :=
  if role = roleName .leaf then some .leaf
  else if role = roleName .node then some .node
  else if role = roleName .root then some .root
  else if role = roleName .fpp then some .fpp
  else if role = roleName .piop then some .piop
  else if role = roleName .decs then some .decs else none

theorem role_roundtrip (kind : Kind) : decodeRole (roleName kind) = some kind := by
  cases kind <;> decide

/-- Length includes every digest, coefficient, salt, tape, count and binding byte.
No unary node exists in the exact 2^23-leaf source tree. -/
def payloadBytes : Kind → Nat
  | .leaf => 1280
  | .node => 128
  | .root => 1200
  | .fpp => 17408
  | .piop => 24904
  | .decs => 39040

structure Payload where
  kind : Kind
  bytes : List Byte
deriving DecidableEq

def Payload.Valid (context : Context) (payload : Payload) : Prop :=
  context.Canonical ∧ payload.bytes.length = payloadBytes payload.kind ∧
  match payload.kind with
  | .leaf => payload.bytes.take 32 = context.salt ∧
      wordAt payload.bytes 4 < 8388608 ∧ wordAt payload.bytes 13 = 140 ∧
      wordAt payload.bytes 154 = 5 ∧
      (∀ i : Fin 140, wordAt payload.bytes (14 + i.val) < goldilocksModulus) ∧
      (∀ i : Fin 5, wordAt payload.bytes (155 + i.val) < goldilocksModulus)
  | .node => True
  | .root => payload.bytes.take 32 = context.salt ∧
      payload.bytes.drop 96 = context.binding
  | .fpp => (∀ i : Fin 2030, wordAt payload.bytes (8 + i.val) < goldilocksModulus) ∧
      payload.bytes.drop 16304 = context.binding
  | .piop => ∀ i : Fin 3105, wordAt payload.bytes (8 + i.val) < goldilocksModulus
  | .decs => ∀ i : Fin 4872, wordAt payload.bytes (8 + i.val) < goldilocksModulus

instance (context : Context) (payload : Payload) : Decidable (payload.Valid context) := by
  unfold Payload.Valid
  cases payload.kind <;> infer_instance

/-- Full raw payload remains accessible as `value.bytes`; validation evidence
only records the checks actually performed by `parsePayload`. -/
abbrev ParsedInput (context : Context) := { payload : Payload // payload.Valid context }

def parsePayload (context : Context) (role bytes : List Byte) : Option (ParsedInput context) := do
  let kind ← decodeRole role
  let payload : Payload := ⟨kind, bytes⟩
  if valid : payload.Valid context then some ⟨payload, valid⟩ else none

theorem payload_roundtrip (context : Context) (parsed : ParsedInput context) :
    parsePayload context (roleName parsed.val.kind) parsed.val.bytes = some parsed := by
  rcases parsed with ⟨⟨kind, bytes⟩, valid⟩
  simp [parsePayload, role_roundtrip, valid]

theorem parsed_payload_exact_length (context : Context) (parsed : ParsedInput context) :
    parsed.val.bytes.length = payloadBytes parsed.val.kind := parsed.property.2.1

theorem accepted_fpp_checks_all_2030_coefficients (context : Context)
    (parsed : ParsedInput context) (kind : parsed.val.kind = .fpp) :
    (∀ i : Fin 2030, wordAt parsed.val.bytes (8 + i.val) < goldilocksModulus) ∧
      parsed.val.bytes.drop 16304 = context.binding := by
  have checked := parsed.property.2.2
  simpa only [kind] using checked

theorem accepted_fpp_cannot_have_q20_length (context : Context)
    (parsed : ParsedInput context) (kind : parsed.val.kind = .fpp) :
    parsed.val.bytes.length ≠ 16688 := by
  have exactLength := parsed_payload_exact_length context parsed
  rw [kind] at exactLength
  simp only [payloadBytes] at exactLength
  omega

theorem accepted_root_retains_exact_context (context : Context)
    (parsed : ParsedInput context) (kind : parsed.val.kind = .root) :
    parsed.val.bytes.take 32 = context.salt ∧ parsed.val.bytes.drop 96 = context.binding := by
  have checked := parsed.property.2.2
  simpa only [kind] using checked

def framedInput (role payload : List Byte) : RawInput :=
  encodeLE 8 profileDomain.length ++ profileDomain ++
  encodeLE 8 role.length ++ role ++ encodeLE 8 (payload.length / 8) ++ payload ++ encodeLE 8 0

def parseFramed (input : RawInput) : Option (List Byte × List Byte) := do
  let (profileLength, rest) ← readFixed 8 input
  let (profile, rest) ← readFixed (decodeLE profileLength) rest
  let (roleLength, rest) ← readFixed 8 rest
  let (role, rest) ← readFixed (decodeLE roleLength) rest
  let (wordCount, rest) ← readFixed 8 rest
  let (payload, rest) ← readFixed (8 * decodeLE wordCount) rest
  let (counter, rest) ← readFixed 8 rest
  if profile = profileDomain ∧ decodeLE counter = 0 ∧ rest = [] then
    some (role, payload) else none

theorem frame_roundtrip (role payload : List Byte)
    (roleBound : role.length < 256 ^ 8) (countBound : payload.length / 8 < 256 ^ 8)
    (aligned : 8 * (payload.length / 8) = payload.length) :
    parseFramed (framedInput role payload) = some (role, payload) := by
  have profileLength : profileDomain.length = 53 := by decide
  have roleMod : role.length % 18446744073709551616 = role.length := Nat.mod_eq_of_lt roleBound
  have countMod : (payload.length / 8) % 18446744073709551616 = payload.length / 8 := Nat.mod_eq_of_lt countBound
  simp [parseFramed, framedInput, List.append_assoc, readFixed, encodeLE_length,
    decodeLE_encodeLE, roleMod, countMod, profileLength, aligned]
  decide

def rawPayload (input : RawInput) : Option Payload := do
  let (role, payload) ← parseFramed input
  let kind ← decodeRole role
  if payload.length = payloadBytes kind then some ⟨kind, payload⟩ else none

def parseSource (context : Context) (input : RawInput) : Option (ParsedInput context) := do
  let payload ← rawPayload input
  if valid : payload.Valid context then some ⟨payload, valid⟩ else none

def payloadChildren (payload : Payload) : Finset RawDigest :=
  match payload.kind with
  | .leaf => ∅
  | .node => {digestAt payload.bytes 0, digestAt payload.bytes 64}
  | .root => {digestAt payload.bytes 32}
  | _ => {digestAt payload.bytes 0}

def parsedChildren {context : Context} (parsed : ParsedInput context) : Finset RawDigest :=
  payloadChildren parsed.val

def sourceChildren (context : Context) (input : RawInput) : Finset RawDigest :=
  match parseSource context input with
  | none => ∅
  | some parsed => parsedChildren parsed

theorem parsed_children_arity {context : Context} (parsed : ParsedInput context) :
    (parsedChildren parsed).card ≤ 2 := by
  cases kind : parsed.val.kind <;> simp [parsedChildren, payloadChildren, kind]
  exact Finset.card_le_two

theorem source_children_arity (context : Context) (input : RawInput) :
    (sourceChildren context input).card ≤ 2 := by
  cases parsed : parseSource context input with
  | none => simp [sourceChildren, parsed]
  | some value => simpa [sourceChildren, parsed] using parsed_children_arity value

inductive Stage where
  | tree (remaining : Nat)
  | root | fpp | piop | decs
deriving DecidableEq

def parsedNext {context : Context} (stage : Stage) (parsed : ParsedInput context) :
    Option (List (Stage × RawDigest)) :=
  match stage, parsed.val.kind with
  | .tree 0, .leaf => some []
  | .tree (depth + 1), .node => some [(.tree depth, digestAt parsed.val.bytes 0),
      (.tree depth, digestAt parsed.val.bytes 64)]
  | .root, .root => some [(.tree 23, digestAt parsed.val.bytes 32)]
  | .fpp, .fpp => some [(.root, digestAt parsed.val.bytes 0)]
  | .piop, .piop => some [(.fpp, digestAt parsed.val.bytes 0)]
  | .decs, .decs => some [(.piop, digestAt parsed.val.bytes 0)]
  | _, _ => none

def sourceNext (context : Context) (stage : Stage) (input : RawInput) :
    Option (List (Stage × RawDigest)) :=
  (parseSource context input).bind (parsedNext stage)

theorem parsed_next_child {context : Context} (stage : Stage) (parsed : ParsedInput context)
    (edges : List (Stage × RawDigest)) (decoded : parsedNext stage parsed = some edges)
    (edge : Stage × RawDigest) (member : edge ∈ edges) : edge.2 ∈ parsedChildren parsed := by
  cases stage with
  | tree depth =>
    cases depth <;> cases kind : parsed.val.kind <;> simp [parsedNext, kind] at decoded
    all_goals subst edges; simp_all [parsedChildren, payloadChildren]
    all_goals aesop
  | root | fpp | piop | decs =>
    cases kind : parsed.val.kind <;> simp [parsedNext, kind] at decoded
    all_goals subst edges; simp_all [parsedChildren, payloadChildren]

theorem source_next_child (context : Context) (stage : Stage) (input : RawInput)
    (edges : List (Stage × RawDigest)) (decoded : sourceNext context stage input = some edges)
    (edge : Stage × RawDigest) (member : edge ∈ edges) : edge.2 ∈ sourceChildren context input := by
  cases parsed : parseSource context input with
  | none => simp [sourceNext, parsed] at decoded
  | some value =>
    simp only [sourceNext, parsed, Option.bind_some] at decoded
    simpa only [sourceChildren, parsed] using parsed_next_child stage value edges decoded edge member

/-- Instability follows from this parser's real outgoing digests. It is not an
extraction-success premise and does not use the historical sourceNext. -/
theorem changed_outputs_card_le (context : Context)
    (records : V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest)
    (input : RawInput) (fuel : Nat) (targets : List (Stage × RawDigest)) :
    (V8Smz9CoherentMerkleGeometry.changedOutputs (sourceNext context) records input fuel targets).card
      ≤ targets.length + records.card * 2 := by
  exact V8Smz9CoherentMerkleGeometry.changed_outputs_card_le
    (sourceNext context) (sourceChildren context) (source_next_child context)
    2 (source_children_arity context) records input fuel targets

/-- Context-independent outgoing digest envelope. Only exact role lengths
are admitted, so digestAt never pads a missing child. This includes records
whose field/context checks fail, which is a safe superset for instability. -/
def rawChildren (input : RawInput) : Finset RawDigest :=
  match rawPayload input with
  | none => ∅
  | some payload => payloadChildren payload

theorem raw_children_arity (input : RawInput) : (rawChildren input).card ≤ 2 := by
  cases raw : rawPayload input with
  | none => simp [rawChildren, raw]
  | some payload =>
    cases kind : payload.kind <;> simp [rawChildren, raw, payloadChildren, kind]
    exact Finset.card_le_two

theorem accepted_children_are_raw (context : Context) (input : RawInput)
    (parsed : ParsedInput context) (accepted : parseSource context input = some parsed) :
    rawChildren input = parsedChildren parsed := by
  unfold parseSource at accepted
  cases raw : rawPayload input with
  | none => simp [raw] at accepted
  | some payload =>
    rw [raw] at accepted
    change (if valid : payload.Valid context then some (⟨payload, valid⟩ : ParsedInput context) else none) = some parsed at accepted
    split at accepted
    · next valid =>
      have same := Option.some.inj accepted
      subst parsed
      simp [rawChildren, raw, parsedChildren]
    · simp at accepted

theorem source_next_raw_child (context : Context) (stage : Stage) (input : RawInput)
    (edges : List (Stage × RawDigest)) (decoded : sourceNext context stage input = some edges)
    (edge : Stage × RawDigest) (member : edge ∈ edges) : edge.2 ∈ rawChildren input := by
  cases parsed : parseSource context input with
  | none => simp [sourceNext, parsed] at decoded
  | some value =>
    simp only [sourceNext, parsed, Option.bind_some] at decoded
    rw [accepted_children_are_raw context input value parsed]
    exact parsed_next_child stage value edges decoded edge member

/-- Every target carries its own expected salt/PB02 context. Multiple statements
share one raw record database without silently fixing a global binding. -/
abbrev GlobalStage := Context × Stage

def globalNext (stage : GlobalStage) (input : RawInput) :
    Option (List (GlobalStage × RawDigest)) :=
  (sourceNext stage.1 stage.2 input).map fun edges =>
    edges.map fun edge => ((stage.1, edge.1), edge.2)

theorem global_next_child (stage : GlobalStage) (input : RawInput)
    (edges : List (GlobalStage × RawDigest)) (decoded : globalNext stage input = some edges)
    (edge : GlobalStage × RawDigest) (member : edge ∈ edges) : edge.2 ∈ rawChildren input := by
  unfold globalNext at decoded
  cases localEdges : sourceNext stage.1 stage.2 input with
  | none => simp [localEdges] at decoded
  | some localList =>
    simp only [localEdges, Option.map_some, Option.some.injEq] at decoded
    rw [← decoded] at member
    obtain ⟨localEdge, localMember, same⟩ := List.mem_map.mp member
    subst edge
    exact source_next_raw_child stage.1 stage.2 input localList localEdges localEdge localMember

theorem global_changed_outputs_card_le
    (records : V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest)
    (input : RawInput) (fuel : Nat) (targets : List (GlobalStage × RawDigest)) :
    (V8Smz9CoherentMerkleGeometry.changedOutputs globalNext records input fuel targets).card
      ≤ targets.length + records.card * 2 := by
  exact V8Smz9CoherentMerkleGeometry.changed_outputs_card_le
    globalNext rawChildren global_next_child 2 raw_children_arity records input fuel targets

end HegemonCrypto.SmallWood.V8SmzaOracleParser
