import SmallWoodV8SmzaOracleParserR2

/-!
Context-free online SMZA extraction. The algorithm receives only the raw
record database and actual final-sampler query bytes. Expected PB02 context is
used only by the separate offline parser; it is not free online advice.
No Rust refinement or quantum/extraction-success conclusion is asserted here.
-/
namespace HegemonCrypto.SmallWood.V8SmzaOnlineParser

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8SmzaOracleParser
open scoped Classical

set_option maxRecDepth 5000
set_option maxHeartbeats 1000000

/-- Wrappers validate their own full PB02 payload. Salt/binding agreement
between separate recorded preimages is a later offline acceptance check. -/
def syntaxValid (payload : Payload) : Prop :=
  payload.bytes.length = payloadBytes payload.kind ∧
  match payload.kind with
  | .leaf => wordAt payload.bytes 4 < 8388608 ∧ wordAt payload.bytes 13 = 140 ∧
      wordAt payload.bytes 154 = 5 ∧
      (∀ i : Fin 140, wordAt payload.bytes (14 + i.val) < goldilocksModulus) ∧
      (∀ i : Fin 5, wordAt payload.bytes (155 + i.val) < goldilocksModulus)
  | .node => True
  | .root => (Context.mk (payload.bytes.take 32) (payload.bytes.drop 96)).Canonical
  | .fpp => (∀ i : Fin 2030, wordAt payload.bytes (8 + i.val) < goldilocksModulus) ∧
      (Context.mk (List.replicate 32 0) (payload.bytes.drop 16304)).Canonical
  | .piop => ∀ i : Fin 3105, wordAt payload.bytes (8 + i.val) < goldilocksModulus
  | .decs => ∀ i : Fin 4872, wordAt payload.bytes (8 + i.val) < goldilocksModulus

instance (payload : Payload) : Decidable (syntaxValid payload) := by
  unfold syntaxValid
  cases payload.kind <;> infer_instance

def payloadNext (stage : Stage) (payload : Payload) : Option (List (Stage × RawDigest)) :=
  match stage, payload.kind with
  | .tree 0, .leaf => some []
  | .tree (depth + 1), .node => some [(.tree depth, digestAt payload.bytes 0),
      (.tree depth, digestAt payload.bytes 64)]
  | .root, .root => some [(.tree 23, digestAt payload.bytes 32)]
  | .fpp, .fpp => some [(.root, digestAt payload.bytes 0)]
  | .piop, .piop => some [(.fpp, digestAt payload.bytes 0)]
  | .decs, .decs => some [(.piop, digestAt payload.bytes 0)]
  | _, _ => none

def onlineNext (stage : Stage) (input : RawInput) : Option (List (Stage × RawDigest)) :=
  match rawPayload input with
  | none => none
  | some payload => if syntaxValid payload then payloadNext stage payload else none

theorem payload_next_child (stage : Stage) (payload : Payload)
    (edges : List (Stage × RawDigest)) (decoded : payloadNext stage payload = some edges)
    (edge : Stage × RawDigest) (member : edge ∈ edges) : edge.2 ∈ payloadChildren payload := by
  cases stage with
  | tree depth =>
    cases depth <;> cases kind : payload.kind <;> simp [payloadNext, kind] at decoded
    all_goals subst edges; simp_all [payloadChildren]
    all_goals aesop
  | root | fpp | piop | decs =>
    cases kind : payload.kind <;> simp [payloadNext, kind] at decoded
    all_goals subst edges; simp_all [payloadChildren]

theorem online_next_child (stage : Stage) (input : RawInput)
    (edges : List (Stage × RawDigest)) (decoded : onlineNext stage input = some edges)
    (edge : Stage × RawDigest) (member : edge ∈ edges) : edge.2 ∈ rawChildren input := by
  cases raw : rawPayload input with
  | none => simp [onlineNext, raw] at decoded
  | some payload =>
    by_cases valid : syntaxValid payload
    · simp only [onlineNext, raw, if_pos valid] at decoded
      simpa only [rawChildren, raw] using payload_next_child stage payload edges decoded edge member
    · simp [onlineNext, raw, valid] at decoded

theorem online_changed_outputs_card_le
    (records : V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest)
    (input : RawInput) (fuel : Nat) (targets : List (Stage × RawDigest)) :
    (V8Smz9CoherentMerkleGeometry.changedOutputs onlineNext records input fuel targets).card
      ≤ targets.length + records.card * 2 := by
  exact V8Smz9CoherentMerkleGeometry.changed_outputs_card_le
    onlineNext rawChildren online_next_child 2 raw_children_arity records input fuel targets

/-- Actual SMZA fixed-sampling source has only h_decs's eight raw words.
It does not append the zero returned nonce. Counter is physical XOF block
counter, not a grinding nonce; its source scheduling bound remains separate. -/
structure FinalQuery where
  target : RawDigest
  counter : Nat
  raw : RawInput

def parseFinalQuery (input : RawInput) : Option FinalQuery := do
  let (profileLength, rest) ← readFixed 8 input
  let (profile, rest) ← readFixed (decodeLE profileLength) rest
  let (roleLength, rest) ← readFixed 8 rest
  let (role, rest) ← readFixed (decodeLE roleLength) rest
  let (wordCount, rest) ← readFixed 8 rest
  let (payload, rest) ← readFixed (8 * decodeLE wordCount) rest
  let (counter, suffix) ← readFixed 8 rest
  if profile = profileDomain ∧ role = decsFixedSamplingDomain ∧
      payload.length = 64 ∧ suffix = [] then
    some ⟨digestAt payload 0, decodeLE counter, input⟩ else none

/-- Deterministic label computed only from actual recorded bytes and TIC.
The extraction trace keeps every selected full payload, including PB02. -/
def onlineLabel (records : V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest)
    (fuel : Nat) (actualRawQuery : RawInput) :
    V8Smz9CoherentMerkleGeometry.ExtractionTrace RawInput :=
  match parseFinalQuery actualRawQuery with
  | none => .missing
  | some query => V8Smz9CoherentMerkleGeometry.extract onlineNext records fuel .decs query.target

end HegemonCrypto.SmallWood.V8SmzaOnlineParser
