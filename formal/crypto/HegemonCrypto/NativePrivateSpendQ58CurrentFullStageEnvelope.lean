import HegemonCrypto.NativePrivateSpendQ58CurrentLeafInput
import HegemonCrypto.NativePrivateSpendQ58EnvelopeInstability
import SmzaRp05ExecutableMerklePaths

/-! Current70-byte COMPFF01 source extraction grammar. The whole raw input is
preserved, all six roles are distinguished, and only counter0 enters this
stage decoder. This is not a definition of proof acceptance or a prior-cut
membership premise. Historical SMZA sources are imported without modification. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFullStageEnvelope

open HegemonCrypto.CanonicalBytes
  (Byte encodeLE encodeLE_length decodeLE decodeLE_encodeLE readFixed)
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle V8SmzaOnlineParser
open SmzaRp05FilteredDecoderInstability
open SmzaRp04StatementRecordFilter SmzaRp04AuthorizedLabelTransport
open SmzaDynamicDatabaseSoundness
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false

abbrev RawInput := List Byte
abbrev RawDigest := Fin 64 → Byte
abbrev Kind := V8SmzaOracleParser.Kind
abbrev Payload := V8SmzaOracleParser.Payload
abbrev Stage := V8SmzaOracleParser.Stage
abbrev Trace := ExtractionTrace RawInput
abbrev Next := Stage → RawInput → Option (List (Stage × RawDigest))
local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

/-- Binding is the complete current77-word public source binding. Equality
below preserves every byte. The suite/mode is bound separately by the exact
70-byte COMPFF01 profile in parseFrame. F1 supplies binding from the native
verifier context constructor, not from this parser or a new acceptance axiom. -/
structure Context where
  salt : List Byte
  binding : List Byte
  deriving DecidableEq

def Context.Canonical (context : Context) : Prop :=
  context.salt.length = 32 ∧ context.binding.length = 616 ∧
  ∀ i : Fin 77, wordAt context.binding i.val <
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus

instance (context : Context) : Decidable context.Canonical := by
  unfold Context.Canonical
  infer_instance

def roleName : Kind → List Byte
  | .leaf => NativePrivateSpendQ58CurrentLeafInput.currentLeafRole
  | .node => SmallWoodTranscript.merkleNodeDomain
  | .root => SmallWoodTranscript.merkleRootDomain
  | .fpp => SmallWoodTranscript.piopInputDomain
  | .piop => SmallWoodTranscript.piopTranscriptDomain
  | .decs => SmallWoodTranscript.decsOpeningDomain

def decodeRole (role : List Byte) : Option Kind :=
  if role = roleName .leaf then some .leaf
  else if role = roleName .node then some .node
  else if role = roleName .root then some .root
  else if role = roleName .fpp then some .fpp
  else if role = roleName .piop then some .piop
  else if role = roleName .decs then some .decs else none

theorem role_roundtrip (kind : Kind) : decodeRole (roleName kind) = some kind := by
  cases kind <;> decide

/-- Bytes inside the literal word payload, excluding profile/role framing. -/
def payloadBytes : Kind → Nat
  | .leaf => 1896
  | .node => 128
  | .root => 712
  | .fpp => 527600
  | .piop => 8344
  | .decs => 1264672

def canonicalFields (bytes : List Byte) (start count : Nat) : Prop :=
  ∀ i : Fin count, wordAt bytes (start + i.val) <
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus

/-- Typed field words are checked only in actual field positions. SHA512
children, four raw salt words and eight raw leaf-tape words are unrestricted
u64 data. Treating any of those raw coordinates as canonical field elements
would wrongly change the native grammar. -/
def Valid (context : Context) (payload : Payload) : Prop :=
  context.Canonical ∧ payload.bytes.length = payloadBytes payload.kind ∧
  match payload.kind with
  | .leaf => payload.bytes.take 616 = context.binding ∧
      (payload.bytes.drop 616).take 32 = context.salt ∧
      wordAt payload.bytes 81 < 8388608 ∧
      wordAt payload.bytes 90 = 140 ∧ wordAt payload.bytes 231 = 5 ∧
      canonicalFields payload.bytes 91 140 ∧ canonicalFields payload.bytes 232 5
  | .node => True
  | .root => payload.bytes.take 32 = context.salt ∧
      payload.bytes.drop 96 = context.binding
  | .fpp => canonicalFields payload.bytes 8 65865 ∧
      payload.bytes.drop 526984 = context.binding
  | .piop => canonicalFields payload.bytes 8 1035
  | .decs => canonicalFields payload.bytes 8 158076

instance (context : Context) (payload : Payload) : Decidable (Valid context payload) := by
  unfold Valid canonicalFields
  cases payload.kind <;> infer_instance

abbrev ParsedInput (context : Context) := { payload : Payload // Valid context payload }

def parseFrame (input : RawInput) : Option (List Byte × List Byte) := do
  let (profileLength, rest) ← readFixed 8 input
  let (profile, rest) ← readFixed (decodeLE profileLength) rest
  let (roleLength, rest) ← readFixed 8 rest
  let (role, rest) ← readFixed (decodeLE roleLength) rest
  let (wordCount, rest) ← readFixed 8 rest
  let (payload, rest) ← readFixed (8 * decodeLE wordCount) rest
  let (counter, suffix) ← readFixed 8 rest
  if profile = NativePrivateSpendQ58CurrentLeafInput.currentProfile ∧
      decodeLE counter = 0 ∧ suffix = [] then some (role, payload) else none

def frame (role : List Byte) (count : Nat) (payload : List Byte) : RawInput :=
  encodeLE 8 70 ++ NativePrivateSpendQ58CurrentLeafInput.currentProfile ++
    encodeLE 8 role.length ++ role ++ encodeLE 8 count ++ payload ++ encodeLE 8 0

/-- Pure serialization roundtrip; no successful-extraction premise. -/
theorem frame_roundtrip (role : List Byte) (count : Nat) (payload : List Byte)
    (roleBound : role.length < 256 ^ 8) (countBound : count < 256 ^ 8)
    (payloadLength : payload.length = 8 * count) :
    parseFrame (frame role count payload) = some (role, payload) := by
  have profileLength : NativePrivateSpendQ58CurrentLeafInput.currentProfile.length = 70 := by
    decide
  have roleMod : role.length % 18446744073709551616 = role.length :=
    Nat.mod_eq_of_lt roleBound
  have countMod : count % 18446744073709551616 = count :=
    Nat.mod_eq_of_lt countBound
  have finalRead : readFixed 8 (encodeLE 8 0) = some (encodeLE 8 0, []) := by
    simpa only [List.append_nil] using
      (HegemonCrypto.CanonicalBytes.readFixed_append
        (count := 8) (pre := encodeLE 8 0) (suffix := []) (encodeLE_length 8 0))
  simp [parseFrame, frame, List.append_assoc, encodeLE_length,
    decodeLE_encodeLE, profileLength, roleMod, countMod, payloadLength, finalRead]

def rawPayload (input : RawInput) : Option Payload := do
  let (role, bytes) ← parseFrame input
  let kind ← decodeRole role
  if bytes.length = payloadBytes kind then some ⟨kind, bytes⟩ else none

def parseSource (context : Context) (input : RawInput) : Option (ParsedInput context) := do
  let payload ← rawPayload input
  if valid : Valid context payload then some ⟨payload, valid⟩ else none

/-- Same six finite child shapes as PR205, with the complete new frame parser.
The raw envelope safely includes context-invalid inputs; the decoder does not. -/
def rawChildren (input : RawInput) : Finset RawDigest :=
  match rawPayload input with
  | none => ∅
  | some payload => V8SmzaOracleParser.payloadChildren payload

theorem raw_children_arity (input : RawInput) : (rawChildren input).card ≤ 2 := by
  cases parsed : rawPayload input with
  | none => simp [rawChildren, parsed]
  | some payload =>
    cases kind : payload.kind <;>
      simp [rawChildren, parsed, V8SmzaOracleParser.payloadChildren, kind]
    exact Finset.card_le_two

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

def rawNext (stage : Stage) (input : RawInput) : Option (List (Stage × RawDigest)) :=
  (rawPayload input).bind (payloadNext stage)

def sourceNext (context : Context) (stage : Stage) (input : RawInput) :
    Option (List (Stage × RawDigest)) :=
  (parseSource context input).bind (fun parsed => payloadNext stage parsed.val)

theorem payload_next_child (stage : Stage) (payload : Payload)
    (edges : List (Stage × RawDigest)) (decoded : payloadNext stage payload = some edges)
    (edge : Stage × RawDigest) (member : edge ∈ edges) :
    edge.2 ∈ V8SmzaOracleParser.payloadChildren payload := by
  cases stage with
  | tree depth =>
    cases depth <;> cases kind : payload.kind <;> simp [payloadNext, kind] at decoded
    all_goals subst edges; simp_all [V8SmzaOracleParser.payloadChildren]
    all_goals aesop
  | root | fpp | piop | decs =>
    cases kind : payload.kind <;> simp [payloadNext, kind] at decoded
    all_goals subst edges; simp_all [V8SmzaOracleParser.payloadChildren]

theorem source_next_child (context : Context) (stage : Stage) (input : RawInput)
    (edges : List (Stage × RawDigest)) (decoded : sourceNext context stage input = some edges)
    (edge : Stage × RawDigest) (member : edge ∈ edges) : edge.2 ∈ rawChildren input := by
  cases raw : rawPayload input with
  | none => simp [sourceNext, parseSource, raw] at decoded
  | some payload =>
    by_cases valid : Valid context payload
    · have parsed : parseSource context input = some ⟨payload, valid⟩ := by
        unfold parseSource
        rw [raw]
        change (if checked : Valid context payload then
          some (Subtype.mk payload checked : ParsedInput context) else none) =
            some (Subtype.mk payload valid : ParsedInput context)
        rw [dif_pos valid]
      rw [sourceNext, parsed, Option.bind_some] at decoded
      simpa only [rawChildren, raw] using payload_next_child stage payload edges decoded edge member
    · simp [sourceNext, parseSource, raw, valid] at decoded

/-- Exact literal constructor for each role; the payload length remains data. -/
theorem raw_payload_frame (kind : Kind) (count : Nat) (bytes : List Byte)
    (countBound : count < 256 ^ 8) (aligned : bytes.length = 8 * count)
    (length : bytes.length = payloadBytes kind) :
    rawPayload (frame (roleName kind) count bytes) = some ⟨kind, bytes⟩ := by
  have parsed := frame_roundtrip (roleName kind) count bytes
    (by cases kind <;> decide) countBound aligned
  unfold rawPayload
  rw [parsed]
  change (decodeRole (roleName kind)).bind
    (fun parsedKind => if bytes.length = payloadBytes parsedKind then
      some (V8SmzaOracleParser.Payload.mk parsedKind bytes) else none) =
        some (V8SmzaOracleParser.Payload.mk kind bytes)
  rw [role_roundtrip, Option.bind_some, if_pos length]

def nodeInput (left right : RawDigest) : RawInput :=
  frame (roleName .node) 16 (List.ofFn left ++ List.ofFn right)

def rootInput (context : Context) (root : RawDigest) : RawInput :=
  frame (roleName .root) 89 (context.salt ++ List.ofFn root ++ context.binding)

theorem node_constructor_edges (depth : Nat) (left right : RawDigest) :
    rawNext (.tree (depth + 1)) (nodeInput left right) =
      some [(.tree depth, left), (.tree depth, right)] := by
  have parsed := raw_payload_frame .node 16 (List.ofFn left ++ List.ofFn right)
    (by decide) (by simp) (by simp [payloadBytes])
  have leftRead := SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append left (List.ofFn right)
  have rightRead := SmzaRp05ExecutableMerkleVerifier.digest_at_prefix_ofFn (List.ofFn left) [] right
  simp only [List.append_nil, List.length_ofFn] at rightRead
  simp only [rawNext, nodeInput, parsed, Option.bind_some, payloadNext]
  rw [leftRead, rightRead]

theorem root_constructor_edges (context : Context) (root : RawDigest)
    (canonical : context.Canonical) :
    rawNext .root (rootInput context root) = some [(.tree 23, root)] := by
  have parsed := raw_payload_frame .root 89 (context.salt ++ List.ofFn root ++ context.binding)
    (by decide) (by simp [canonical.1, canonical.2.1])
    (by simp [payloadBytes, canonical.1, canonical.2.1])
  have rootRead := SmzaRp05ExecutableMerkleVerifier.digest_at_prefix_ofFn
    context.salt context.binding root
  rw [canonical.1] at rootRead
  simp only [rawNext, rootInput, parsed, Option.bind_some, payloadNext]
  rw [List.append_assoc, rootRead]

/-- Parsed source frames retain every canonical/context check. -/
theorem source_payload_frame (context : Context) (kind : Kind)
    (count : Nat) (bytes : List Byte) (countBound : count < 256 ^ 8)
    (aligned : bytes.length = 8 * count) (valid : Valid context ⟨kind, bytes⟩) :
    parseSource context (frame (roleName kind) count bytes) = some ⟨⟨kind, bytes⟩, valid⟩ := by
  have length : bytes.length = payloadBytes kind := valid.2.1
  have parsed := raw_payload_frame kind count bytes countBound aligned length
  unfold parseSource
  rw [parsed]
  change (if checked : Valid context (V8SmzaOracleParser.Payload.mk kind bytes) then
    some (Subtype.mk (V8SmzaOracleParser.Payload.mk kind bytes) checked : ParsedInput context)
      else none) =
        some (Subtype.mk (V8SmzaOracleParser.Payload.mk kind bytes) valid : ParsedInput context)
  rw [dif_pos valid]

/-- A current canonical context admits both native node children. -/
theorem source_node_constructor_edges (context : Context) (depth : Nat)
    (left right : RawDigest) (canonical : context.Canonical) :
    sourceNext context (.tree (depth + 1)) (nodeInput left right) =
      some [(.tree depth, left), (.tree depth, right)] := by
  have valid : Valid context ⟨.node, List.ofFn left ++ List.ofFn right⟩ := by
    change context.Canonical ∧ (List.ofFn left ++ List.ofFn right).length = 128 ∧ True
    exact ⟨canonical, by simp, trivial⟩
  have parsed := source_payload_frame context .node 16
    (List.ofFn left ++ List.ofFn right) (by decide) (by simp) valid
  have leftRead := SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append left (List.ofFn right)
  have rightRead := SmzaRp05ExecutableMerkleVerifier.digest_at_prefix_ofFn (List.ofFn left) [] right
  simp only [List.append_nil, List.length_ofFn] at rightRead
  simp only [sourceNext, nodeInput, parsed, Option.bind_some, payloadNext]
  rw [leftRead, rightRead]

/-- A current root checks the complete salt and77-word binding before exposing
its source tree root. No old1104-byte context is silently retained. -/
theorem source_root_constructor_edges (context : Context) (root : RawDigest)
    (canonical : context.Canonical) :
    sourceNext context .root (rootInput context root) = some [(.tree 23, root)] := by
  have valid : Valid context ⟨.root, context.salt ++ List.ofFn root ++ context.binding⟩ := by
    refine ⟨canonical, ?_, ?_⟩
    · simp only [List.length_append, List.length_ofFn, payloadBytes, canonical.1, canonical.2.1]
    · constructor
      · simp [canonical.1]
      · simp [List.drop_append, canonical.1]
  have parsed := source_payload_frame context .root 89
    (context.salt ++ List.ofFn root ++ context.binding) (by decide)
    (by simp [canonical.1, canonical.2.1]) valid
  have rootRead := SmzaRp05ExecutableMerkleVerifier.digest_at_prefix_ofFn
    context.salt context.binding root
  rw [canonical.1] at rootRead
  simp only [sourceNext, rootInput, parsed, Option.bind_some, payloadNext]
  rw [List.append_assoc, rootRead]

/-- One current-envelope instability bound. The next-child law and arity are
proved above; neither is supplied as an instability or accepted-coverage
assumption. All authorized labels, filters and original table state are kept. -/
theorem current_complete_filtered_two_pass_change_bound
    {Key Counter Statement Label : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [DecidableEq Statement]
    (context : Context) (keyBytes : Key → RawInput) (counter : Counter)
    (leafStatement : StatementParser RawInput Statement)
    (outerTarget : Key → Stage × RawDigest) (outerDecode : Key → Trace → Option Statement)
    (innerTarget : Statement → Key → Stage × RawDigest)
    (innerDecode : Statement → Key → Trace → Label)
    (outerFuel innerFuel : Nat) (authorized : Finset Statement) (cap : Nat)
    (database : Database Key (VectorOutput Counter)) (bounded : size database < cap)
    (queried : Key) :
    stepProbability
        (TrackedLabelChange
          (fun db input => completeFilteredLabel leafStatement
            (rawTraceDecoder (sourceNext context) outerTarget outerDecode outerFuel)
            (statementTraceDecoder (sourceNext context) innerTarget innerDecode innerFuel) authorized
            (rawRecords keyBytes (vectorOutputBytes counter) db) input)
          database queried) database queried ≤ (6 * cap : Rat) / (2^512 : Rat) := by
  exact NativePrivateSpendQ58EnvelopeInstability.complete_filtered_two_pass_change_bound
    rawChildren raw_children_arity (sourceNext context) (source_next_child context)
    keyBytes counter leafStatement outerTarget outerDecode innerTarget innerDecode
    outerFuel innerFuel authorized cap database bounded queried

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFullStageEnvelope
