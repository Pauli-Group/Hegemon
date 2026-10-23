import HegemonCrypto.NativeLaunchLeafReadback
import HegemonCrypto.NativeLaunchFppHistoryBinding

/-! Deterministic finite-path binding, not a probability or accepted-execution
claim. Ordinary node inputs contain only ordered child digests: no level/index.
Recorded prior input membership is explicit. Actual committed-tree construction,
index-route/compact-loop refinement, chronology and QROM accounting remain open. -/
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchMerklePathBinding
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput profileDomain parseSourceFrame)
open NativeLaunchRelationModelStatement
open NativeLaunchLeafReadback
open NativeLaunchFppHistoryBinding (Digest Oracle History RelevantCollision equal_of_no_relevant_collision digestBytes digest_bytes_length)
open SmallWood.V8Smz9RawCounterCompiler (typedWordPayload typed_word_payload_length typed_word_payload_injective typed_word_payload_is_source_payload)
open SmallWood.V8Smz9WholeViewObservation (RawSha512OracleKey)

def nodeRole : List Byte := [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,108,101,118,101,108,53,46,109,101,114,107,108,101,45,110,111,100,101]
def rootRole : List Byte := [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,108,101,118,101,108,53,46,109,101,114,107,108,101,45,114,111,111,116]

def encodeRole (family : Family) (role : List Byte) (words : List Word) : RawInput :=
  (RawSha512OracleKey.mk (some (profileDomain family)) role (words.map Fin.val) 0).preimage

def parseRolePayload (family : Family) (role : List Byte) (wordCount : Nat) (raw : RawInput) : Option RawInput := do
  let (profile, actualRole, payload, counter) ← parseSourceFrame raw
  if profile = profileDomain family ∧ actualRole = role ∧ counter = 0 ∧
      payload.length = 8 * wordCount then some payload else none

theorem role_frame_roundtrip (family : Family) (role : List Byte) (words : List Word)
    (roleBound : role.length < 18446744073709551616)
    (wordBound : words.length < 18446744073709551616) :
    parseSourceFrame (encodeRole family role words) =
      some (profileDomain family, role, typedWordPayload words, 0) := by
  have pm : (profileDomain family).length % 18446744073709551616 = (profileDomain family).length :=
    Nat.mod_eq_of_lt (NativeLaunchAdaptiveHistoryCodec.profileDomain_length_lt family)
  have rm := Nat.mod_eq_of_lt roleBound
  have wm := Nat.mod_eq_of_lt wordBound
  simp only [encodeRole, RawSha512OracleKey.preimage, List.length_map]
  rw [← typed_word_payload_is_source_payload]
  simp [parseSourceFrame, List.append_assoc, readFixed, encodeLE_length,
    decodeLE_encodeLE, pm, rm, wm, typed_word_payload_length]
  have ct : (encodeLE 8 0).take 8 = encodeLE 8 0 := by
    simpa only [encodeLE_length] using (List.take_length (l := encodeLE 8 0))
  rw [ct, decodeLE_encodeLE]
  rfl

theorem role_payload_roundtrip (family : Family) (role : List Byte) (words : List Word)
    (roleBound : role.length < 18446744073709551616)
    (wordBound : words.length < 18446744073709551616) :
    parseRolePayload family role words.length (encodeRole family role words) = some (typedWordPayload words) := by
  simp [parseRolePayload, role_frame_roundtrip family role words roleBound wordBound, typed_word_payload_length]

def nodeFrame (family : Family) (left right : Digest) : RawInput :=
  encodeRole family nodeRole (List.ofFn left ++ List.ofFn right)
def parseNode (family : Family) (raw : RawInput) : Option (RawInput × RawInput) :=
  (parseRolePayload family nodeRole 16 raw).map fun bytes => (bytes.take 64, bytes.drop 64)

theorem node_roundtrip (family : Family) (left right : Digest) :
    parseNode family (nodeFrame family left right) = some (digestBytes left, digestBytes right) := by
  have parsed := role_payload_roundtrip family nodeRole (List.ofFn left ++ List.ofFn right)
    (by decide) (by simp)
  simp only [List.length_append, List.length_ofFn] at parsed
  simp only [parseNode, nodeFrame, parsed, Option.map_some, typed_payload_append]
  change some ((digestBytes left ++ digestBytes right).take 64,
    (digestBytes left ++ digestBytes right).drop 64) = _
  rw [← digest_bytes_length left, List.take_left, List.drop_left]

theorem node_frame_injective (family : Family) (al ar bl br : Digest)
    (equal : nodeFrame family al ar = nodeFrame family bl br) : al = bl ∧ ar = br := by
  have parsed := congrArg (parseNode family) equal
  rw [node_roundtrip, node_roundtrip] at parsed
  have pair := Option.some.inj parsed
  exact ⟨List.ofFn_injective (typed_word_payload_injective (congrArg Prod.fst pair)),
    List.ofFn_injective (typed_word_payload_injective (congrArg Prod.snd pair))⟩

def saltBytes (salt : Fin 4 → Word) : RawInput := typedWordPayload (List.ofFn salt)
def rootFrame {family : Family} (salt : Fin 4 → Word) (root : Digest) (statement : Statement family) : RawInput :=
  encodeRole family rootRole (List.ofFn salt ++ List.ofFn root ++ statementWords statement)
def parseRoot (family : Family) (raw : RawInput) : Option (RawInput × RawInput × RawInput) :=
  (parseRolePayload family rootRole (12 + preambleWordCount family) raw).map fun bytes =>
    (bytes.take 32, (bytes.drop 32).take 64, (bytes.drop 32).drop 64)

theorem root_roundtrip {family : Family} (salt : Fin 4 → Word) (root : Digest) (statement : Statement family) :
    parseRoot family (rootFrame salt root statement) =
      some (saltBytes salt, digestBytes root, statementBytes statement) := by
  have bound : (List.ofFn salt ++ List.ofFn root ++ statementWords statement).length < 18446744073709551616 := by
    simp only [List.length_append, List.length_ofFn, statement_words_length]
    cases family <;> decide
  have parsed := role_payload_roundtrip family rootRole
    (List.ofFn salt ++ List.ofFn root ++ statementWords statement) (by decide) bound
  have length : (List.ofFn salt ++ List.ofFn root ++ statementWords statement).length =
      12 + preambleWordCount family := by
    simp only [List.length_append, List.length_ofFn, statement_words_length]
  rw [length] at parsed
  unfold parseRoot rootFrame
  rw [parsed]
  simp only [Option.map_some, typed_payload_append, List.append_assoc]
  change some ((saltBytes salt ++ (digestBytes root ++ statementBytes statement)).take 32,
    ((saltBytes salt ++ (digestBytes root ++ statementBytes statement)).drop 32).take 64,
    ((saltBytes salt ++ (digestBytes root ++ statementBytes statement)).drop 32).drop 64) = _
  have sl : (saltBytes salt).length = 32 := by simp [saltBytes, typed_word_payload_length]
  rw [← sl, List.take_left, List.drop_left, ← digest_bytes_length root, List.take_left, List.drop_left]

theorem root_frame_injective {family : Family} (as bs : Fin 4 → Word) (ar br : Digest)
    (ast bst : Statement family) (equal : rootFrame as ar ast = rootFrame bs br bst) :
    as = bs ∧ ar = br ∧ ast = bst := by
  have parsed := congrArg (parseRoot family) equal
  rw [root_roundtrip, root_roundtrip] at parsed
  have parts := Option.some.inj parsed
  exact ⟨List.ofFn_injective (typed_word_payload_injective (congrArg Prod.fst parts)),
    List.ofFn_injective (typed_word_payload_injective (congrArg (fun p => p.2.1) parts)),
    statementBytes_injective family (congrArg (fun p => p.2.2) parts)⟩

/-- Two paths share each index direction bit but may have different siblings.
Bottom-up ordering; true means the current digest is the right child. -/
inductive PairedPath : Nat → Type where
  | nil : PairedPath 0
  | step {depth : Nat} (right : Bool) (priorSibling rebuiltSibling : Digest)
      (rest : PairedPath depth) : PairedPath (depth+1)

def nodeInput (family : Family) (right : Bool) (current sibling : Digest) : RawInput :=
  if right then nodeFrame family sibling current else nodeFrame family current sibling

def pathRoot (H : Oracle) (family : Family) (rebuilt : Bool) :
    {depth : Nat} → PairedPath depth → Digest → Digest
  | _, .nil, current => current
  | _, .step right priorSibling rebuiltSibling rest, current =>
    pathRoot H family rebuilt rest (H (nodeInput family right current (if rebuilt then rebuiltSibling else priorSibling)))

def pathInputs (H : Oracle) (family : Family) (rebuilt : Bool) :
    {depth : Nat} → PairedPath depth → Digest → History
  | _, .nil, _ => []
  | _, .step right priorSibling rebuiltSibling rest, current =>
    let key := nodeInput family right current (if rebuilt then rebuiltSibling else priorSibling)
    key :: pathInputs H family rebuilt rest (H key)

/-- Induct backwards through equal roots. Every hash inversion is justified
only by explicit membership and the finite no-collision hypothesis. -/
theorem path_digest_binding {depth : Nat} (H : Oracle) (family : Family) (path : PairedPath depth)
    (inputs : History) (clean : ¬ RelevantCollision H inputs) (left right : Digest)
    (leftMem : ∀ key ∈ pathInputs H family false path left, key ∈ inputs)
    (rightMem : ∀ key ∈ pathInputs H family true path right, key ∈ inputs)
    (equal : pathRoot H family false path left = pathRoot H family true path right) : left = right := by
  induction path generalizing left right with
  | nil => exact equal
  | step direction priorSibling rebuiltSibling rest ih =>
    have next : H (nodeInput family direction left priorSibling) = H (nodeInput family direction right rebuiltSibling) := by
      apply ih
      · intro key member
        apply leftMem key
        simp [pathInputs, member]
      · intro key member
        apply rightMem key
        simp [pathInputs, member]
      · exact equal
    have keys := equal_of_no_relevant_collision H inputs clean
      (nodeInput family direction left priorSibling) (nodeInput family direction right rebuiltSibling)
      (leftMem _ (by simp [pathInputs])) (rightMem _ (by simp [pathInputs])) next
    cases direction with
    | false => exact (node_frame_injective family _ _ _ _ keys).1
    | true => exact (node_frame_injective family _ _ _ _ keys).2

def wrappedPath {depth : Nat} (H : Oracle) (family : Family) (rebuilt : Bool)
    (path : PairedPath depth) (leaf : RawInput) (salt : Fin 4 → Word) (statement : Statement family) : RawInput :=
  rootFrame salt (pathRoot H family rebuilt path (H leaf)) statement

def relevantInputs {depth : Nat} (H : Oracle) (history : History) (family : Family)
    (path : PairedPath depth) (rebuiltLeaf : RawInput) (salt : Fin 4 → Word) (statement : Statement family) : History :=
  rebuiltLeaf :: wrappedPath H family true path rebuiltLeaf salt statement ::
    (pathInputs H family true path (H rebuiltLeaf) ++ history)

/-- Equal wrapper digests yield wrapper-field equality before path induction.
No direct Rust comparison of original tree roots is assumed. -/
theorem wrapper_digest_binds_leaf {depth : Nat} (H : Oracle) (history : History) (family : Family)
    (path : PairedPath depth) (priorLeaf rebuiltLeaf : RawInput)
    (priorSalt rebuiltSalt : Fin 4 → Word) (priorStatement rebuiltStatement : Statement family)
    (leafRecorded : priorLeaf ∈ history)
    (nodesRecorded : ∀ key ∈ pathInputs H family false path (H priorLeaf), key ∈ history)
    (wrapperRecorded : wrappedPath H family false path priorLeaf priorSalt priorStatement ∈ history)
    (equal : H (wrappedPath H family false path priorLeaf priorSalt priorStatement) =
      H (wrappedPath H family true path rebuiltLeaf rebuiltSalt rebuiltStatement))
    (clean : ¬ RelevantCollision H (relevantInputs H history family path rebuiltLeaf rebuiltSalt rebuiltStatement)) :
    priorLeaf = rebuiltLeaf ∧ priorSalt = rebuiltSalt ∧ priorStatement = rebuiltStatement := by
  have wrappers := equal_of_no_relevant_collision H _ clean _ _
    (by simp [relevantInputs, wrapperRecorded]) (by simp [relevantInputs]) equal
  obtain ⟨salts, roots, statements⟩ := root_frame_injective priorSalt rebuiltSalt _ _ priorStatement rebuiltStatement wrappers
  have leaves : H priorLeaf = H rebuiltLeaf := by
    apply path_digest_binding H family path _ clean _ _
    · intro key member
      have recorded := nodesRecorded key member
      simp [relevantInputs, recorded]
    · intro key member
      simp [relevantInputs, member]
    · exact roots
  exact ⟨equal_of_no_relevant_collision H _ clean _ _
    (by simp [relevantInputs, leafRecorded]) (by simp [relevantInputs]) leaves, salts, statements⟩

/-- Specialization recovers all actual strict-leaf fields. This does not
construct the recorded committed tree or refine the compact Rust loop. -/
theorem wrapped_strict_leaf_fields {depth : Nat} (H : Oracle) (history : History) (family : Family)
    (path : PairedPath depth) (left right : Statement family) (lf rf : LeafFields)
    (leafRecorded : strictLeafFrame left lf ∈ history)
    (nodesRecorded : ∀ key ∈ pathInputs H family false path (H (strictLeafFrame left lf)), key ∈ history)
    (wrapperRecorded : wrappedPath H family false path (strictLeafFrame left lf) lf.salt left ∈ history)
    (equal : H (wrappedPath H family false path (strictLeafFrame left lf) lf.salt left) =
      H (wrappedPath H family true path (strictLeafFrame right rf) rf.salt right))
    (clean : ¬ RelevantCollision H (relevantInputs H history family path (strictLeafFrame right rf) rf.salt right)) :
    left = right ∧ lf.index = rf.index ∧ lf.committed = rf.committed ∧
      lf.masks = rf.masks ∧ lf.salt = rf.salt ∧ lf.tape = rf.tape := by
  have raw := (wrapper_digest_binds_leaf H history family path
    (strictLeafFrame left lf) (strictLeafFrame right rf) lf.salt rf.salt left right
    leafRecorded nodesRecorded wrapperRecorded equal clean).1
  exact raw_leaf_equality_recovers_fields left right lf rf raw
end HegemonCrypto.NativeLaunchMerklePathBinding
