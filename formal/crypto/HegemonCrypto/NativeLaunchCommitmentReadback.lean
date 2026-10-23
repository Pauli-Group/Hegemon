import HegemonCrypto.NativeLaunchRelationModelStatement
import HegemonCrypto.NativeLaunchRelationModelResponse

/-! Complete FPP input codec at dd5e50cf031567f1d52a3422fa1c5c86c158a281.
Typed coefficients are canonical field representatives. Statements remain fixed
words, not accepted source statements. Parser success proves neither calculated
polynomial identity, authenticated oracle/Merkle readback, nor Rust refinement.
No security endpoint, chronology, public simulation or release claim is made. -/
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchCommitmentReadback
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Family Word profileDomain parseSourceFrame)
open NativeLaunchRelationModelStatement
open SmallWood.NativeLaunchRelationModelResponse (Branch degree)
open SmallWood.V8Smz9RawCounterCompiler
  (typedWordPayload typed_word_payload_length typed_word_payload_is_source_payload)
open SmallWood.V8Smz9WholeViewObservation (RawSha512OracleKey)

def family : Branch → Family | .rp06 => .rp06 | _ => .htlc
def coefficientCount (branch : Branch) : Nat := 5 * (degree branch + 1)
def bindingOffset (branch : Branch) : Nat := 64 + 8 * coefficientCount branch
def payloadBytes (branch : Branch) : Nat := bindingOffset branch + preambleByteCount (family branch)
def fppRole : List Byte := [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,108,101,118,101,108,53,46,112,105,111,112,45,105,110,112,117,116]

def encodeFields : List FieldWord → List Byte
  | [] => []
  | field :: rest => encodeLE 8 field.val ++ encodeFields rest

def readFields : Nat → List Byte → Option (List FieldWord × List Byte)
  | 0, input => some ([], input)
  | n+1, input => do
    let (bytes, rest) ← readFixed 8 input
    if bound : decodeLE bytes < 18446744069414584321 then
      let (fields, suffix) ← readFields n rest
      some (⟨decodeLE bytes, bound⟩ :: fields, suffix)
    else none

theorem fields_length (fields : List FieldWord) :
    (encodeFields fields).length = 8 * fields.length := by
  induction fields with
  | nil => rfl
  | cons field rest ih => simp [encodeFields, encodeLE_length, ih, Nat.mul_add, Nat.add_comm]

theorem fields_roundtrip (fields : List FieldWord) (suffix : List Byte) :
    readFields fields.length (encodeFields fields ++ suffix) = some (fields, suffix) := by
  induction fields with
  | nil => rfl
  | cons field rest ih =>
    have modulus : field.val % 18446744073709551616 = field.val :=
      Nat.mod_eq_of_lt (lt_trans field.isLt (by decide))
    simp [encodeFields, readFields, List.append_assoc, encodeLE_length,
      decodeLE_encodeLE, modulus, field.isLt, ih]

theorem fields_eq_words (fields : List FieldWord) :
    encodeFields fields = typedWordPayload (fields.map fieldAsWord) := by
  induction fields with
  | nil => rfl
  | cons field rest ih => simp [encodeFields, typedWordPayload, fieldAsWord, ih]

structure Commitment (branch : Branch) where
  root : Fin 8 → Word
  coefficients : Fin 5 → Fin (degree branch + 1) → FieldWord
  statement : Statement (family branch)

def coefficientList {branch : Branch} (c : Commitment branch) : List FieldWord :=
  (List.ofFn c.coefficients).flatMap List.ofFn

theorem coefficients_length {branch : Branch} (c : Commitment branch) :
    (coefficientList c).length = coefficientCount branch := by
  simp [coefficientList, coefficientCount]
  omega

def words {branch : Branch} (c : Commitment branch) : List Word :=
  List.ofFn c.root ++ (coefficientList c).map fieldAsWord ++ statementWords c.statement

def payload {branch : Branch} (c : Commitment branch) : List Byte :=
  typedWordPayload (List.ofFn c.root) ++ encodeFields (coefficientList c) ++ statementBytes c.statement

theorem payload_eq_words {branch : Branch} (c : Commitment branch) :
    payload c = typedWordPayload (words c) := by
  simp only [payload, words, typed_payload_append, fields_eq_words, statementBytes]

theorem payload_length {branch : Branch} (c : Commitment branch) :
    (payload c).length = payloadBytes branch := by
  simp [payload, typed_word_payload_length, fields_length, coefficients_length,
    statement_bytes_length, payloadBytes, bindingOffset, Nat.add_assoc]

def frame {branch : Branch} (c : Commitment branch) : List Byte :=
  (RawSha512OracleKey.mk (some (profileDomain (family branch))) fppRole
    ((words c).map Fin.val) 0).preimage

theorem frame_roundtrip {branch : Branch} (c : Commitment branch) :
    parseSourceFrame (frame c) = some (profileDomain (family branch), fppRole, payload c, 0) := by
  have profileMod : (profileDomain (family branch)).length % 18446744073709551616 =
      (profileDomain (family branch)).length := by cases branch <;> decide
  have roleMod : fppRole.length % 18446744073709551616 = fppRole.length := by decide
  have wordBound : (words c).length < 18446744073709551616 := by
    simp only [words, List.length_append, List.length_ofFn, List.length_map,
      coefficients_length, statement_words_length]
    cases branch <;> decide
  have wordMod := Nat.mod_eq_of_lt wordBound
  have payloadLength := typed_word_payload_length (words c)
  rw [payload_eq_words]
  simp only [frame, RawSha512OracleKey.preimage, List.length_map]
  rw [← typed_word_payload_is_source_payload]
  simp [parseSourceFrame, List.append_assoc, readFixed, encodeLE_length,
    decodeLE_encodeLE, profileMod, roleMod, wordMod, payloadLength]
  have counterTake : (encodeLE 8 0).take 8 = encodeLE 8 0 := by
    simpa only [encodeLE_length] using (List.take_length (l := encodeLE 8 0))
  rw [counterTake, decodeLE_encodeLE]
  rfl

/-- Root bytes, every canonical coefficient in source row order, and every
statement byte. No supplied semantic correctness flag is consumed. -/
def parseCommitment (branch : Branch) (input : List Byte) :
    Option (List Byte × List FieldWord × List Byte) := do
  let (profile, role, bytes, counter) ← parseSourceFrame input
  if profile = profileDomain (family branch) ∧ role = fppRole ∧ counter = 0 ∧
      bytes.length = payloadBytes branch then
    let (root, rest) ← readFixed 64 bytes
    let (coefficients, rest) ← readFields (coefficientCount branch) rest
    let (statement, suffix) ← readFixed (preambleByteCount (family branch)) rest
    if suffix = [] then some (root, coefficients, statement) else none
  else none

theorem complete_readback {branch : Branch} (c : Commitment branch) :
    parseCommitment branch (frame c) =
      some (typedWordPayload (List.ofFn c.root), coefficientList c, statementBytes c.statement) := by
  have rootLength : (typedWordPayload (List.ofFn c.root)).length = 64 := by
    simp [typed_word_payload_length]
  have read := fields_roundtrip (coefficientList c) (statementBytes c.statement)
  rw [coefficients_length] at read
  have finalRead : readFixed (preambleByteCount (family branch)) (statementBytes c.statement) =
      some (statementBytes c.statement, []) := by
    simpa using (readFixed_append (suffix := []) (statement_bytes_length c.statement))
  simp [parseCommitment, frame_roundtrip, payload_length]
  simp only [payload, List.append_assoc]
  rw [readFixed_append rootLength]
  simp [read, finalRead]

theorem complete_readback_injective {branch : Branch} (left right : Commitment branch)
    (equal : frame left = frame right) :
    coefficientList left = coefficientList right ∧ left.statement = right.statement := by
  have parsed := congrArg (parseCommitment branch) equal
  rw [complete_readback, complete_readback] at parsed
  have parts := Option.some.inj parsed
  exact ⟨congrArg (fun p => p.2.1) parts,
    statementBytes_injective _ (congrArg (fun p => p.2.2) parts)⟩

theorem exact_geometry :
    (coefficientCount .rp06, bindingOffset .rp06, payloadBytes .rp06) = (2030,16304,17496) ∧
    (coefficientCount .htlcLock, bindingOffset .htlcLock, payloadBytes .htlcLock) = (10600,84864,85440) ∧
    (coefficientCount .htlcClaim, bindingOffset .htlcClaim, payloadBytes .htlcClaim) = (49670,397424,398000) ∧
    (coefficientCount .htlcRefund, bindingOffset .htlcRefund, payloadBytes .htlcRefund) = (10600,84864,85440) := by decide

/-- Lock and Refund share the actual parser layout. Their statement content,
not a fabricated branch tag, distinguishes source actions. -/
theorem lock_refund_same_parser : parseCommitment .htlcLock = parseCommitment .htlcRefund := rfl

theorem wrong_geometry_rejected {source target : Branch} (c : Commitment source)
    (different : payloadBytes source ≠ payloadBytes target) :
    parseCommitment target (frame c) = none := by
  simp [parseCommitment, frame_roundtrip, payload_length, different]
end HegemonCrypto.NativeLaunchCommitmentReadback
