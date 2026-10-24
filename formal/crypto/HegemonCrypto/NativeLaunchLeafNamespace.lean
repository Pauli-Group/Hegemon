import HegemonCrypto.NativeLaunchRelationModelStatement

/-!
Literal RP06/HTLC leaf namespace parsing at bd4d8c8131be7c8208631427847505a68c7b40c0.
Runtime source equals frozen 185a132b821ad319a49f4a8746c6110ea7ba0476.
Reuse complete source-shaped statement/leaf constructors and actual role literals.
This is byte framing and namespace separation, not accepted Rust execution,
canonical digest/intent/row computation, security, simulation or release authority.
-/
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchLeafNamespace
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Family profileDomain parseSourceFrame)
open NativeLaunchRelationModelStatement
open SmallWood.V8Smz9RawCounterCompiler
  (typedWordPayload typed_word_payload_length typed_word_payload_is_source_payload)
open SmallWood.V8Smz9WholeViewObservation (RawSha512OracleKey)

/-- Retain all suffix bytes; no supplied canonicality predicate. -/
def parseLeafNamespace (family : Family) (input : List Byte) :
    Option (List Byte × List Byte) := do
  let (profile, role, payload, counter) ← parseSourceFrame input
  if profile = profileDomain family ∧ role = leafRole family ∧ counter = 0 ∧
      payload.length = preambleByteCount family + 1280 then
    some (payload.take (preambleByteCount family), payload.drop (preambleByteCount family))
  else none

theorem leaf_role_lengths :
    (leafRole .rp06).length = 42 ∧ (leafRole .htlc).length = 47 := by decide

theorem literal_frame_roundtrip {family : Family}
    (statement : Statement family) (fields : LeafFields) :
    parseSourceFrame (strictLeafFrame statement fields) =
      some (profileDomain family, leafRole family,
        typedWordPayload (strictLeafWords statement fields), 0) := by
  have profileMod : (profileDomain family).length % 18446744073709551616 =
      (profileDomain family).length := by cases family <;> decide
  have roleMod : (leafRole family).length % 18446744073709551616 =
      (leafRole family).length := by cases family <;> decide
  have wordMod : (strictLeafWords statement fields).length % 18446744073709551616 =
      (strictLeafWords statement fields).length := by
    rw [strict_leaf_word_count]
    cases family <;> decide
  have payloadLength : (typedWordPayload (strictLeafWords statement fields)).length =
      8 * (strictLeafWords statement fields).length := typed_word_payload_length _
  simp only [strictLeafFrame, RawSha512OracleKey.preimage, List.length_map]
  rw [← typed_word_payload_is_source_payload]
  simp [parseSourceFrame, List.append_assoc, readFixed, encodeLE_length,
    decodeLE_encodeLE, profileMod, roleMod, wordMod,
    payloadLength]
  have counterTake : (encodeLE 8 0).take 8 = encodeLE 8 0 := by
    simpa only [encodeLE_length] using (List.take_length (l := encodeLE 8 0))
  rw [counterTake, decodeLE_encodeLE]
  rfl

theorem namespace_roundtrip {family : Family}
    (statement : Statement family) (fields : LeafFields) :
    parseLeafNamespace family (strictLeafFrame statement fields) =
      some (statementBytes statement,
        (typedWordPayload (strictLeafWords statement fields)).drop (preambleByteCount family)) := by
  have length : (typedWordPayload (strictLeafWords statement fields)).length =
      preambleByteCount family + 1280 := by
    rw [typed_word_payload_length, strict_leaf_word_count]
    simp [preambleByteCount, Nat.mul_add]
  simp [parseLeafNamespace, literal_frame_roundtrip, length, strict_leaf_statement_projection]

theorem recovered_suffix_length {family : Family}
    (statement : Statement family) (fields : LeafFields) :
    ((typedWordPayload (strictLeafWords statement fields)).drop
      (preambleByteCount family)).length = 1280 := by
  rw [List.length_drop, typed_word_payload_length, strict_leaf_word_count]
  simp [preambleByteCount, Nat.mul_add]

/-- Raw address equality determines the whole preamble, not just its digest. -/
theorem complete_namespace_injective {family : Family}
    (left right : Statement family) (lf rf : LeafFields)
    (equal : strictLeafFrame left lf = strictLeafFrame right rf) : left = right := by
  have parsed := congrArg (parseLeafNamespace family) equal
  rw [namespace_roundtrip, namespace_roundtrip] at parsed
  exact statementBytes_injective family (congrArg Prod.fst (Option.some.inj parsed))

theorem unequal_complete_preambles_disjoint {family : Family}
    (left right : Statement family) (lf rf : LeafFields) (different : left ≠ right) :
    strictLeafFrame left lf ≠ strictLeafFrame right rf := by
  intro equal
  exact different (complete_namespace_injective left right lf rf equal)

/-- Outer profile framing separates families; this is address separation,
not hash collision resistance. RP06 still shares the SMZA v2 leaf role. -/
theorem distinct_families_disjoint
    (left : Statement .rp06) (right : Statement .htlc) (lf rf : LeafFields) :
    strictLeafFrame left lf ≠ strictLeafFrame right rf := by
  intro equal
  have parsed := congrArg parseSourceFrame equal
  rw [literal_frame_roundtrip, literal_frame_roundtrip] at parsed
  have profiles := congrArg Prod.fst (Option.some.inj parsed)
  exact (by decide : profileDomain .rp06 ≠ profileDomain .htlc) profiles

theorem other_family_rejected {family other : Family}
    (different : family ≠ other) (statement : Statement family) (fields : LeafFields) :
    parseLeafNamespace other (strictLeafFrame statement fields) = none := by
  have profileDifferent : profileDomain family ≠ profileDomain other := by
    intro equal
    exact different (NativeLaunchAdaptiveHistoryCodec.profileDomain_injective equal)
  simp [parseLeafNamespace, literal_frame_roundtrip, profileDifferent]

/-- Neither parser truncates to the historical 1104-byte prefix. -/
theorem complete_preamble_lengths :
    preambleByteCount .rp06 = 1192 ∧ preambleByteCount .htlc = 576 ∧
    preambleByteCount .rp06 ≠ 1104 ∧ preambleByteCount .htlc ≠ 1104 := by decide
end HegemonCrypto.NativeLaunchLeafNamespace
