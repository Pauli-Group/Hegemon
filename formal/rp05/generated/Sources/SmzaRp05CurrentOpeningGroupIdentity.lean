import SmzaRp05CurrentGroupedRecordReadback
import SmzaRp05ExecutableMerklePaths

/-! Exact grouped-address identity for current opening counter frames.  The
zero-counter parser receipt is obtained by evaluating the real byte parser;
the grouped address is not inferred from a caller-supplied route. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningGroupIdentity

open HegemonCrypto.CanonicalBytes
open SmzaRp05GroupedSuffix
open SmzaChallengeStageTargets
open SmzaRp05CurrentGroupedRecordReadback (canonicalQueryPrefix)
open SmzaRp05CurrentOpeningProgram (openingCounterInput)

abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev RawInput := V8SmzaOracleParser.RawInput

noncomputable section
set_option autoImplicit false

private theorem decode_eight_byte_counter (value : Nat) (bound : value < 2 ^ 64) :
    decodeLE (encodeLE 8 value) = value := by
  rw [decodeLE_encodeLE]
  have power : 256 ^ 8 = 2 ^ 64 := by norm_num
  rw [power]
  exact Nat.mod_eq_of_lt bound

/-- Parsing the same opening frame with counter zero produces the literal
opening query carrying the target and attempted nonce. -/
theorem opening_counter_zero_parser_receipt
    (digest : RawDigest) (nonce : Nat) (nonceBound : nonce < 2 ^ 32) :
    parseStageQuery (openingCounterInput digest nonce 0) =
      some ⟨.piopOpening, digest, nonce, 0⟩ := by
  have profileLength : V8SmzaOracleParser.profileDomain.length = 53 := by decide
  have profileBound : V8SmzaOracleParser.profileDomain.length < 2 ^ 64 := by
    rw [profileLength]
    norm_num
  have decodeProfile := decode_eight_byte_counter _ profileBound
  have roleBound : SmallWoodTranscript.piopOpeningDomain.length < 2 ^ 64 := by decide
  have decodeRoleLength := decode_eight_byte_counter _ roleBound
  have decodeCount := decode_eight_byte_counter 9 (by norm_num)
  have openingRole : decodeChallengeRole SmallWoodTranscript.piopOpeningDomain =
      some .piopOpening := by
    change decodeChallengeRole (roleDomain .piopOpening) = some .piopOpening
    exact role_roundtrip .piopOpening
  have nonceWord : V8SmzaOracleParser.wordAt
      (encodeLE 8 nonce ++ List.ofFn digest) 0 = nonce := by
    have nonce64 : nonce < 2 ^ 64 := by omega
    have noncePayload :
        (encodeLE 8 nonce ++ List.ofFn digest).take 8 = encodeLE 8 nonce := by
      simp [encodeLE_length]
    simp only [V8SmzaOracleParser.wordAt,
      V8Smz9CoherentMerkleGeometry.wordAt, Nat.mul_zero, List.drop_zero]
    rw [noncePayload]
    exact decode_eight_byte_counter nonce nonce64
  have payloadRead : readFixed 72
      ((encodeLE 8 nonce ++ List.ofFn digest) ++ encodeLE 8 0) =
      some (encodeLE 8 nonce ++ List.ofFn digest, encodeLE 8 0) := by
    have payloadLength : (encodeLE 8 nonce ++ List.ofFn digest).length = 72 := by
      simp only [List.length_append, encodeLE_length, List.length_ofFn]
    exact readFixed_append payloadLength
  have payloadReadRight : readFixed 72
      (encodeLE 8 nonce ++ (List.ofFn digest ++ encodeLE 8 0)) =
      some (encodeLE 8 nonce ++ List.ofFn digest, encodeLE 8 0) := by
    simpa only [List.append_assoc] using payloadRead
  have counterRead : readFixed 8 (encodeLE 8 0) = some (encodeLE 8 0, []) := by
    simpa only [List.append_nil] using
      (show readFixed 8 (encodeLE 8 0 ++ []) = some (encodeLE 8 0, []) from
        readFixed_append (by simp [encodeLE_length]))
  have counterWord : decodeLE (encodeLE 8 0) = 0 := by
    exact decode_eight_byte_counter 0 (by norm_num)
  have digestRead : V8SmzaOracleParser.digestAt
      (encodeLE 8 nonce ++ List.ofFn digest) 8 = digest := by
    simpa [encodeLE_length] using
      HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleVerifier.digest_at_prefix_ofFn
        (encodeLE 8 nonce) [] digest
  simp only [parseStageQuery, openingCounterInput, Bind.bind, Option.bind,
    List.append_assoc, readFixed_append, payloadReadRight, counterRead,
    decodeProfile, decodeRoleLength, decodeCount, nonceWord, openingRole,
    counterWord, encodeLE_length, SmzaChallengeStageTargets.payloadLength]
  have payloadLength : (encodeLE 8 nonce ++ List.ofFn digest).length = 72 := by
    simp only [List.length_append, encodeLE_length, List.length_ofFn]
  simp only [if_pos (show True from trivial)]
  rw [if_pos (show True ∧ (encodeLE 8 nonce ++ List.ofFn digest).length = 72 ∧
      True ∧ nonce < 2 ^ 32 from ⟨trivial, payloadLength, trivial, nonceBound⟩)]
  simp only [digestOffset, digestRead]

/-- The physical grouped address of every actual opening counter call is
its canonical opening prefix and that exact counter. -/
theorem opening_counter_call_group_address
    (digest : RawDigest) (nonce : Nat) (nonceBound : nonce < 2 ^ 32)
    (counter : GroupCounter) :
    ∃ rolePrefix : CanonicalRolePrefix,
      groupAddress (openingCounterInput digest nonce counter.val) =
          (Sum.inl rolePrefix, counter) ∧
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) =
          some ⟨.piopOpening, digest, nonce, 0⟩ ∧
      groupEncode (rolePrefix, counter) =
          openingCounterInput digest nonce counter.val := by
  let leading : RawInput :=
    encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
      V8SmzaOracleParser.profileDomain ++
      encodeLE 8 SmallWoodTranscript.piopOpeningDomain.length ++
      SmallWoodTranscript.piopOpeningDomain ++ encodeLE 8 9 ++
      encodeLE 8 nonce ++ List.ofFn digest
  have parsedZero : parseStageQuery (leading ++ encodeLE 8 0) =
      some ⟨.piopOpening, digest, nonce, 0⟩ := by
    change parseStageQuery (openingCounterInput digest nonce 0) = _
    exact opening_counter_zero_parser_receipt digest nonce nonceBound
  let rolePrefix : CanonicalRolePrefix :=
    ⟨.piopOpening, leading, ⟨⟨.piopOpening, digest, nonce, 0⟩, parsedZero, rfl⟩⟩
  have encoded : groupEncode (rolePrefix, counter) =
      openingCounterInput digest nonce counter.val := by
    change leading ++ encodeLE 8 counter.val = _
    rfl
  refine ⟨rolePrefix, ?_, ?_, encoded⟩
  · rw [← encoded]
    exact group_address_encode rolePrefix counter
  · simpa only [groupRepresentative, groupEncode,
      rolePrefix, groupZero, V8Smz9CoherentVectorMerkle.canonicalRepresentative,
      V8Smz9RawCounterCompiler.boundedCounterInput,
      V8Smz9RawCounterCompiler.counterInput,
      Fin.val_mk] using parsedZero

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningGroupIdentity
