import SmzaRp05ExecutableChallengeStage
import SmzaRp05CurrentOpeningProgram
import SmzaRp05ExecutableMerklePaths

namespace HegemonCrypto.SmallWood.SmzaRp05CertifiedReplaySchedule

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CurrentOpeningProgram (openingCounterInput)
open SmzaRp05ExecutableMerkleVerifier (digest_at_ofFn_append digest_at_prefix_ofFn)
open SmzaChallengeStageTargets

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000

private theorem decode_eight_byte_counter (value : Nat) (bound : value < 2 ^ 64) :
    decodeLE (encodeLE 8 value) = value := by
  rw [decodeLE_encodeLE]
  have power : 256 ^ 8 = 2 ^ 64 := by norm_num
  rw [power]
  exact Nat.mod_eq_of_lt bound

theorem replay_digest_at_zero (digest : RawDigest) :
    V8Smz9CoherentMerkleGeometry.digestAt (List.ofFn digest) 0 = digest := by
  simpa using digest_at_ofFn_append digest []

theorem replay_digest_after_nonce (digest : RawDigest) (nonce : Nat) :
    V8Smz9CoherentMerkleGeometry.digestAt (encodeLE 8 nonce ++ List.ofFn digest) 8 = digest := by
  simpa [encodeLE_length] using digest_at_prefix_ofFn (encodeLE 8 nonce) [] digest

theorem replay_nonce_word (digest : RawDigest) (nonce : Fin (2 ^ 32)) :
    V8SmzaOracleParser.wordAt (encodeLE 8 nonce.val ++ List.ofFn digest) 0 = nonce.val := by
  have within64 : nonce.val < 2 ^ 64 := by have h := nonce.isLt; omega
  have takeNonce :
      (encodeLE 8 nonce.val ++ List.ofFn digest).take 8 = encodeLE 8 nonce.val := by
    simp [encodeLE_length]
  simp only [V8SmzaOracleParser.wordAt,
    V8Smz9CoherentMerkleGeometry.wordAt, Nat.mul_zero, List.drop_zero]
  rw [takeNonce]
  exact decode_eight_byte_counter nonce.val within64

theorem ordinary_counter_roundtrip
    (role : Role) (notOpening : role ≠ .piopOpening)
    (digest : RawDigest) (counter : Fin (2 ^ 64)) :
    parseStageQuery (counterInput (roleDomain role) digest counter.val) =
      some ⟨role, digest, 0, counter.val⟩ := by
  have profileLength : V8SmzaOracleParser.profileDomain.length = 53 := by decide
  have profileBound : V8SmzaOracleParser.profileDomain.length < 2 ^ 64 := by
    rw [profileLength]
    norm_num
  have decodeProfile := decode_eight_byte_counter _ profileBound
  have roleBound : (roleDomain role).length < 2 ^ 64 := by
    cases role <;> decide
  have decodeRoleLength := decode_eight_byte_counter _ roleBound
  have decodeEight : decodeLE (encodeLE 8 8) = 8 :=
    decode_eight_byte_counter 8 (by norm_num)
  have counterRead : readFixed 8 (encodeLE 8 counter.val) =
      some (encodeLE 8 counter.val, []) := by
    simpa only [List.append_nil] using
      (show readFixed 8 (encodeLE 8 counter.val ++ []) =
          some (encodeLE 8 counter.val, []) from
        readFixed_append (encodeLE_length 8 counter.val))
  have counterWord : decodeLE (encodeLE 8 counter.val) = counter.val :=
    decode_eight_byte_counter counter.val counter.isLt
  have digestRead : readFixed 64 (List.ofFn digest ++ encodeLE 8 counter.val) =
      some (List.ofFn digest, encodeLE 8 counter.val) := by
    rw [readFixed_append (by simp : (List.ofFn digest).length = 64)]
  have digestAtZero : V8SmzaOracleParser.digestAt (List.ofFn digest) 0 = digest := by
    change V8Smz9CoherentMerkleGeometry.digestAt (List.ofFn digest) 0 = digest
    exact replay_digest_at_zero digest
  cases role with
  | decsMatrix =>
      simp only [parseStageQuery, counterInput, Bind.bind, Option.bind,
        List.append_assoc, readFixed_append, digestRead, encodeLE_length,
        List.length_ofFn, decodeProfile, decodeRoleLength, decodeEight,
        counterRead, counterWord, role_roundtrip, payloadLength]
      simp [digestOffset]
      exact digestAtZero
  | piopMatrix =>
      simp only [parseStageQuery, counterInput, Bind.bind, Option.bind,
        List.append_assoc, readFixed_append, digestRead, encodeLE_length,
        List.length_ofFn, decodeProfile, decodeRoleLength, decodeEight,
        counterRead, counterWord, role_roundtrip, payloadLength]
      simp [digestOffset]
      exact digestAtZero
  | piopOpening => exact (notOpening rfl).elim
  | decsSample =>
      simp only [parseStageQuery, counterInput, Bind.bind, Option.bind,
        List.append_assoc, readFixed_append, digestRead, encodeLE_length,
        List.length_ofFn, decodeProfile, decodeRoleLength, decodeEight,
        counterRead, counterWord, role_roundtrip, payloadLength]
      simp [digestOffset]
      exact digestAtZero

theorem opening_counter_roundtrip
    (digest : RawDigest) (nonce : Fin (2 ^ 32)) (counter : Fin (2 ^ 64)) :
    parseStageQuery (openingCounterInput digest nonce.val counter.val) =
      some ⟨.piopOpening, digest, nonce.val, counter.val⟩ := by
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
      (encodeLE 8 nonce.val ++ List.ofFn digest) 0 = nonce.val :=
    replay_nonce_word digest nonce
  have payloadRead : readFixed 72
      ((encodeLE 8 nonce.val ++ List.ofFn digest) ++ encodeLE 8 counter.val) =
      some (encodeLE 8 nonce.val ++ List.ofFn digest, encodeLE 8 counter.val) := by
    have payloadLength : (encodeLE 8 nonce.val ++ List.ofFn digest).length = 72 := by
      simp only [List.length_append, encodeLE_length, List.length_ofFn]
    exact readFixed_append payloadLength
  have payloadReadRight : readFixed 72
      (encodeLE 8 nonce.val ++ (List.ofFn digest ++ encodeLE 8 counter.val)) =
      some (encodeLE 8 nonce.val ++ List.ofFn digest, encodeLE 8 counter.val) := by
    simpa only [List.append_assoc] using payloadRead
  have counterRead : readFixed 8 (encodeLE 8 counter.val) =
      some (encodeLE 8 counter.val, []) := by
    simpa only [List.append_nil] using
      (show readFixed 8 (encodeLE 8 counter.val ++ []) =
          some (encodeLE 8 counter.val, []) from
        readFixed_append (encodeLE_length 8 counter.val))
  have counterWord : decodeLE (encodeLE 8 counter.val) = counter.val :=
    decode_eight_byte_counter counter.val counter.isLt
  have digestAtAfterNonce :
      V8SmzaOracleParser.digestAt (encodeLE 8 nonce.val ++ List.ofFn digest) 8 = digest := by
    change V8Smz9CoherentMerkleGeometry.digestAt
      (encodeLE 8 nonce.val ++ List.ofFn digest) 8 = digest
    exact replay_digest_after_nonce digest nonce.val
  simp only [parseStageQuery, openingCounterInput, Bind.bind, Option.bind,
    List.append_assoc, readFixed_append, payloadReadRight, counterRead,
    counterWord, encodeLE_length, decodeProfile, decodeRoleLength, decodeCount,
    nonceWord, openingRole, payloadLength]
  simp [encodeLE_length, digestOffset]
  exact digestAtAfterNonce

end
end HegemonCrypto.SmallWood.SmzaRp05CertifiedReplaySchedule
