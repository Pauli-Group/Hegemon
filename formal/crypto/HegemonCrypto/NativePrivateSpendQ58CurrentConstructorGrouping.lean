import HegemonCrypto.NativePrivateSpendQ58CurrentExecutableVerifier
import HegemonCrypto.NativePrivateSpendQ58CurrentRoleClassifier
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CertifiedReplayScheduleFrames

/-! Literal COMPFF01 counter grouping for the current adversarial Program.
The 70-byte current profile, current four role domains, opening nonce and
840376-coordinate cap are constructors, not historical parser aliases.
Other raw inputs retain independent complement keys. The finite universe
ranges over every digest continuation of this same fixed Program.
SOURCE PROPOSAL: no compiler receipt or accepted-invalid mass claim. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentConstructorGrouping

open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets (Role StageQuery payloadLength digestOffset)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableChallengeStage (callCap)
open SmzaRp05PhysicalAcceptedReplayLite
open V8Smz9RawCounterCompiler
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes canonicalRepresentative
  canonical_representative_address)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsOracleDatabaseBridge (coordinateEventProjection)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

namespace C
export NativePrivateSpendQ58CurrentRoleClassifier
  (roleDomain current_role_roundtrip parseCurrentStageQuery canonicalCurrentQueryBytes)
end C
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (fieldKeys literal_request_counts)
end E
namespace A
export SmzaRp05ExecutableAddressCompiler (reachable)
end A
namespace P
export SmzaRp05CurrentFiniteGroupedProgram (answer_log_input_reachable)
end P
namespace L
export NativePrivateSpendQ58CurrentLeafInput (currentProfile)
end L

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev Counter := Fin 840376

def zero : Counter := ⟨0, by decide⟩

theorem current_profile_width : L.currentProfile.length = 70 := by decide

theorem current_counter_capacity :
    callCap 700 = 92 ∧ callCap (5 * 1344594) = 840376 := by
  exact ⟨E.literal_request_counts.2.1, E.literal_request_counts.2.2.2⟩

private theorem decode_counter (value : Nat) (bound : value < 2 ^ 64) :
    decodeLE (encodeLE 8 value) = value := by
  rw [decodeLE_encodeLE]
  have power : 256 ^ 8 = 2 ^ 64 := by norm_num
  rw [power]
  exact Nat.mod_eq_of_lt bound

/-- Forward parser receipt for the current ordinary role frame. -/
theorem current_ordinary_counter_roundtrip
    (role : Role) (notOpening : role ≠ .piopOpening)
    (target : RawDigest) (counter : Fin (2 ^ 64)) :
    C.parseCurrentStageQuery (C.canonicalCurrentQueryBytes
      ⟨role, target, 0, counter.val⟩) = some ⟨role, target, 0, counter.val⟩ := by
  have profileBound : L.currentProfile.length < 2 ^ 64 := by
    rw [current_profile_width]; norm_num
  have decodeProfile := decode_counter _ profileBound
  have roleBound : (C.roleDomain role).length < 2 ^ 64 := by cases role <;> decide
  have decodeRoleLength := decode_counter _ roleBound
  have decodeEight : decodeLE (encodeLE 8 8) = 8 := decode_counter 8 (by norm_num)
  have counterRead : readFixed 8 (encodeLE 8 counter.val) =
      some (encodeLE 8 counter.val, []) := by
    simpa only [List.append_nil] using
      (readFixed_append (suffix := []) (encodeLE_length 8 counter.val))
  have counterWord := decode_counter counter.val counter.isLt
  have digestRead : readFixed 64 (List.ofFn target ++ encodeLE 8 counter.val) =
      some (List.ofFn target, encodeLE 8 counter.val) :=
    readFixed_append (by simp : (List.ofFn target).length = 64)
  have digestAtZero : V8SmzaOracleParser.digestAt (List.ofFn target) 0 = target := by
    change V8Smz9CoherentMerkleGeometry.digestAt (List.ofFn target) 0 = target
    exact SmzaRp05CertifiedReplaySchedule.replay_digest_at_zero target
  cases role with
  | decsMatrix =>
      simp only [C.parseCurrentStageQuery, C.canonicalCurrentQueryBytes, reduceCtorEq, if_false, Bind.bind,
        Option.bind, List.append_assoc, readFixed_append, digestRead, encodeLE_length,
        List.length_ofFn, decodeProfile, decodeRoleLength, decodeEight,
        counterRead, counterWord, C.current_role_roundtrip, payloadLength]
      simp [digestOffset]
      exact digestAtZero
  | piopMatrix =>
      simp only [C.parseCurrentStageQuery, C.canonicalCurrentQueryBytes, reduceCtorEq, if_false, Bind.bind,
        Option.bind, List.append_assoc, readFixed_append, digestRead, encodeLE_length,
        List.length_ofFn, decodeProfile, decodeRoleLength, decodeEight,
        counterRead, counterWord, C.current_role_roundtrip, payloadLength]
      simp [digestOffset]
      exact digestAtZero
  | piopOpening => exact (notOpening rfl).elim
  | decsSample =>
      simp only [C.parseCurrentStageQuery, C.canonicalCurrentQueryBytes, reduceCtorEq, if_false, Bind.bind,
        Option.bind, List.append_assoc, readFixed_append, digestRead, encodeLE_length,
        List.length_ofFn, decodeProfile, decodeRoleLength, decodeEight,
        counterRead, counterWord, C.current_role_roundtrip, payloadLength]
      simp [digestOffset]
      exact digestAtZero

/-- Current opening nonce bytes are decoded, not ignored or assumed. -/
theorem current_opening_counter_roundtrip
    (target : RawDigest) (nonce : Fin (2 ^ 32)) (counter : Fin (2 ^ 64)) :
    C.parseCurrentStageQuery (C.canonicalCurrentQueryBytes
      ⟨.piopOpening, target, nonce.val, counter.val⟩) =
      some ⟨.piopOpening, target, nonce.val, counter.val⟩ := by
  have profileBound : L.currentProfile.length < 2 ^ 64 := by
    rw [current_profile_width]; norm_num
  have decodeProfile := decode_counter _ profileBound
  have roleBound : (C.roleDomain .piopOpening).length < 2 ^ 64 := by decide
  have decodeRoleLength := decode_counter _ roleBound
  have decodeCount := decode_counter 9 (by norm_num)
  have openingRole := C.current_role_roundtrip .piopOpening
  have nonceWord := SmzaRp05CertifiedReplaySchedule.replay_nonce_word target nonce
  have payloadRead : readFixed 72
      ((encodeLE 8 nonce.val ++ List.ofFn target) ++ encodeLE 8 counter.val) =
      some (encodeLE 8 nonce.val ++ List.ofFn target, encodeLE 8 counter.val) := by
    exact readFixed_append (by simp only [List.length_append, encodeLE_length, List.length_ofFn])
  have payloadReadRight : readFixed 72
      (encodeLE 8 nonce.val ++ (List.ofFn target ++ encodeLE 8 counter.val)) =
      some (encodeLE 8 nonce.val ++ List.ofFn target, encodeLE 8 counter.val) := by
    simpa only [List.append_assoc] using payloadRead
  have counterRead : readFixed 8 (encodeLE 8 counter.val) =
      some (encodeLE 8 counter.val, []) := by
    simpa only [List.append_nil] using
      (readFixed_append (suffix := []) (encodeLE_length 8 counter.val))
  have counterWord := decode_counter counter.val counter.isLt
  have digestAtNonce : V8SmzaOracleParser.digestAt
      (encodeLE 8 nonce.val ++ List.ofFn target) 8 = target := by
    change V8Smz9CoherentMerkleGeometry.digestAt
      (encodeLE 8 nonce.val ++ List.ofFn target) 8 = target
    exact SmzaRp05CertifiedReplaySchedule.replay_digest_after_nonce target nonce.val
  simp only [C.parseCurrentStageQuery, C.canonicalCurrentQueryBytes, if_true, Bind.bind,
    Option.bind, List.append_assoc, readFixed_append, payloadReadRight, counterRead,
    counterWord, encodeLE_length, decodeProfile, decodeRoleLength, decodeCount,
    nonceWord, openingRole, payloadLength]
  simp [encodeLE_length, digestOffset]
  exact digestAtNonce

def nonceValue (role : Role) (nonce : Fin (2 ^ 32)) : Nat :=
  if role = .piopOpening then nonce.val else 0

def leading (role : Role) (target : RawDigest) (nonce : Fin (2 ^ 32)) : RawInput :=
  let payload := if role = .piopOpening then
    encodeLE 8 nonce.val ++ List.ofFn target else List.ofFn target
  encodeLE 8 L.currentProfile.length ++ L.currentProfile ++
    encodeLE 8 (C.roleDomain role).length ++ C.roleDomain role ++
    encodeLE 8 (if role = .piopOpening then 9 else 8) ++ payload

abbrev Prefix := { raw : RawInput // ∃ query,
  C.parseCurrentStageQuery (raw ++ encodeLE 8 0) = some query }

def frame (role : Role) (target : RawDigest) (nonce : Fin (2 ^ 32))
    (counter : Counter) : RawInput := leading role target nonce ++ encodeLE 8 counter.val

theorem frame_is_literal_current (role : Role) (target : RawDigest)
    (nonce : Fin (2 ^ 32)) (counter : Counter) :
    frame role target nonce counter = C.canonicalCurrentQueryBytes
      ⟨role, target, nonceValue role nonce, counter.val⟩ := by
  by_cases opening : role = .piopOpening <;>
    simp only [frame, leading, C.canonicalCurrentQueryBytes, nonceValue,
      opening, if_true, if_false]

theorem frame_parser_receipt (role : Role) (target : RawDigest)
    (nonce : Fin (2 ^ 32)) (counter : Counter) :
    C.parseCurrentStageQuery (frame role target nonce counter) =
      some ⟨role, target, nonceValue role nonce, counter.val⟩ := by
  rw [frame_is_literal_current]
  have cap : counter.val < 2 ^ 64 := by have h := counter.isLt; omega
  by_cases opening : role = .piopOpening
  · subst role
    simpa only [nonceValue, if_true] using
      current_opening_counter_roundtrip target nonce ⟨counter.val, cap⟩
  · simpa only [nonceValue, if_neg opening] using
      current_ordinary_counter_roundtrip role opening target ⟨counter.val, cap⟩

def «prefix» (role : Role) (target : RawDigest) (nonce : Fin (2 ^ 32)) : Prefix :=
  ⟨leading role target nonce, ⟨⟨role, target, nonceValue role nonce, 0⟩,
    frame_parser_receipt role target nonce zero⟩⟩

def groupEncode : Prefix × Counter → RawInput :=
  fun pair => boundedCounterInput 840376 (by norm_num) (pair.1.val, pair.2)

theorem group_encode_injective : Function.Injective groupEncode := by
  intro left right same
  have pairs : (left.1.val, left.2) = (right.1.val, right.2) :=
    bounded_counter_input_injective 840376 (by norm_num) same
  exact Prod.ext
    (Subtype.ext (congrArg (fun pair : RawInput × Counter => pair.1) pairs))
    (congrArg (fun pair : RawInput × Counter => pair.2) pairs)

abbrev ComplementKey := Complement groupEncode
abbrev GroupKey := Prefix ⊕ ComplementKey

def address : RawInput → GroupKey × Counter :=
  fullRawPaddedCoordinate groupEncode group_encode_injective zero

def representative : GroupKey → RawInput := canonicalRepresentative groupEncode zero

def groupKeyOf (raw : RawInput) : GroupKey := (address raw).1

def coordinate (raw : RawInput) : Counter := (address raw).2

theorem representative_address (key : GroupKey) :
    address (representative key) = (key, zero) :=
  canonical_representative_address groupEncode group_encode_injective zero key

theorem representative_injective : Function.Injective representative := by
  intro left right same
  have addresses := congrArg address same
  rw [representative_address, representative_address] at addresses
  exact congrArg Prod.fst addresses

@[simp] theorem address_encode (p : Prefix) (counter : Counter) :
    address (groupEncode (p, counter)) = (Sum.inl p, counter) := by
  simp [address, fullRawPaddedCoordinate, paddedCoordinate]

@[simp] theorem address_complement (raw : ComplementKey) :
    address raw.val = (Sum.inr raw, zero) := by
  simp [address, fullRawPaddedCoordinate, paddedCoordinate]

theorem frame_is_group_encode (role : Role) (target : RawDigest)
    (nonce : Fin (2 ^ 32)) (counter : Counter) :
    frame role target nonce counter = groupEncode («prefix» role target nonce, counter) := rfl

theorem current_frame_address (role : Role) (target : RawDigest)
    (nonce : Fin (2 ^ 32)) (counter : Counter) :
    address (frame role target nonce counter) =
      (Sum.inl («prefix» role target nonce), counter) := by
  rw [frame_is_group_encode]
  exact address_encode _ _

/-- Ex-ante all-answer support; it is not selected from an accepted branch. -/
def groups {Result : Type} (program : Program Result) : Finset GroupKey :=
  (A.reachable program).image groupKeyOf

def Key {Result : Type} (program : Program Result) :=
  { key : GroupKey // key ∈ insert (groupKeyOf []) (groups program) }

noncomputable instance keyFintype {Result : Type} (program : Program Result) : Fintype (Key program) :=
  Fintype.ofFinset (insert (groupKeyOf []) (groups program)) (by intro key; simp)

noncomputable instance keyDecidableEq {Result : Type} (program : Program Result) :
    DecidableEq (Key program) := Classical.decEq _

def included {Result : Type} (program : Program Result) : Key program → GroupKey := Subtype.val

def encode {Result : Type} (program : Program Result) (raw : RawInput) : Key program :=
  if member : groupKeyOf raw ∈ insert (groupKeyOf []) (groups program) then
    ⟨groupKeyOf raw, member⟩ else ⟨groupKeyOf [], Finset.mem_insert_self _ _⟩

def keyBytes {Result : Type} (program : Program Result) : Key program → RawInput :=
  representative ∘ included program

theorem key_bytes_injective {Result : Type} (program : Program Result) :
    Function.Injective (keyBytes program) :=
  representative_injective.comp Subtype.val_injective

/-- The exact vector coordinate decoder used by physical replay. -/
def decode (raw : RawInput) (vector : VectorOutput Counter) : RawDigest :=
  vectorOutputBytes (coordinate raw) vector

theorem included_encode_of_reachable {Result : Type} (program : Program Result)
    (raw : RawInput) (member : raw ∈ A.reachable program) :
    included program (encode program raw) = groupKeyOf raw := by
  have inGroups : groupKeyOf raw ∈ groups program := Finset.mem_image.mpr ⟨raw, member, rfl⟩
  have inUniverse := Finset.mem_insert_of_mem (b := groupKeyOf []) inGroups
  simp only [encode, included, dif_pos inUniverse]

private theorem encode_eq_of_group_eq {Result : Type} (program : Program Result)
    (left right : RawInput) (same : groupKeyOf left = groupKeyOf right) :
    encode program left = encode program right := by
  apply Subtype.ext
  simp only [encode, same]

/-- The representative of every recorded current counter is its literal
current base frame. This is the receipt consumed by CurrentRoleClassifier. -/
theorem recorded_current_base_parser {Result : Type} (program : Program Result)
    (branch : Branches decode program) (role : Role) (target : RawDigest)
    (nonce : Fin (2 ^ 32)) (counter : Counter) (vector : VectorOutput Counter)
    (recorded : (frame role target nonce counter, vector) ∈ answerLog decode program branch) :
    C.parseCurrentStageQuery (keyBytes program (encode program (frame role target nonce counter))) =
      some ⟨role, target, nonceValue role nonce, 0⟩ := by
  have reached := P.answer_log_input_reachable decode program branch _ recorded
  have includedEq := included_encode_of_reachable program _ reached
  have rawGroup : groupKeyOf (frame role target nonce counter) = Sum.inl («prefix» role target nonce) :=
    congrArg Prod.fst (current_frame_address role target nonce counter)
  unfold keyBytes
  rw [Function.comp_apply, includedEq, rawGroup]
  change C.parseCurrentStageQuery (frame role target nonce zero) = _
  exact frame_parser_receipt role target nonce zero

/-- All literal current counters decode one stored whole vector. This is
proved from its one actual database cell, not an oracle-agreement premise. -/
theorem stored_current_vector_answers_every_counter {Result Work : Type}
    (program : Program Result)
    (basis : Basis (Key program) (VectorOutput Counter) (VectorOutput Counter) Work)
    (role : Role) (target : RawDigest) (nonce : Fin (2 ^ 32))
    (vector : VectorOutput Counter)
    (stored : basis.database (encode program (frame role target nonce zero)) = some vector)
    (counter : Counter) (fallback : RawDigest) :
    basisOracle (encode program) decode basis fallback (frame role target nonce counter) =
      rawDigestBits.symm (vector counter) := by
  have sameKey : groupKeyOf (frame role target nonce counter) =
      groupKeyOf (frame role target nonce zero) := by
    exact (congrArg Prod.fst (current_frame_address role target nonce counter)).trans
      (congrArg Prod.fst (current_frame_address role target nonce zero)).symm
  have same := encode_eq_of_group_eq program _ _ sameKey
  have coord : coordinate (frame role target nonce counter) = counter :=
    congrArg Prod.snd (current_frame_address role target nonce counter)
  simp only [basisOracle, same, stored, decode, coord, vectorOutputBytes]

/-- Every measured physical branch answer is stored in its own nonzero
standard final view, allowing the whole-vector lemma above to be applied. -/
theorem nonzero_record_stored {Result Work : Type} [Fintype Work] [DecidableEq Work]
    (program : Program Result) (branch : Branches decode program)
    (state : HegemonCrypto.CmsCompressedOracle.State
      (Key program) (VectorOutput Counter) (VectorOutput Counter) Work)
    (basis : Basis (Key program) (VectorOutput Counter) (VectorOutput Counter) Work)
    (nonzero : globalDecompress (physicalRun (encode program) decode program branch state) basis ≠ 0)
    (call : RawInput × VectorOutput Counter) (recorded : call ∈ answerLog decode program branch) :
    basis.database (encode program call.1) = some call.2 := by
  have member : (encode program call.1, call.2) ∈
      branchClaims (branchKeys (encode program) decode program branch)
        (branchAnswers (encode program) decode program branch) := by
    rw [branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨call, recorded, rfl⟩
  have known := branch_claim_known_at_repeated
    (branchKeys (encode program) decode program branch)
    (branchAnswers (encode program) decode program branch) (globalDecompress state)
    (encode program call.1, call.2) member
  have atFinal : KnownAt (encode program call.1) call.2
      (globalDecompress (physicalRun (encode program) decode program branch state)) := by
    rw [global_decompress_physical_run_eq_retainedTrace]
    exact known
  have atBasis := congrFun atFinal basis
  by_contra missing
  unfold coordinateEventProjection at atBasis
  rw [if_neg missing] at atBasis
  exact nonzero atBasis.symm

/-- DECS92 and PIOP840376 use the same derived address and coordinate laws. -/
theorem current_field_key_address (role : Role) (target : RawDigest)
    (nonce : Fin (2 ^ 32)) (requested : Nat) (counter : Fin (callCap requested))
    (bounded : callCap requested ≤ 840376) :
    address (C.canonicalCurrentQueryBytes ⟨role, target, nonceValue role nonce, counter.val⟩) =
      (Sum.inl («prefix» role target nonce),
        (⟨counter.val, counter.isLt.trans_le bounded⟩ : Counter)) := by
  exact (congrArg address
    (frame_is_literal_current role target nonce
      (⟨counter.val, counter.isLt.trans_le bounded⟩ : Counter))).symm.trans
    (current_frame_address role target nonce
      (⟨counter.val, counter.isLt.trans_le bounded⟩ : Counter))

/-- A literal-key scan may stop early, but every key it can query decodes
from the same actual base vector, including rejected/exhausted words. -/
theorem current_decs_basis_agreement {Result Work : Type}
    [Fintype Work] [DecidableEq Work]
    (program : Program Result) (branch : Branches decode program)
    (state : HegemonCrypto.CmsCompressedOracle.State
      (Key program) (VectorOutput Counter) (VectorOutput Counter) Work)
    (basis : Basis (Key program) (VectorOutput Counter) (VectorOutput Counter) Work)
    (nonzero : globalDecompress (physicalRun (encode program) decode program branch state) basis ≠ 0)
    (root : RawDigest) (vector : VectorOutput Counter)
    (recorded : (frame .decsMatrix root ⟨0, by decide⟩ zero, vector) ∈
      answerLog decode program branch) (fallback : RawDigest) :
    ∀ input ∈ E.fieldKeys .decsMatrix 700 root,
      basisOracle (encode program) decode basis fallback input = decode input vector := by
  have stored := nonzero_record_stored program branch state basis nonzero _ recorded
  intro input member
  change input ∈ (List.range (callCap 700)).map
    (fun counter => C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, counter⟩) at member
  rcases List.mem_map.mp member with ⟨counter, inRange, rfl⟩
  have bounded : counter < 840376 := by
    have small := List.mem_range.mp inRange
    have cap := E.literal_request_counts.2.1
    rw [cap] at small
    omega
  let c : Counter := ⟨counter, bounded⟩
  have literal : C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, counter⟩ =
      frame .decsMatrix root ⟨0, by decide⟩ c :=
        (frame_is_literal_current .decsMatrix root (⟨0, by decide⟩ : Fin (2 ^ 32)) c).symm
  rw [literal]
  have answered := stored_current_vector_answers_every_counter program basis
    .decsMatrix root ⟨0, by decide⟩ vector stored c fallback
  have coord : coordinate (frame .decsMatrix root ⟨0, by decide⟩ c) = c :=
    congrArg Prod.snd (current_frame_address _ _ _ _)
  simpa only [decode, coord, vectorOutputBytes] using answered

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentConstructorGrouping
