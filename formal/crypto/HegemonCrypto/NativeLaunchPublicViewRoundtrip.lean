import HegemonCrypto.NativeLaunchPublicViewCodec

set_option autoImplicit false
set_option maxHeartbeats 1000000
set_option maxRecDepth 10000
namespace HegemonCrypto.NativeLaunchPublicViewRoundtrip
open CanonicalBytes SmallWoodProofWire
open NativeLaunchPublicProofView NativeLaunchPublicViewCodec
open SmallWood.NativeLaunchRelationModelResponse (Branch queryCount)


def rawAuth {b : Branch} {c : Config} (v : View b c) : AuthPathsWire :=
  ⟨encodeLE 2 (queryCount b), List.ofFn (fun i =>
    (⟨(v.paths i).count.val, lt_trans (v.paths i).count.isLt (by decide)⟩ : Byte)),
    encodeDigests (pathNodes v.paths)⟩

theorem auth_rows {b : Branch} {c : Config} (v : View b c) :
    (rawAuth v).rowCount = queryCount b := by
  unfold rawAuth AuthPathsWire.rowCount
  rw [decodeLE_encodeLE]
  exact Nat.mod_eq_of_lt (by cases b <;> decide)

theorem auth_nodes {b : Branch} {c : Config} (v : View b c) :
    (rawAuth v).nodeCount = (pathNodes v.paths).length := by
  simp [rawAuth, AuthPathsWire.nodeCount, path_node_count, Function.comp_def]

theorem raw_auth_canonical {b : Branch} {c : Config} (v : View b c) :
    (rawAuth v).Canonical := by
  unfold AuthPathsWire.Canonical
  rw [auth_rows, auth_nodes]
  refine ⟨encodeLE_length _ _, ?_, List.length_ofFn, ?_⟩
  · cases b <;> decide
  · simp [rawAuth, digests_length, digestBytes, Nat.mul_comm]

theorem raw_auth_guard {b : Branch} {c : Config} (v : View b c) :
    NativeLaunchPublicProofParser.nativeAuthGuard b (rawAuth v) := by
  refine ⟨auth_rows v, ?_⟩
  intro byte member
  obtain ⟨i, same⟩ := List.mem_ofFn.mp member
  subst byte
  exact Nat.le_of_lt_succ (v.paths i).count.isLt

def rawWitness {b : Branch} {c : Config} (v : View b c) : OpenedWitnessWire :=
  .rowScalars (rawMatrix v 7) (encodeLE 4 0) (encodeLE 4 0) []

theorem raw_witness_canonical {b : Branch} {c : Config} (v : View b c) :
    (NativeLaunchPublicProofParser.emptyAuxCodec).canonical (rawWitness v) := by
  change (rawWitness v).Canonical ∧ NativeLaunchPublicProofParser.EmptyAux (rawWitness v)
  simp [rawWitness, OpenedWitnessWire.Canonical, NativeLaunchPublicProofParser.EmptyAux, raw_matrix_canonical,
    encodeLE_length, decodeLE_encodeLE, fieldWordsCanonicalB]

def rawWire {b : Branch} {c : Config} (v : View b c) : NativeLaunchPublicProofParser.ProofWire where
  saltBytes := List.ofFn v.salt
  nonceBytes := encodeLE 4 v.nonce.val
  piopHashBytes := List.ofFn v.hPiop
  piop := ⟨rawMatrix v 0, rawMatrix v 1⟩
  pcs := ⟨rawMatrix v 2, rawMatrix v 3, rawMatrix v 4,
    ⟨rawAuth v, tapeBytes v.tapes, rawMatrix v 5, rawMatrix v 6⟩⟩
  openedWitness := rawWitness v

theorem raw_payload_canonical {b : Branch} {c : Config} (v : View b c) :
    (NativeLaunchPublicProofParser.proofPayloadCodec b).canonical (rawWire v) := by
  exact ⟨List.length_ofFn, encodeLE_length _ _, List.length_ofFn,
    ⟨raw_matrix_canonical v 0, raw_matrix_canonical v 1⟩,
    ⟨raw_matrix_canonical v 2, raw_matrix_canonical v 3, raw_matrix_canonical v 4,
      ⟨⟨raw_auth_canonical v, raw_auth_guard v⟩,
        by change (tapeBytes v.tapes).length = queryCount b * 64
           rw [tapes_length, Nat.mul_comm],
        raw_matrix_canonical v 5, raw_matrix_canonical v 6⟩⟩,
    raw_witness_canonical v⟩

theorem raw_exact_shape {b : Branch} {c : Config} (v : View b c) :
    NativeLaunchPublicProofParser.exactShape b c (rawWire v) := by
  simp only [NativeLaunchPublicProofParser.exactShape, rawWire, rawWitness, NativeLaunchPublicProofParser.matrixShape, matrix_rows, matrix_columns,
    and_self]

theorem raw_guarded_canonical {b : Branch} {c : Config} (v : View b c) :
    (NativeLaunchPublicProofParser.guardedPayload b c).canonical (rawWire v) :=
  ⟨raw_payload_canonical v, v.shape, raw_exact_shape v⟩

theorem actual_encoder_equality {b : Branch} {c : Config} (v : View b c) :
    NativeLaunchPublicProofParser.encode b (rawWire v) = NativeLaunchPublicProofView.encode v := by
  simp [NativeLaunchPublicProofParser.encode, NativeLaunchPublicProofParser.proofPayloadCodec, NativeLaunchPublicProofParser.pcsCodec, NativeLaunchPublicProofParser.decsCodec, NativeLaunchPublicProofParser.nativeAuthCodec,
    NativeLaunchPublicProofParser.emptyAuxCodec, PrefixCodec.xmap, PrefixCodec.pair, PrefixCodec.fixed, PrefixCodec.refine,
    piopCodec, matrixCodec, authPathsCodec, openedWitnessCodec,
    rawWire, rawWitness, OpenedWitnessWire.encode, raw_matrix_encode,
    AuthPathsWire.encode, rawAuth, NativeLaunchPublicProofView.encode, authBytes,
    List.append_assoc]

theorem typed_view_exact_roundtrip {b : Branch} {c : Config} (v : View b c)
    (cap : (NativeLaunchPublicProofView.encode v).length ≤ NativeLaunchPublicProofParser.maximumBytes b) :
    NativeLaunchPublicProofParser.decodeExact b c (NativeLaunchPublicProofView.encode v) = some (rawWire v) := by
  rw [← actual_encoder_equality v] at cap ⊢
  exact NativeLaunchPublicProofParser.decode_exact_encode b c (rawWire v) (raw_guarded_canonical v) cap

end HegemonCrypto.NativeLaunchPublicViewRoundtrip
