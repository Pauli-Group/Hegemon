import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05ExecutablePcsClosureOpening

/-! Propagate the actual final pending guard through PCS, q38, DECS, and
opening nonce selection. These are consequences of the same execution, not
sampler-success certificates supplied to the verifier. -/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureClean

open SmzaRp05ExecutableMerkleVerifier (Oracle Input)
open SmzaRp05ExecutableChallengeStage (FieldWord scan counterKeys)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureSampling
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false
noncomputable section

theorem merkle_input_pending (salt binding : List HegemonCrypto.CanonicalBytes.Byte)
    (pending : Bool) (indices : List Nat) (rows : List (List Goldilocks))
    (masks : SmzaRp05PcsWireProjection.FieldMatrix)
    (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (paths : List (List RawDigest)) (input : Input)
    (built : SmzaRp05PcsMerklePayload.makeMerkleInput salt binding pending indices
      rows masks tapes paths = some input) : input.pendingXofFailure = pending := by
  unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
  split at built
  · simp at built
  · exact (congrArg Input.pendingXofFailure (Option.some.inj built)).symm

theorem pcs_stages_clean (ns : SmzaRp05LeafNamespace.Namespace) (pending : Bool)
    (digest : RawDigest) (wire : SmzaRp05PcsWireProjection.DecodedMiddleWire)
    (decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List HegemonCrypto.CanonicalBytes.Byte)
    (statementBinding : List Nat) (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (paths : List (List RawDigest)) (oracle : Oracle) (hashFpp : RawDigest)
    (finalPending : Bool)
    (stages : PcsStages ns pending digest wire decs points salt binding statementBinding
      tapes paths oracle hashFpp finalPending) (clean : finalPending = false) :
    pending = false ∧ ∃ queryWords decsWords,
      scan oracle 50 [] (counterKeys SmallWoodTranscript.decsFixedSamplingDomain
        50 stages.openingDigest) = some queryWords ∧
      scan oracle 700 [] (counterKeys SmallWoodTranscript.decsCoefficientDomain
        700 stages.post.root) = some decsWords ∧
      stages.post.sampled = some decsWords := by
  obtain ⟨_merkleExecuted, sampled, accumulated, _values⟩ :=
    SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core ns oracle
      stages.merkleInput stages.post stages.postExecuted
  have postClean : stages.post.pending = false := stages.pendingReturned.symm.trans clean
  obtain ⟨inputClean, decsWords, decoded⟩ :=
    SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words _ _
      (accumulated.symm.trans postClean)
  have inputPending := merkle_input_pending salt binding stages.sampledPending
    stages.indexes stages.rows decs.maskingEvals tapes paths stages.merkleInput stages.inputBuilt
  obtain ⟨earlierClean, queryWords, queryDecoded⟩ := query_execution_clean pending
    stages.openingDigest oracle stages.indexes stages.sampledPending stages.queryExecuted
    (inputPending.symm.trans inputClean)
  exact ⟨earlierClean, queryWords, decsWords, queryDecoded, sampled.symm.trans decoded, decoded⟩

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureClean
