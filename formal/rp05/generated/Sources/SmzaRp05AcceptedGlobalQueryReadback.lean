import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05ExecutableMerkleMeasured
import SmzaRp05ExecutablePcsClosureStatement

/-! Accepted same-run PCS stages to authenticated current-leaf readback.

This closes the deterministic bridge from the actual `postMerkleProgram`
execution embedded in `PcsStages` to the global query claims, provided the
parser-visible records from that same run are retained in the measured
relation and that relation is collision-free.  It does not manufacture
FiveMcaChecks or TwelveLvcsChecks: the assembled accepted verifier currently
does not execute those gates (see `SmzaRp05ExecutableFinalVerifier`).
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedGlobalQueryReadback

open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05ExecutableChallengeStage (PostMerkle pendingFailure)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05PiopMatrixStage (matrixProgram)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open V8Smz9PiopReconstruction (points)
open SmzaRp05ExecutableMerkleMeasured
open SmzaRp05GlobalOpeningReadback
open SmzaRp05FilteredDecoderInstability (RawRecords globalOnlineNext)
open SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.SmallWood
open scoped Classical

set_option autoImplicit false
noncomputable section
abbrev RawDigest := V8SmzaOracleParser.RawDigest

/-- A clean PIOP-coefficient sampler cannot erase an earlier PCS/XOF
failure.  This recovers the cleanliness needed by `PcsStages` from the
actual matrix-program result rather than confusing it with the later state. -/
private theorem matrix_clean_preserves_input
    (width : Nat) (pending : Bool) (hashFpp : RawDigest) (oracle : Oracle)
    (matrix : V8Smz9PiopSoundness.Matrix width) (finalPending : Bool)
    (executed : (matrixProgram width pending hashFpp).eval oracle =
      some (matrix, finalPending)) (clean : finalPending = false) :
    pending = false := by
  rw [matrixProgram, SmzaRp05ExecutableMerkleVerifier.Program.eval_bind] at executed
  cases sampled : (SmzaRp05ExecutableChallengeStage.fieldXof
      SmallWoodTranscript.piopCoefficientDomain (5 * width) hashFpp).eval oracle with
  | none => simp [sampled] at executed
  | some values =>
      simp only [sampled, Option.bind_some] at executed
      have outputEq := Option.some.inj executed
      have pendingEq :
          SmzaRp05ExecutableChallengeStage.pendingFailure pending values = finalPending :=
        congrArg Prod.snd outputEq
      have sampledClean :
          SmzaRp05ExecutableChallengeStage.pendingFailure pending values = false :=
        pendingEq.trans clean
      exact (SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words
        pending values sampledClean).1

private theorem successful_merkle_input_payload
    (salt binding : List HegemonCrypto.CanonicalBytes.Byte)
    (pending : Bool) (indexes : List Nat) (rows : List (List Goldilocks))
    (masks : SmzaRp05PcsWireProjection.FieldMatrix)
    (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (paths : List (List RawDigest)) (input : SmzaRp05ExecutableMerkleVerifier.Input)
    (built : SmzaRp05PcsMerklePayload.makeMerkleInput salt binding pending indexes
      rows masks tapes paths = some input) (j : Fin 38) :
    input.payloads j = SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
      (tapes.getD j.val []) (indexes.getD j.val 0) (rows.getD j.val [])
      (masks.getD j.val []) := by
  unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
  split at built
  · simp at built
  · injection built with equal
    subst input
    rfl

private theorem successful_merkle_input_index
    (salt binding : List HegemonCrypto.CanonicalBytes.Byte)
    (pending : Bool) (indexes : List Nat) (rows : List (List Goldilocks))
    (masks : SmzaRp05PcsWireProjection.FieldMatrix)
    (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (paths : List (List RawDigest)) (input : SmzaRp05ExecutableMerkleVerifier.Input)
    (built : SmzaRp05PcsMerklePayload.makeMerkleInput salt binding pending indexes
      rows masks tapes paths = some input) (j : Fin 38) :
    input.indices j = indexes.getD j.val 0 := by
  unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
  split at built
  · simp at built
  · injection built with equal
    subst input
    rfl

/-- A successful PCS post-Merkle execution with a clean accumulated failure
flag is the ordinary Merkle acceptance of its calculated input.  This uses
the input, output root, and oracle from `PcsStages`; none is an independent
accepted-path certificate. -/
theorem pcs_stages_merkle_acceptance
    (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : SmzaRp05PcsWireProjection.DecodedMiddleWire)
    (decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List HegemonCrypto.CanonicalBytes.Byte)
    (statementBinding : List Nat) (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (paths : List (List RawDigest)) (oracle : Oracle) (hashFpp : RawDigest)
    (finalPending : Bool) (stages : PcsStages ns pending hPiop wire decs points
      salt binding statementBinding tapes paths oracle hashFpp finalPending)
    (clean : finalPending = false) :
    SmzaRp05ExecutableMerkleVerifier.acceptedResult ns oracle stages.merkleInput =
      some stages.post.root := by
  obtain ⟨core, _sampled, _pending, _values⟩ :=
    SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core ns oracle
      stages.merkleInput stages.post stages.postExecuted
  obtain ⟨inputClean, _words⟩ :=
    SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words
      stages.merkleInput.pendingXofFailure stages.post.sampled
      (_pending.symm.trans (stages.pendingReturned.symm.trans clean))
  simp [SmzaRp05ExecutableMerkleVerifier.acceptedResult, inputClean, core]

/-- Construct `GlobalQueryReadback` for the exact 38 indices and leaves
calculated by successful accepted PCS stages.  The sole external evidence
premise is retention of parser-visible records from the same run in the
measured relation, plus its collision-free property for extraction. -/
theorem accepted_pcs_stages_global_query_readback
    (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : SmzaRp05PcsWireProjection.DecodedMiddleWire)
    (decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List HegemonCrypto.CanonicalBytes.Byte)
    (statementBinding : List Nat) (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (paths : List (List RawDigest)) (oracle : Oracle) (hashFpp : RawDigest)
    (finalPending : Bool) (stages : PcsStages ns pending hPiop wire decs points
      salt binding statementBinding tapes paths oracle hashFpp finalPending)
    (clean : finalPending = false) (measured : RawRecords)
    (retained : ∀ stage raw digest,
      (raw, digest) ∈
        (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle stages.merkleInput).2 →
      (globalOnlineNext ns stage raw).isSome → (raw, digest) ∈ measured) :
    ∃ coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position,
      ∃ query : SmzaQ38McaSourceBinding.Query,
        ∃ claims : GlobalQueryReadback ns measured stages.post.root query,
          (∀ j, (coordinates j).val = stages.merkleInput.indices j) ∧
          StrictMono coordinates ∧ query.val = Finset.univ.image coordinates ∧
          (∀ j, claims.input (coordinates j) =
            SmzaRp05LeafNamespace.encodeLeaf stages.merkleInput.binding
              (stages.merkleInput.payloads j)) ∧
          (∀ j, (claims.leaf (coordinates j)).bytes =
            stages.merkleInput.payloads j) ∧
          (∀ j, (coordinates j).val = stages.indexes.getD j.val 0) ∧
          (∀ j, (claims.leaf (coordinates j)).bytes =
            SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
              (tapes.getD j.val []) (stages.indexes.getD j.val 0)
              (stages.rows.getD j.val []) (decs.maskingEvals.getD j.val [])) := by
  have accepted := pcs_stages_merkle_acceptance ns pending hPiop wire decs points salt
    binding statementBinding tapes paths oracle hashFpp finalPending stages clean
  obtain ⟨coordinates, query, claims, indices, ordered, image, inputs, bytes⟩ :=
    accepted_same_measured_readback ns oracle stages.merkleInput stages.post.root
      accepted measured retained
  have payload (j : Fin 38) := successful_merkle_input_payload salt binding
    stages.sampledPending stages.indexes stages.rows decs.maskingEvals tapes paths
    stages.merkleInput stages.inputBuilt j
  have coordinateIndexes : ∀ j, (coordinates j).val = stages.indexes.getD j.val 0 := by
    intro j
    rw [indices j, successful_merkle_input_index salt binding stages.sampledPending
      stages.indexes stages.rows decs.maskingEvals tapes paths stages.merkleInput
      stages.inputBuilt j]
  refine ⟨coordinates, query, claims, indices, ordered, image, inputs, bytes,
    coordinateIndexes, ?_⟩
  intro j
  rw [bytes j, payload j]

/-- Recover the PCS-stage object from `ExecutionStages.pcsExecuted` and then
construct same-run global readback.  Retention is quantified over every
stage object satisfying those exact execution indices, so no chosen stage
object or query claims are supplied as verifier evidence. -/
theorem accepted_execution_stages_global_query_readback
    (ns : Namespace) (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List HegemonCrypto.CanonicalBytes.Byte)
    (statementBinding : List Nat) (nonce : Fin (2 ^ 32))
    (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : Oracle) (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending binding statementBinding nonce
      wire oracle transcript)
    (clean : transcript.pendingXofFailure = false)
    (measured : RawRecords)
    (retained : ∀ pcs : PcsStages ns execution.openingPending wire.hPiop
        (sameProofRows execution.middle.pcs execution.piop) execution.decs
        (List.ofFn fun j : Fin 6 => points execution.opening j)
        wire.salt binding statementBinding wire.tapes wire.paths oracle
        execution.hashFpp execution.pcsPending,
      ∀ stage raw digest,
        (raw, digest) ∈
          (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle
            pcs.merkleInput).2 →
        (globalOnlineNext ns stage raw).isSome → (raw, digest) ∈ measured) :
    ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (sameProofRows execution.middle.pcs execution.piop) execution.decs
        (List.ofFn fun j : Fin 6 => points execution.opening j)
        wire.salt binding statementBinding wire.tapes wire.paths oracle
        execution.hashFpp execution.pcsPending,
      ∃ coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position,
        ∃ query : SmzaQ38McaSourceBinding.Query,
          ∃ claims : GlobalQueryReadback ns measured pcs.post.root query,
            (∀ j, (coordinates j).val = pcs.indexes.getD j.val 0) ∧
            StrictMono coordinates ∧ query.val = Finset.univ.image coordinates ∧
            (∀ j, (claims.leaf (coordinates j)).bytes =
              SmzaRp05PcsMerklePayload.normalizedLeafPayload wire.salt
                (wire.tapes.getD j.val []) (pcs.indexes.getD j.val 0)
                (pcs.rows.getD j.val []) (execution.decs.maskingEvals.getD j.val [])) := by
  have pcsClean : execution.pcsPending = false :=
    matrix_clean_preserves_input (dsl.width statement) execution.pcsPending
      execution.hashFpp oracle execution.matrix execution.finalPending
      execution.matrixExecuted (by
        have pendingEq := congrArg
          SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript.pendingXofFailure
          execution.reconstructed
        have finalEq : execution.finalPending = transcript.pendingXofFailure := by
          simpa [SmzaRp05ExecutableReconstruction.reconstruct] using pendingEq
        exact finalEq.trans clean)
  obtain ⟨pcs⟩ := SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages
    ns execution.openingPending wire.hPiop
    (sameProofRows execution.middle.pcs execution.piop) execution.decs
    (List.ofFn fun j : Fin 6 => points execution.opening j)
    wire.salt binding statementBinding wire.tapes wire.paths oracle
    execution.hashFpp execution.pcsPending execution.pcsExecuted
  obtain ⟨coordinates, query, claims, _indexEq, ordered, image, _inputEq,
      _bytesEq, coordinateIndexEq, payloadEq⟩ :=
    accepted_pcs_stages_global_query_readback ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => points execution.opening j)
      wire.salt binding statementBinding wire.tapes wire.paths oracle
      execution.hashFpp execution.pcsPending pcs pcsClean measured
      (retained pcs)
  exact ⟨pcs, coordinates, query, claims, coordinateIndexEq, ordered, image, payloadEq⟩

/-- Single endpoint from the assembled verifier's accepted result.  Both the
`ExecutionStages` value and its clean guard are extracted from acceptance;
the only environmental premise is retention of that computed PCS Merkle
subexecution's parser-visible records in the same measured relation. -/
theorem accepted_verifier_global_query_readback
    (ns : Namespace) (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : Oracle)
    (accepted : (SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl
      statement pending nonce wire).eval oracle = some ())
    (measured : RawRecords)
    (retained : ∀ transcript
      (execution : ExecutionStages ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire oracle transcript),
      transcript.pendingXofFailure = false →
      ∀ pcs : PcsStages ns execution.openingPending wire.hPiop
        (sameProofRows execution.middle.pcs execution.piop) execution.decs
        (List.ofFn fun j : Fin 6 => points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
      ∀ stage raw digest,
        (raw, digest) ∈
          (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle
            pcs.merkleInput).2 →
        (globalOnlineNext ns stage raw).isSome → (raw, digest) ∈ measured) :
    ∃ transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript,
      ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire oracle transcript,
      ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (sameProofRows execution.middle.pcs execution.piop) execution.decs
        (List.ofFn fun j : Fin 6 => points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
      ∃ coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position,
      ∃ query : SmzaQ38McaSourceBinding.Query,
      ∃ claims : GlobalQueryReadback ns measured pcs.post.root query,
        transcript.pendingXofFailure = false ∧
        oracle (SmzaRp05ExecutableFinalVerifier.finalInput transcript) = wire.hPiop ∧
        (∀ j, (coordinates j).val = pcs.indexes.getD j.val 0) ∧
        StrictMono coordinates ∧ query.val = Finset.univ.image coordinates ∧
        (∀ j, (claims.leaf (coordinates j)).bytes =
          SmzaRp05PcsMerklePayload.normalizedLeafPayload wire.salt
            (wire.tapes.getD j.val []) (pcs.indexes.getD j.val 0)
            (pcs.rows.getD j.val []) (execution.decs.maskingEvals.getD j.val [])) := by
  obtain ⟨transcript, ⟨execution⟩, clean, hashEqual, _recorded⟩ :=
    SmzaRp05ExecutablePcsClosureStatement.accepted_current_statement_has_stages
      ns dsl statement pending nonce wire oracle accepted
  obtain ⟨pcs, coordinates, query, claims, coordinateEq, ordered, image, payloadEq⟩ :=
    accepted_execution_stages_global_query_readback ns dsl statement pending
      statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript execution clean measured
      (retained transcript execution clean)
  refine Exists.intro transcript ?_
  refine Exists.intro execution ?_
  refine Exists.intro pcs ?_
  refine Exists.intro coordinates ?_
  refine Exists.intro query ?_
  refine Exists.intro claims ?_
  refine ⟨clean, ?_⟩
  refine ⟨hashEqual, ?_⟩
  refine ⟨coordinateEq, ?_⟩
  refine ⟨ordered, ?_⟩
  refine ⟨image, ?_⟩
  exact payloadEq

end
end HegemonCrypto.SmallWood.SmzaRp05AcceptedGlobalQueryReadback
