import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentExecutedEarlierAdvice
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05ExecutablePcsClosureStatement

/-! # Earlier-role advice from the actual accepted current execution

Compose the same-execution causal record readback with the earlier-advice
decoder. Opening, final, and FPP memberships are derived from the accepted
verifier and DECS/PIOP/FPP parser-normalized payloads; clean-stage flags are
derived from the accepted transcript rather than passed as certificates.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedEarlierAdvice

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05AcceptedRoleLabels (EarlierReadback CausalPayloads)
open SmzaRp05CurrentAcceptedCausalPayloads (Records)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

/-- An actual accepted execution supplies its exact causal record memberships
and all clean flags needed for earlier-role advice. The only raw-log premise
is parse-none retention; no message-record memberships or clean outcomes are
assumed independently of this execution. -/
theorem accepted_execution_supplies_earlier_advice_of_nonchallenge_retention
    (dsl : RelationDsl)
    (certificates : SmzaRp05RelationRefinement.GeneratedCertificates dsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (ns : Namespace) (pending : Bool) (nonce : Fin (2 ^ 32))
    (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype V8SmzaOracleParser.RawDigest]
    (records : Records) (collisionFree : SmzaRecordedTracePath.RecordsCollisionFree records)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval oracle = some ())
    (transcriptSuccess : (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire).eval
        oracle = some transcript)
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 →
      SmzaChallengeStageTargets.parseStageQuery call.1 = none → call ∈ records) :
    ∃ trace : SmzaRp05TracePrefixes.Trace,
      trace = V8Smz9CoherentMerkleGeometry.extract
        (SmzaRp05FilteredDecoderInstability.globalOnlineNext ns) records
        28 .decs pcs.openingDigest ∧
      ∃ messages : CausalPayloads ns trace,
      EarlierReadback (SmzaRp05RelationRefinement.relationModel dsl certificates) statement
        (fun selected => SmzaRp05CurrentExecutedEarlierAdvice.currentOracleAllAdvice
          (SmzaRp05RelationRefinement.relationModel dsl certificates)
          oracle selected statement)
        messages
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
        execution.matrix execution.opening := by
  obtain ⟨openingRecorded, finalRecorded, hashRecordRetained⟩ :=
    SmzaRp05CurrentCausalNonchallengeRetention.accepted_execution_causal_record_memberships
      ns dsl statement pending nonce wire oracle transcript execution pcs records
      verifierAccepted transcriptSuccess nonchallengeRetained
  obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, transcriptClean,
      _hashEq, _finalMember⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
      statement pending statement.toBytes (statementBindingWords statement)
      nonce wire oracle verifierAccepted
  have sameTranscript : acceptedTranscript = transcript :=
    Option.some.inj (acceptedTranscriptSuccess.symm.trans transcriptSuccess)
  subst acceptedTranscript
  have stagesClean :=
    SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle
      transcript execution transcriptClean
  have coefficientsClean : pcs.post.pending = false :=
    pcs.pendingReturned.symm.trans stagesClean.1
  have openingCleanData :=
    SmzaRp05ExecutablePcsClosureClean.pcs_stages_clean ns execution.openingPending
      wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs stagesClean.1
  have openingClean : execution.openingPending = false := openingCleanData.1
  exact SmzaRp05CurrentExecutedEarlierAdvice.actual_execution_supplies_earlier_readback
    dsl certificates statement ns pending nonce wire oracle transcript execution pcs
    records collisionFree openingRecorded finalRecorded hashRecordRetained
    coefficientsClean transcriptClean openingClean

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedEarlierAdvice
