import SmzaRp05CurrentAcceptedQueryExtraction
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05PhysicalProducerVerifierPrefix
import SmzaRp05PhysicalHashFppRecordRetention
import SmzaRp05ExecutablePcsClosureSampling

/-! # Accepted physical execution to current-map failure event

This is a deterministic same-branch inclusion.  The Merkle attempt and
`hash_fpp` query records are both retained from one source-derived successful
execution into its full physical raw log.  The existing accepted-stage
decoder theorem is then rerun on the full physical record set.  The collision
alternative is retained explicitly; this theorem does not assert an
independent-query law for a post-q38 response.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedCurrentExtraction

open HegemonCrypto.CmsCompressedOracle (State Basis)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches physicalRun branchResult rawLog basisOracle)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

/-- Every accepted, nonzero physical verifier branch supplies the actual PCS
stage whose full physical record set entails a collision, a current 406-map
decoder/LVCS failure, or exact recovery of all twelve authenticated checks.
The retained response is derived from the same stage's post-q38 hash query;
no caller-selected tables, sublogs, checks, or execution witnesses are used.
-/
theorem accepted_physical_current_decoder_outcome
    {Key Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype RawDigest] [DecidableEq RawDigest] [AddCommGroup RawDigest]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key) (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire =>
        SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire))
    (state : State Key RawDigest Phase Work)
    (basis : Basis Key RawDigest Phase Work) (fallback : RawDigest)
    (nonzero : globalDecompress
      (physicalRun encode (fun (_ : RawInput) (answer : RawDigest) => answer)
        (producer.bind fun wire =>
          SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
            pending nonce wire) branch state) basis ≠ 0)
    (accepted : branchResult (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire =>
        SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire) branch = some ())
    (fuel : Nat) (enough : 25 ≤ fuel) :
    let decode : RawInput → RawDigest → RawDigest :=
      fun (_ : RawInput) (answer : RawDigest) => answer
    let oracle := basisOracle encode decode basis fallback
    let program := producer.bind fun wire =>
      SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
        pending nonce wire
    let records : RawRecords := (rawLog decode program branch).toFinset
    ¬ RecordsCollisionFree records ∨
      ∃ wire transcript,
        ∃ execution : SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement
          pending statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          nonce wire oracle transcript,
        ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
          execution.decs
          (List.ofFn fun j : Fin 6 =>
            V8Smz9PiopReconstruction.points execution.opening j)
          wire.salt statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
        (∃ coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position,
          ∃ query : SmzaQ38McaSourceBinding.Query,
            ∃ input : RawInput,
              StrictMono coordinates ∧
              query.val = Finset.univ.image coordinates ∧
              (∀ j : Fin 38,
                (coordinates j).val = pcs.indexes.getD j.val 0) ∧
              (input, execution.hashFpp) ∈ rawLog decode program branch ∧
              (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2 ∧
              SmzaRp05CurrentAcceptedQueryExtraction.CurrentDecoderOutcome
                (SmzaRp05CurrentRetainedQuerySupport.measuredDataTable ns records fuel pcs.post.root)
                (SmzaRp05CurrentRetainedQuerySupport.measuredMaskTable ns records fuel pcs.post.root)
                (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
                  (fun _ : SmzaRp05CurrentMaxAgreementRecovery.Coefficients => input))
                (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
                  (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
                pcs.heads
                (SmzaRp05CurrentTwelveCalculated.currentStageTails
                  (SmzaRp05PcsToFinalProgram.sameProofRows
                    execution.middle.pcs execution.piop))
                (fun opening =>
                  (List.ofFn fun j : Fin 6 =>
                    V8Smz9PiopReconstruction.points execution.opening j).getD
                      opening.val 0) query) := by
  classical
  let decode : RawInput → RawDigest → RawDigest :=
    fun (_ : RawInput) (answer : RawDigest) => answer
  let oracle := basisOracle encode decode basis fallback
  let program := producer.bind fun wire =>
    SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
      pending nonce wire
  let records : RawRecords := (rawLog decode program branch).toFinset
  obtain ⟨wire, _producerSuccess, _verifierAccepted, rawSplitPrefix,
      _prefixOutcome⟩ :=
    SmzaRp05PhysicalProducerVerifierPrefix.accepted_physical_producer_prefix_dichotomy
      encode producer ns dsl statement pending nonce branch state basis fallback
      nonzero accepted
  obtain ⟨wireFromPcs, transcript, execution, pcs, producerSuccess,
      verifierAcceptedFromPcs, transcriptSuccess, merkleRetained⟩ :=
    SmzaRp05PhysicalPcsRecordRetention.accepted_physical_run_merkle_records_in_raw_log
      encode producer ns dsl statement pending nonce branch state basis fallback
      nonzero accepted
  have wireEq : wire = wireFromPcs :=
    Option.some.inj (_producerSuccess.symm.trans producerSuccess)
  subst wire
  have rawSplit : rawLog decode program branch =
      (producer.record oracle).2 ++
        ((SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wireFromPcs).record oracle).2 := by
    simpa [decode, oracle, program] using rawSplitPrefix
  have transcriptCleanData :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript
      ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wireFromPcs oracle verifierAcceptedFromPcs
  obtain ⟨cleanTranscript, cleanExecution, clean, _rootEq, _rootRecord⟩ :=
    transcriptCleanData
  have transcriptEq : cleanTranscript = transcript :=
    Option.some.inj (cleanExecution.symm.trans transcriptSuccess)
  have transcriptClean : transcript.pendingXofFailure = false := by
    rw [← transcriptEq]
    exact clean
  have cleanStages :=
    SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
      ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wireFromPcs oracle transcript execution transcriptClean
  have pointCount :
      (List.ofFn fun j : Fin 6 =>
        V8Smz9PiopReconstruction.points execution.opening j).length = 6 :=
    SmzaRp05CurrentTwelveCalculated.generated_opening_points_length execution.opening
  have bindingLength :
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement).length = 138 :=
    SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement
  have merkleSublog : ∀ call,
      call ∈ (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle
        pcs.merkleInput).2 → call ∈ records := by
    intro call member
    apply List.mem_toFinset.mpr
    have memberPhysical := merkleRetained call member
    simpa [records, decode, program] using memberPhysical
  have hashToVerifier :=
    SmzaRp05PhysicalHashFppRecordRetention.execution_hash_fpp_records_retained_in_verifier
      ns dsl statement pending nonce wireFromPcs oracle transcript execution pcs
      transcriptSuccess
  have hashSublog : ∀ call,
      call ∈ (pcs.hashProgram.record oracle).2 → call ∈ records := by
    intro call member
    have inVerifier := hashToVerifier call member
    have inPhysical : call ∈ rawLog decode program branch := by
      rw [rawSplit]
      exact List.mem_append.mpr (Or.inr inVerifier)
    exact List.mem_toFinset.mpr inPhysical
  have outcome :=
    SmzaRp05CurrentAcceptedQueryExtraction.accepted_stage_retained_decoder_outcome
      pcs pointCount cleanStages.1 fuel enough bindingLength records
      merkleSublog hashSublog
  rcases outcome with collision | source
  · exact Or.inl collision
  · rcases source with ⟨coordinates, query, input, ordered, image, coordinateIndex,
      inputMember, inputHashMember, currentOutcome⟩
    refine Or.inr ⟨wireFromPcs, transcript, execution, pcs,
      ⟨coordinates, query, input, ordered, image, coordinateIndex, ?_,
        inputHashMember, currentOutcome⟩⟩
    have inRecords := List.mem_toFinset.mp inputMember
    simpa [records, decode, program] using inRecords

end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedCurrentExtraction
