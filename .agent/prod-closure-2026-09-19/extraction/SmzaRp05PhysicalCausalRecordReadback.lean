import SmzaRp05PhysicalAcceptedCurrentExtraction
import SmzaRp05CurrentPrequeryChronology
import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05PhysicalProducerVerifierPrefix

/-! # Accepted-run causal opening readback

The canonical DECS-opening query is an actual first call in the PCS program,
and the accepted physical branch retains that exact call in its full raw log.
The result is tied to the same source-produced wire and successful execution
stages; it does not admit a caller-chosen trace or query pair.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalCausalRecordReadback

open HegemonCrypto.CmsCompressedOracle (State Basis)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult rawLog basisOracle physicalRun)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

/-- The actual canonical-opening hash query of an accepted nonzero physical
run is present, with its actual sampled digest, in that same run's full raw
log. The `PcsStages` witness is produced from the accepted transcript, and
the lift uses source bind chronology through PCS and verifier records.
-/
theorem accepted_physical_opening_query_in_raw_log
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
          pending nonce wire) branch = some ()) :
    ∃ wire transcript,
      ∃ execution : SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement
        pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback) transcript,
      ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback)
        execution.hashFpp execution.pcsPending,
      (pcs.openingInput, pcs.openingDigest) ∈
        rawLog (fun (_ : RawInput) (answer : RawDigest) => answer)
          (producer.bind fun wire =>
            SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
              pending nonce wire) branch := by
  let decode : RawInput → RawDigest → RawDigest :=
    fun (_ : RawInput) (answer : RawDigest) => answer
  let oracle := basisOracle encode decode basis fallback
  obtain ⟨wire, producerSuccess, verifierAccepted, rawSplit, _eventDichotomy⟩ :=
    SmzaRp05PhysicalProducerVerifierPrefix.accepted_physical_producer_prefix_dichotomy
      encode producer ns dsl statement pending nonce branch state basis fallback
      nonzero accepted
  obtain ⟨transcript, transcriptSuccess, _clean, _hashEq, _finalMember⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
      statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement) nonce wire
      oracle verifierAccepted
  obtain ⟨execution⟩ :=
    SmzaRp05ExecutablePcsClosure.transcript_execution_has_stages ns dsl statement
      pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement) nonce wire
      oracle transcript transcriptSuccess
  obtain ⟨pcs⟩ :=
    SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages ns
      execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending
      execution.pcsExecuted
  have pcsRetained :=
    SmzaRp05PhysicalPcsRecordRetention.execution_pcs_records_retained_in_verifier
      ns dsl statement pending nonce wire oracle transcript execution transcriptSuccess
  have openingInPcs : (pcs.openingInput, pcs.openingDigest) ∈
      ((SmzaRp05ExecutablePcsClosure.pcsProgram ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths).record oracle).2 := by
    rw [SmzaRp05CurrentPrequeryChronology.pcs_q38_record_split ns
      execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs]
    simp
  have openingInVerifier := pcsRetained (pcs.openingInput, pcs.openingDigest)
    openingInPcs
  refine ⟨wire, transcript, execution, pcs, ?_⟩
  rw [rawSplit]
  exact List.mem_append.mpr (Or.inr openingInVerifier)

end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalCausalRecordReadback
