import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05ExecutableAcceptedFailureJoin
import SmzaRp05ExecutableMerklePaths

/-!
# Same-branch producer prefix and accepted verifier suffix

The producer and statement-bound verifier are composed in one source
`Program`. On any accepted physical branch with nonzero final coefficient,
the branch determines the basis oracle and its raw log is exactly the
producer record followed by the accepted verifier record. The existing
retention/collision/reconstruction dichotomy is then applied to that actual
producer record, not to an independently supplied earlier log.

This establishes source-program chronology before verifier execution. It does
not place the producer hash query before q38 inside the verifier, and it does
not provide a full physical-Born or QROM probability bound.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalProducerVerifierPrefix

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableAcceptedFailureJoin
open SmzaRp05ExecutablePcsClosureStatement
  (verifierProgram statementBindingWords)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

theorem accepted_physical_producer_prefix_dichotomy
    {Key Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype RawDigest] [DecidableEq RawDigest] [AddCommGroup RawDigest]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key)
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (state : State Key RawDigest Phase Work)
    (basis : Basis Key RawDigest Phase Work) (fallback : RawDigest)
    (nonzero : globalDecompress
      (physicalRun encode (fun (_ : RawInput) (answer : RawDigest) => answer)
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        branch state) basis ≠ 0)
    (accepted : branchResult (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      branch = some ()) :
    ∃ wire,
      producer.eval
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback) = some wire ∧
      (verifierProgram ns dsl statement pending nonce wire).eval
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback) = some () ∧
      rawLog (fun (_ : RawInput) (answer : RawDigest) => answer)
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        branch =
          (producer.record
            (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
              basis fallback)).2 ++
          ((verifierProgram ns dsl statement pending nonce wire).record
            (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
              basis fallback)).2 ∧
      (retentionFailure
          ((producer.record
            (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
              basis fallback)).2) wire.hPiop ∨
        ¬ SmzaRecordedTracePath.RecordsCollisionFree (publicRecords
          ((producer.record
            (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
              basis fallback)).2)
          ((verifierProgram ns dsl statement pending nonce wire).record
            (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
              basis fallback)).2) ∨
        ∃ transcript,
          Nonempty (SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement
            pending statement.toBytes (statementBindingWords statement) nonce wire
            (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
              basis fallback) transcript) ∧
          transcript.pendingXofFailure = false ∧
          (SmzaRp05ExecutableFinalVerifier.finalInput transcript, wire.hPiop) ∈
            (producer.record
              (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
                basis fallback)).2) := by
  let decode : RawInput → RawDigest → RawDigest :=
    fun (_ : RawInput) (answer : RawDigest) => answer
  let oracle := basisOracle encode decode basis fallback
  let next := fun wire => verifierProgram ns dsl statement pending nonce wire
  let program := producer.bind next
  have branchRecord := accepted_branch_record_eq_physical_rawLog
    encode decode program branch state basis fallback nonzero accepted
  have acceptedEval : program.eval oracle = some () := by
    have resultEq := congrArg Prod.fst branchRecord
    simpa [oracle, Program.record_result] using resultEq
  have bindEval : (producer.eval oracle).bind
      (fun wire => (next wire).eval oracle) = some () := by
    simpa [program, Program.eval_bind] using acceptedEval
  cases producerResult : producer.eval oracle with
  | none => simp [producerResult] at bindEval
  | some wire =>
      have verifierAccepted : (next wire).eval oracle = some () := by
        simpa [producerResult] using bindEval
      have recordSplit := Program.record_bind_success oracle producer next wire
        producerResult
      have physicalLogSplit : rawLog decode program branch =
          (producer.record oracle).2 ++ ((next wire).record oracle).2 := by
        calc
          rawLog decode program branch = (program.record oracle).2 := by
            rw [branchRecord]
          _ = (producer.record oracle).2 ++ ((next wire).record oracle).2 :=
            congrArg Prod.snd recordSplit
      have eventDichotomy :=
        accepted_prefix_retention_or_collision_or_reconstruction ns dsl statement
          pending nonce wire oracle ((producer.record oracle).2) verifierAccepted
      exact ⟨wire, rfl, verifierAccepted, by
        simpa [decode, oracle, program, next] using physicalLogSplit,
        by simpa [decode, oracle, next] using eventDichotomy⟩

end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalProducerVerifierPrefix
