import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05ExecutablePcsClosure
import SmzaRp05OrderedPrequeryTrace

/-!
# Accepted physical branch to the verifier's actual final-log suffix

For a nonzero physical branch of the assembled verifier, the accepted branch
itself determines a basis oracle.  Its measured answers then replay the
ordinary verifier record exactly.  Consequently the existing accepted-run
stage extraction and final-query suffix apply to this same oracle, and the
suffix is literally the physical branch's raw log.  No independent oracle,
record, or adversary log is supplied to the theorem.

This is a branch-conditional realization theorem, not a claim that every
physical run has nonzero mass, nor a Rust/native implementation refinement.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedExecutionSuffix

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutablePcsClosure
open SmzaRp05OrderedPrequeryTrace
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.CanonicalBytes (Byte)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

theorem accepted_physical_branch_has_stages_and_raw_suffix
    {Key Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype RawDigest] [DecidableEq RawDigest] [AddCommGroup RawDigest]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (branch : Branches (fun (_ : RawInput) (answer : RawDigest) => answer)
      (verifierProgram ns dsl statement pending binding statementBinding nonce wire))
    (state : State Key RawDigest Phase Work)
    (basis : Basis Key RawDigest Phase Work) (fallback : RawDigest)
    (nonzero : globalDecompress
      (physicalRun encode (fun (_ : RawInput) (answer : RawDigest) => answer)
        (verifierProgram ns dsl statement pending binding statementBinding nonce wire)
        branch state) basis ≠ 0)
    (accepted : branchResult (fun (_ : RawInput) (answer : RawDigest) => answer)
      (verifierProgram ns dsl statement pending binding statementBinding nonce wire)
      branch = some ()) :
    ∃ transcript priorLog,
      Nonempty (ExecutionStages ns dsl statement pending binding statementBinding
        nonce wire
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer) basis fallback)
        transcript) ∧
      transcript.pendingXofFailure = false ∧
      basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer) basis fallback
        (SmzaRp05ExecutableFinalVerifier.finalInput transcript) = wire.hPiop ∧
      rawLog (fun (_ : RawInput) (answer : RawDigest) => answer)
        (verifierProgram ns dsl statement pending binding statementBinding nonce wire)
        branch = priorLog ++
          [(SmzaRp05ExecutableFinalVerifier.finalInput transcript, wire.hPiop)] := by
  let oracle := basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer) basis fallback
  let program := verifierProgram ns dsl statement pending binding statementBinding nonce wire
  have branchRecord := accepted_branch_record_eq_physical_rawLog
    encode (fun (_ : RawInput) (answer : RawDigest) => answer) program branch state basis fallback
    nonzero accepted
  have acceptedEval : program.eval oracle = some () := by
    have resultEq := congrArg Prod.fst branchRecord
    simpa [oracle, Program.record_result] using resultEq
  obtain ⟨transcript, transcriptEval, clean, finalHash, _finalMember⟩ :=
    accepted_execution_constructs_transcript ns dsl statement pending binding
      statementBinding nonce wire oracle acceptedEval
  have stages := transcript_execution_has_stages ns dsl statement pending binding
    statementBinding nonce wire oracle transcript transcriptEval
  obtain ⟨suffixTranscript, priorLog, suffixEval, _suffixClean,
      _suffixHash, suffix⟩ :=
    accepted_final_recomputation_is_ordered_suffix ns dsl statement pending
      binding statementBinding nonce wire oracle acceptedEval
  have sameTranscript : transcript = suffixTranscript := by
    apply Option.some.inj
    exact transcriptEval.symm.trans suffixEval
  subst suffixTranscript
  refine ⟨transcript, priorLog, stages, clean, finalHash, ?_⟩
  simpa [program, oracle, branchRecord,
    SmzaRp05ExecutableFinalVerifier.finalInput] using suffix

end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedExecutionSuffix
