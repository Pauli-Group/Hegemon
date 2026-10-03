import SmzaRp05CurrentFixedAdviceOpeningSource
import SmzaRp05ExecutablePcsClosureStatement
import SmzaRp05ExecutableMerklePaths

/-! # Lift actual PIOP reads into one accepted grouped branch

These adapters start from the verifier/transcript program's real raw record,
then lift that read through the successful producer bind and the same
branch's record equation. They do not posit an answer-log call or a separate
database cell.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRecordLift

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult rawLog answerLog)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFixedAdviceOpeningSource (verifier_record_pair_has_branch_answer)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentFiniteGroupedProgram (Key)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)

noncomputable section
set_option autoImplicit false

private theorem verifier_member_lifts_to_program_record
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (wire : ExistingProofFieldView) (oracle : Oracle)
    (producerSuccess : producer.eval oracle = some wire)
    (input : RawInput) (digest : RawDigest)
    (member : (input, digest) ∈
      ((verifierProgram ns dsl statement pending nonce wire).record oracle).2) :
    (input, digest) ∈
      ((producer.bind fun actualWire =>
        verifierProgram ns dsl statement pending nonce actualWire).record oracle).2 := by
  exact Program.bind_log_right oracle producer
    (fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
    wire producerSuccess member

/-- A real verifier-record pair becomes an answer-log pair of the accepted
producer/verifier branch. The branch equation is the only grouped-replay
bridge; successful producer evaluation identifies the same verifier run. -/
theorem verifier_record_pair_is_accepted_branch_answer
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (branch : Branches groupedDecode
      (producer.bind fun actualWire =>
        verifierProgram ns dsl statement pending nonce actualWire))
    (recordEq :
      (producer.bind fun actualWire =>
        verifierProgram ns dsl statement pending nonce actualWire).record oracle =
      (branchResult groupedDecode
        (producer.bind fun actualWire =>
          verifierProgram ns dsl statement pending nonce actualWire) branch,
       rawLog groupedDecode
        (producer.bind fun actualWire =>
          verifierProgram ns dsl statement pending nonce actualWire) branch))
    (producerSuccess : producer.eval oracle = some wire)
    (input : RawInput) (digest : RawDigest)
    (member : (input, digest) ∈
      ((verifierProgram ns dsl statement pending nonce wire).record oracle).2) :
    ∃ output, (input, output) ∈ answerLog groupedDecode
        (producer.bind fun actualWire =>
          verifierProgram ns dsl statement pending nonce actualWire) branch ∧
      groupedDecode input output = digest := by
  have wholeMember : (input, digest) ∈
      ((producer.bind fun actualWire =>
        verifierProgram ns dsl statement pending nonce actualWire).record oracle).2 :=
    verifier_member_lifts_to_program_record producer ns dsl
      statement pending nonce wire oracle producerSuccess input digest member
  exact verifier_record_pair_has_branch_answer
    (Key := Key (producer.bind fun actualWire =>
      verifierProgram ns dsl statement pending nonce actualWire))
    (program := producer.bind fun actualWire =>
      verifierProgram ns dsl statement pending nonce actualWire)
    branch oracle recordEq input digest wholeMember

/-- The transcript-level form used by PIOP samplers: lift an actual raw
transcript read first through the verifier continuation, then through the
successful producer and into the same accepted branch. -/
theorem transcript_record_pair_is_accepted_branch_answer
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (transcriptSuccess :
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl statement pending
        statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire).eval oracle = some transcript)
    (branch : Branches groupedDecode
      (producer.bind fun actualWire =>
        verifierProgram ns dsl statement pending nonce actualWire))
    (recordEq :
      (producer.bind fun actualWire =>
        verifierProgram ns dsl statement pending nonce actualWire).record oracle =
      (branchResult groupedDecode
        (producer.bind fun actualWire =>
          verifierProgram ns dsl statement pending nonce actualWire) branch,
       rawLog groupedDecode
        (producer.bind fun actualWire =>
          verifierProgram ns dsl statement pending nonce actualWire) branch))
    (producerSuccess : producer.eval oracle = some wire)
    (input : RawInput) (digest : RawDigest)
    (member : (input, digest) ∈
      ((SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl statement pending
        statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire).record oracle).2) :
    ∃ output, (input, output) ∈ answerLog groupedDecode
        (producer.bind fun actualWire =>
          verifierProgram ns dsl statement pending nonce actualWire) branch ∧
      groupedDecode input output = digest := by
  have verifierMember : (input, digest) ∈
      ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 := by
    exact Program.bind_log_left oracle
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl statement pending
        statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire)
      (SmzaRp05ExecutableFinalVerifier.finalize wire.hPiop)
      transcript transcriptSuccess member
  exact verifier_record_pair_is_accepted_branch_answer producer ns dsl statement
    pending nonce wire oracle branch recordEq producerSuccess input digest verifierMember

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRecordLift
