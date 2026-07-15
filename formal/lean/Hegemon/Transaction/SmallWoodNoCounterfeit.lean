import Hegemon.Consensus.RecursiveBlockAdmission
import Hegemon.Transaction.ProofSystemBoundary
import Hegemon.Transaction.SmallWoodProductionConstraintRefinement
import Hegemon.Transaction.SmallWoodSemanticClosure

namespace Hegemon
namespace Transaction
namespace SmallWoodNoCounterfeit

open Hegemon.Consensus.RecursiveBlockAdmission
open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.AssetIsolation
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofSystemBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SmallWoodSemanticClosure
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open Hegemon.Transaction.SpendAuthorization

theorem accepted_recursive_artifact_exposes_statement_and_replay_binding
    {artifact : ArtifactAdmissionInput}
    (accepted : artifactAccepts artifact = true) :
    artifact.statementCommitmentMatches = true
      ∧ artifact.publicReplayMatches = true := by
  have preconditions : artifactPreconditions artifact = true := by
    rw [← artifact_accepts_iff_preconditions]
    exact accepted
  unfold artifactPreconditions at preconditions
  repeat split at preconditions <;> simp_all

theorem semantic_constraints_canonical_surface_imply_no_theft_boundary
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputWitnesses : List SmallWoodOutputWitness}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (semanticConstraints :
      SmallWoodSemanticConstraintsSatisfied
        shape
        merkleRoot
        spendWitnesses
        inputRows
        outputWitnesses
        outputRows
        balanceWitness
        slots)
    (balancePublicFields :
      BalancePublicFieldFacts publicFields balanceWitness) :
    CanonicalProofSystemNoTheftBoundaryFacts
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot
      spendWitnesses
      balanceWitness
      slots := by
  have spendSound :
      DeployedTxVerifierSpendSoundnessAssumption
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses := by
    intro _
    exact semantic_constraints_imply_spend_authorized semanticConstraints
  have balanceSound :
      DeployedTxVerifierBalancePublicFieldSoundnessAssumption
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        balanceWitness
        slots := by
    intro _
    exact
      {
        balanceSlotsEq :=
          semanticConstraints.balanceConstraints.slotsMaterialized,
        validBalanceEq :=
          balance_constraints_imply_valid_balance
            semanticConstraints.balanceConstraints,
        publicFields := balancePublicFields
      }
  exact
    deployed_soundness_parts_canonical_surface_implies_no_theft_boundary_facts
      surface
      spendSound
      balanceSound

theorem accepted_recursive_v2_artifact_still_requires_semantic_replay
    {artifact : ArtifactAdmissionInput}
    (expectedKind : artifact.expectedKind = ArtifactKind.recursiveBlockV2)
    (accepted : artifactAccepts artifact = true) :
    artifact.envelopeKind = ArtifactKind.recursiveBlockV2
      ∧ evaluateDirectVerifierRejection artifact.envelopeKind =
        some DirectVerifierReject.requiresSemanticReplay := by
  have envelopeMatches : artifact.envelopeKind = artifact.expectedKind := by
    by_cases kindEq : artifact.envelopeKind = artifact.expectedKind
    · exact kindEq
    · unfold artifactAccepts evaluateArtifactRejection at accepted
      simp [kindEq] at accepted
  have recursiveKind :
      artifact.envelopeKind = ArtifactKind.recursiveBlockV2 := by
    rw [envelopeMatches, expectedKind]
  constructor
  · exact recursiveKind
  · rw [recursiveKind]
    exact direct_v2_requires_semantic_replay
end SmallWoodNoCounterfeit
end Transaction
end Hegemon
