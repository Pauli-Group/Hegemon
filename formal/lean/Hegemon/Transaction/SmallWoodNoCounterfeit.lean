import Hegemon.Consensus.RecursiveBlockAdmission
import Hegemon.Consensus.ProvenBatchBinding
import Hegemon.Consensus.SupplyInvariant
import Hegemon.Transaction.SmallWoodSemanticClosure
import Hegemon.Transaction.TxValidityClaimMatching

namespace Hegemon
namespace Transaction
namespace SmallWoodNoCounterfeit

open Hegemon.Consensus.RecursiveBlockAdmission
open Hegemon.Consensus.SupplyInvariant
open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.AssetIsolation
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofSystemBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SmallWoodSemanticClosure
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

structure ExactSmallWoodAcceptedTransition where
  wrapper : ProofWrapperInput
  shape : PublicInputShape
  merkleRoot : Digest
  spendWitnesses : List InputSpendWitness
  inputRows : List SmallWoodInputConstraintRow
  outputWitnesses : List SmallWoodOutputWitness
  outputRows : List SmallWoodOutputConstraintRow
  balanceWitness : BalanceWitness
  slots : List BalanceSlot
  accepted : proofWrapperAccepts wrapper = true
  semanticConstraints :
    SmallWoodSemanticConstraintsSatisfied
      shape
      merkleRoot
      spendWitnesses
      inputRows
      outputWitnesses
      outputRows
      balanceWitness
      slots

def ExactSmallWoodAcceptedTransition.toAcceptedAssetTransition
    (transition : ExactSmallWoodAcceptedTransition) : AcceptedAssetTransition :=
  {
    wrapper := transition.wrapper,
    shape := transition.shape,
    merkleRoot := transition.merkleRoot,
    spendWitnesses := transition.spendWitnesses,
    balanceWitness := transition.balanceWitness,
    slots := transition.slots,
    relation :=
      accepted_proof_and_semantic_constraints_imply_transaction_relation
        transition.accepted
        transition.semanticConstraints
  }

def exactSmallWoodAcceptedChain
    (transitions : List ExactSmallWoodAcceptedTransition) :
    List AcceptedAssetTransition :=
  transitions.map ExactSmallWoodAcceptedTransition.toAcceptedAssetTransition

theorem exact_smallwood_accepted_chain_yields_supply_conservation_certificate
    {parent next : Nat}
    {step : ClaimedSupplyStep}
    {transitions : List ExactSmallWoodAcceptedTransition}
    (feeBinding :
      step.fees =
        acceptedChainAssetDelta
          Transaction.nativeAsset
          (exactSmallWoodAcceptedChain transitions))
    (acceptedSupply : validateClaimedSupplyStep parent step = some next) :
    AcceptedChainSupplyConservationCertificate
      parent
      next
      step
      (exactSmallWoodAcceptedChain transitions) :=
  accepted_transaction_chain_yields_supply_conservation_certificate
    feeBinding
    acceptedSupply

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

theorem exact_constraint_extraction_canonical_surface_implies_no_theft_boundary
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
    (extraction :
      SmallWoodExactConstraintExtractionAssumption
        wrapper
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
      slots :=
  semantic_constraints_canonical_surface_imply_no_theft_boundary
    surface
    (extraction surface.accepted)
    balancePublicFields

theorem exact_smallwood_constraints_yield_production_supply_conservation
    {parent next : Nat}
    {step : ClaimedSupplyStep}
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
    (extraction :
      SmallWoodExactConstraintExtractionAssumption
        wrapper
        shape
        merkleRoot
        spendWitnesses
        inputRows
        outputWitnesses
        outputRows
        balanceWitness
        slots)
    (balancePublicFields :
      BalancePublicFieldFacts publicFields balanceWitness)
    (feeBinding :
      step.fees =
        publicAuthorizedAssetDeltaValue publicFields Transaction.nativeAsset)
    (acceptedSupply : validateClaimedSupplyStep parent step = some next) :
    CanonicalProductionSupplyConservationCertificate
      parent
      next
      step
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
      slots :=
  canonical_no_theft_boundary_yields_production_supply_conservation_certificate
    (exact_constraint_extraction_canonical_surface_implies_no_theft_boundary
      surface
      extraction
      balancePublicFields)
    feeBinding
    acceptedSupply

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

structure RecursiveSmallWoodObjectIdentity where
  canonicalStatementBytes : List Byte
  statementCommitment : Digest
  publicReplayCommitment : Digest
  transactionCount : Nat
  daRoot : Digest
deriving DecidableEq, Repr

structure RecursiveSmallWoodCrossObjectIdentityRefinementAssumption
    (statementBytes : List Byte)
    (artifactIdentity claimIdentity batchIdentity transactionIdentity
      supplyIdentity : RecursiveSmallWoodObjectIdentity) : Prop where
  transactionBindsCanonicalStatement :
    transactionIdentity.canonicalStatementBytes = statementBytes
  artifactMatchesClaim : artifactIdentity = claimIdentity
  claimMatchesBatch : claimIdentity = batchIdentity
  batchMatchesTransaction : batchIdentity = transactionIdentity
  transactionMatchesSupply : transactionIdentity = supplyIdentity

theorem cross_object_identity_mismatch_rejects
    {statementBytes : List Byte}
    {artifactIdentity claimIdentity batchIdentity transactionIdentity
      supplyIdentity : RecursiveSmallWoodObjectIdentity}
    (mismatch : artifactIdentity ≠ transactionIdentity) :
    ¬ RecursiveSmallWoodCrossObjectIdentityRefinementAssumption
      statementBytes
      artifactIdentity
      claimIdentity
      batchIdentity
      transactionIdentity
      supplyIdentity := by
  intro binding
  apply mismatch
  exact
    binding.artifactMatchesClaim.trans
      (binding.claimMatchesBatch.trans binding.batchMatchesTransaction)

theorem canonical_statement_bytes_mismatch_rejects
    {statementBytes : List Byte}
    {artifactIdentity claimIdentity batchIdentity transactionIdentity
      supplyIdentity : RecursiveSmallWoodObjectIdentity}
    (mismatch : transactionIdentity.canonicalStatementBytes ≠ statementBytes) :
    ¬ RecursiveSmallWoodCrossObjectIdentityRefinementAssumption
      statementBytes
      artifactIdentity
      claimIdentity
      batchIdentity
      transactionIdentity
      supplyIdentity := by
  intro binding
  exact mismatch binding.transactionBindsCanonicalStatement

structure AcceptedRecursiveSmallWoodCompositionBoundary
    (artifact : ArtifactAdmissionInput)
    (claimMatch : TxValidityClaimMatching.ClaimMatchInput)
    (batchBinding : Hegemon.Consensus.ProvenBatchBinding.BindingInput)
    (artifactIdentity claimIdentity batchIdentity transactionIdentity
      supplyIdentity : RecursiveSmallWoodObjectIdentity)
    (parent next : Nat)
    (step : ClaimedSupplyStep)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : PublicInputBinding.PublicFields)
    (serializedFields : PublicInputBinding.SerializedFields)
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields : ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses : List InputSpendWitness)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop where
  crossObjectIdentityRefinement :
    RecursiveSmallWoodCrossObjectIdentityRefinementAssumption
      statementBytes
      artifactIdentity
      claimIdentity
      batchIdentity
      transactionIdentity
      supplyIdentity
  recursiveArtifactAccepted : artifactAccepts artifact = true
  recursiveArtifactKind : artifact.envelopeKind = ArtifactKind.recursiveBlockV2
  recursiveArtifactStatementCommitmentMatches :
    artifact.statementCommitmentMatches = true
  recursiveArtifactPublicReplayMatches : artifact.publicReplayMatches = true
  directArtifactCannotBypassSemanticReplay :
    evaluateDirectVerifierRejection artifact.envelopeKind =
      some DirectVerifierReject.requiresSemanticReplay
  txValidityClaimMatchesVerifiedArtifact :
    TxValidityClaimMatching.acceptedClaimMatchSurface claimMatch
  recursiveBatchRoute :
    batchBinding.batchMode =
      Hegemon.Consensus.ProvenBatchBinding.BatchMode.recursiveBlock
  recursiveBatchKind :
    batchBinding.proofKind =
      Hegemon.Consensus.ProvenBatchBinding.ArtifactKind.recursiveBlockV2
  recursiveBatchBindingAccepted :
    Hegemon.Consensus.ProvenBatchBinding.acceptsBinding batchBinding = true
  transactionRelation :
    AcceptedTransactionRelation
      wrapper
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots
  supplyConservation :
    CanonicalProductionSupplyConservationCertificate
      parent
      next
      step
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
      slots

theorem accepted_recursive_smallwood_transaction_yields_conditional_composition_boundary
    {artifact : ArtifactAdmissionInput}
    {claimMatch : TxValidityClaimMatching.ClaimMatchInput}
    {batchBinding : Hegemon.Consensus.ProvenBatchBinding.BindingInput}
    {artifactIdentity claimIdentity batchIdentity transactionIdentity
      supplyIdentity : RecursiveSmallWoodObjectIdentity}
    {parent next : Nat}
    {step : ClaimedSupplyStep}
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
    (crossObjectIdentityRefinement :
      RecursiveSmallWoodCrossObjectIdentityRefinementAssumption
        statementBytes
        artifactIdentity
        claimIdentity
        batchIdentity
        transactionIdentity
        supplyIdentity)
    (expectedKind : artifact.expectedKind = ArtifactKind.recursiveBlockV2)
    (artifactAccepted : artifactAccepts artifact = true)
    (claimMatchAccepted :
      TxValidityClaimMatching.claimMatchAccepts claimMatch = true)
    (batchRoute :
      batchBinding.batchMode =
        Hegemon.Consensus.ProvenBatchBinding.BatchMode.recursiveBlock)
    (batchKind :
      batchBinding.proofKind =
        Hegemon.Consensus.ProvenBatchBinding.ArtifactKind.recursiveBlockV2)
    (batchBindingAccepted :
      Hegemon.Consensus.ProvenBatchBinding.acceptsBinding batchBinding = true)
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
    (extraction :
      SmallWoodExactConstraintExtractionAssumption
        wrapper
        shape
        merkleRoot
        spendWitnesses
        inputRows
        outputWitnesses
        outputRows
        balanceWitness
        slots)
    (balancePublicFields :
      BalancePublicFieldFacts publicFields balanceWitness)
    (feeBinding :
      step.fees =
        publicAuthorizedAssetDeltaValue publicFields Transaction.nativeAsset)
    (acceptedSupply : validateClaimedSupplyStep parent step = some next) :
    AcceptedRecursiveSmallWoodCompositionBoundary
      artifact
      claimMatch
      batchBinding
      artifactIdentity
      claimIdentity
      batchIdentity
      transactionIdentity
      supplyIdentity
      parent
      next
      step
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
  have recursiveFacts :=
    accepted_recursive_v2_artifact_still_requires_semantic_replay
      expectedKind
      artifactAccepted
  have artifactBinding :=
    accepted_recursive_artifact_exposes_statement_and_replay_binding
      artifactAccepted
  exact
    {
      crossObjectIdentityRefinement := crossObjectIdentityRefinement,
      recursiveArtifactAccepted := artifactAccepted,
      recursiveArtifactKind := recursiveFacts.left,
      recursiveArtifactStatementCommitmentMatches := artifactBinding.left,
      recursiveArtifactPublicReplayMatches := artifactBinding.right,
      directArtifactCannotBypassSemanticReplay := recursiveFacts.right,
      txValidityClaimMatchesVerifiedArtifact :=
        TxValidityClaimMatching.claimMatchAccepts_implies_exact_surface
          claimMatchAccepted,
      recursiveBatchRoute := batchRoute,
      recursiveBatchKind := batchKind,
      recursiveBatchBindingAccepted := batchBindingAccepted,
      transactionRelation :=
        accepted_proof_with_exact_constraint_extraction_implies_relation
          surface.accepted
          extraction,
      supplyConservation :=
        exact_smallwood_constraints_yield_production_supply_conservation
          surface
          extraction
          balancePublicFields
          feeBinding
          acceptedSupply
    }

end SmallWoodNoCounterfeit
end Transaction
end Hegemon
