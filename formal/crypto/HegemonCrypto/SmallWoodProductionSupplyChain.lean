import Hegemon.Consensus.AcceptedSmallWoodBlockComposition
import HegemonCrypto.SmallWoodCmsExtraction
import HegemonCrypto.SmallWoodProductionAcceptanceClosure

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Accepted proof bytes to accepted block supply

This module composes the active parser/verifier refinement with the deterministic
SmallWood extractor and the ledger's transaction and block relations. The only
ways out are named explicitly:

* a collision in the recorded SHA-512 Merkle database;
* the finite-QROM `NoValidExtraction` event; or
* the separately named Poseidon2 collision-resistance assumption used by note
  commitments.
-/

namespace HegemonCrypto.SmallWood.ProductionSupplyChain

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.CmsExtraction
open HegemonCrypto.SmallWood.LogicalOracle
open HegemonCrypto.SmallWood.NativeDecsReconstruction
open HegemonCrypto.SmallWood.NativeLvcsReconstruction
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionAcceptanceClosure
open HegemonCrypto.SmallWood.ProductionAccumulatedExtraction
open HegemonCrypto.SmallWood.ProductionBcsInstantiation
open HegemonCrypto.SmallWood.ProductionMerkleExtraction
open HegemonCrypto.SmallWood.ProductionTranscriptRefinement
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.RoundByRound.Interactive
open HegemonCrypto.SmallWood.Sha512Xof
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open Hegemon.Consensus.AcceptedSmallWoodBlockComposition

noncomputable section

def acceptedProductionOracle
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database) :
    CommittedOracle :=
  accumulatedCommittedOracle (acceptedTrace accepted)

def acceptedProductionDecsMessage
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database) :
    DecsPolynomialMessage :=
  reconstructNativeDecsMessage
    (productionDecsChallenge rawOracle accepted.transcript)
    accepted.coordinates
    (reconstructNativeProductionRows
      (productionPiopOpening accepted.canonicalOpeningNonce)
      accepted.pcsMessage accepted.coordinates
      accepted.baseRows accepted.maskingRows)
    accepted.nativeDecsHigh

/-- The exact final logical-oracle query represented by one accepted native proof. -/
def acceptedFourthQuery
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database) :
    VerifierQuery statement :=
  .fourth
    { oracle := acceptedProductionOracle accepted
      decsChallenge :=
        productionDecsChallenge rawOracle accepted.transcript
      decsMessage := acceptedProductionDecsMessage accepted
      piopChallenge :=
        productionPiopChallenge rawOracle accepted.transcript statement
      piopMessage := accepted.piopMessage
      piopOpening :=
        productionPiopOpening accepted.canonicalOpeningNonce
      pcsMessage := accepted.pcsMessage }

def acceptedLogicalOutput
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database) :
    LogicalOutput statement :=
  { decsChallenge :=
      productionDecsChallenge rawOracle accepted.transcript
    piopChallenge :=
      productionPiopChallenge rawOracle accepted.transcript statement
    piopOpening :=
      productionPiopOpening accepted.canonicalOpeningNonce
    decsOpening :=
      productionDecsOpening accepted.decsSamplerSucceeds }

/--
The accepted Rust transcript is the good final transition selected by the
logical QROM theorem.
-/
theorem accepted_production_query_reaches_good_state
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database)
    (hashDatabaseCollisionFree : CollisionFree database) :
    semanticState
        (verifierExtension
          (queryPrefix accepted.active (acceptedFourthQuery accepted))
          (queryChallenge accepted.active
            (acceptedFourthQuery accepted)
            (acceptedLogicalOutput accepted))) =
      true := by
  apply (semantic_state_true_iff _).2
  simpa [acceptedFourthQuery, acceptedLogicalOutput, queryPrefix,
    queryChallenge, verifierExtension, SemanticGood,
    acceptedProductionOracle] using
      production_acceptance_implies_fourth_round_good
        accepted hashDatabaseCollisionFree

/--
Outside the explicitly bounded QROM extraction-failure event, the accepted
proof's deterministic committed oracle yields a witness for the exact
production constraint map.
-/
theorem accepted_production_proof_extracts_exact_relation
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database)
    (extractionSucceeds :
      ¬NoValidExtraction accepted.active
        (acceptedFourthQuery accepted)) :
    ∃ witness,
      (statement, witness) ∈ HegemonCrypto.SmallWood.Relation := by
  unfold NoValidExtraction at extractionSucceeds
  have extracted :
      ∃ witness,
        extractedWitnessAtPrefix
            (queryPrefix accepted.active (acceptedFourthQuery accepted)) =
          some witness ∧
        ((queryPrefix accepted.active
            (acceptedFourthQuery accepted)).statement, witness) ∈
          HegemonCrypto.SmallWood.Relation := by
    by_contra missing
    exact extractionSucceeds missing
  obtain ⟨witness, witnessAtPrefix, relation⟩ := extracted
  refine ⟨witness, ?_⟩
  rw [query_prefix_statement accepted.active
    (acceptedFourthQuery accepted)] at relation
  exact relation

theorem accepted_production_proof_extracts_exact_constraints
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database)
    (extractionSucceeds :
      ¬NoValidExtraction accepted.active
        (acceptedFourthQuery accepted)) :
    ∃ witness,
      ProductionSmallWoodSemanticConstraintsSatisfied statement witness := by
  obtain ⟨witness, relation⟩ :=
    accepted_production_proof_extracts_exact_relation
      accepted extractionSucceeds
  exact
    ⟨witness,
      production_smallwood_air_rows_are_implementation_equivalent
        relation.1 relation.2⟩

/--
Per-transaction evidence that the parser-derived crypto object is the same
byte string accepted by consensus and that its bounded extraction event did
not occur.
-/
structure ProductionCryptoTransactionEvidence
    (proof : DeployedSmallWoodProof) : Type where
  canonicalProofBytes : List HegemonCrypto.CanonicalBytes.Byte
  rawOracle : RawOracle
  fallback : ActiveDigest
  database : ProductionHashDatabase
  accepted :
    ProductionVerifierAccepted canonicalProofBytes proof.exactMap
      rawOracle fallback database
  proofBytesExact :
    canonicalProofBytes.map Fin.val = proof.proofBytes
  hashDatabaseCollisionFree : CollisionFree database
  extractionSucceeds :
    ¬NoValidExtraction accepted.active (acceptedFourthQuery accepted)

theorem production_crypto_transaction_evidence_yields_relation
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {proof : DeployedSmallWoodProof}
    (accepted :
      DeployedSmallWoodProofAccepted verifier hashes proof)
    (crypto : ProductionCryptoTransactionEvidence proof) :
    ProductionAcceptedTransactionRelation verifier proof.exactMap
      (productionVerifierPublicValues proof.bound proof.statementFields)
      proof.proofBytes proof.serializedPublicInputBytes
      proof.verifierProfile proof.wrapper :=
  { wrapperAccepted := accepted.canonicalSurface.accepted
    exactProofArtifactAccepted := accepted.exactArtifactAccepted
    constraintMapBound := accepted.constraintMapBound
    canonicalPublicValuesBound := accepted.constraintPublicValuesBound
    exactSemanticConstraints :=
      accepted_production_proof_extracts_exact_constraints
        crypto.accepted crypto.extractionSucceeds }

def DeployedSmallWoodBlockProductionCryptoEvidence
    (codec : ProductionActionCodec DeployedSmallWoodProof)
    (block : AcceptedCanonicalBlock) : Type :=
  forall actions,
    decodeCanonicalActionStream codec block.actionBytes = some actions ->
    forall proof, proof ∈ canonicalTransfers actions ->
      ProductionCryptoTransactionEvidence proof

theorem accepted_deployed_smallwood_block_with_production_crypto_yields_no_counterfeit
    {hashes : ProductionIdentityFunctions}
    {codec : ProductionActionCodec DeployedSmallWoodProof}
    {verifier : ProductionSmallWoodProofVerifier}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    (accepted :
      AcceptedDeployedSmallWoodBlock codec verifier hashes acceptedParent block)
    (crypto :
      DeployedSmallWoodBlockProductionCryptoEvidence codec block)
    (poseidon2HashCollisionResistance :
      DeployedSmallWoodBlockPoseidon2HashCollisionResistance codec block) :
    DeployedNoCounterfeitCriticalPathCertificate
      hashes codec verifier acceptedParent block := by
  apply
    accepted_deployed_smallwood_block_of_transaction_relations_yields_no_counterfeit_critical_path
      accepted
  · intro actions decoded proof membership
    exact production_crypto_transaction_evidence_yields_relation
      (accepted.decodedProofsAccepted actions decoded proof membership)
      (crypto actions decoded proof membership)
  · exact poseidon2HashCollisionResistance

end

end HegemonCrypto.SmallWood.ProductionSupplyChain
