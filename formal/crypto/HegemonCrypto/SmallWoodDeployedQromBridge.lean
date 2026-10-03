import HegemonCrypto.SmallWoodHeterogeneousCmsQrom
import HegemonCrypto.SmallWoodProductionSupplyChain
import HegemonCrypto.KnowledgeSoundnessTarget

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact compiled-acceptance to ideal-QROM composition boundary

This module closes the deterministic composition gaps that can be closed without postulating a
cryptographic reduction:

* a refinement witness is indexed by the exact deployed proof, statement, public inputs, profile,
  wrapper, and compiled verifier acceptance record;
* the modeled proof bytes must equal the exact bytes accepted by production;
* an accepting modeled transcript with no valid extraction deterministically selects the first of
  the four logical-oracle rounds that changes the semantic state from false to true; and
* per-proof failure bounds compose over every transfer in one accepted block by a proved finite
  union bound; and
* a separate statement-indexed product-output ideal oracle supplies one non-unioned CMS theorem
  under a single global query run, while the exact cost and loss of reducing deployed SHA-512 to
  that stronger oracle remain explicit premises.

The remaining deployment boundary is explicit. `CompiledVerifierRefinementObligation` requires
arbitrary successful compiled executions to construct the exact modeled evidence record.
`DeployedSha512QromTransferObligation` is the fixed-statement quantitative reduction, while
`OrderedBlockSharedQromTransferObligation` is the heterogeneous shared-budget reduction and charges
product-output simulation explicitly. No theorem constructs these obligations from finite vectors.
Canonical semantic refinement and Poseidon2 output security stay outside the probability event.
The proof-oracle transcript modeled by this file is the active SHA-512 transcript. The separate
native-consensus event covers the active RFC 7693 BLAKE2b-384 V3 identity/work/rules-manifest
boundary -- including `hegemon.consensus.header-precommit.v3`,
`hegemon.pow.work.blake2b-384.v3\0`, `hegemon.consensus.block-id.v3`, and
`hegemon.consensus.rules-manifest.v3` -- together with commitment binding. Its reduction and loss
remain explicit, unproved inputs here. None of these conditional theorems creates
`SecurityAuthority.deployedEndToEnd` authority.
-/

namespace HegemonCrypto.SmallWood.DeployedQromBridge

open scoped BigOperators

open HegemonCrypto.SecurityAuthority
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsFinitePhaseSystem
open HegemonCrypto.CmsLifting
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.CmsExtraction
open HegemonCrypto.SmallWood.CmsQrom
open HegemonCrypto.SmallWood.HeterogeneousCmsQrom
open HegemonCrypto.SmallWood.LogicalOracle
open HegemonCrypto.SmallWood.ProductionAcceptanceClosure
open HegemonCrypto.SmallWood.ProductionBcsInstantiation
open HegemonCrypto.SmallWood.ProductionMerkleExtraction
open HegemonCrypto.SmallWood.ProductionSupplyChain
open HegemonCrypto.SmallWood.ProductionTranscriptRefinement
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.RoundByRound.Interactive
open HegemonCrypto.SmallWood.Sha512Xof
open Hegemon.Consensus.AcceptedSmallWoodBlockComposition
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

noncomputable section

local instance classicalPropDecidable (proposition : Prop) : Decidable proposition :=
  Classical.propDecidable proposition

/-! ## Exact compiled-verifier refinement obligation -/

/--
One exact refinement witness for one production-accepted proof. The caller-supplied Lean evidence
is indexed by the same production constraint statement, and its canonical byte list must be the
exact byte list accepted by the compiled verifier. This is a target type, not a constructor from a
Rust Boolean.
-/
structure ExactCompiledVerifierRefinementEvidence
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions)
    (statement : Statement)
    (proof : DeployedSmallWoodProof) : Type where
  productionAccepted : DeployedSmallWoodProofAccepted verifier hashes proof
  exactStatement : proof.exactMap = statement
  modeledProofBytes : List HegemonCrypto.CanonicalBytes.Byte
  exactProofBytes : modeledProofBytes.map Fin.val = proof.proofBytes
  rawOracle : RawOracle
  fallback : ActiveDigest
  database : ProductionHashDatabase
  modeledVerifierEvidence :
    CallerSuppliedVerifierEvidence modeledProofBytes statement
      rawOracle fallback database

/--
The exact missing compiler/native refinement theorem. It is deliberately universally quantified
over every production-accepted proof and returns only a `Nonempty` witness, so no implementation
can satisfy it by selecting one fixture or by changing proof bytes after acceptance.
-/
def CompiledVerifierRefinementObligation
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions) : Prop :=
  forall proof,
    DeployedSmallWoodProofAccepted verifier hashes proof ->
      Nonempty
        (ExactCompiledVerifierRefinementEvidence
          verifier hashes proof.exactMap proof)

theorem exact_refinement_binds_production_acceptance_and_proof_bytes
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {proof : DeployedSmallWoodProof}
    (refinement :
      ExactCompiledVerifierRefinementEvidence verifier hashes statement proof) :
    DeployedSmallWoodProofAccepted verifier hashes proof
      ∧ refinement.modeledProofBytes.map Fin.val = proof.proofBytes
      ∧ proof.exactMap = statement := by
  exact
    ⟨refinement.productionAccepted, refinement.exactProofBytes,
      refinement.exactStatement⟩

/-- Choose the exact refinement evidence promised for one production-accepted proof. -/
noncomputable def exactRefinementOfCompiledObligation
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    (obligation : CompiledVerifierRefinementObligation verifier hashes)
    (proof : DeployedSmallWoodProof)
    (accepted : DeployedSmallWoodProofAccepted verifier hashes proof) :
    ExactCompiledVerifierRefinementEvidence
      verifier hashes proof.exactMap proof :=
  Classical.choice (obligation proof accepted)

/--
The native/compiled refinement obligation removes proof-byte substitution for every accepted
execution: it supplies modeled verifier evidence for the exact production statement and exact byte
list. This theorem does not construct the obligation.
-/
theorem compiled_refinement_obligation_supplies_exact_modeled_execution
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    (obligation : CompiledVerifierRefinementObligation verifier hashes)
    (proof : DeployedSmallWoodProof)
    (accepted : DeployedSmallWoodProofAccepted verifier hashes proof) :
    exists (modeledProofBytes : List HegemonCrypto.CanonicalBytes.Byte)
      (rawOracle : RawOracle)
      (fallback : ActiveDigest)
      (database : ProductionHashDatabase),
      modeledProofBytes.map Fin.val = proof.proofBytes
        ∧ Nonempty
            (CallerSuppliedVerifierEvidence modeledProofBytes proof.exactMap
              rawOracle fallback database) := by
  let refinement := exactRefinementOfCompiledObligation obligation proof accepted
  exact
    ⟨refinement.modeledProofBytes, refinement.rawOracle, refinement.fallback,
      refinement.database, refinement.exactProofBytes,
      ⟨refinement.modeledVerifierEvidence⟩⟩

/-- Transport a selected exact refinement to a definitionally fixed statement index. -/
noncomputable def exactRefinementAtStatementOfCompiledObligation
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    (obligation : CompiledVerifierRefinementObligation verifier hashes)
    (proof : DeployedSmallWoodProof)
    (accepted : DeployedSmallWoodProofAccepted verifier hashes proof)
    (exactStatement : proof.exactMap = statement) :
    ExactCompiledVerifierRefinementEvidence verifier hashes statement proof := by
  subst statement
  exact exactRefinementOfCompiledObligation obligation proof accepted

/-! ## The first accepting logical-oracle round -/

def callerEvidenceFirstQuery
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database) :
    VerifierQuery statement :=
  .first (callerEvidenceCommittedOracle accepted)

def callerEvidenceSecondQuery
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database) :
    VerifierQuery statement :=
  .second
    { oracle := callerEvidenceCommittedOracle accepted
      decsChallenge :=
        productionDecsChallenge rawOracle accepted.transcript
      decsMessage := callerEvidenceDecsMessage accepted }

def callerEvidenceThirdQuery
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database) :
    VerifierQuery statement :=
  .third
    { oracle := callerEvidenceCommittedOracle accepted
      decsChallenge :=
        productionDecsChallenge rawOracle accepted.transcript
      decsMessage := callerEvidenceDecsMessage accepted
      piopChallenge :=
        productionPiopChallenge rawOracle accepted.transcript statement
      piopMessage := accepted.piopMessage }

def queryAccepts
    {statement : Statement}
    (active : ActiveStatement statement)
    (query : VerifierQuery statement)
    (output : LogicalOutput statement) : Prop :=
  semanticState
      (verifierExtension
        (queryPrefix active query)
        (queryChallenge active query output)) =
    true

/-- Select the earliest accepting verifier round from the exact modeled transcript. -/
noncomputable def callerEvidenceFirstAcceptingQuery
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database) :
    VerifierQuery statement :=
  let output := callerEvidenceLogicalOutput accepted
  if queryAccepts accepted.active (callerEvidenceFirstQuery accepted) output then
    callerEvidenceFirstQuery accepted
  else if queryAccepts accepted.active (callerEvidenceSecondQuery accepted) output then
    callerEvidenceSecondQuery accepted
  else if queryAccepts accepted.active (callerEvidenceThirdQuery accepted) output then
    callerEvidenceThirdQuery accepted
  else
    callerEvidenceFourthQuery accepted

theorem caller_evidence_first_query_is_doomed
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database) :
    semanticState
        (queryPrefix accepted.active (callerEvidenceFirstQuery accepted)) =
      false := by
  simp [callerEvidenceFirstQuery, queryPrefix, semanticState, SemanticGood]

theorem caller_evidence_first_rejection_dooms_second_prefix
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database)
    (firstRejected :
      semanticState
          (verifierExtension
            (queryPrefix accepted.active (callerEvidenceFirstQuery accepted))
            (queryChallenge accepted.active
              (callerEvidenceFirstQuery accepted)
              (callerEvidenceLogicalOutput accepted))) = false) :
    semanticState
        (queryPrefix accepted.active (callerEvidenceSecondQuery accepted)) =
      false := by
  have extension :
      ProverExtension
        (verifierExtension
          (queryPrefix accepted.active (callerEvidenceFirstQuery accepted))
          (queryChallenge accepted.active
            (callerEvidenceFirstQuery accepted)
            (callerEvidenceLogicalOutput accepted)))
        (queryPrefix accepted.active (callerEvidenceSecondQuery accepted)) := by
    simpa [callerEvidenceSecondQuery, callerEvidenceFirstQuery,
      callerEvidenceLogicalOutput, queryPrefix, queryChallenge,
      verifierExtension] using
      (ProverExtension.decsPolynomials statement accepted.active
        (callerEvidenceCommittedOracle accepted)
        (productionDecsChallenge rawOracle accepted.transcript)
        (callerEvidenceDecsMessage accepted))
  exact semantic_state_survives_prover_message extension firstRejected

theorem caller_evidence_second_rejection_dooms_third_prefix
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database)
    (secondRejected :
      semanticState
          (verifierExtension
            (queryPrefix accepted.active (callerEvidenceSecondQuery accepted))
            (queryChallenge accepted.active
              (callerEvidenceSecondQuery accepted)
              (callerEvidenceLogicalOutput accepted))) = false) :
    semanticState
        (queryPrefix accepted.active (callerEvidenceThirdQuery accepted)) =
      false := by
  have extension :
      ProverExtension
        (verifierExtension
          (queryPrefix accepted.active (callerEvidenceSecondQuery accepted))
          (queryChallenge accepted.active
            (callerEvidenceSecondQuery accepted)
            (callerEvidenceLogicalOutput accepted)))
        (queryPrefix accepted.active (callerEvidenceThirdQuery accepted)) := by
    simpa [callerEvidenceThirdQuery, callerEvidenceSecondQuery,
      callerEvidenceLogicalOutput, queryPrefix, queryChallenge,
      verifierExtension] using
      (ProverExtension.piopPolynomials statement accepted.active
        (callerEvidenceCommittedOracle accepted)
        (productionDecsChallenge rawOracle accepted.transcript)
        (callerEvidenceDecsMessage accepted)
        (productionPiopChallenge rawOracle accepted.transcript statement)
        accepted.piopMessage)
  exact semantic_state_survives_prover_message extension secondRejected

theorem caller_evidence_third_rejection_dooms_fourth_prefix
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database)
    (thirdRejected :
      semanticState
          (verifierExtension
            (queryPrefix accepted.active (callerEvidenceThirdQuery accepted))
            (queryChallenge accepted.active
              (callerEvidenceThirdQuery accepted)
              (callerEvidenceLogicalOutput accepted))) = false) :
    semanticState
        (queryPrefix accepted.active (callerEvidenceFourthQuery accepted)) =
      false := by
  have extension :
      ProverExtension
        (verifierExtension
          (queryPrefix accepted.active (callerEvidenceThirdQuery accepted))
          (queryChallenge accepted.active
            (callerEvidenceThirdQuery accepted)
            (callerEvidenceLogicalOutput accepted)))
        (queryPrefix accepted.active (callerEvidenceFourthQuery accepted)) := by
    simpa [callerEvidenceFourthQuery, callerEvidenceThirdQuery,
      callerEvidenceLogicalOutput, queryPrefix, queryChallenge,
      verifierExtension] using
      (ProverExtension.pcsCombination statement accepted.active
        (callerEvidenceCommittedOracle accepted)
        (productionDecsChallenge rawOracle accepted.transcript)
        (callerEvidenceDecsMessage accepted)
        (productionPiopChallenge rawOracle accepted.transcript statement)
        accepted.piopMessage
        (productionPiopOpening accepted.canonicalOpeningNonce)
        accepted.pcsMessage)
  exact semantic_state_survives_prover_message extension thirdRejected

theorem caller_evidence_extracted_witness_is_round_invariant
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database)
    (query : VerifierQuery statement)
    (queryIsTranscriptRound :
      query = callerEvidenceFirstQuery accepted
        ∨ query = callerEvidenceSecondQuery accepted
        ∨ query = callerEvidenceThirdQuery accepted
        ∨ query = callerEvidenceFourthQuery accepted) :
    extractedWitnessAtPrefix (queryPrefix accepted.active query) =
      extractedWitnessAtPrefix
        (queryPrefix accepted.active (callerEvidenceFourthQuery accepted)) := by
  rcases queryIsTranscriptRound with first | second | third | fourth
  · rw [first]
    rfl
  · rw [second]
    rfl
  · rw [third]
    rfl
  · rw [fourth]

theorem caller_evidence_no_valid_extraction_is_round_invariant
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database)
    (noExtraction :
      NoValidExtraction accepted.active (callerEvidenceFourthQuery accepted))
    (query : VerifierQuery statement)
    (queryIsTranscriptRound :
      query = callerEvidenceFirstQuery accepted
        ∨ query = callerEvidenceSecondQuery accepted
        ∨ query = callerEvidenceThirdQuery accepted
        ∨ query = callerEvidenceFourthQuery accepted) :
    NoValidExtraction accepted.active query := by
  unfold NoValidExtraction at noExtraction ⊢
  intro extracted
  apply noExtraction
  obtain ⟨witness, witnessAtQuery, relation⟩ := extracted
  refine ⟨witness, ?_, ?_⟩
  · rw [← caller_evidence_extracted_witness_is_round_invariant
      accepted query queryIsTranscriptRound]
    exact witnessAtQuery
  · rw [query_prefix_statement accepted.active query] at relation
    rw [query_prefix_statement accepted.active
      (callerEvidenceFourthQuery accepted)]
    exact relation

/--
An exact accepted modeled transcript with collision-free recorded hashes and no valid extraction
always supplies the first false-to-true logical-oracle transition. No probabilistic or hash
instantiation assumption is used in this selection theorem.
-/
theorem caller_evidence_first_accepting_query_is_ideal_failure_claim
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database)
    (hashDatabaseCollisionFree : CollisionFree database)
    (noExtraction :
      NoValidExtraction accepted.active (callerEvidenceFourthQuery accepted)) :
    semanticState
        (queryPrefix accepted.active
          (callerEvidenceFirstAcceptingQuery accepted)) = false
      ∧ queryAccepts accepted.active
          (callerEvidenceFirstAcceptingQuery accepted)
          (callerEvidenceLogicalOutput accepted)
      ∧ NoValidExtraction accepted.active
          (callerEvidenceFirstAcceptingQuery accepted) := by
  let output := callerEvidenceLogicalOutput accepted
  let first := callerEvidenceFirstQuery accepted
  let second := callerEvidenceSecondQuery accepted
  let third := callerEvidenceThirdQuery accepted
  let fourth := callerEvidenceFourthQuery accepted
  have firstDoomed : semanticState (queryPrefix accepted.active first) = false := by
    exact caller_evidence_first_query_is_doomed accepted
  have fourthAccepted : queryAccepts accepted.active fourth output := by
    exact caller_supplied_evidence_with_collision_freedom_reaches_good_state
      accepted hashDatabaseCollisionFree
  by_cases firstAccepted : queryAccepts accepted.active first output
  · have selected : callerEvidenceFirstAcceptingQuery accepted = first := by
      simp [callerEvidenceFirstAcceptingQuery, output, first, firstAccepted]
    rw [selected]
    refine ⟨firstDoomed, firstAccepted, ?_⟩
    exact caller_evidence_no_valid_extraction_is_round_invariant accepted
      noExtraction first (Or.inl rfl)
  · by_cases secondAccepted : queryAccepts accepted.active second output
    · have selected : callerEvidenceFirstAcceptingQuery accepted = second := by
        simp [callerEvidenceFirstAcceptingQuery, output, first, second,
          firstAccepted, secondAccepted]
      rw [selected]
      refine ⟨?_, secondAccepted, ?_⟩
      · exact caller_evidence_first_rejection_dooms_second_prefix accepted
          (Bool.eq_false_of_not_eq_true firstAccepted)
      · exact caller_evidence_no_valid_extraction_is_round_invariant accepted
          noExtraction second (Or.inr (Or.inl rfl))
    · by_cases thirdAccepted : queryAccepts accepted.active third output
      · have selected : callerEvidenceFirstAcceptingQuery accepted = third := by
          simp [callerEvidenceFirstAcceptingQuery, output, first, second, third,
            firstAccepted, secondAccepted, thirdAccepted]
        rw [selected]
        refine ⟨?_, thirdAccepted, ?_⟩
        · exact caller_evidence_second_rejection_dooms_third_prefix accepted
            (Bool.eq_false_of_not_eq_true secondAccepted)
        · exact caller_evidence_no_valid_extraction_is_round_invariant accepted
            noExtraction third (Or.inr (Or.inr (Or.inl rfl)))
      · have selected : callerEvidenceFirstAcceptingQuery accepted = fourth := by
          simp [callerEvidenceFirstAcceptingQuery, output, first, second, third,
            fourth, firstAccepted, secondAccepted, thirdAccepted]
        rw [selected]
        refine ⟨?_, fourthAccepted, ?_⟩
        · exact caller_evidence_third_rejection_dooms_fourth_prefix accepted
            (Bool.eq_false_of_not_eq_true thirdAccepted)
        · exact caller_evidence_no_valid_extraction_is_round_invariant accepted
            noExtraction fourth (Or.inr (Or.inr (Or.inr rfl)))

/-! ## Exact compiled-failure selector and ideal-QROM theorem -/

/--
Refinement data for an adversary's enabled compiled failure workspaces. Disabled workspaces need
only harmless default logical values because selector obligations are conditional on `enabled`.
-/
structure CompiledFailureSelectorRefinement
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions)
    (statement : Statement)
    (active : ActiveStatement statement)
    (Workspace : Type*) where
  enabled : Workspace -> Prop
  proof : Workspace -> DeployedSmallWoodProof
  exactRefinement : forall workspace,
    ExactCompiledVerifierRefinementEvidence
      verifier hashes statement (proof workspace)
  hashDatabaseCollisionFree : forall workspace,
    (enabledEvidence : enabled workspace) ->
      CollisionFree (exactRefinement workspace).database
  noValidExtraction : forall workspace,
    (enabledEvidence : enabled workspace) ->
      NoValidExtraction
        (exactRefinement workspace).modeledVerifierEvidence.active
        (callerEvidenceFourthQuery
          (exactRefinement workspace).modeledVerifierEvidence)

/--
Construct the selector refinement from the universal native/compiled refinement obligation and
only the collision/no-extraction conditions for enabled failure workspaces. This is the explicit
consumer of `CompiledVerifierRefinementObligation`; it does not manufacture that obligation.
-/
noncomputable def CompiledFailureSelectorRefinement.ofCompiledObligation
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (obligation : CompiledVerifierRefinementObligation verifier hashes)
    (enabled : Workspace -> Prop)
    (proof : Workspace -> DeployedSmallWoodProof)
    (accepted : forall workspace,
      DeployedSmallWoodProofAccepted verifier hashes (proof workspace))
    (exactStatement : forall workspace, (proof workspace).exactMap = statement)
    (hashDatabaseCollisionFree : forall workspace,
      (enabledEvidence : enabled workspace) ->
        CollisionFree
          (exactRefinementAtStatementOfCompiledObligation obligation
            (proof workspace) (accepted workspace)
            (exactStatement workspace)).database)
    (noValidExtraction : forall workspace,
      (enabledEvidence : enabled workspace) ->
        NoValidExtraction
          (exactRefinementAtStatementOfCompiledObligation obligation
            (proof workspace) (accepted workspace)
            (exactStatement workspace)).modeledVerifierEvidence.active
          (callerEvidenceFourthQuery
            (exactRefinementAtStatementOfCompiledObligation obligation
              (proof workspace) (accepted workspace)
              (exactStatement workspace)).modeledVerifierEvidence)) :
    CompiledFailureSelectorRefinement
      verifier hashes statement active Workspace where
  enabled := enabled
  proof := proof
  exactRefinement := fun workspace =>
    exactRefinementAtStatementOfCompiledObligation obligation
      (proof workspace) (accepted workspace) (exactStatement workspace)
  hashDatabaseCollisionFree := hashDatabaseCollisionFree
  noValidExtraction := noValidExtraction

noncomputable def compiledFailureQuery
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (refinement :
      CompiledFailureSelectorRefinement
        verifier hashes statement active Workspace)
    (workspace : Workspace) : VerifierQuery statement :=
  callerEvidenceFirstAcceptingQuery
    (refinement.exactRefinement workspace).modeledVerifierEvidence

noncomputable def compiledFailureOutput
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (refinement :
      CompiledFailureSelectorRefinement
        verifier hashes statement active Workspace)
    (workspace : Workspace) : LogicalOutput statement :=
  callerEvidenceLogicalOutput
    (refinement.exactRefinement workspace).modeledVerifierEvidence

noncomputable def compiledFailureSelector
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (refinement :
      CompiledFailureSelectorRefinement
        verifier hashes statement active Workspace) :
    IdealLogicalFailureSelector active Workspace where
  enabled := refinement.enabled
  query := compiledFailureQuery refinement
  output := compiledFailureOutput refinement
  doomed := by
    intro workspace enabledEvidence
    simp only [compiledFailureQuery]
    let exact := refinement.exactRefinement workspace
    let accepted := exact.modeledVerifierEvidence
    have activeEqual : active = accepted.active := Subsingleton.elim _ _
    have claim :=
      (caller_evidence_first_accepting_query_is_ideal_failure_claim accepted
        (refinement.hashDatabaseCollisionFree workspace enabledEvidence)
        (refinement.noValidExtraction workspace enabledEvidence)).1
    simpa only [activeEqual] using claim
  accepted := by
    intro workspace enabledEvidence
    simp only [compiledFailureQuery, compiledFailureOutput]
    let exact := refinement.exactRefinement workspace
    let accepted := exact.modeledVerifierEvidence
    have activeEqual : active = accepted.active := Subsingleton.elim _ _
    have claim :=
      (caller_evidence_first_accepting_query_is_ideal_failure_claim accepted
        (refinement.hashDatabaseCollisionFree workspace enabledEvidence)
        (refinement.noValidExtraction workspace enabledEvidence)).2.1
    change queryAccepts active
      (callerEvidenceFirstAcceptingQuery accepted)
      (callerEvidenceLogicalOutput accepted)
    simpa only [activeEqual] using claim
  noValidExtraction := by
    intro workspace enabledEvidence
    simp only [compiledFailureQuery]
    let exact := refinement.exactRefinement workspace
    let accepted := exact.modeledVerifierEvidence
    have activeEqual : active = accepted.active := Subsingleton.elim _ _
    have claim :=
      (caller_evidence_first_accepting_query_is_ideal_failure_claim accepted
        (refinement.hashDatabaseCollisionFree workspace enabledEvidence)
        (refinement.noValidExtraction workspace enabledEvidence)).2.2
    simpa only [activeEqual] using claim

theorem compiled_failure_selector_binds_exact_production_acceptance_and_bytes
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (refinement :
      CompiledFailureSelectorRefinement
        verifier hashes statement active Workspace)
    (workspace : Workspace)
    (_enabledEvidence : refinement.enabled workspace) :
    DeployedSmallWoodProofAccepted verifier hashes (refinement.proof workspace)
      ∧ (refinement.exactRefinement workspace).modeledProofBytes.map
          Fin.val = (refinement.proof workspace).proofBytes
      ∧ (refinement.proof workspace).exactMap = statement := by
  exact exact_refinement_binds_production_acceptance_and_proof_bytes
    (refinement.exactRefinement workspace)

/-! ## Exact heterogeneous-statement selector target -/

/--
The dependent selector needed for a genuine adaptive multi-theorem block proof. Each workspace may
select a different statement index, query type, and local output type. This local-output view is
useful for exact production indexing, but the shared ideal-QROM theorem below requires an explicit
common product output whose selected coordinate is exactly this local output.
-/
structure HeterogeneousIdealLogicalFailureSelector
    (Index : Type*)
    (statement : Index -> Statement)
    (active : (index : Index) -> ActiveStatement (statement index))
    (Workspace : Type*) where
  enabled : Workspace -> Prop
  selectedIndex : Workspace -> Index
  query : (workspace : Workspace) ->
    VerifierQuery (statement (selectedIndex workspace))
  output : (workspace : Workspace) ->
    LogicalOutput (statement (selectedIndex workspace))
  doomed : forall workspace, enabled workspace ->
    semanticState
        (queryPrefix (active (selectedIndex workspace)) (query workspace)) =
      false
  accepted : forall workspace, enabled workspace ->
    semanticState
        (verifierExtension
          (queryPrefix (active (selectedIndex workspace)) (query workspace))
          (queryChallenge (active (selectedIndex workspace))
            (query workspace) (output workspace))) =
      true
  noValidExtraction : forall workspace, enabled workspace ->
    NoValidExtraction (active (selectedIndex workspace)) (query workspace)

/-- Exact compiled evidence for a workspace-selected member of a heterogeneous proof family. -/
structure HeterogeneousCompiledFailureSelectorRefinement
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions)
    (Index Workspace : Type*) where
  enabled : Workspace -> Prop
  selectedIndex : Workspace -> Index
  proof : Index -> DeployedSmallWoodProof
  active : (index : Index) -> ActiveStatement (proof index).exactMap
  exactRefinement : forall workspace,
    ExactCompiledVerifierRefinementEvidence verifier hashes
      (proof (selectedIndex workspace)).exactMap
      (proof (selectedIndex workspace))
  hashDatabaseCollisionFree : forall workspace,
    enabled workspace -> CollisionFree (exactRefinement workspace).database
  noValidExtraction : forall workspace,
    enabled workspace ->
      NoValidExtraction
        (exactRefinement workspace).modeledVerifierEvidence.active
        (callerEvidenceFourthQuery
          (exactRefinement workspace).modeledVerifierEvidence)

/--
Deterministically build the heterogeneous first-accepting selector. This closes statement and byte
indexing for ordered proof families. It does not by itself supply the common product output needed
by the shared-query CMS theorem.
-/
noncomputable def heterogeneousCompiledFailureSelector
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {Index Workspace : Type*}
    (refinement :
      HeterogeneousCompiledFailureSelectorRefinement
        verifier hashes Index Workspace) :
    HeterogeneousIdealLogicalFailureSelector Index
      (fun index => (refinement.proof index).exactMap)
      refinement.active Workspace where
  enabled := refinement.enabled
  selectedIndex := refinement.selectedIndex
  query := fun workspace =>
    callerEvidenceFirstAcceptingQuery
      (refinement.exactRefinement workspace).modeledVerifierEvidence
  output := fun workspace =>
    callerEvidenceLogicalOutput
      (refinement.exactRefinement workspace).modeledVerifierEvidence
  doomed := by
    intro workspace enabledEvidence
    let accepted :=
      (refinement.exactRefinement workspace).modeledVerifierEvidence
    have activeEqual :
        refinement.active (refinement.selectedIndex workspace) = accepted.active :=
      Subsingleton.elim _ _
    have claim :=
      (caller_evidence_first_accepting_query_is_ideal_failure_claim accepted
        (refinement.hashDatabaseCollisionFree workspace enabledEvidence)
        (refinement.noValidExtraction workspace enabledEvidence)).1
    simpa only [activeEqual] using claim
  accepted := by
    intro workspace enabledEvidence
    let accepted :=
      (refinement.exactRefinement workspace).modeledVerifierEvidence
    have activeEqual :
        refinement.active (refinement.selectedIndex workspace) = accepted.active :=
      Subsingleton.elim _ _
    have claim :=
      (caller_evidence_first_accepting_query_is_ideal_failure_claim accepted
        (refinement.hashDatabaseCollisionFree workspace enabledEvidence)
        (refinement.noValidExtraction workspace enabledEvidence)).2.1
    change queryAccepts
      (refinement.active (refinement.selectedIndex workspace))
      (callerEvidenceFirstAcceptingQuery accepted)
      (callerEvidenceLogicalOutput accepted)
    simpa only [activeEqual] using claim
  noValidExtraction := by
    intro workspace enabledEvidence
    let accepted :=
      (refinement.exactRefinement workspace).modeledVerifierEvidence
    have activeEqual :
        refinement.active (refinement.selectedIndex workspace) = accepted.active :=
      Subsingleton.elim _ _
    have claim :=
      (caller_evidence_first_accepting_query_is_ideal_failure_claim accepted
        (refinement.hashDatabaseCollisionFree workspace enabledEvidence)
        (refinement.noValidExtraction workspace enabledEvidence)).2.2
    simpa only [activeEqual] using claim

theorem heterogeneous_compiled_failure_selector_binds_selected_production_proof
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {Index Workspace : Type*}
    (refinement :
      HeterogeneousCompiledFailureSelectorRefinement
        verifier hashes Index Workspace)
    (workspace : Workspace) :
    let index := refinement.selectedIndex workspace
    let exact := refinement.exactRefinement workspace
    DeployedSmallWoodProofAccepted verifier hashes (refinement.proof index)
      ∧ exact.modeledProofBytes.map Fin.val = (refinement.proof index).proofBytes := by
  exact ⟨(refinement.exactRefinement workspace).productionAccepted,
    (refinement.exactRefinement workspace).exactProofBytes⟩

/--
Block-specialized heterogeneous refinement. The proof family is definitionally the ordered
`canonicalTransfers` list, so a future shared-query theorem cannot substitute an unrelated proof.
-/
structure OrderedBlockCompiledFailureSelectorRefinement
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions)
    (actions : List (CanonicalAction DeployedSmallWoodProof))
    (Workspace : Type*) where
  enabled : Workspace -> Prop
  selectedIndex : Workspace -> Fin (canonicalTransfers actions).length
  active : (index : Fin (canonicalTransfers actions).length) ->
    ActiveStatement ((canonicalTransfers actions).get index).exactMap
  exactRefinement : forall workspace,
    ExactCompiledVerifierRefinementEvidence verifier hashes
      ((canonicalTransfers actions).get (selectedIndex workspace)).exactMap
      ((canonicalTransfers actions).get (selectedIndex workspace))
  hashDatabaseCollisionFree : forall workspace,
    enabled workspace -> CollisionFree (exactRefinement workspace).database
  noValidExtraction : forall workspace,
    enabled workspace ->
      NoValidExtraction
        (exactRefinement workspace).modeledVerifierEvidence.active
        (callerEvidenceFourthQuery
          (exactRefinement workspace).modeledVerifierEvidence)

/--
Select exact compiled-refinement evidence for one canonical transfer of an actually accepted
decoded block. This is the direct bridge from block production acceptance to the universal native
compiled-verifier refinement obligation.
-/
noncomputable def acceptedBlockExactRefinementAtIndex
    {codec : ProductionActionCodec DeployedSmallWoodProof}
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    (compiled : CompiledVerifierRefinementObligation verifier hashes)
    (acceptedBlock :
      AcceptedDeployedSmallWoodBlock codec verifier hashes acceptedParent block)
    (decoded : decodeCanonicalActionStream codec block.actionBytes = some actions)
    (index : Fin (canonicalTransfers actions).length) :
    ExactCompiledVerifierRefinementEvidence verifier hashes
      ((canonicalTransfers actions).get index).exactMap
      ((canonicalTransfers actions).get index) :=
  exactRefinementOfCompiledObligation compiled
    ((canonicalTransfers actions).get index)
    (acceptedBlock.decodedProofsAccepted actions decoded
      ((canonicalTransfers actions).get index)
      (List.get_mem _ index))

theorem accepted_block_exact_refinement_at_index_binds_acceptance_and_bytes
    {codec : ProductionActionCodec DeployedSmallWoodProof}
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    (compiled : CompiledVerifierRefinementObligation verifier hashes)
    (acceptedBlock :
      AcceptedDeployedSmallWoodBlock codec verifier hashes acceptedParent block)
    (decoded : decodeCanonicalActionStream codec block.actionBytes = some actions)
    (index : Fin (canonicalTransfers actions).length) :
    let exact :=
      acceptedBlockExactRefinementAtIndex compiled acceptedBlock decoded index
    DeployedSmallWoodProofAccepted verifier hashes
        ((canonicalTransfers actions).get index)
      ∧ exact.modeledProofBytes.map Fin.val =
          ((canonicalTransfers actions).get index).proofBytes
      ∧ ((canonicalTransfers actions).get index).exactMap =
          ((canonicalTransfers actions).get index).exactMap := by
  exact exact_refinement_binds_production_acceptance_and_proof_bytes
    (acceptedBlockExactRefinementAtIndex compiled acceptedBlock decoded index)

/--
Construct the ordered exact selector refinement from an accepted block plus the still-unproved
universal compiled-verifier refinement. Collision freedom and no-extraction are event premises;
neither is manufactured from acceptance.
-/
noncomputable def OrderedBlockCompiledFailureSelectorRefinement.ofAcceptedBlockAndCompiledObligation
    {codec : ProductionActionCodec DeployedSmallWoodProof}
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    {Workspace : Type*}
    (compiled : CompiledVerifierRefinementObligation verifier hashes)
    (acceptedBlock :
      AcceptedDeployedSmallWoodBlock codec verifier hashes acceptedParent block)
    (decoded : decodeCanonicalActionStream codec block.actionBytes = some actions)
    (enabled : Workspace -> Prop)
    (selectedIndex : Workspace -> Fin (canonicalTransfers actions).length)
    (active : (index : Fin (canonicalTransfers actions).length) ->
      ActiveStatement ((canonicalTransfers actions).get index).exactMap)
    (hashDatabaseCollisionFree : forall workspace,
      enabled workspace ->
        CollisionFree
          (acceptedBlockExactRefinementAtIndex compiled acceptedBlock decoded
            (selectedIndex workspace)).database)
    (noValidExtraction : forall workspace,
      enabled workspace ->
        NoValidExtraction
          (acceptedBlockExactRefinementAtIndex compiled acceptedBlock decoded
            (selectedIndex workspace)).modeledVerifierEvidence.active
          (callerEvidenceFourthQuery
            (acceptedBlockExactRefinementAtIndex compiled acceptedBlock decoded
              (selectedIndex workspace)).modeledVerifierEvidence)) :
    OrderedBlockCompiledFailureSelectorRefinement
      verifier hashes actions Workspace where
  enabled := enabled
  selectedIndex := selectedIndex
  active := active
  exactRefinement := fun workspace =>
    acceptedBlockExactRefinementAtIndex compiled acceptedBlock decoded
      (selectedIndex workspace)
  hashDatabaseCollisionFree := hashDatabaseCollisionFree
  noValidExtraction := noValidExtraction

def OrderedBlockCompiledFailureSelectorRefinement.toHeterogeneous
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    {Workspace : Type*}
    (refinement :
      OrderedBlockCompiledFailureSelectorRefinement
        verifier hashes actions Workspace) :
    HeterogeneousCompiledFailureSelectorRefinement verifier hashes
      (Fin (canonicalTransfers actions).length) Workspace where
  enabled := refinement.enabled
  selectedIndex := refinement.selectedIndex
  proof := fun index => (canonicalTransfers actions).get index
  active := refinement.active
  exactRefinement := refinement.exactRefinement
  hashDatabaseCollisionFree := refinement.hashDatabaseCollisionFree
  noValidExtraction := refinement.noValidExtraction

noncomputable def orderedBlockHeterogeneousFailureSelector
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    {Workspace : Type*}
    (refinement :
      OrderedBlockCompiledFailureSelectorRefinement
        verifier hashes actions Workspace) :
    HeterogeneousIdealLogicalFailureSelector
      (Fin (canonicalTransfers actions).length)
      (fun index => ((canonicalTransfers actions).get index).exactMap)
      refinement.active Workspace :=
  heterogeneousCompiledFailureSelector refinement.toHeterogeneous

/-! ## Exact ordered-block selector for the shared heterogeneous oracle -/

/--
The additional deterministic input needed by the shared ideal theorem. `indexedOutput` is one
output of the common product oracle, and `selectedCoordinateExact` prevents replacing the logical
answer read from the exact production proof with an unrelated coordinate. Coordinates for other
statements remain part of the stronger ideal experiment and must be simulated by the deployed
standard-to-ideal reduction below.
-/
structure OrderedBlockSharedIdealFailureSelectorRefinement
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions)
    (actions : List (CanonicalAction DeployedSmallWoodProof))
    (Workspace : Type*) where
  ordered : OrderedBlockCompiledFailureSelectorRefinement
    verifier hashes actions Workspace
  indexedOutput : Workspace ->
    IndexedLogicalOutput
      (Fin (canonicalTransfers actions).length)
      (fun index => ((canonicalTransfers actions).get index).exactMap)
  selectedCoordinateExact : forall workspace,
    indexedLogicalOutputCoordinate
        (indexedOutput workspace)
        (ordered.selectedIndex workspace) =
      callerEvidenceLogicalOutput
        (ordered.exactRefinement workspace).modeledVerifierEvidence

/--
Construct the exact heterogeneous ideal failure selector. The selected statement, query, and
logical response are all tied to the same ordered production proof and exact accepted proof bytes.
-/
noncomputable def orderedBlockSharedIdealFailureSelector
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    {Workspace : Type*}
    (refinement :
      OrderedBlockSharedIdealFailureSelectorRefinement
        verifier hashes actions Workspace) :
    IndexedIdealFailureSelector refinement.ordered.active Workspace where
  enabled := refinement.ordered.enabled
  selectedIndex := refinement.ordered.selectedIndex
  query := fun workspace =>
    callerEvidenceFirstAcceptingQuery
      (refinement.ordered.exactRefinement workspace).modeledVerifierEvidence
  output := refinement.indexedOutput
  doomed := by
    intro workspace enabledEvidence
    let accepted :=
      (refinement.ordered.exactRefinement workspace).modeledVerifierEvidence
    have activeEqual :
        refinement.ordered.active (refinement.ordered.selectedIndex workspace) =
          accepted.active :=
      Subsingleton.elim _ _
    have claim :=
      (caller_evidence_first_accepting_query_is_ideal_failure_claim accepted
        (refinement.ordered.hashDatabaseCollisionFree workspace enabledEvidence)
        (refinement.ordered.noValidExtraction workspace enabledEvidence)).1
    simpa only [activeEqual] using claim
  accepted := by
    intro workspace enabledEvidence
    let accepted :=
      (refinement.ordered.exactRefinement workspace).modeledVerifierEvidence
    have activeEqual :
        refinement.ordered.active (refinement.ordered.selectedIndex workspace) =
          accepted.active :=
      Subsingleton.elim _ _
    have claim :=
      (caller_evidence_first_accepting_query_is_ideal_failure_claim accepted
        (refinement.ordered.hashDatabaseCollisionFree workspace enabledEvidence)
        (refinement.ordered.noValidExtraction workspace enabledEvidence)).2.1
    change queryAccepts
      (refinement.ordered.active (refinement.ordered.selectedIndex workspace))
      (callerEvidenceFirstAcceptingQuery accepted)
      (indexedLogicalOutputCoordinate
        (refinement.indexedOutput workspace)
        (refinement.ordered.selectedIndex workspace))
    rw [refinement.selectedCoordinateExact workspace]
    simpa only [activeEqual] using claim
  noValidExtraction := by
    intro workspace enabledEvidence
    let accepted :=
      (refinement.ordered.exactRefinement workspace).modeledVerifierEvidence
    have activeEqual :
        refinement.ordered.active (refinement.ordered.selectedIndex workspace) =
          accepted.active :=
      Subsingleton.elim _ _
    have claim :=
      (caller_evidence_first_accepting_query_is_ideal_failure_claim accepted
        (refinement.ordered.hashDatabaseCollisionFree workspace enabledEvidence)
        (refinement.ordered.noValidExtraction workspace enabledEvidence)).2.2
    simpa only [activeEqual] using claim

theorem ordered_block_shared_selector_binds_selected_production_proof
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    {Workspace : Type*}
    (refinement :
      OrderedBlockSharedIdealFailureSelectorRefinement
        verifier hashes actions Workspace)
    (workspace : Workspace) :
    let index := refinement.ordered.selectedIndex workspace
    let exact := refinement.ordered.exactRefinement workspace
    DeployedSmallWoodProofAccepted verifier hashes
        ((canonicalTransfers actions).get index)
      ∧ exact.modeledProofBytes.map Fin.val =
          ((canonicalTransfers actions).get index).proofBytes := by
  exact
    ⟨(refinement.ordered.exactRefinement workspace).productionAccepted,
      (refinement.ordered.exactRefinement workspace).exactProofBytes⟩

/-! ## Probability interfaces -/

/-- Minimal real-valued probability interface needed for event reduction and finite union bounds. -/
structure RealEventProbability (Omega : Type*) where
  probability : Set Omega -> ℝ
  empty : probability ∅ = 0
  nonnegative : forall event, 0 ≤ probability event
  atMostOne : forall event, probability event ≤ 1
  monotone : forall {left right}, left ⊆ right -> probability left ≤ probability right
  union_le : forall left right,
    probability (left ∪ right) ≤ probability left + probability right

/--
The exact compiled-artifact Boolean used in the standard-QROM extraction event. The proof object
fixes the public-input bytes, verifier profile, wrapper, and proof bytes; the first conjunct prevents
substitution of a different production constraint statement.
-/
def deployedCompiledArtifactVerifier
    (verifier : ProductionSmallWoodProofVerifier) :
    Statement -> DeployedSmallWoodProof -> Bool :=
  fun statement proof =>
    decide (proof.exactMap = statement) &&
      verifier.accepts proof.proofBytes proof.serializedPublicInputBytes
        proof.verifierProfile proof.wrapper

theorem deployed_compiled_artifact_verifier_accepts_iff
    (verifier : ProductionSmallWoodProofVerifier)
    (statement : Statement)
    (proof : DeployedSmallWoodProof) :
    deployedCompiledArtifactVerifier verifier statement proof = true ↔
      proof.exactMap = statement ∧
        verifier.accepts proof.proofBytes proof.serializedPublicInputBytes
          proof.verifierProfile proof.wrapper = true := by
  simp [deployedCompiledArtifactVerifier]

theorem production_acceptance_implies_exact_compiled_artifact_boolean
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {proof : DeployedSmallWoodProof}
    (accepted : DeployedSmallWoodProofAccepted verifier hashes proof) :
    deployedCompiledArtifactVerifier verifier proof.exactMap proof = true := by
  rw [deployed_compiled_artifact_verifier_accepts_iff]
  exact ⟨rfl, accepted.exactArtifactAccepted⟩

/-- The standard-game trial determined by one exact modeled production execution. -/
def exactCompiledExtractionTrial
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {proof : DeployedSmallWoodProof}
    (refinement :
      ExactCompiledVerifierRefinementEvidence verifier hashes statement proof) :
    ExtractionTrial DeployedSmallWoodProof :=
  { statement := statement
    proof := proof
    extractedWitness :=
      extractedWitnessAtPrefix
        (queryPrefix refinement.modeledVerifierEvidence.active
          (callerEvidenceFourthQuery refinement.modeledVerifierEvidence)) }

/--
Exact production acceptance plus modeled no-extraction supplies the standard-game
`ExtractionFailure` predicate for the same proof bytes, public inputs, profile, wrapper, and
constraint statement. This is a deterministic event bridge, not a probability reduction.
-/
theorem exact_compiled_no_extraction_is_standard_game_failure
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {proof : DeployedSmallWoodProof}
    (refinement :
      ExactCompiledVerifierRefinementEvidence verifier hashes statement proof)
    (noExtraction :
      NoValidExtraction refinement.modeledVerifierEvidence.active
        (callerEvidenceFourthQuery refinement.modeledVerifierEvidence)) :
    ExtractionFailure (deployedCompiledArtifactVerifier verifier)
      (exactCompiledExtractionTrial refinement) := by
  constructor
  · rw [deployed_compiled_artifact_verifier_accepts_iff]
    exact ⟨refinement.exactStatement, refinement.productionAccepted.exactArtifactAccepted⟩
  · intro extracted
    apply noExtraction
    obtain ⟨witness, witnessExact, relation⟩ := extracted
    refine ⟨witness, witnessExact, ?_⟩
    rw [query_prefix_statement refinement.modeledVerifierEvidence.active
      (callerEvidenceFourthQuery refinement.modeledVerifierEvidence)]
    exact relation

/-!
The quantitative deployment boundary is deliberately split into three inequalities. A review must
reduce the probability of the fixed deployed accepted-without-witness event to commitment/hash
failure plus the fixed standard-QROM game event, then prove the standard-to-ideal QROM transfer.
The event, game, exact target proof, and query counts are parameters rather than caller-selected
probability fields, preventing a vacuous all-zero inhabitant.
-/
structure DeployedSha512QromTransferObligation
    {Omega Adversary : Type*}
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {active : ActiveStatement statement}
    {Phase Workspace : Type*}
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (measure : RealEventProbability Omega)
    (deployedAcceptedWithoutWitnessEvent : Set Omega)
    (commitmentOrHashFailureEvent : Set Omega)
    (targetProof : DeployedSmallWoodProof)
    (standardGame : AdaptiveOracleGame Adversary DeployedSmallWoodProof)
    (adversary : Adversary)
    (refinement :
      CompiledFailureSelectorRefinement
        verifier hashes statement active Workspace)
    (completePhaseSystem : CompletePhaseSystem (LogicalOutput statement) Phase)
    (steps : List (DatabaseIndependentContraction
      (Input := VerifierQuery statement)
      (Output := LogicalOutput statement)
      (Phase := Phase)
      (Workspace := Workspace)))
    (initialRegisters :
      RegisterBasis
        (Input := VerifierQuery statement)
        (Phase := Phase)
        (Workspace := Workspace) -> ℂ) where
  standardOracleModelExact : standardGame.model = .standardQrom
  standardQueryBudget : QueryBudget
  standardQuantumQueriesWithinBudget :
    standardGame.quantumHashQueries adversary ≤
      standardQueryBudget.quantumHashQueries
  priorProofInteractionsWithinBudget :
    standardGame.priorProofInteractions adversary ≤
      standardQueryBudget.priorProofInteractions
  logicalQueriesWithinBudget : steps.length ≤ standardQueryBudget.quantumHashQueries
  enabledWorkspacesUseTargetProof : forall workspace,
    refinement.enabled workspace -> refinement.proof workspace = targetProof
  commitmentOrHashFailureBound : ℝ
  sha512StandardToIdealLoss : QueryBudget -> ℝ
  commitmentBoundNonnegative : 0 ≤ commitmentOrHashFailureBound
  instantiationLossNonnegative : 0 ≤ sha512StandardToIdealLoss standardQueryBudget
  deployedToStandardFailureReduction :
    measure.probability deployedAcceptedWithoutWitnessEvent ≤
      measure.probability commitmentOrHashFailureEvent +
        standardGame.eventProbability adversary
          (ExtractionFailure (deployedCompiledArtifactVerifier verifier))
  commitmentOrHashFailureBounded :
    measure.probability commitmentOrHashFailureEvent ≤ commitmentOrHashFailureBound
  standardSha512ToIdealLogical :
    standardGame.eventProbability adversary
        (ExtractionFailure (deployedCompiledArtifactVerifier verifier)) ≤
      normSquared
          (workspaceEventProjection
            (IdealLogicalFailureEvent (compiledFailureSelector refinement))
            (totalOracleFamilyState
              (oracleFamilyRun completePhaseSystem.system steps
                (fun _oracle => initialRegisters))))
        + sha512StandardToIdealLoss standardQueryBudget

/--
Conditional deployed failure bound. The ideal term is kernel-proved; the two named deployment
losses remain exactly the fields that a SHA-512/QROM reduction and hash-binding analysis must fill.
-/
theorem deployed_compiled_acceptance_failure_probability_le_ideal_qrom_plus_explicit_losses
    {Omega Adversary : Type*}
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {active : ActiveStatement statement}
    {Phase Workspace : Type*}
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (measure : RealEventProbability Omega)
    (deployedAcceptedWithoutWitnessEvent : Set Omega)
    (commitmentOrHashFailureEvent : Set Omega)
    (targetProof : DeployedSmallWoodProof)
    (standardGame : AdaptiveOracleGame Adversary DeployedSmallWoodProof)
    (adversary : Adversary)
    (refinement :
      CompiledFailureSelectorRefinement
        verifier hashes statement active Workspace)
    (completePhaseSystem : CompletePhaseSystem (LogicalOutput statement) Phase)
    (steps : List (DatabaseIndependentContraction
      (Input := VerifierQuery statement)
      (Output := LogicalOutput statement)
      (Phase := Phase)
      (Workspace := Workspace)))
    (initialRegisters :
      RegisterBasis
        (Input := VerifierQuery statement)
        (Phase := Phase)
        (Workspace := Workspace) -> ℂ)
    (initialSubnormalized :
      Subnormalized
        (partialRandomOracleState
          (Output := LogicalOutput statement) ∅ initialRegisters))
    (transfer :
      DeployedSha512QromTransferObligation measure deployedAcceptedWithoutWitnessEvent
        commitmentOrHashFailureEvent targetProof standardGame adversary refinement
        completePhaseSystem steps initialRegisters) :
    measure.probability deployedAcceptedWithoutWitnessEvent ≤
      idealLogicalQromFailureBound statement steps.length
        + transfer.commitmentOrHashFailureBound
        + transfer.sha512StandardToIdealLoss transfer.standardQueryBudget := by
  have idealBound :=
    (ideal_logical_qrom_accepts_and_no_valid_witness_probability_le
      active completePhaseSystem steps initialRegisters initialSubnormalized
      (compiledFailureSelector refinement)).holds
  linarith [transfer.deployedToStandardFailureReduction,
    transfer.commitmentOrHashFailureBounded,
    transfer.standardSha512ToIdealLogical]

/-! ## One shared-query deployed block boundary -/

/--
The compiled verifier for a proof selected by its canonical ordered-block index. The statement is
still checked against the selected proof's exact production constraint map.
-/
def deployedOrderedBlockArtifactVerifier
    (verifier : ProductionSmallWoodProofVerifier)
    (actions : List (CanonicalAction DeployedSmallWoodProof)) :
    Statement -> Fin (canonicalTransfers actions).length -> Bool :=
  fun statement index =>
    deployedCompiledArtifactVerifier verifier statement
      ((canonicalTransfers actions).get index)

/--
Conditional standard-to-ideal reduction target for an entire heterogeneous ordered block.

This obligation has one standard-QROM adversary, one global quantum-query/prior-proof budget, and
one ideal product-output run. `productOutputSimulationQuantumQueries` is reduction overhead and is
charged in the same global quantum budget. The SHA-512 proof-transcript loss and the native
RFC 7693 BLAKE2b-384 V3 header-precommit/block-identity/work/rules-manifest plus
commitment-binding failure event are distinct explicit premises; this file supplies no numerical
security claim for either. Likewise, it neither constructs the compiled-verifier refinement
contained in `refinement`, proves the SHA-512-to-product-oracle inequality, nor proves a
BLAKE2b-384 V3 collision/preimage reduction.
-/
structure OrderedBlockSharedQromTransferObligation
    {Omega Adversary : Type*}
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    {Phase Workspace : Type*}
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (measure : RealEventProbability Omega)
    (deployedAnyExtractionFailureEvent : Set Omega)
    (blake2b384V3IdentityWorkRulesOrBindingFailureEvent : Set Omega)
    (standardGame :
      AdaptiveOracleGame Adversary (Fin (canonicalTransfers actions).length))
    (adversary : Adversary)
    (refinement :
      OrderedBlockSharedIdealFailureSelectorRefinement
        verifier hashes actions Workspace)
    (completePhaseSystem :
      CompletePhaseSystem
        (IndexedLogicalOutput
          (Fin (canonicalTransfers actions).length)
          (fun index => ((canonicalTransfers actions).get index).exactMap))
        Phase)
    (steps : List (DatabaseIndependentContraction
      (Input := IndexedVerifierQuery
        (Fin (canonicalTransfers actions).length)
        (fun index => ((canonicalTransfers actions).get index).exactMap))
      (Output := IndexedLogicalOutput
        (Fin (canonicalTransfers actions).length)
        (fun index => ((canonicalTransfers actions).get index).exactMap))
      (Phase := Phase)
      (Workspace := Workspace)))
    (initialRegisters :
      RegisterBasis
        (Input := IndexedVerifierQuery
          (Fin (canonicalTransfers actions).length)
          (fun index => ((canonicalTransfers actions).get index).exactMap))
        (Phase := Phase)
        (Workspace := Workspace) -> ℂ) where
  standardOracleModelExact : standardGame.model = .standardQrom
  sharedGlobalBudget : QueryBudget
  productOutputSimulationQuantumQueries : Nat
  globalQuantumQueriesWithinBudget :
    standardGame.quantumHashQueries adversary +
        productOutputSimulationQuantumQueries ≤
      sharedGlobalBudget.quantumHashQueries
  globalPriorProofInteractionsWithinBudget :
    standardGame.priorProofInteractions adversary ≤
      sharedGlobalBudget.priorProofInteractions
  logicalProductQueriesCoveredBySimulationCost :
    steps.length ≤ productOutputSimulationQuantumQueries
  blake2b384V3IdentityWorkRulesOrBindingFailureBound : ℝ
  sha512StandardToIndexedProductIdealLoss : QueryBudget -> Nat -> ℝ
  nativeLossNonnegative :
    0 ≤ blake2b384V3IdentityWorkRulesOrBindingFailureBound
  sha512ProductLossNonnegative :
    0 ≤ sha512StandardToIndexedProductIdealLoss
      sharedGlobalBudget productOutputSimulationQuantumQueries
  deployedBlockToSelectedStandardFailureReduction :
    measure.probability deployedAnyExtractionFailureEvent ≤
      measure.probability blake2b384V3IdentityWorkRulesOrBindingFailureEvent +
        standardGame.eventProbability adversary
          (ExtractionFailure
            (deployedOrderedBlockArtifactVerifier verifier actions))
  blake2b384V3IdentityWorkRulesOrBindingFailureBounded :
    measure.probability blake2b384V3IdentityWorkRulesOrBindingFailureEvent ≤
      blake2b384V3IdentityWorkRulesOrBindingFailureBound
  standardSha512ToIndexedProductIdeal :
    standardGame.eventProbability adversary
        (ExtractionFailure
          (deployedOrderedBlockArtifactVerifier verifier actions)) ≤
      normSquared
          (workspaceEventProjection
            (IndexedIdealFailureEvent
              (orderedBlockSharedIdealFailureSelector refinement))
            (totalOracleFamilyState
              (oracleFamilyRun completePhaseSystem.system steps
                (fun _oracle => initialRegisters)))) +
        sha512StandardToIndexedProductIdealLoss
          sharedGlobalBudget productOutputSimulationQuantumQueries

/--
One non-unioned heterogeneous block failure bound. The ideal term is proved for one total tagged
oracle run. Every deployed/native/hash loss in the conclusion comes from the explicit transfer
obligation; no numeric PQ128 claim or deployed end-to-end authority is constructed.
-/
theorem ordered_block_shared_extraction_failure_probability_le_ideal_qrom_plus_explicit_losses
    {Omega Adversary : Type*}
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    {Phase Workspace : Type*}
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (measure : RealEventProbability Omega)
    (deployedAnyExtractionFailureEvent : Set Omega)
    (blake2b384V3IdentityWorkRulesOrBindingFailureEvent : Set Omega)
    (standardGame :
      AdaptiveOracleGame Adversary (Fin (canonicalTransfers actions).length))
    (adversary : Adversary)
    (refinement :
      OrderedBlockSharedIdealFailureSelectorRefinement
        verifier hashes actions Workspace)
    (completePhaseSystem :
      CompletePhaseSystem
        (IndexedLogicalOutput
          (Fin (canonicalTransfers actions).length)
          (fun index => ((canonicalTransfers actions).get index).exactMap))
        Phase)
    (steps : List (DatabaseIndependentContraction
      (Input := IndexedVerifierQuery
        (Fin (canonicalTransfers actions).length)
        (fun index => ((canonicalTransfers actions).get index).exactMap))
      (Output := IndexedLogicalOutput
        (Fin (canonicalTransfers actions).length)
        (fun index => ((canonicalTransfers actions).get index).exactMap))
      (Phase := Phase)
      (Workspace := Workspace)))
    (initialRegisters :
      RegisterBasis
        (Input := IndexedVerifierQuery
          (Fin (canonicalTransfers actions).length)
          (fun index => ((canonicalTransfers actions).get index).exactMap))
        (Phase := Phase)
        (Workspace := Workspace) -> ℂ)
    (initialSubnormalized :
      Subnormalized
        (partialRandomOracleState
          (Output := IndexedLogicalOutput
            (Fin (canonicalTransfers actions).length)
            (fun index => ((canonicalTransfers actions).get index).exactMap))
          ∅ initialRegisters))
    (transfer :
      OrderedBlockSharedQromTransferObligation measure
        deployedAnyExtractionFailureEvent
        blake2b384V3IdentityWorkRulesOrBindingFailureEvent
        standardGame adversary refinement completePhaseSystem steps initialRegisters) :
    measure.probability deployedAnyExtractionFailureEvent ≤
      indexedIdealLogicalQromFailureBound
          (Fin (canonicalTransfers actions).length)
          (fun index => ((canonicalTransfers actions).get index).exactMap)
          steps.length +
        transfer.blake2b384V3IdentityWorkRulesOrBindingFailureBound +
        transfer.sha512StandardToIndexedProductIdealLoss
          transfer.sharedGlobalBudget
          transfer.productOutputSimulationQuantumQueries := by
  have idealBound :=
    (indexed_ideal_logical_qrom_failure_probability_le
      refinement.ordered.active completePhaseSystem steps initialRegisters
      initialSubnormalized
      (orderedBlockSharedIdealFailureSelector refinement)).holds
  linarith
    [transfer.deployedBlockToSelectedStandardFailureReduction,
      transfer.blake2b384V3IdentityWorkRulesOrBindingFailureBounded,
      transfer.standardSha512ToIndexedProductIdeal]

/-! ## Probabilistic block composition -/

namespace RealEventProbability

theorem finite_iUnion_le_sum
    {Omega Index : Type*}
    [DecidableEq Index]
    (measure : RealEventProbability Omega)
    (indices : Finset Index)
    (event : Index -> Set Omega) :
    measure.probability (⋃ index ∈ indices, event index) ≤
      ∑ index ∈ indices, measure.probability (event index) := by
  classical
  induction indices using Finset.induction_on with
  | empty =>
      simp [measure.empty]
  | @insert index indices indexNotMem induction =>
      rw [Finset.sum_insert indexNotMem]
      have unionEquation :
          (⋃ selected ∈ insert index indices, event selected) =
            event index ∪ ⋃ selected ∈ indices, event selected := by
        ext outcome
        simp
      rw [unionEquation]
      exact (measure.union_le (event index) (⋃ selected ∈ indices, event selected)).trans
        (by
          simpa [add_comm] using
            add_le_add_left induction (measure.probability (event index)))

end RealEventProbability

/--
Per-transaction extraction evidence only. Canonical semantic refinement is intentionally absent:
it is a deterministic statement-to-production obligation and must not be charged to a QROM
probability bound.
-/
structure CallerSuppliedExtractionEvidence
    (proof : DeployedSmallWoodProof) : Type where
  modeledProofBytes : List HegemonCrypto.CanonicalBytes.Byte
  modeledProofBytesMatch : modeledProofBytes.map Fin.val = proof.proofBytes
  rawOracle : RawOracle
  fallback : ActiveDigest
  database : ProductionHashDatabase
  verifierEvidence :
    CallerSuppliedVerifierEvidence modeledProofBytes proof.exactMap
      rawOracle fallback database
  extractionSucceeds :
    ¬NoValidExtraction verifierEvidence.active
      (callerEvidenceFourthQuery verifierEvidence)

def CallerSuppliedExtractionEvidence.withSemanticRefinement
    {proof : DeployedSmallWoodProof}
    (extraction : CallerSuppliedExtractionEvidence proof)
    (semanticRefinement :
      ProductionSmallWoodCanonicalSemanticRefinementAssumption
        proof.exactMap proof.shape proof.merkleRoot) :
    CallerSuppliedTransactionConditionalEvidence proof :=
  { modeledProofBytes := extraction.modeledProofBytes
    modeledProofBytesMatch := extraction.modeledProofBytesMatch
    rawOracle := extraction.rawOracle
    fallback := extraction.fallback
    database := extraction.database
    verifierEvidence := extraction.verifierEvidence
    extractionSucceeds := extraction.extractionSucceeds
    semanticRefinement := semanticRefinement }

/--
Outcome-indexed extraction evidence for every ordered transfer in one already decoded block.
`none` is exactly the per-transaction failure event charged to the QROM/hash bounds.
-/
structure AcceptedBlockExtractionExperiment
    (Omega : Type*)
    (actions : List (CanonicalAction DeployedSmallWoodProof)) where
  evidence :
    Omega ->
      (index : Fin (canonicalTransfers actions).length) ->
        Option
          (CallerSuppliedExtractionEvidence
            ((canonicalTransfers actions).get index))
  indexOfMembership :
    forall (proof : DeployedSmallWoodProof), proof ∈ canonicalTransfers actions ->
      Fin (canonicalTransfers actions).length
  indexOfMembershipExact :
    forall (proof : DeployedSmallWoodProof),
      (membership : proof ∈ canonicalTransfers actions) ->
      (canonicalTransfers actions).get (indexOfMembership proof membership) = proof

def transactionExtractionFailureEvent
    {Omega : Type*}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    (experiment : AcceptedBlockExtractionExperiment Omega actions)
    (index : Fin (canonicalTransfers actions).length) : Set Omega :=
  { outcome | experiment.evidence outcome index = none }

/--
Specialize the deployment-to-QROM reduction to the exact proof at one block-transfer index. The
failure event here is definitionally the absence of extraction evidence for that proof; the native
compiled-verifier and SHA-512/QROM reductions remain fields of `transfer`.
-/
theorem transaction_extraction_failure_probability_le_ideal_qrom_plus_explicit_losses
    {Omega Adversary : Type*}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {statement : Statement}
    {active : ActiveStatement statement}
    {Phase Workspace : Type*}
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (measure : RealEventProbability Omega)
    (experiment : AcceptedBlockExtractionExperiment Omega actions)
    (index : Fin (canonicalTransfers actions).length)
    (commitmentOrHashFailureEvent : Set Omega)
    (standardGame : AdaptiveOracleGame Adversary DeployedSmallWoodProof)
    (adversary : Adversary)
    (refinement :
      CompiledFailureSelectorRefinement
        verifier hashes statement active Workspace)
    (completePhaseSystem : CompletePhaseSystem (LogicalOutput statement) Phase)
    (steps : List (DatabaseIndependentContraction
      (Input := VerifierQuery statement)
      (Output := LogicalOutput statement)
      (Phase := Phase)
      (Workspace := Workspace)))
    (initialRegisters :
      RegisterBasis
        (Input := VerifierQuery statement)
        (Phase := Phase)
        (Workspace := Workspace) -> ℂ)
    (initialSubnormalized :
      Subnormalized
        (partialRandomOracleState
          (Output := LogicalOutput statement) ∅ initialRegisters))
    (transfer :
      DeployedSha512QromTransferObligation measure
        (transactionExtractionFailureEvent experiment index)
        commitmentOrHashFailureEvent
        ((canonicalTransfers actions).get index)
        standardGame adversary refinement completePhaseSystem steps initialRegisters) :
    measure.probability (transactionExtractionFailureEvent experiment index) ≤
      idealLogicalQromFailureBound statement steps.length
        + transfer.commitmentOrHashFailureBound
        + transfer.sha512StandardToIdealLoss transfer.standardQueryBudget := by
  exact
    deployed_compiled_acceptance_failure_probability_le_ideal_qrom_plus_explicit_losses
      measure (transactionExtractionFailureEvent experiment index)
      commitmentOrHashFailureEvent
      ((canonicalTransfers actions).get index)
      standardGame adversary refinement completePhaseSystem steps initialRegisters
      initialSubnormalized transfer

def anyTransactionExtractionFailureEvent
    {Omega : Type*}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    (experiment : AcceptedBlockExtractionExperiment Omega actions) : Set Omega :=
  ⋃ index : Fin (canonicalTransfers actions).length,
    transactionExtractionFailureEvent experiment index

/--
Exact non-vacuity requirement for a per-proof union argument. For a nonempty block with `n`
transfers, proving each extraction-failure probability at most `target / n` is sufficient for the
whole block to meet `target`. This leaves the active numerical instantiation open; it does not turn
one maximum-query per-proof envelope into a block-security claim.
-/
theorem any_transaction_extraction_failure_probability_le_target_of_per_proof_share
    {Omega : Type*}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    (measure : RealEventProbability Omega)
    (experiment : AcceptedBlockExtractionExperiment Omega actions)
    (target : ℝ)
    (transferCountPositive : 0 < (canonicalTransfers actions).length)
    (perProofShare : forall index,
      measure.probability (transactionExtractionFailureEvent experiment index) ≤
        target / ((canonicalTransfers actions).length : ℝ)) :
    measure.probability (anyTransactionExtractionFailureEvent experiment) ≤ target := by
  let transferCount := (canonicalTransfers actions).length
  have transferCountRealNe : (transferCount : ℝ) ≠ 0 := by
    exact_mod_cast (Nat.ne_of_gt transferCountPositive)
  calc
    measure.probability (anyTransactionExtractionFailureEvent experiment) ≤
        ∑ index : Fin transferCount,
          measure.probability
            (transactionExtractionFailureEvent experiment index) := by
      simpa [anyTransactionExtractionFailureEvent, transferCount] using
        measure.finite_iUnion_le_sum
          (Finset.univ : Finset (Fin transferCount))
          (transactionExtractionFailureEvent experiment)
    _ ≤ ∑ _index : Fin transferCount, target / (transferCount : ℝ) := by
      exact Finset.sum_le_sum fun index _ => by
        simpa [transferCount] using perProofShare index
    _ = target := by
      rw [Finset.sum_const, nsmul_eq_mul, Finset.card_univ, Fintype.card_fin]
      field_simp

theorem extraction_evidence_exists_outside_failure_union
    {Omega : Type*}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    (experiment : AcceptedBlockExtractionExperiment Omega actions)
    (outcome : Omega)
    (outside : outcome ∉ anyTransactionExtractionFailureEvent experiment)
    (index : Fin (canonicalTransfers actions).length) :
    exists evidence,
      experiment.evidence outcome index = some evidence := by
  have notNone : experiment.evidence outcome index ≠ none := by
    intro missing
    apply outside
    simp only [anyTransactionExtractionFailureEvent, Set.mem_iUnion]
    exact ⟨index, missing⟩
  exact Option.ne_none_iff_exists'.mp notNone

noncomputable def extractionEvidenceOutsideFailureUnion
    {Omega : Type*}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    (experiment : AcceptedBlockExtractionExperiment Omega actions)
    (outcome : Omega)
    (outside : outcome ∉ anyTransactionExtractionFailureEvent experiment)
    (index : Fin (canonicalTransfers actions).length) :
    CallerSuppliedExtractionEvidence
      ((canonicalTransfers actions).get index) :=
  (experiment.evidence outcome index).get (by
    have notNone : experiment.evidence outcome index ≠ none := by
      intro missing
      apply outside
      simp only [anyTransactionExtractionFailureEvent, Set.mem_iUnion]
      exact ⟨index, missing⟩
    cases found : experiment.evidence outcome index with
    | none => exact (notNone found).elim
    | some evidence => rfl)

/-- Outside the finite extraction-failure union, every accepted proof supplies block evidence. -/
theorem accepted_block_outside_extraction_failure_union_yields_no_counterfeit
    {Omega : Type*}
    {hashes : ProductionIdentityFunctions}
    {codec : ProductionActionCodec DeployedSmallWoodProof}
    {verifier : ProductionSmallWoodProofVerifier}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    (accepted :
      AcceptedDeployedSmallWoodBlock codec verifier hashes acceptedParent block)
    (decoded : decodeCanonicalActionStream codec block.actionBytes = some actions)
    (experiment : AcceptedBlockExtractionExperiment Omega actions)
    (semanticRefinement :
      DeployedSmallWoodBlockCanonicalSemanticRefinementEvidence codec block)
    (poseidon2OutputSecurity :
      DeployedSmallWoodBlockPoseidon2OutputSecurityAssumptions codec block)
    (outcome : Omega)
    (outside : outcome ∉ anyTransactionExtractionFailureEvent experiment) :
    ScopedSecurityClaim .conditionalSupply
      (DeployedNoCounterfeitCriticalPathCertificate
        hashes codec verifier acceptedParent block) := by
  apply
    accepted_block_given_caller_extraction_semantic_refinement_and_output_security_yields_no_counterfeit
      accepted
  · intro decodedActions decodedAgain proof membership
    have actionsEqual : decodedActions = actions := by
      rw [decoded] at decodedAgain
      exact Option.some.inj decodedAgain.symm
    subst decodedActions
    let index := experiment.indexOfMembership proof membership
    have proofAtIndex := experiment.indexOfMembershipExact proof membership
    let evidence := extractionEvidenceOutsideFailureUnion
      experiment outcome outside index
    rw [proofAtIndex] at evidence
    exact evidence.withSemanticRefinement
      (semanticRefinement actions decoded proof membership)
  · exact poseidon2OutputSecurity

/--
Accepted-block theorem with an explicit transaction union bound. Each per-proof premise can be
instantiated by `deployed_compiled_acceptance_failure_probability_le_ideal_qrom_plus_explicit_losses`.
The canonical semantic-refinement and Poseidon2 output-security boundaries remain separately named
block premises and are not hidden inside the probabilistic extraction event. This theorem does not
claim that repeating one maximum-query per-proof bound yields a useful block-security level;
`any_transaction_extraction_failure_probability_le_target_of_per_proof_share` states the exact
`target / transferCount` premise required for a non-vacuous per-proof argument. A true shared-query
multi-theorem QROM result still requires a statement-indexed ideal theorem not present here.
-/
theorem accepted_block_failure_probability_le_sum_and_good_outcomes_yield_no_counterfeit
    {Omega : Type*}
    {hashes : ProductionIdentityFunctions}
    {codec : ProductionActionCodec DeployedSmallWoodProof}
    {verifier : ProductionSmallWoodProofVerifier}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    {actions : List (CanonicalAction DeployedSmallWoodProof)}
    (measure : RealEventProbability Omega)
    (accepted :
      AcceptedDeployedSmallWoodBlock codec verifier hashes acceptedParent block)
    (decoded : decodeCanonicalActionStream codec block.actionBytes = some actions)
    (experiment : AcceptedBlockExtractionExperiment Omega actions)
    (perProofBound : Fin (canonicalTransfers actions).length -> ℝ)
    (perProofFailureBound : forall index,
      measure.probability (transactionExtractionFailureEvent experiment index) ≤
        perProofBound index)
    (semanticRefinement :
      DeployedSmallWoodBlockCanonicalSemanticRefinementEvidence codec block)
    (poseidon2OutputSecurity :
      DeployedSmallWoodBlockPoseidon2OutputSecurityAssumptions codec block) :
    measure.probability (anyTransactionExtractionFailureEvent experiment) ≤
        ∑ index, perProofBound index
      ∧ forall outcome,
        outcome ∉ anyTransactionExtractionFailureEvent experiment ->
          ScopedSecurityClaim .conditionalSupply
            (DeployedNoCounterfeitCriticalPathCertificate
              hashes codec verifier acceptedParent block) := by
  constructor
  · calc
      measure.probability (anyTransactionExtractionFailureEvent experiment) ≤
          ∑ index,
            measure.probability
              (transactionExtractionFailureEvent experiment index) := by
        simpa [anyTransactionExtractionFailureEvent] using
          measure.finite_iUnion_le_sum
            (Finset.univ : Finset (Fin (canonicalTransfers actions).length))
            (transactionExtractionFailureEvent experiment)
      _ ≤ ∑ index, perProofBound index := by
        exact Finset.sum_le_sum fun index _ => perProofFailureBound index
  · intro outcome outside
    exact accepted_block_outside_extraction_failure_union_yields_no_counterfeit
      accepted decoded experiment semanticRefinement poseidon2OutputSecurity outcome outside

end

end HegemonCrypto.SmallWood.DeployedQromBridge
