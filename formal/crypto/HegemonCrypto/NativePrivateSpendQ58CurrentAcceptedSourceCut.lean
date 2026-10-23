import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceEndpoint
import SmzaRp05CurrentKnownClaimsFailureMass
import SmzaRp05CurrentPhysicalNonchallengeClaims
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceCut
open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun)
open SmzaChallengeStageTargets (Role)
open NativePrivateSpendQ58CurrentCanonicalSourceClassifier
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport (sourceProjection sourceKeys)
end X
noncomputable section
set_option autoImplicit false
variable {BaseWork:Type}[Fintype BaseWork][DecidableEq BaseWork]
local notation "Work"=>SmzaRp05CurrentAdaptiveExecution.Work (Counter:=G.Counter) (BaseWork:=BaseWork)
variable (prod:Program E.Wire) (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
 (rel:NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce:Fin (2^32))
local notation "Root"=>root prod ns rel nonce
variable (branch:Branches G.decode (root prod ns rel nonce))
def bad (view:NativePrivateSpendQ58CurrentSourceSelectorTransport.SourceView Root):Prop:=
 ¬SmzaRecordedTracePath.RecordsCollisionFree (records prod ns rel nonce view)∨
 ∃role,Choice prod ns rel nonce branch role view
def run (initial:State (G.Key Root) (V8Smz9CoherentVectorMerkle.VectorOutput G.Counter)
 (V8Smz9CoherentVectorMerkle.VectorOutput G.Counter) Work):=
 physicalRun (G.encode Root) G.decode Root branch initial
theorem unselected_full_claim_failure_le (initial:State (G.Key Root) (V8Smz9CoherentVectorMerkle.VectorOutput G.Counter)
 (V8Smz9CoherentVectorMerkle.VectorOutput G.Counter) Work):
 normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims Root branch) (run prod ns rel nonce branch initial))≤
 (((2*(Q.fullClaims Root branch).toFinset.card:Nat):ℝ)/
 Fintype.card (V8Smz9CoherentVectorMerkle.VectorOutput G.Counter))*normSquared (run prod ns rel nonce branch initial):=by
 apply SmzaRp05CurrentKnownClaimsFailureMass.global_known_claims_failure_mass_le
 intro claim member
 exact SmzaRp05CurrentPhysicalBranchClaimReadback.physical_branch_claim_known_at_standard
  (G.encode Root) G.decode Root branch initial claim member
theorem accepted_unselected_raw_source_cut (initial:State (G.Key Root) (V8Smz9CoherentVectorMerkle.VectorOutput G.Counter)
 (V8Smz9CoherentVectorMerkle.VectorOutput G.Counter) Work)
 (accepted:SmzaRp05PhysicalAcceptedReplayLite.branchResult G.decode Root branch=some ())
 (invalid:¬∃source:NativePrivateSpendQ58CurrentDecodedRelation.Decoded,
  NativePrivateSpendQ58CurrentPublicOpening.Satisfies rel (NativePrivateSpendQ58CurrentDecodedRelation.decodedValues source)):
 normSquared (run prod ns rel nonce branch initial)≤
 normSquared (X.sourceProjection Root (fun view _=>bad prod ns rel nonce branch view) (run prod ns rel nonce branch initial))+
 (((2*(Q.fullClaims Root branch).toFinset.card:Nat):ℝ)/
 Fintype.card (V8Smz9CoherentVectorMerkle.VectorOutput G.Counter))*normSquared (run prod ns rel nonce branch initial):=by
 have split:=SmzaRp05CurrentKnownClaimsFailureMass.database_event_complement_mass_split
  (ClaimsDatabaseEvent (Q.fullClaims Root branch)) (run prod ns rel nonce branch initial)
 have debt:=unselected_full_claim_failure_le prod ns rel nonce branch initial
 have included:normSquared (databaseEventProjection (ClaimsDatabaseEvent (Q.fullClaims Root branch))
  (run prod ns rel nonce branch initial))≤
  normSquared (X.sourceProjection Root (fun view _=>bad prod ns rel nonce branch view) (run prod ns rel nonce branch initial)):=by
  change normSquared (workspaceEventProjection
    (fun _ database => ClaimsDatabaseEvent (Q.fullClaims Root branch) database)
    (run prod ns rel nonce branch initial)) ≤
    normSquared (workspaceEventProjection
      (fun _ database => bad prod ns rel nonce branch
        (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) database))
      (run prod ns rel nonce branch initial))
  apply SmzaRp05CurrentPhysicalBranchClaims.workspace_event_mass_le_of_inclusion
    (fun _ database => ClaimsDatabaseEvent (Q.fullClaims Root branch) database)
    (fun _ database => bad prod ns rel nonce branch
      (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) database))
    (run prod ns rel nonce branch initial)
  intro work database claims
  have coherent:=SC.consistent_of_claims Root branch database claims
  have sources:SC.SourceClaims Root branch (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) database):=by
   intro key value member source
   exact claims (key,value) member
  exact accepted_invalid_chosen_role prod ns rel nonce branch _ coherent sources accepted invalid
 change normSquared (databaseEventProjection (fun db=>¬ClaimsDatabaseEvent (Q.fullClaims Root branch) db)
  (run prod ns rel nonce branch initial))≤_ at debt
 linarith
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceCut
