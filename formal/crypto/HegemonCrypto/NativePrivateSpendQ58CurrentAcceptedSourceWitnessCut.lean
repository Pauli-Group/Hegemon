import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceWitnessOrBad
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceWitnessCut
open scoped Classical
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open NativePrivateSpendQ58CurrentCanonicalSourceClassifier
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport (sourceProjection sourceKeys)
end X
namespace K
export SmzaRp05CurrentPhysicalBranchClaims (workspace_event_mass_le_of_inclusion)
export SmzaRp05CurrentKnownClaimsFailureMass (database_event_complement_mass_split)
end K
noncomputable section
set_option autoImplicit false
variable{BaseWork:Type}[Fintype BaseWork][DecidableEq BaseWork]
variable (p:Program E.Wire) (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
 (rel:NativePrivateSpendQ58CurrentPublicOpening.Relation) (n:Fin (2^32))
local notation "Root"=>root p ns rel n
local notation "S"=>SmzaRp05CurrentAdaptiveExecution.CmsState (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork)
variable (b:Branches G.decode (root p ns rel n))
def failure (s:S):=X.sourceProjection Root (fun v _=>¬SourceWitness p ns rel n b v) s
/-- The no-witness selector is split on the RAW physical branch. Its fullclaim
 failure is charged against the SAME unselected original branch norm. -/
theorem accepted_no_source_witness_raw_cut (initial:S) (a:branchResult G.decode Root b=some ()):
 let s:=NativePrivateSpendQ58CurrentAcceptedSourceCut.run p ns rel n b initial
 normSquared (failure p ns rel n b s)≤
 normSquared (X.sourceProjection Root (fun v _=>NativePrivateSpendQ58CurrentAcceptedSourceCut.bad p ns rel n b v) s)+
 (((2*(Q.fullClaims Root b).toFinset.card:Nat):ℝ)/Fintype.card (VectorOutput G.Counter))*normSquared s:=by
 dsimp only
 let s:=NativePrivateSpendQ58CurrentAcceptedSourceCut.run p ns rel n b initial
 let cl:=ClaimsDatabaseEvent (Q.fullClaims Root b)
 let miss:=fun db=>¬cl db
 let nw:=fun db=>¬SourceWitness p ns rel n b (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) db)
 have split:=K.database_event_complement_mass_split cl (failure p ns rel n b s)
 have full:normSquared (databaseEventProjection cl (failure p ns rel n b s))≤
  normSquared (X.sourceProjection Root (fun v _=>NativePrivateSpendQ58CurrentAcceptedSourceCut.bad p ns rel n b v) s):=by
  convert K.workspace_event_mass_le_of_inclusion (fun _ db=>cl db∧nw db)
   (fun _ db=>NativePrivateSpendQ58CurrentAcceptedSourceCut.bad p ns rel n b (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) db)) s
   (by
    intro _ db both
    have src:SC.SourceClaims Root b (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) db):=by
     intro key value member hk;exact both.1 (key,value) member
    rcases accepted_source_witness_or_chosen_role p ns rel n b _ (SC.consistent_of_claims Root b db both.1) src a with
     collision|chosen|witness
    · exact Or.inl collision
    · exact Or.inr chosen
    · exact (both.2 witness).elim) using 1
  · congr 1
    funext basis
    by_cases recorded:cl basis.database<;>by_cases excluded:nw basis.database<;>
     simp[failure,X.sourceProjection,SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection,
      databaseEventProjection,workspaceEventProjection,nw,cl,recorded,excluded]
  · rfl
 have debt:=NativePrivateSpendQ58CurrentAcceptedSourceCut.unselected_full_claim_failure_le p ns rel n b initial
 have selected:normSquared (databaseEventProjection miss (failure p ns rel n b s))≤
  normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims Root b) s):=by
  convert K.workspace_event_mass_le_of_inclusion (fun _ db=>miss db∧nw db) (fun _ db=>miss db) s
   (by intro _ _ h;exact h.1) using 1
  · congr 1
    funext basis
    by_cases missing:miss basis.database<;>by_cases excluded:nw basis.database<;>
     simp[failure,X.sourceProjection,SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection,
      databaseEventProjection,workspaceEventProjection,nw,miss,cl,missing,excluded]
  · rfl
 have paid:=selected.trans debt
 change normSquared (databaseEventProjection (fun db=>¬cl db) (failure p ns rel n b s))≤_ at paid
 linarith
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceWitnessCut
