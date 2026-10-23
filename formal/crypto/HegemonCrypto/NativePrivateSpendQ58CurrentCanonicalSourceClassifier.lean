import HegemonCrypto.NativePrivateSpendQ58CurrentSourceCompletion
import HegemonCrypto.NativePrivateSpendQ58CurrentDecsSourceJoin
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCanonicalSourceClassifier
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier(Program)
open SmzaRp05PhysicalAcceptedReplayLite(Branches branchResult answerLog rawLog)
open HegemonCrypto.FiniteOracleDatabase(Database)
open HegemonCrypto.CmsOracleDatabaseBridge(ClaimsDatabaseEvent)
open V8Smz9CoherentVectorMerkle(VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument(rawRecords)
open SmzaRecordedTracePath(RecordsCollisionFree)
open V8Smz9CoherentMerkleGeometry(extract)
open SmzaChallengeStageTargets(Role)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping(Key Counter RawInput RawDigest encode decode keyBytes zero)
end G
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay(fullClaims claimOracle current_claims_store_every_branch_vector current_grouped_claims_replay_actual_program)
end Q
namespace SC
export NativePrivateSpendQ58CurrentSourceCompletion
 (SourceClaims Consistent completeSourceView complete_source_claims canonicalRecords active_source_records lookup)
end SC
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport
 (SourceView sourceKeys activeSourceView source_keys_active_for_each_role)
end X
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims(live activeClaims fixedCompatible)
export NativePrivateSpendQ58CurrentGammaFiber(currentRoleCaps)
end AC
namespace A
export NativePrivateSpendQ58ActiveEventProjection(ActiveKey merge merge_active merge_fixed)
end A
namespace P
export NativePrivateSpendQ58PartitionTransport(FixedTable)
end P
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
 (Wire Transcript ExecutionStages verifierProgram decsInput finalInput)
end E
namespace U
export NativePrivateSpendQ58CurrentDecsSourceJoin
 (Context program records oracle geometry_identities_give_piop_bad)
end U





noncomputable section
set_option autoImplicit false
set_option Elab.async false
variable (prod : Program E.Wire) (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
  (rel : NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce : Fin (2^32))
abbrev root := prod.bind (E.verifierProgram ns rel false nonce)
local notation "Root" => root prod ns rel nonce
def fullDB (branch : Branches G.decode (Root)) (view : X.SourceView (Root)) :
    Database (G.Key (Root)) (VectorOutput G.Counter) :=
  SC.completeSourceView (Root) branch view 0
def live (role : Role) := AC.live (Root) role AC.currentRoleCaps
local notation "Live" => live prod ns rel nonce
def fixed (branch : Branches G.decode (Root)) (role : Role) (view : X.SourceView (Root)) :
    P.FixedTable (Counter := G.Counter) (Live role) :=
  fun key => (fullDB prod ns rel nonce branch view key.val).getD 0
def db (branch : Branches G.decode (Root)) (role : Role) (view : X.SourceView (Root)) :
    Database (A.ActiveKey (Live role)) (VectorOutput G.Counter) :=
  fun key => fullDB prod ns rel nonce branch view key.val
theorem merge_full (branch : Branches G.decode (Root)) (role : Role) (view : X.SourceView (Root)) :
    A.merge (Live role) (fixed prod ns rel nonce branch role view)
      (db prod ns rel nonce branch role view) = fullDB prod ns rel nonce branch view := by
  funext key
  by_cases active : Live role key
  · exact A.merge_active _ _ _ ⟨key,active⟩
  · rw [A.merge_fixed _ _ _ ⟨key,active⟩]
    have outside : key ∉ X.sourceKeys (Root) := by
      intro member
      exact active (X.source_keys_active_for_each_role _ role key member)
    dsimp only [fixed,fullDB]
    simp only [SC.completeSourceView,dif_neg outside]
    cases SC.lookup key (Q.fullClaims (Root) branch) <;> rfl
theorem selected_claims (branch : Branches G.decode (Root)) (role : Role) (view : X.SourceView (Root))
    (all : ClaimsDatabaseEvent (Q.fullClaims (Root) branch)
      (fullDB prod ns rel nonce branch view)) :
    ClaimsDatabaseEvent (AC.activeClaims (Root) role AC.currentRoleCaps branch)
      (db prod ns rel nonce branch role view) := by
  intro claim member
  unfold AC.activeClaims at member
  obtain ⟨original,recorded,mapped⟩ := List.mem_filterMap.mp member
  by_cases active : Live role original.1
  · dsimp only [live] at active
    rw [dif_pos active] at mapped
    cases Option.some.inj mapped
    exact all original recorded
  · dsimp only [live] at active
    rw [dif_neg active] at mapped
    cases mapped
theorem compatible (branch : Branches G.decode (Root)) (role : Role) (view : X.SourceView (Root))
    (all : ClaimsDatabaseEvent (Q.fullClaims (Root) branch)
      (fullDB prod ns rel nonce branch view)) :
    AC.fixedCompatible (Root) role AC.currentRoleCaps
      (fixed prod ns rel nonce branch role view) branch := by
  intro call recorded inactive
  have stored := Q.current_claims_store_every_branch_vector _ branch _ all call recorded
  change (fullDB prod ns rel nonce branch view (G.encode _ call.1)).getD 0 = call.2
  rw [stored]; rfl
def context (branch : Branches G.decode (Root)) (view : X.SourceView (Root))
    (consistent : SC.Consistent (Q.fullClaims (Root) branch))
    (source : SC.SourceClaims (Root) branch view)
    (accepted : branchResult G.decode (Root) branch = some ()) : U.Context :=
  let all := SC.complete_source_claims _ branch view 0 source consistent
  { producer := prod, ns := ns, relation := rel, nonce := nonce, branch := branch,
    fixed := fixed prod ns rel nonce branch .decsSample view,
    database := db prod ns rel nonce branch .decsSample view, fallback := fun _ => 0,
    compatible := compatible prod ns rel nonce branch .decsSample view all,
    claims := selected_claims prod ns rel nonce branch .decsSample view all, accepted := accepted }
def sourceOracle (branch : Branches G.decode (Root)) (view : X.SourceView (Root)) :
    SmzaRp05ExecutableMerkleVerifier.Oracle :=
  Q.claimOracle (Root) (fullDB prod ns rel nonce branch view) (fun _ => 0)
theorem canonical_recorded_vector (branch : Branches G.decode (Root)) (view : X.SourceView (Root))
    (all : ClaimsDatabaseEvent (Q.fullClaims (Root) branch) (fullDB prod ns rel nonce branch view))
    (w : E.Wire) (produced : prod.eval (sourceOracle prod ns rel nonce branch view) = some w) (x : G.RawInput)
    (member : (x,sourceOracle prod ns rel nonce branch view x) ∈
      ((E.verifierProgram ns rel false nonce w).record (sourceOracle prod ns rel nonce branch view)).2) :
    ∃v, (x,v) ∈ answerLog G.decode (Root) branch ∧
      fullDB prod ns rel nonce branch view (G.encode (Root) x) = some v := by
  have replay := Q.current_grouped_claims_replay_actual_program (Root) branch
    (fullDB prod ns rel nonce branch view) all (fun _ => 0)
  have present : (x,sourceOracle prod ns rel nonce branch view x) ∈ rawLog G.decode (Root) branch := by
    have logEq := congrArg Prod.snd replay
    dsimp only [Prod.snd] at logEq
    rw [← logEq]
    exact Program.bind_log_right _ prod _ w produced member
  obtain ⟨call,recorded,same⟩ := List.mem_map.mp present
  rcases call with ⟨input,v⟩
  have eq := congrArg Prod.fst same
  dsimp only at eq
  subst input
  exact ⟨v,recorded,Q.current_claims_store_every_branch_vector _ branch _ all (x,v) recorded⟩

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCanonicalSourceClassifier
