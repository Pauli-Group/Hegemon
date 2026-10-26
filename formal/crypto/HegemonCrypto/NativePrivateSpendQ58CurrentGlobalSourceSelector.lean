import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalSourceSupport
import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceTransport

/-! Source-only selectors on ONE original adaptive global program. Canonical
completion retains the global branch answers and the actual source view.
Every selected stage is internal to the four predicates. The fixed-fiber
transport below derives observer vector claims from the SAME original raw log,
canonical and actual full claims; raw digest equality alone is never used as
vector equality. No observer is run as a new physical program. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalSourceSelector
open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult rawLog answerLog physicalRun)
open SmzaChallengeStageTargets (Role)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRecordedTracePath (RecordsCollisionFree)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter keyBytes encode decode zero)
end G
namespace H
export NativePrivateSpendQ58CurrentGlobalRawLogTransport
  (Stage adaptiveHistoryProgram historyProgram actualTerminalRoot actualTerminalProducer
   actualTerminalKeys actualTerminal_encode_exact actualTerminal_keyBytes_exact)
end H
namespace GS
export NativePrivateSpendQ58CurrentGlobalSourceSupport
  (NativeStageInput nativeConstructor AllActualSourceWitnesses
   actual_native_constructor_derives_relation_data actual_chosen_role_derives_causal_event
   actual_observer_causal_event_is_global roleFixed roleDatabase)
end GS
namespace CS
export NativePrivateSpendQ58CurrentCausalSourceJoin (SourceTemplate)
end CS
namespace GC
export NativePrivateSpendQ58CurrentGlobalSourceClassification
  (observerSourceView globalSourceRecords actual_accepted_global_history_has_same_source_classifiers)
end GC
namespace SC
export NativePrivateSpendQ58CurrentSourceCompletion
  (completeSourceView canonicalRecords consistent_of_claims SourceClaims complete_source_claims
   complete_source_records)
end SC
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport
  (SourceView sourceKeys sourceProjection activeSourceView source_keys_active_for_each_role
   current_source_selector_commutes source_view_fixed_completion)
end X
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay
  (claimOracle fullClaims current_claims_store_every_branch_vector)
end Q
namespace CC
export NativePrivateSpendQ58CurrentCanonicalSourceClassifier (Choice SourceWitness)
end CC
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims
  (live activeClaims fixedCompatible current_active_claims_complete_full_branch)
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end AC
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey FixedTable merge merge_active merge_fixed)
end A
namespace FM
export NativePrivateSpendQ58CurrentFiberMassTransport
  (Active FixedVectors actualActiveEquiv actualFixedEquiv actualFixed)
end FM
namespace RI
export NativePrivateSpendQ58CurrentRoleInsertion (pullDB pullFixed)
end RI
namespace GM
export NativePrivateSpendQ58CurrentGlobalCausalMass (event)
end GM
namespace K
export SmzaRp05CurrentPhysicalBranchClaims (workspace_event_mass_le_of_inclusion)
export SmzaRp05CurrentKnownClaimsFailureMass
  (database_event_complement_mass_split global_known_claims_failure_mass_le)
end K
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
variable (template : CS.SourceTemplate) (inputConstructor : Program (List GS.NativeStageInput))
local notation "Ctor" => GS.nativeConstructor template inputConstructor
local notation "Global" => H.adaptiveHistoryProgram Ctor
local notation "V" => VectorOutput G.Counter
variable (branch : Branches (Output := VectorOutput G.Counter) (Result := Unit) G.decode
      (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor)))

def canonical (branch : Branches (Output := VectorOutput G.Counter) (Result := Unit) G.decode
      (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor)))
    (view : X.SourceView (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor))) :
    Database (G.Key (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor))) (VectorOutput G.Counter) :=
  SC.completeSourceView (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor)) branch view 0

def missingSource (branch : Branches (Output := VectorOutput G.Counter) (Result := Unit) G.decode
      (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor)))
    (view : X.SourceView (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor))) : Prop :=
  ¬GS.AllActualSourceWitnesses (GS.nativeConstructor template inputConstructor) branch
    (canonical template inputConstructor branch view)

def sourceCollision (view : X.SourceView (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor))) : Prop :=
  ¬RecordsCollisionFree (SC.canonicalRecords (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor)) view)

/-- One causal selector contains the actual index existential. Its complete
canonical claims/observer data are obligations derived by the classifier,
not caller hypotheses or a new source validity certificate. -/
def chosen (branch : Branches (Output := VectorOutput G.Counter) (Result := Unit) G.decode
      (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor))) (role : Role)
    (view : X.SourceView (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor))) : Prop :=
  let database : Database (G.Key (H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor))) (VectorOutput G.Counter) :=
    canonical template inputConstructor branch view
  let oracle := Q.claimOracle Global database (fun _ => 0)
  ClaimsDatabaseEvent (Q.fullClaims Global branch) database ∧
    ∃ (stages : List H.Stage) (constructed : (Ctor).eval oracle = some stages),
      ∃ i : Fin stages.length,
        ∃ observerBranch : Branches G.decode (H.actualTerminalRoot Ctor stages i),
          branchResult G.decode (H.actualTerminalRoot Ctor stages i) observerBranch = some () ∧
          (rawLog G.decode (H.actualTerminalRoot Ctor stages i) observerBranch).toFinset =
            (rawLog G.decode Global branch).toFinset ∧
          ClaimsDatabaseEvent (Q.fullClaims (H.actualTerminalRoot Ctor stages i) observerBranch)
            (fun key => database (H.actualTerminalKeys Ctor oracle stages constructed i key)) ∧
          CC.Choice (H.actualTerminalProducer Ctor stages i)
            stages[i.val].ns stages[i.val].relation stages[i.val].nonce observerBranch role
            (GC.observerSourceView Ctor oracle stages constructed i database)

include branch in
theorem actual_full_claims_cover_source_selector
    (database : Database (G.Key Global) V)
    (claims : ClaimsDatabaseEvent (Q.fullClaims Global branch) database)
    (accepted : branchResult G.decode Global branch = some ())
    (missing : missingSource template inputConstructor branch
      (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database)) :
    sourceCollision template inputConstructor
        (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database) ∨
      ∃ role, chosen template inputConstructor branch role
        (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database) := by
  let view := SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database
  let full := canonical template inputConstructor branch view
  have sources : SC.SourceClaims Global branch view := by
    intro key value member source
    exact claims (key,value) member
  have all : ClaimsDatabaseEvent (Q.fullClaims Global branch) full :=
    SC.complete_source_claims Global branch view 0 sources (SC.consistent_of_claims Global branch database claims)
  obtain ⟨stages, constructed, historyAccepted, classified⟩ :=
    GC.actual_accepted_global_history_has_same_source_classifiers Ctor branch full all accepted
  have recordsEq : GC.globalSourceRecords Ctor full = SC.canonicalRecords Global view :=
    SC.complete_source_records Global branch view 0
  by_cases free : RecordsCollisionFree (SC.canonicalRecords Global view)
  · right
    by_contra absent
    apply missing
    refine ⟨stages, constructed, historyAccepted, ?_⟩
    intro i
    obtain ⟨observerBranch, observerAccepted, logEq, observerClaims, result⟩ := classified i
    refine ⟨observerBranch, observerAccepted, logEq, observerClaims, ?_⟩
    rcases result with collision | selected | witness
    · exact (collision (recordsEq.symm ▸ free)).elim
    · obtain ⟨role, choice⟩ := selected
      exact (absent ⟨role, all, stages, constructed, i, observerBranch,
        observerAccepted, logEq, observerClaims, choice⟩).elim
    · exact witness
  · exact Or.inl free

include branch in
/-- Exact observer vector claims on any other full database satisfying the
SAME original branch. The stored vectors are identified using BOTH claim
events at the exact encoded query key, not using output digest equality. -/
theorem observer_claims_from_same_original_branch
    (left right : Database (G.Key Global) V)
    (leftAll : ClaimsDatabaseEvent (Q.fullClaims Global branch) left)
    (rightAll : ClaimsDatabaseEvent (Q.fullClaims Global branch) right)
    (oracle : Oracle) (stages : List H.Stage) (constructed : (Ctor).eval oracle = some stages)
    (i : Fin stages.length)
    (observerBranch : Branches G.decode (H.actualTerminalRoot Ctor stages i))
    (logEq : (rawLog G.decode (H.actualTerminalRoot Ctor stages i) observerBranch).toFinset =
      (rawLog G.decode Global branch).toFinset)
    (observerClaims : ClaimsDatabaseEvent (Q.fullClaims (H.actualTerminalRoot Ctor stages i) observerBranch)
      (fun key => left (H.actualTerminalKeys Ctor oracle stages constructed i key))) :
    ClaimsDatabaseEvent (Q.fullClaims (H.actualTerminalRoot Ctor stages i) observerBranch)
      (fun key => right (H.actualTerminalKeys Ctor oracle stages constructed i key)) := by
  rintro ⟨key,value⟩ member
  rw [Q.fullClaims, SmzaRp05PhysicalAcceptedReplayLite.branch_claims_eq_answer_log] at member
  obtain ⟨call, recorded, same⟩ := List.mem_map.mp member
  cases same
  have localRaw : (call.1, G.decode call.1 call.2) ∈
      rawLog G.decode (H.actualTerminalRoot Ctor stages i) observerBranch :=
    List.mem_map.mpr ⟨call,recorded,rfl⟩
  have globalRaw : (call.1, G.decode call.1 call.2) ∈ rawLog G.decode Global branch := by
    apply List.mem_toFinset.mp
    rw [← logEq]
    exact List.mem_toFinset.mpr localRaw
  obtain ⟨original, originalRecorded, rawEq⟩ := List.mem_map.mp globalRaw
  have inputEq : original.1 = call.1 := congrArg
    (fun pair : V8SmzaOracleParser.RawInput ×
      NativePrivateSpendQ58CurrentConstructorGrouping.RawDigest => pair.1) rawEq
  have leftStored := Q.current_claims_store_every_branch_vector Global branch left leftAll original originalRecorded
  have localStored := Q.current_claims_store_every_branch_vector
    (H.actualTerminalRoot Ctor stages i) observerBranch _ observerClaims call recorded
  rw [H.actualTerminal_encode_exact] at localStored
  rw [inputEq] at leftStored
  have vectors : original.2 = call.2 := Option.some.inj (leftStored.symm.trans localStored)
  have keyEq := H.actualTerminal_encode_exact Ctor oracle stages constructed i call.1
  have rightStored := Q.current_claims_store_every_branch_vector Global branch right rightAll original originalRecorded
  rw [inputEq, vectors] at rightStored
  exact (congrArg right keyEq).trans rightStored

include branch in
private theorem observer_views_same_source
    (role : Role) (fixed : A.FixedTable (Counter := G.Counter) (AC.live Global role AC.currentRoleCaps))
    (database : Database (A.ActiveKey (AC.live Global role AC.currentRoleCaps)) V)
    (oracle : Oracle) (stages : List H.Stage) (constructed : (Ctor).eval oracle = some stages)
    (i : Fin stages.length) :
    GC.observerSourceView Ctor oracle stages constructed i
      (canonical template inputConstructor branch (X.activeSourceView Global role database)) =
    GC.observerSourceView Ctor oracle stages constructed i
      (A.merge (AC.live Global role AC.currentRoleCaps) fixed database) := by
  funext key
  let globalKey := H.actualTerminalKeys Ctor oracle stages constructed i key.val
  have source : globalKey ∈ X.sourceKeys Global := by
    apply Finset.mem_filter.mpr
    refine ⟨Finset.mem_univ _, ?_⟩
    rw [H.actualTerminal_keyBytes_exact]
    exact (Finset.mem_filter.mp key.property).2
  change SC.completeSourceView Global branch (X.activeSourceView Global role database) 0 globalKey = _
  simp only [SC.completeSourceView, dif_pos source]
  exact (A.merge_active _ fixed database
    ⟨globalKey,X.source_keys_active_for_each_role Global role globalKey source⟩).symm

private theorem full_role_db (role : Role)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live Global role AC.currentRoleCaps))
    (database : Database (A.ActiveKey (AC.live Global role AC.currentRoleCaps)) V) :
    GS.roleDatabase Global role (A.merge (AC.live Global role AC.currentRoleCaps) fixed database) =
      RI.pullDB Global role database := by
  funext key
  exact A.merge_active _ fixed database (FM.actualActiveEquiv role (G.keyBytes Global) key)

private theorem full_role_fixed (role : Role)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live Global role AC.currentRoleCaps))
    (database : Database (A.ActiveKey (AC.live Global role AC.currentRoleCaps)) V) :
    GS.roleFixed Global role (A.merge (AC.live Global role AC.currentRoleCaps) fixed database) =
      RI.pullFixed Global role fixed := by
  funext key
  have stored := A.merge_fixed (AC.live Global role AC.currentRoleCaps) fixed database
    (FM.actualFixedEquiv role (G.keyBytes Global) key)
  exact congrArg (fun value : Option (VectorOutput G.Counter) => value.getD 0) stored

include branch in
/-- The SOURCE-only existential selector enters the actual original role
event after exactly its compatible fixed cells and selected claims are read.
No mass, stage inclusion or validity certificate is supplied. -/
theorem actual_global_chosen_selector_inserts
    (role : Role)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live Global role AC.currentRoleCaps))
    (database : Database (A.ActiveKey (AC.live Global role AC.currentRoleCaps)) V)
    (compatible : AC.fixedCompatible Global role AC.currentRoleCaps fixed branch)
    (claims : ClaimsDatabaseEvent (AC.activeClaims Global role AC.currentRoleCaps branch) database)
    (selected : chosen template inputConstructor branch role (X.activeSourceView Global role database)) :
    GM.event Global template (fun _ => 0) role
      (RI.pullFixed Global role fixed) (RI.pullDB Global role database) := by
  let actual := A.merge (AC.live Global role AC.currentRoleCaps) fixed database
  have actualAll := AC.current_active_claims_complete_full_branch
    Global role AC.currentRoleCaps fixed branch database compatible claims
  obtain ⟨canonicalAll,stages,constructed,i,observerBranch,accepted,logEq,observerClaims,choice⟩ := selected
  let canon := canonical template inputConstructor branch (X.activeSourceView Global role database)
  let oracle := Q.claimOracle Global canon (fun _ => 0)
  have actualObserverClaims := observer_claims_from_same_original_branch template inputConstructor branch
    canon actual canonicalAll actualAll oracle stages constructed i observerBranch logEq observerClaims
  have sourceEq := observer_views_same_source template inputConstructor branch role fixed database
    oracle stages constructed i
  rw [sourceEq] at choice
  have data := GS.actual_native_constructor_derives_relation_data template inputConstructor oracle stages constructed i
  have hit := GS.actual_chosen_role_derives_causal_event
    (H.actualTerminalProducer Ctor stages i) stages[i.val].ns stages[i.val].relation stages[i.val].nonce
    observerBranch (fun key => actual (H.actualTerminalKeys Ctor oracle stages constructed i key))
    actualObserverClaims accepted template data role choice
  have globalHit := GS.actual_observer_causal_event_is_global Ctor oracle stages constructed i
    actual template role hit
  simpa only [actual,full_role_db,full_role_fixed] using globalHit

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalSourceSelector
