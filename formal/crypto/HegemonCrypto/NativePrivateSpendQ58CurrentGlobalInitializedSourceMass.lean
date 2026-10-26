import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalSourceSelector
import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceInitialized128

/-! The original global Born execution is cut once on source-only selectors.
Four causal selectors share one initialized prefix, actual branch weights and
the complete lifetime Q. There is no invocation sum, observer physical run,
event-inclusion premise or assumed source/Fourier commutation. SHA512 collision
terms apply only to this concrete current 64-byte oracle. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalInitializedSourceMass
open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.FiniteOracleDatabase
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun branchResult branchKeys)
open SmzaRp05AdaptivePhysicalReadBound (ReadsAtMost physicalBranchesFintype)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaChallengeStageTargets (Role)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter keyBytes encode decode zero)
end G
namespace H
export NativePrivateSpendQ58CurrentGlobalRawLogTransport (adaptiveHistoryProgram)
end H
namespace GS
export NativePrivateSpendQ58CurrentGlobalSourceSupport (NativeStageInput nativeConstructor)
end GS
namespace CS
export NativePrivateSpendQ58CurrentCausalSourceJoin (SourceTemplate)
end CS
namespace S
export NativePrivateSpendQ58CurrentGlobalSourceSelector
  (missingSource sourceCollision chosen actual_full_claims_cover_source_selector
   actual_global_chosen_selector_inserts)
end S
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay (fullClaims)
end Q
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims (live activeClaims fixedCompatible)
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end AC
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport
  (sourceKeys SourceView sourceProjection activeSourceView source_keys_active_for_each_role
   current_source_selector_commutes)
end X
namespace SC
export NativePrivateSpendQ58CurrentSourceCompletion (canonicalRecords)
end SC
namespace R
export NativePrivateSpendQ58CurrentFiberMassTransport
  (Active FixedVectors activeBytes actualActiveEquiv actualFixed routingTag)
end R
namespace RT
export NativePrivateSpendQ58CurrentRouteTransport (cap routeContext route_predicate fiber_exact)
end RT
namespace RI
export NativePrivateSpendQ58CurrentRoleInsertion (pullDB pullFixed)
end RI
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey Memory SparseState restrictFiber)
end A
namespace GM
export NativePrivateSpendQ58CurrentGlobalCausalMass
  (event current_global_four_role_causal_initialized_mass
   current_global_causal_coefficient_with_collision_and_cut_below_128)
end GM
namespace N
export NativePrivateSpendQ58CurrentRoleEventPhysicalMass (contexts localLoss)
end N
namespace K
export NativePrivateSpendQ58CurrentSelectedClaimFailureMass
  (Context sparse selected penalty internal_selector_claims_mass_transport)
export SmzaRp05CurrentPhysicalBranchClaims (workspace_event_mass_le_of_inclusion)
export SmzaRp05CurrentKnownClaimsFailureMass (database_event_complement_mass_split global_known_claims_failure_mass_le)
end K
namespace O
export SmzaRp05OrdinarySoundnessExecution
  (OrdinaryPrefix ordinaryRun compileOrdinary compileOrdinary_certified emptyAuthorizationContexts
   ordinaryRun_eq_compiled outside_empty_authorization_identity)
end O
namespace ST
export SmzaRp05OrdinarySoundnessStandardTotal (initialized_ordinary_run_standard_total)
end ST
namespace FC
export SmzaRp05FilteredCollision
  (filteredRawCollision filteredRawRecords filtered_raw_collision_instability filtered_raw_records_subset_raw)
end FC
namespace AR
export NativePrivateSpendQ58CurrentAcceptedSourceArithmetic
  (totalLoss total_loss_lt vector_card_lower)
end AR
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
variable (template : CS.SourceTemplate) (inputConstructor : Program (List GS.NativeStageInput))
local notation "Global" => H.adaptiveHistoryProgram (GS.nativeConstructor template inputConstructor)
local notation "V" => VectorOutput G.Counter
local notation "W" => SmzaRp05CurrentAdaptiveExecution.Work (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "State" => SmzaRp05CurrentAdaptiveExecution.CmsState (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "Metadata" => SmzaRp05CurrentAdaptiveExecution.Context (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "Registers" => RegisterBasis (Input:=G.Key Global) (Phase:=V) (Workspace:=W) → ℂ
def initial (registers : Registers) : State := partialRandomOracleState (Output:=V) ∅ registers
def reached {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) : State := O.ordinaryRun «prefix» (initial template inputConstructor registers)
def terminal {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) (branch : Branches G.decode Global) : State :=
  physicalRun (G.encode Global) G.decode Global branch (reached template inputConstructor «prefix» registers)
def failure (branch : Branches G.decode Global) (state : State) : State :=
  X.sourceProjection Global (fun view _ => S.missingSource template inputConstructor branch view) state
def missingSourceMass {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) : ℝ :=
  letI := physicalBranchesFintype G.decode Global
  ∑ branch : Branches G.decode Global, if branchResult G.decode Global branch = some () then
    normSquared (failure template inputConstructor branch (terminal template inputConstructor «prefix» registers branch)) else 0
def fiber (role : Role) (metadata : Metadata) (dummy : R.Active role (G.keyBytes Global))
    (fixed : R.FixedVectors (Counter:=G.Counter) role (G.keyBytes Global)) (state : State) :=
  SmzaRp05ConditionedExecution.fixedFiberToActive (N.contexts Global metadata role) RT.cap dummy fixed
    (SmzaRp05ConditionedExecution.otherRoleTransform (N.contexts Global metadata role) RT.cap state)
def nativeDB (role : Role) (database : Database (R.Active role (G.keyBytes Global)) V) :=
  fun key : A.ActiveKey (AC.live Global role AC.currentRoleCaps) =>
    database ((R.actualActiveEquiv role (G.keyBytes Global)).symm key)
def selector (role : Role) (select : X.SourceView Global → Prop) :=
  fun (_ : A.Memory (Key:=G.Key Global) (Counter:=G.Counter) (Work:=W)) database =>
    select (X.activeSourceView Global role (nativeDB template inputConstructor role database))
def roleMass (metadata : Metadata) (dummy : (role : Role) → R.Active role (G.keyBytes Global))
    (role : Role) (state : State) :=
  ∑ fixed : R.FixedVectors (Counter:=G.Counter) role (G.keyBytes Global),
    normSquared (workspaceEventProjection
      (fun _ database => GM.event Global template (fun _ => 0) role fixed database)
      (fiber template inputConstructor role metadata (dummy role) fixed state))
def collision (metadata : Metadata) :=
  FC.filteredRawCollision metadata.leafNamespace ∅ (R.activeBytes .decsSample (G.keyBytes Global)) G.zero
def collisionMass (metadata : Metadata) (dummy : R.Active .decsSample (G.keyBytes Global)) (state : State) :=
  ∑ fixed : R.FixedVectors (Counter:=G.Counter) .decsSample (G.keyBytes Global),
    normSquared (workspaceEventProjection (fun _ database => collision template inputConstructor metadata database)
      (fiber template inputConstructor .decsSample metadata dummy fixed state))

private theorem cast_indexed {Index : Type} {Family : Index → Type}
    {left right : Index} (same : left = right) (value : Family left) :
    (same ▸ value : Family right) = Eq.mp (congrArg Family same) value := by
  cases same
  rfl
private theorem cast_subtype_val {Index Key : Type}
    (pred : Index → Key → Prop) {left right : Index} (same : left = right)
    (key : { key : Key // pred left key }) :
    (Eq.mp (congrArg (fun index => { key : Key // pred index key }) same) key).val = key.val := by
  cases same
  rfl
private theorem cast_function_apply {Index : Type} {Domain : Index → Type} {Value : Type}
    {left right : Index} (same : left = right) (fn : Domain left → Value) (arg : Domain right) :
    (Eq.mp (congrArg (fun index => Domain index → Value) same) fn) arg =
      fn (Eq.mp (congrArg Domain same.symm) arg) := by
  cases same
  rfl
private theorem current_restrict_fiber_zero {Key Counter Work : Type}
    (live : Key → Prop) (dummy : A.ActiveKey live)
    (fixed : NativePrivateSpendQ58ActiveEventProjection.FixedTable (Counter := Counter) live) :
    A.restrictFiber (Work := Work) live dummy fixed 0 = 0 := by
  funext basis
  simp only [A.restrictFiber, Pi.zero_apply, ite_self]
private theorem current_workspace_projection_zero {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Output] [Fintype Phase] [Fintype Workspace]
    (event : Workspace → Database Input Output → Prop) :
    workspaceEventProjection event (0 : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace) = 0 := by
  funext basis
  simp only [workspaceEventProjection, Pi.zero_apply, ite_self]
private theorem current_norm_squared_zero {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Output] [Fintype Phase] [Fintype Workspace] :
    normSquared (0 : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace) = 0 := by
  simp only [normSquared, Pi.zero_apply, Complex.normSq_zero, Finset.sum_const_zero]
private theorem current_zero_projection_bound {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Output] [Fintype Phase] [Fintype Workspace]
    (leftEvent rightEvent : Workspace → Database Input Output → Prop) (factor : ℝ) :
    normSquared (workspaceEventProjection leftEvent (0 : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace)) ≤
      normSquared (workspaceEventProjection rightEvent (0 : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace)) +
        factor * normSquared (0 : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace) := by
  have massZero := current_norm_squared_zero
    (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)
  have leftZero := (congrArg normSquared (current_workspace_projection_zero
    (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace) leftEvent)).trans massZero
  have rightZero := (congrArg normSquared (current_workspace_projection_zero
    (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace) rightEvent)).trans massZero
  have rhsZero : normSquared (workspaceEventProjection rightEvent (0 : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace)) +
      factor * normSquared (0 : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace) = 0 := by
    rw [rightZero, massZero, mul_zero, add_zero]
  exact leftZero.le.trans rhsZero.symm.le
private theorem true_projection_mass {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Output] [Fintype Phase] [Fintype Workspace]
    (state : HegemonCrypto.CmsCompressedOracle.State Input Output Phase Workspace) :
    normSquared (workspaceEventProjection (fun _ _ => True) state) = normSquared state := by
  apply congrArg normSquared
  funext basis
  exact if_pos trivial
omit [DecidableEq BaseWork] in
private theorem nn (state : State) : 0 ≤ normSquared state := by
  unfold normSquared
  exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)
omit [DecidableEq BaseWork] in
private theorem cast_mass {l₀ l₁ : G.Key Global → Prop} (same : l₀=l₁)
    (event : A.Memory (Key:=G.Key Global) (Counter:=G.Counter) (Work:=W) →
      Database (A.ActiveKey l₀) V → Prop)
    (state : A.SparseState (Counter:=G.Counter) (Work:=W) l₀) :
    normSquared (workspaceEventProjection event state) =
      normSquared (workspaceEventProjection
        (fun memory database => event memory
          (Eq.mp (congrArg (fun live => Database (A.ActiveKey live) V) same.symm) database))
        (Eq.mp (congrArg (fun live => A.SparseState (Counter := G.Counter) (Work := W) live) same) state)) := by
  cases same
  rfl
private theorem fiber_mass (role : Role) (metadata : Metadata)
    (dummy : R.Active role (G.keyBytes Global)) (fixed : R.FixedVectors (Counter:=G.Counter) role (G.keyBytes Global))
    (state : State) (event : Database (R.Active role (G.keyBytes Global)) V → Prop) :
    normSquared (workspaceEventProjection (fun _ database => event database)
      (fiber template inputConstructor role metadata dummy fixed state)) =
    normSquared (workspaceEventProjection (fun _ database => event (RI.pullDB Global role database))
      (A.restrictFiber (AC.live Global role AC.currentRoleCaps)
        (R.actualActiveEquiv role (G.keyBytes Global) dummy) (R.actualFixed role (G.keyBytes Global) fixed)
        (NativePrivateSpendQ58PartitionTransport.conditioned (AC.live Global role AC.currentRoleCaps)
          (R.actualFixed role (G.keyBytes Global) fixed) state))) := by
  let same := RT.route_predicate role (G.keyBytes Global)
  have hd : Eq.mp (congrArg (fun live : G.Key Global → Prop => A.ActiveKey live) same) dummy =
      R.actualActiveEquiv role (G.keyBytes Global) dummy := by
   apply Subtype.ext
   exact cast_subtype_val (fun live key => live key) same dummy
  have hf : Eq.mp (congrArg (fun live : G.Key Global → Prop => NativePrivateSpendQ58ActiveEventProjection.FixedTable (Counter := G.Counter) live) same) fixed =
      R.actualFixed role (G.keyBytes Global) fixed := by
   funext key
   change (Eq.mp (congrArg (fun live : G.Key Global → Prop => {key : G.Key Global // ¬live key} → V) same) fixed) key =
     fixed ((NativePrivateSpendQ58CurrentFiberMassTransport.actualFixedEquiv role (G.keyBytes Global)).symm key)
   rw [cast_function_apply (Domain := fun live : G.Key Global → Prop => {key : G.Key Global // ¬live key}) same fixed key]
   exact congrArg fixed (Subtype.ext (cast_subtype_val (fun live key => ¬live key) same.symm key))
  have dbcast (d : Database (A.ActiveKey (AC.live Global role AC.currentRoleCaps)) V) :
      Eq.mp (congrArg (fun live : G.Key Global → Prop => Database (A.ActiveKey live) V) same.symm) d =
        RI.pullDB Global role d := by
   funext key
   change (Eq.mp (congrArg (fun live : G.Key Global → Prop => A.ActiveKey live → Option V) same.symm) d) key =
     d (R.actualActiveEquiv role (G.keyBytes Global) key)
   rw [cast_function_apply (Domain := fun live : G.Key Global → Prop => A.ActiveKey live) (Value := Option V) same.symm d key]
   exact congrArg d (Subtype.ext (cast_subtype_val (fun live key => live key) same key))
  have fiberEq :
      Eq.mp (congrArg (fun live : G.Key Global → Prop =>
        A.SparseState (Counter := G.Counter) (Work := W) live) same)
        (fiber template inputConstructor role metadata dummy fixed state) =
      A.restrictFiber (AC.live Global role AC.currentRoleCaps)
        (Eq.mp (congrArg (fun live : G.Key Global → Prop => A.ActiveKey live) same) dummy)
        (Eq.mp (congrArg (fun live : G.Key Global → Prop => NativePrivateSpendQ58ActiveEventProjection.FixedTable (Counter := G.Counter) live) same) fixed)
        (NativePrivateSpendQ58PartitionTransport.conditioned (AC.live Global role AC.currentRoleCaps)
          (Eq.mp (congrArg (fun live : G.Key Global → Prop => NativePrivateSpendQ58ActiveEventProjection.FixedTable (Counter := G.Counter) live) same) fixed) state) := by
   have retained := RT.fiber_exact metadata role (G.keyBytes Global) dummy fixed state
   have argsEq := congrArg₂
     (fun (dummy : A.ActiveKey (AC.live Global role AC.currentRoleCaps)) (fixed : NativePrivateSpendQ58ActiveEventProjection.FixedTable (Counter := G.Counter) (AC.live Global role AC.currentRoleCaps)) => (dummy, fixed))
     (cast_indexed (Family := fun live : G.Key Global → Prop => A.ActiveKey live) same dummy)
     (cast_indexed (Family := fun live : G.Key Global → Prop => NativePrivateSpendQ58ActiveEventProjection.FixedTable (Counter := G.Counter) live) same fixed)
   have resultEq := congrArg
     (fun args : A.ActiveKey (AC.live Global role AC.currentRoleCaps) × NativePrivateSpendQ58ActiveEventProjection.FixedTable (Counter := G.Counter) (AC.live Global role AC.currentRoleCaps) =>
       A.restrictFiber (AC.live Global role AC.currentRoleCaps) args.1 args.2
         (NativePrivateSpendQ58PartitionTransport.conditioned (AC.live Global role AC.currentRoleCaps) args.2 state)) argsEq
   exact retained.trans resultEq
  have mass := cast_mass template inputConstructor same (fun _ d => event d) (fiber template inputConstructor role metadata dummy fixed state)
  calc
   _ = normSquared (workspaceEventProjection
       (fun _ d => event (Eq.mp (congrArg (fun live : G.Key Global → Prop => Database (A.ActiveKey live) V) same.symm) d))
       (Eq.mp (congrArg (fun live : G.Key Global → Prop => A.SparseState (Counter := G.Counter) (Work := W) live) same)
         (fiber template inputConstructor role metadata dummy fixed state))) := mass
   _ = _ := by
    have argsEq := congrArg₂
      (fun (dummy : A.ActiveKey (AC.live Global role AC.currentRoleCaps)) (fixed : NativePrivateSpendQ58ActiveEventProjection.FixedTable (Counter := G.Counter) (AC.live Global role AC.currentRoleCaps)) => (dummy, fixed)) hd hf
    have stateEq := fiberEq.trans (congrArg
     (fun args : A.ActiveKey (AC.live Global role AC.currentRoleCaps) × NativePrivateSpendQ58ActiveEventProjection.FixedTable (Counter := G.Counter) (AC.live Global role AC.currentRoleCaps) =>
       A.restrictFiber (AC.live Global role AC.currentRoleCaps) args.1 args.2
         (NativePrivateSpendQ58PartitionTransport.conditioned (AC.live Global role AC.currentRoleCaps) args.2 state)) argsEq)
    have eventEq :
        (fun (_ : A.Memory (Key := G.Key Global) (Counter := G.Counter) (Work := W)) d =>
          event (Eq.mp (congrArg (fun live : G.Key Global → Prop => Database (A.ActiveKey live) V) same.symm) d)) =
        (fun _ d => event (RI.pullDB Global role d)) := by
     funext memory database
     exact congrArg event (dbcast database)
    exact congrArg normSquared (congrArg₂ workspaceEventProjection eventEq stateEq)

/-- Generic original-program specialization of the retained selector law;
the source selector commutation is proved on Global before norm preservation. -/
theorem source_mass (role : Role) (metadata : Metadata) (dummy : R.Active role (G.keyBytes Global))
    (branch : Branches G.decode Global) {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) (select : X.SourceView Global → Prop) :
    normSquared (X.sourceProjection Global (fun view _ => select view)
      (terminal template inputConstructor «prefix» registers branch)) =
    ∑ fixed : R.FixedVectors (Counter:=G.Counter) role (G.keyBytes Global),
      normSquared (workspaceEventProjection (selector template inputConstructor role select)
        (fiber template inputConstructor role metadata dummy fixed
          (terminal template inputConstructor «prefix» registers branch))) := by
  have unparsed : ∀ key ∈ X.sourceKeys Global,
      SmzaChallengeStageTargets.parseStageQuery ((N.contexts Global metadata role).keyBytes key)=none := by
    intro key member
    have active := X.source_keys_active_for_each_role Global role key member
    change NativePrivateSpendQ58CurrentRoleClassifier.RoleActive role
      NativePrivateSpendQ58CurrentGammaFiber.currentRoleCaps (G.keyBytes Global) key at active
    dsimp only [N.contexts, RT.routeContext, R.routingTag]
    rw [if_pos active]
    rfl
  have split := SmzaRp05OrdinarySoundnessStandardTotal.ordinary_physical_branch_selector_mass_eq_active_fiber_sum
    «prefix» registers (G.encode Global) G.decode Global branch (N.contexts Global metadata role) RT.cap dummy
    (X.sourceKeys Global) unparsed (fun view _ => select view)
  have commuting := congrArg normSquared (X.current_source_selector_commutes Global metadata role
    (fun view _ => select view) (terminal template inputConstructor «prefix» registers branch))
  rw [SmzaRp05ConditionedExecution.other_role_transform_norm_squared] at commuting
  dsimp only [X.sourceProjection] at commuting
  have joined := commuting.symm.trans split
  refine joined.trans ?_
  apply Finset.sum_congr rfl
  intro fixed _
  refine congrArg normSquared ?_
  refine congrArg (fun event => workspaceEventProjection event
    (fiber template inputConstructor role metadata dummy fixed
      (terminal template inputConstructor «prefix» registers branch))) ?_
  funext memory database
  rfl

theorem chosen_mass (role : Role) (metadata : Metadata) (dummy : R.Active role (G.keyBytes Global))
    (fixed : R.FixedVectors (Counter:=G.Counter) role (G.keyBytes Global))
    (branch : Branches G.decode Global) (initialState : State) :
    normSquared (workspaceEventProjection (selector template inputConstructor role (S.chosen template inputConstructor branch role))
      (fiber template inputConstructor role metadata dummy fixed (physicalRun (G.encode Global) G.decode Global branch initialState))) ≤
    normSquared (workspaceEventProjection (fun _ database => GM.event Global template (fun _ => 0) role fixed database)
      (fiber template inputConstructor role metadata dummy fixed (physicalRun (G.encode Global) G.decode Global branch initialState))) +
      (((2*(AC.activeClaims Global role AC.currentRoleCaps branch).toFinset.card : Nat):ℝ)/Fintype.card V) *
        normSquared (fiber template inputConstructor role metadata dummy fixed (physicalRun (G.encode Global) G.decode Global branch initialState)) := by
  let context : K.Context Global role W :=
    ⟨R.actualActiveEquiv role (G.keyBytes Global) dummy,R.actualFixed role (G.keyBytes Global) fixed,branch,initialState⟩
  have unselectedRaw := fiber_mass template inputConstructor role metadata dummy fixed
   (physicalRun (G.encode Global) G.decode Global branch initialState) (fun _ => True)
  have unselected :=
   (true_projection_mass (fiber template inputConstructor role metadata dummy fixed
     (physicalRun (G.encode Global) G.decode Global branch initialState))).symm.trans
    (unselectedRaw.trans (true_projection_mass
     (A.restrictFiber (AC.live Global role AC.currentRoleCaps) (R.actualActiveEquiv role (G.keyBytes Global) dummy)
      (R.actualFixed role (G.keyBytes Global) fixed)
      (NativePrivateSpendQ58PartitionTransport.conditioned (AC.live Global role AC.currentRoleCaps)
       (R.actualFixed role (G.keyBytes Global) fixed) (physicalRun (G.encode Global) G.decode Global branch initialState)))))
  have leftMass := fiber_mass template inputConstructor role metadata dummy fixed
   (physicalRun (G.encode Global) G.decode Global branch initialState)
   (fun database => S.chosen template inputConstructor branch role (X.activeSourceView Global role (nativeDB template inputConstructor role database)))
  have rightMass := fiber_mass template inputConstructor role metadata dummy fixed
   (physicalRun (G.encode Global) G.decode Global branch initialState)
   (fun database => GM.event Global template (fun _ => 0) role fixed database)
  change normSquared (workspaceEventProjection
   (fun _ database => S.chosen template inputConstructor branch role (X.activeSourceView Global role (nativeDB template inputConstructor role database)))
   (fiber template inputConstructor role metadata dummy fixed (physicalRun (G.encode Global) G.decode Global branch initialState))) ≤ _
  rw [leftMass, rightMass, unselected]
  have pull:RI.pullFixed Global role (R.actualFixed role (G.keyBytes Global) fixed)=fixed:=by funext k;rfl
  have dbpull (database : Database (A.ActiveKey (AC.live Global role AC.currentRoleCaps)) V) :
      nativeDB template inputConstructor role (RI.pullDB Global role database) = database := by
   funext key
   rfl
  by_cases compatible:AC.fixedCompatible Global role AC.currentRoleCaps context.fixed branch
  · have bound :=
     K.internal_selector_claims_mass_transport context (fun _ database=>S.chosen template inputConstructor branch role (X.activeSourceView Global role database))
     (fun _ database=>GM.event Global template (fun _ => 0) role (RI.pullFixed Global role context.fixed) (RI.pullDB Global role database))
     (by intro _ database selected claims;exact S.actual_global_chosen_selector_inserts template inputConstructor branch role context.fixed database compatible claims selected)
    dsimp (config := { instances := true }) only
     [K.selected, K.sparse, K.penalty,
      NativePrivateSpendQ58CurrentSelectedClaimFailureMass.conditioned,
      NativePrivateSpendQ58CurrentSelectedClaimFailureMass.claims, context,
      NativePrivateSpendQ58CurrentSelectedClaimFailureMass.live,
      NativePrivateSpendQ58CurrentSourceSelectorTransport.live, AC.live] at bound
    dsimp (config := { instances := true }) only [NativePrivateSpendQ58CurrentSelectedClaimFailureMass.live,
      NativePrivateSpendQ58CurrentSourceSelectorTransport.live, AC.live] at dbpull ⊢
    simpa only [dbpull, pull] using bound
  · have zero:=NativePrivateSpendQ58CurrentConditionedBranchReadback.current_incompatible_conditioned_branch_is_zero
     Global role AC.currentRoleCaps context.fixed branch compatible initialState
    have zeroTyped : NativePrivateSpendQ58PartitionTransport.conditioned (AC.live Global role AC.currentRoleCaps) context.fixed
        (physicalRun (G.encode Global) G.decode Global branch initialState) = 0 := by
     exact zero
    have sparseZero :
        A.restrictFiber (AC.live Global role AC.currentRoleCaps) context.dummy context.fixed
          (NativePrivateSpendQ58PartitionTransport.conditioned (AC.live Global role AC.currentRoleCaps) context.fixed
            (physicalRun (G.encode Global) G.decode Global branch initialState)) = 0 := by
     exact (congrArg (A.restrictFiber (AC.live Global role AC.currentRoleCaps) context.dummy context.fixed) zeroTyped).trans
       (current_restrict_fiber_zero (AC.live Global role AC.currentRoleCaps) context.dummy context.fixed)
    dsimp (config := { instances := true }) only [NativePrivateSpendQ58CurrentSelectedClaimFailureMass.live,
      NativePrivateSpendQ58CurrentSourceSelectorTransport.live, AC.live] at sparseZero ⊢
    rw [sparseZero]
    exact current_zero_projection_bound _ _ _

private theorem key_count {Key Result : Type} (encode : V8SmzaOracleParser.RawInput → Key)
    (program : Program Result) (count : Nat) (branch : Branches G.decode program)
    (reads : ReadsAtMost G.decode count program) : (branchKeys encode G.decode program branch).length ≤ count := by
  induction count generalizing program with
  | zero => cases program with
    | done result => simp [branchKeys]
    | read input next => cases reads
  | succ count ih => cases program with
    | done result => simp [branchKeys]
    | read input next =>
      rcases branch with ⟨answer,tail⟩
      simpa [branchKeys] using Nat.succ_le_succ (ih (next (G.decode input answer)) tail (reads answer))
private theorem current_branch_claims_length {Key Output : Type}
    (keys : List Key) (answers : SmzaRp05PhysicalAcceptedReplayLite.ReadAnswers Output keys) :
    (SmzaRp05PhysicalAcceptedReplayLite.branchClaims keys answers).length = keys.length := by
  induction keys with
  | nil => rfl
  | cons key keys ih =>
    rcases answers with ⟨answer, answers⟩
    exact congrArg Nat.succ (ih answers)
theorem full_count (branch : Branches G.decode Global) (count : Nat) (reads : ReadsAtMost G.decode count Global) :
    (Q.fullClaims Global branch).length ≤ count := by
  rw [Q.fullClaims,current_branch_claims_length]
  exact key_count (G.encode Global) Global count branch reads

private theorem source_cut (branch : Branches G.decode Global) (initialState : State)
    (accepted : branchResult G.decode Global branch=some ()) :
    let state := physicalRun (G.encode Global) G.decode Global branch initialState
    normSquared (failure template inputConstructor branch state) ≤
      normSquared (X.sourceProjection Global (fun view _ =>
        S.sourceCollision template inputConstructor view ∨ ∃ role,S.chosen template inputConstructor branch role view) state) +
      (((2*(Q.fullClaims Global branch).toFinset.card : Nat):ℝ)/Fintype.card V) * normSquared state := by
  dsimp only
  let state := physicalRun (G.encode Global) G.decode Global branch initialState
  let claims := ClaimsDatabaseEvent (Q.fullClaims Global branch)
  let missing := fun database => S.missingSource template inputConstructor branch
    (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database)
  have split := K.database_event_complement_mass_split claims (failure template inputConstructor branch state)
  have included : normSquared (databaseEventProjection claims (failure template inputConstructor branch state)) ≤
      normSquared (X.sourceProjection Global (fun view _ =>
        S.sourceCollision template inputConstructor view ∨ ∃ role,S.chosen template inputConstructor branch role view) state) := by
    convert K.workspace_event_mass_le_of_inclusion (fun _ database => claims database ∧ missing database)
      (fun _ database => S.sourceCollision template inputConstructor
        (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database) ∨
        ∃ role,S.chosen template inputConstructor branch role
          (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database)) state
      (by intro _ database both
          exact S.actual_full_claims_cover_source_selector template inputConstructor branch database both.1 accepted both.2) using 1
    · congr 1
      funext basis
      by_cases recorded : claims basis.database <;> by_cases excluded : missing basis.database <;>
        simp [failure,X.sourceProjection,SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection,
          databaseEventProjection,workspaceEventProjection,missing,claims,recorded,excluded]
    · rfl
  have debt : normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims Global branch) state) ≤
      (((2*(Q.fullClaims Global branch).toFinset.card : Nat):ℝ)/Fintype.card V) * normSquared state := by
    apply K.global_known_claims_failure_mass_le
    intro claim member
    exact SmzaRp05CurrentPhysicalBranchClaimReadback.physical_branch_claim_known_at_standard
      (G.encode Global) G.decode Global branch initialState claim member
  have selected : normSquared (databaseEventProjection (fun database => ¬claims database)
      (failure template inputConstructor branch state)) ≤
      normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims Global branch) state) := by
    convert K.workspace_event_mass_le_of_inclusion (fun _ database => ¬claims database ∧ missing database)
      (fun _ database => ¬claims database) state (by intro _ _ both;exact both.1) using 1
    · congr 1
      funext basis
      by_cases absent : ¬claims basis.database <;> by_cases excluded : missing basis.database <;>
        simp [failure,X.sourceProjection,SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection,
          databaseEventProjection,workspaceEventProjection,missing,claims,absent,excluded]
    · rfl
  have paid := selected.trans debt
  linarith

omit [DecidableEq BaseWork] in
private theorem selector_union (branch : Branches G.decode Global) (state : State) :
    normSquared (X.sourceProjection Global (fun view _ =>
      S.sourceCollision template inputConstructor view ∨ ∃ role,S.chosen template inputConstructor branch role view) state) ≤
    normSquared (X.sourceProjection Global (fun view _ => S.sourceCollision template inputConstructor view) state) +
      ∑ role : Role,normSquared (X.sourceProjection Global (fun view _ => S.chosen template inputConstructor branch role view) state) := by
  unfold X.sourceProjection SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection normSquared workspaceEventProjection
  rw [Finset.sum_comm,←Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro basis _
  by_cases bad : S.sourceCollision template inputConstructor
      (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) basis.database) ∨
      ∃ role,S.chosen template inputConstructor branch role
        (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) basis.database)
  · rw [if_pos bad]
    rcases bad with collisionHit | selected
    · rw [if_pos collisionHit]
      exact le_add_of_nonneg_right (Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _))
    · obtain ⟨role,roleHit⟩ := selected
      let values : Role → ℝ := fun selectedRole => Complex.normSq
        (if S.chosen template inputConstructor branch selectedRole
          (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) basis.database)
         then state basis else 0)
      have one : values role ≤ ∑ selectedRole : Role, values selectedRole := by
        apply Finset.single_le_sum (f := values)
        · intro selectedRole _
          dsimp only [values]
          exact Complex.normSq_nonneg _
        · exact Finset.mem_univ role
      dsimp only [values] at one
      rw [if_pos roleHit] at one
      exact one.trans (le_add_of_nonneg_left (Complex.normSq_nonneg _))
  · rw [if_neg bad]
    simp only [Complex.normSq_zero]
    exact add_nonneg (Complex.normSq_nonneg _) (Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _))

def collisionSpec (metadata : Metadata) (q : Nat)
    (fixed : R.FixedVectors (Counter:=G.Counter) .decsSample (G.keyBytes Global)) :
    SmzaRp05ActualEventRecertification.EventSpec
      (SmzaRp05ConditionedExecution.activeContext (N.contexts Global metadata .decsSample) RT.cap fixed) q where
  base := fun _ => collision template inputConstructor metadata
  bound := (q:ℝ)/2^512
  bound_nonnegative := by positivity
  instability := fun _ => by
    dsimp only [N.contexts, RT.routeContext, collision]
    simpa only [Rat.cast_div, Rat.cast_natCast, Rat.cast_pow, Rat.cast_ofNat] using!
      (FC.filtered_raw_collision_instability metadata.leafNamespace ∅
        (R.activeBytes .decsSample (G.keyBytes Global)) G.zero q).toReal
  mark_mono := fun _ _ _ hit => hit
  marked_write := by
    intro _ statement _ key parsed _ _ _
    have absent : SmzaRp05FilteredReadback.globalLeafStatement metadata.leafNamespace
        (R.routingTag .decsSample (G.keyBytes Global) key.val)=none := by
      unfold R.routingTag
      split <;> rfl
    change SmzaRp05FilteredReadback.globalLeafStatement metadata.leafNamespace
      (R.routingTag .decsSample (G.keyBytes Global) key.val)=some statement at parsed
    rw [absent] at parsed
    cases parsed
  empty_false := by
    intro _
    unfold collision FC.filteredRawCollision
    apply Classical.not_not.mpr
    intro left right output member _
    have raw := FC.filtered_raw_records_subset_raw metadata.leafNamespace ∅
      (R.activeBytes .decsSample (G.keyBytes Global)) G.zero _ member
    simp [V8Smz9CoherentMerkleInstrument.rawRecords] at raw

omit [Fintype BaseWork] [DecidableEq BaseWork] in
private theorem collision_inserts (metadata : Metadata)
    (database : Database (R.Active .decsSample (G.keyBytes Global)) V)
    (hit : S.sourceCollision template inputConstructor
      (X.activeSourceView Global .decsSample (nativeDB template inputConstructor .decsSample database))) :
    collision template inputConstructor metadata database := by
  unfold collision FC.filteredRawCollision
  intro free
  apply hit
  have subset :
      SC.canonicalRecords Global
        (X.activeSourceView Global .decsSample (nativeDB template inputConstructor .decsSample database)) ⊆
      V8Smz9CoherentMerkleInstrument.rawRecords (R.activeBytes .decsSample (G.keyBytes Global)) (V8Smz9CoherentVectorMerkle.vectorOutputBytes G.zero) database := by
    intro pair member
    rcases pair with ⟨input, output⟩
    obtain ⟨key, vector, stored, bytes, digest⟩ :=
      (SmzaRawDatabaseRecords.mem_raw_records_iff
        (fun key : { key : G.Key Global // key ∈ X.sourceKeys Global } => G.keyBytes Global key.val)
        (V8Smz9CoherentVectorMerkle.vectorOutputBytes G.zero)
        (X.activeSourceView Global .decsSample (nativeDB template inputConstructor .decsSample database))
        input output).mp member
    apply (SmzaRawDatabaseRecords.mem_raw_records_iff
      (R.activeBytes .decsSample (G.keyBytes Global)) (V8Smz9CoherentVectorMerkle.vectorOutputBytes G.zero) database input output).mpr
    exact ⟨(R.actualActiveEquiv .decsSample (G.keyBytes Global)).symm
      ⟨key.val, X.source_keys_active_for_each_role Global .decsSample key.val key.property⟩,
      vector, stored, bytes, digest⟩
  have freeRaw : SmzaRecordedTracePath.RecordsCollisionFree
      (V8Smz9CoherentMerkleInstrument.rawRecords (R.activeBytes .decsSample (G.keyBytes Global)) (V8Smz9CoherentVectorMerkle.vectorOutputBytes G.zero) database) := by
    simpa only [FC.filteredRawRecords, O.outside_empty_authorization_identity] using free
  exact SmzaRp04StatementRecordFilter.recordsCollisionFree_mono subset freeRaw

private theorem branch_zero_bound {C R a m : ℝ}
    (cn : 0 ≤ C) (rn : 0 ≤ R) (an : 0 ≤ a) (mn : 0 ≤ m) :
    0 ≤ C+R+a*m :=
  add_nonneg (add_nonneg cn rn) (mul_nonneg an mn)

private theorem branch_scalar_bound {f u c s C R p : ℝ} (q d m : ℝ)
    (cut : f ≤ u+p) (unionBound : u ≤ c+s) (collisionBound : c ≤ C)
    (selectedBound : s ≤ R+4*((2*q/d)*m)) (debtBound : p ≤ (2*q/d)*m)
    (unitNonnegative : 0 ≤ (q/d)*m) : f ≤ C+R+(20*q/d)*m := by
  calc
    f ≤ u+p := cut
    _ ≤ (c+s)+(2*q/d)*m := add_le_add unionBound debtBound
    _ ≤ (C+(R+4*((2*q/d)*m)))+(2*q/d)*m :=
      add_le_add (add_le_add collisionBound selectedBound) le_rfl
    _ = C+R+10*((q/d)*m) := by ring
    _ ≤ C+R+20*((q/d)*m) :=
      add_le_add le_rfl
        (mul_le_mul_of_nonneg_right (by norm_num : (10:ℝ) ≤ 20) unitNonnegative)
    _ = C+R+(20*q/d)*m := by ring

private theorem branch_bound (metadata : Metadata)
    (dummy : (role : Role) → R.Active role (G.keyBytes Global))
    {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) (branch : Branches G.decode Global)
    (count : Nat) (reads : ReadsAtMost G.decode count Global) (within : count≤q) :
    (if branchResult G.decode Global branch=some () then
      normSquared (failure template inputConstructor branch (terminal template inputConstructor «prefix» registers branch)) else 0) ≤
      collisionMass template inputConstructor metadata (dummy .decsSample) (terminal template inputConstructor «prefix» registers branch) +
      (∑ role : Role,roleMass template inputConstructor metadata dummy role (terminal template inputConstructor «prefix» registers branch)) +
      (20*(q:ℝ)/Fintype.card V)*normSquared (terminal template inputConstructor «prefix» registers branch) := by
  let state := terminal template inputConstructor «prefix» registers branch
  have cn : 0≤collisionMass template inputConstructor metadata (dummy .decsSample) state := by
    unfold collisionMass
    exact Finset.sum_nonneg (fun _ _ => by
      unfold normSquared
      exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _))
  have rn : 0≤∑ role : Role,roleMass template inputConstructor metadata dummy role state := by
    unfold roleMass
    exact Finset.sum_nonneg (fun _ _ => Finset.sum_nonneg (fun _ _ => by
      unfold normSquared
      exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)))
  by_cases accepted : branchResult G.decode Global branch=some ()
  · rw [if_pos accepted]
    have cut := source_cut template inputConstructor branch (reached template inputConstructor «prefix» registers) accepted
    have union := selector_union template inputConstructor branch state
    have coll : normSquared (X.sourceProjection Global (fun view _ => S.sourceCollision template inputConstructor view) state) ≤
        collisionMass template inputConstructor metadata (dummy .decsSample) state := by
      rw [source_mass template inputConstructor .decsSample metadata (dummy .decsSample) branch «prefix» registers]
      apply Finset.sum_le_sum
      intro fixed _
      exact K.workspace_event_mass_le_of_inclusion _ _ _
        (by intro _ database hit;exact collision_inserts template inputConstructor metadata database hit)
    have choices : ∀ role : Role,
        normSquared (X.sourceProjection Global (fun view _ => S.chosen template inputConstructor branch role view) state) ≤
        roleMass template inputConstructor metadata dummy role state + (2*(q:ℝ)/Fintype.card V)*normSquared state := by
      intro role
      have rawSplit := source_mass template inputConstructor role metadata (dummy role) branch «prefix» registers (fun _ => True)
      simp only [X.sourceProjection,SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection,
        true_projection_mass] at rawSplit
      have fiberProjection (fixed : R.FixedVectors (Counter:=G.Counter) role (G.keyBytes Global)) :
          workspaceEventProjection (selector template inputConstructor role (fun _ => True))
            (fiber template inputConstructor role metadata (dummy role) fixed state) =
          fiber template inputConstructor role metadata (dummy role) fixed state := by
        funext basis
        exact if_pos trivial
      have split : normSquared state =
          ∑ fixed : R.FixedVectors (Counter:=G.Counter) role (G.keyBytes Global),
            normSquared (fiber template inputConstructor role metadata (dummy role) fixed state) := by
        refine rawSplit.trans ?_
        apply Finset.sum_congr rfl
        intro fixed _
        exact congrArg normSquared (fiberProjection fixed)
      rw [source_mass template inputConstructor role metadata (dummy role) branch «prefix» registers]
      calc
        _ ≤ ∑ fixed : R.FixedVectors (Counter:=G.Counter) role (G.keyBytes Global),
          (normSquared (workspaceEventProjection (fun _ database => GM.event Global template (fun _ => 0) role fixed database)
            (fiber template inputConstructor role metadata (dummy role) fixed state)) +
          (2*(q:ℝ)/Fintype.card V)*normSquared (fiber template inputConstructor role metadata (dummy role) fixed state)) := by
            apply Finset.sum_le_sum
            intro fixed _
            apply (chosen_mass template inputConstructor role metadata (dummy role) fixed branch
              (reached template inputConstructor «prefix» registers)).trans
            apply add_le_add le_rfl
            apply mul_le_mul_of_nonneg_right _ (by
              unfold normSquared
              exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _))
            apply div_le_div_of_nonneg_right _ (by positivity)
            have activeCount : (AC.activeClaims Global role AC.currentRoleCaps branch).toFinset.card≤q :=
              (List.toFinset_card_le _).trans ((List.length_filterMap_le _ _).trans
                ((full_count template inputConstructor branch count reads).trans within))
            exact_mod_cast Nat.mul_le_mul_left 2 activeCount
        _ = _ := by
          rw [Finset.sum_add_distrib,←Finset.mul_sum]
          have transported := congrArg (fun mass : ℝ =>
            roleMass template inputConstructor metadata dummy role state +
              (2*(q:ℝ)/Fintype.card V)*mass) split.symm
          simpa (config := { instances := true }) only [N.contexts, RT.routeContext] using! transported
    have sumChoices := Finset.sum_le_sum (s := (Finset.univ : Finset Role)) (fun role _ => choices role)
    have roleCount : Fintype.card Role=4 := by decide
    rw [Finset.sum_add_distrib] at sumChoices
    simp only [Finset.sum_const,Finset.card_univ,roleCount,nsmul_eq_mul] at sumChoices
    have fullCount : (Q.fullClaims Global branch).toFinset.card≤q :=
      (List.toFinset_card_le _).trans ((full_count template inputConstructor branch count reads).trans within)
    have debt : (((2*(Q.fullClaims Global branch).toFinset.card:Nat):ℝ)/Fintype.card V)*normSquared state ≤
        (2*(q:ℝ)/Fintype.card V)*normSquared state := by
      apply mul_le_mul_of_nonneg_right _ (nn template inputConstructor _)
      apply div_le_div_of_nonneg_right _ (by positivity)
      exact_mod_cast Nat.mul_le_mul_left 2 fullCount
    have qn : 0≤(q:ℝ)/Fintype.card V := by positivity
    have unitDebtNonnegative :
        0 ≤ ((q:ℝ)/Fintype.card V)*normSquared state :=
      mul_nonneg qn (nn template inputConstructor state)
    change normSquared (failure template inputConstructor branch state) ≤
      normSquared (X.sourceProjection Global (fun view _ =>
        S.sourceCollision template inputConstructor view ∨
          ∃ role, S.chosen template inputConstructor branch role view) state) +
      (((2*(Q.fullClaims Global branch).toFinset.card:Nat):ℝ)/Fintype.card V)*
        normSquared state at cut
    change normSquared (failure template inputConstructor branch state) ≤
      collisionMass template inputConstructor metadata (dummy .decsSample) state +
      (∑ role : Role, roleMass template inputConstructor metadata dummy role state) +
      (20*(q:ℝ)/Fintype.card V)*normSquared state
    exact branch_scalar_bound (q:ℝ) (Fintype.card V) (normSquared state)
      cut union coll sumChoices debt unitDebtNonnegative
  · rw [if_neg accepted]
    change 0 ≤
      collisionMass template inputConstructor metadata (dummy .decsSample) state +
      (∑ role : Role, roleMass template inputConstructor metadata dummy role state) +
      (20*(q:ℝ)/Fintype.card V)*normSquared state
    have coefficientNonnegative : 0 ≤ 20*(q:ℝ)/(Fintype.card V:ℝ) :=
      div_nonneg (mul_nonneg (by norm_num : (0:ℝ) ≤ 20) (Nat.cast_nonneg q))
        (Nat.cast_nonneg (Fintype.card V))
    exact branch_zero_bound cn rn coefficientNonnegative
      (nn template inputConstructor state)

/-- The unchanged coarse263 loss already leaves a129-bit proof budget.
No primitive advantage or threshold is renamed by this arithmetic lemma. -/
theorem current_global_coefficient_below_129 (q : Nat) (budget : q≤3*2^64) :
    6*(q:ℝ)^2*(∑ role : Role,(((3*q:Rat)/(2^512:Rat)+N.localLoss role:Rat):ℝ)) +
      16*(q:ℝ)^3/2^512+20*q/Fintype.card V < (2:ℝ)^(-129:ℤ) := by
  have power512 : (2:ℝ)^512 = 2^256*2^256 :=
    pow_add (2:ℝ) 256 256
  have power263 : (2:ℝ)^263 = 2^256*2^7 :=
    pow_add (2:ℝ) 256 7
  have roleCount : Fintype.card Role=4 := by decide
  have sumLoss : (∑ role : Role,(((3*q:Rat)/(2^512:Rat)+N.localLoss role:Rat):ℝ)) =
      12*(q:ℝ)/2^512+(AR.totalLoss:ℝ) := by
    simp only [Rat.cast_add,Rat.cast_div,Rat.cast_mul,Rat.cast_natCast,Rat.cast_pow,Rat.cast_ofNat,
      Finset.sum_add_distrib,Finset.sum_const,Finset.card_univ,roleCount,nsmul_eq_mul,
      AR.totalLoss,Rat.cast_sum]
    simp only [power512]
    ring
  rw [sumLoss]
  have qb : (q:ℝ)≤3*2^64 := by exact_mod_cast budget
  have castLoss := (Rat.cast_lt (K := ℝ)).mpr AR.total_loss_lt
  have loss : (AR.totalLoss:ℝ)≤(1:ℝ)/2^263 := by
    apply le_of_lt
    simpa only [Rat.cast_div, Rat.cast_one, Rat.cast_pow, Rat.cast_ofNat] using castLoss
  have card : (2:ℝ)^512≤Fintype.card V := by
    exact_mod_cast AR.vector_card_lower G.zero
  have equivalent : 6*(q:ℝ)^2*(12*(q:ℝ)/2^512+(AR.totalLoss:ℝ))+
      16*(q:ℝ)^3/2^512+20*q/Fintype.card V =
      6*(q:ℝ)^2*(AR.totalLoss:ℝ)+
        88*(q:ℝ)^3/2^512+20*q/Fintype.card V := by
      simp only [power512]
      ring
  rw [equivalent]
  calc
    _ ≤ 6*(q:ℝ)^2*((1:ℝ)/2^263)+88*(q:ℝ)^3/2^512+20*q/2^512 := by
      apply add_le_add
      · have scaleNonnegative : 0 ≤ 6*(q:ℝ)^2 :=
          mul_nonneg (by norm_num : (0:ℝ) ≤ 6) (sq_nonneg (q:ℝ))
        have scaledLoss : (6*(q:ℝ)^2)*(AR.totalLoss:ℝ) ≤
            (6*(q:ℝ)^2)*((1:ℝ)/2^263) :=
          mul_le_mul_of_nonneg_left loss scaleNonnegative
        exact add_le_add scaledLoss le_rfl
      · have numeratorNonnegative : 0 ≤ 20*(q:ℝ) :=
          mul_nonneg (by norm_num : (0:ℝ) ≤ 20) (Nat.cast_nonneg q)
        have denominatorPositive : 0 < (2:ℝ)^512 :=
          pow_pos (by norm_num : (0:ℝ) < 2) 512
        exact div_le_div_of_nonneg_left numeratorNonnegative denominatorPositive card
    _ ≤ 6*(3*2^64)^2*((1:ℝ)/2^263)+88*(3*2^64)^3/2^512+20*(3*2^64)/2^512 := by
      have qNonnegative : (0:ℝ) ≤ (q:ℝ) := Nat.cast_nonneg q
      have squareBound : (q:ℝ)^2 ≤ ((3:ℝ)*2^64)^2 :=
        pow_le_pow_left₀ qNonnegative qb 2
      have cubeBound : (q:ℝ)^3 ≤ ((3:ℝ)*2^64)^3 :=
        pow_le_pow_left₀ qNonnegative qb 3
      have twoNonnegative : (0:ℝ) ≤ 2 := by norm_num
      have denominator263Nonnegative : (0:ℝ) ≤ (2:ℝ)^263 :=
        pow_nonneg twoNonnegative 263
      have denominator512Nonnegative : (0:ℝ) ≤ (2:ℝ)^512 :=
        pow_nonneg twoNonnegative 512
      have reciprocal263Nonnegative : 0 ≤ (1:ℝ)/2^263 :=
        div_nonneg (by norm_num : (0:ℝ) ≤ 1) denominator263Nonnegative
      have firstTermBound : 6*(q:ℝ)^2*((1:ℝ)/2^263) ≤
          6*((3:ℝ)*2^64)^2*((1:ℝ)/2^263) :=
        mul_le_mul_of_nonneg_right
          (mul_le_mul_of_nonneg_left squareBound (by norm_num : (0:ℝ) ≤ 6))
          reciprocal263Nonnegative
      have secondTermBound : 88*(q:ℝ)^3/2^512 ≤
          88*((3:ℝ)*2^64)^3/2^512 :=
        div_le_div_of_nonneg_right
          (mul_le_mul_of_nonneg_left cubeBound (by norm_num : (0:ℝ) ≤ 88))
          denominator512Nonnegative
      have thirdTermBound : 20*(q:ℝ)/2^512 ≤
          20*((3:ℝ)*2^64)/2^512 :=
        div_le_div_of_nonneg_right
          (mul_le_mul_of_nonneg_left qb (by norm_num : (0:ℝ) ≤ 20))
          denominator512Nonnegative
      exact add_le_add (add_le_add firstTermBound secondTermBound) thirdTermBound
    _ < _ := by
      simp only [power512,power263]
      norm_num

private theorem initialized_aggregate_scalar_bound {f c r n p L : ℝ} (q d k : ℝ)
    (bound : f ≤ c+r+(20*q/k)*p)
    (collisions : c ≤ (6*q^2*(q/d))*n) (roles : r ≤ L*n)
    (collisionScale : (6*q^2*(q/d))*n ≤ (6*q^2*(q/d))*1)
    (roleScale : L*n ≤ L*1) (debtScale : (20*q/k)*p ≤ (20*q/k)*1)
    (growth : 0 ≤ q^3/d) : f ≤ L+16*q^3/d+20*q/k := by
  calc
    f ≤ c+r+(20*q/k)*p := bound
    _ ≤ (6*q^2*(q/d))*n+(L*n)+(20*q/k)*p :=
      add_le_add (add_le_add collisions roles) le_rfl
    _ ≤ (6*q^2*(q/d))*1+(L*1)+(20*q/k)*1 :=
      add_le_add (add_le_add collisionScale roleScale) debtScale
    _ = L+6*(q^3/d)+20*q/k := by ring
    _ ≤ L+16*(q^3/d)+20*q/k :=
      add_le_add
        (add_le_add le_rfl
          (mul_le_mul_of_nonneg_right (by norm_num : (6:ℝ) ≤ 16) growth)) le_rfl
    _ = L+16*q^3/d+20*q/k := by ring

/-- Global initialized SAME-source-witness failure bound on the original
native constructor. The one successful deterministic point lookup is handled
by the caller-free wrapper separately; it is ordinary source data here. -/
theorem initialized_global_source_mass_below_129_of_point_success
    (metadata : Metadata) (dummy : (role : Role) → R.Active role (G.keyBytes Global))
    (sample : NativePrivateSpendQ58CurrentDecsSampleDensity.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point)
    {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) (normalized : Subnormalized (initial template inputConstructor registers))
    (count : Nat) (reads : ReadsAtMost G.decode count Global)
    (support : finish+count≤q) (queriesBound : queries+count≤q) (lifetime : q≤3*2^64) :
    missingSourceMass template inputConstructor «prefix» registers < (2:ℝ)^(-129:ℤ) := by
  letI := physicalBranchesFintype G.decode Global
  let ctx : Metadata := {metadata with authorizedOf:=fun _ => ∅}
  have certified : SmzaRp05ConditionedExecution.CertifiedFor (N.contexts Global ctx) (O.compileOrdinary «prefix») := by
    have contextsEq : O.emptyAuthorizationContexts (N.contexts Global metadata) =
        N.contexts Global ctx := by
      funext role
      rfl
    exact Eq.mp
      (congrArg (fun contexts : Role → Metadata =>
        SmzaRp05ConditionedExecution.CertifiedFor contexts (O.compileOrdinary «prefix»)) contextsEq)
      (O.compileOrdinary_certified (N.contexts Global metadata) «prefix»)
  have total : SmzaRp05RoleReadTotality.StandardOn (Finset.univ:Finset (G.Key Global)).toList
      (reached template inputConstructor «prefix» registers) := by
    intro key _
    exact ST.initialized_ordinary_run_standard_total «prefix» registers key
  have totalCompiled : SmzaRp05RoleReadTotality.StandardOn (Finset.univ:Finset (G.Key Global)).toList
      (SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run (O.compileOrdinary «prefix»)
        (initial template inputConstructor registers)) := by
    simpa [reached,initial,O.ordinaryRun_eq_compiled] using total
  have roles := GM.current_global_four_role_causal_initialized_mass Global ctx template (fun _ => 0)
    dummy sample point lookup certified registers count reads (Finset.univ:Finset (G.Key Global)).toList
    (NativePrivateSpendQ58CurrentAcceptedSourceInitialized128.reads_univ (G.encode Global) Global) support queriesBound totalCompiled
  have collisions := SmzaRp05ActualEventPhysicalMass.sum_physical_fiber_event_mass_le_certified_prefix
    certified .decsSample RT.cap (dummy .decsSample)
    (fun fixed => collisionSpec template inputConstructor ctx q fixed)
    ((q:ℝ)/2^512) (fun _ => rfl) registers count (G.encode Global) G.decode Global reads
    (Finset.univ:Finset (G.Key Global)).toList (NativePrivateSpendQ58CurrentAcceptedSourceInitialized128.reads_univ (G.encode Global) Global) support queriesBound totalCompiled
  have conserved := SmzaRp05CurrentPhysicalNonchallengeClaims.physical_branch_mass_eq_initial_of_reads_within
    (G.encode Global) G.decode Global (reached template inputConstructor «prefix» registers)
    (Finset.univ:Finset (G.Key Global)).toList (NativePrivateSpendQ58CurrentAcceptedSourceInitialized128.reads_univ (G.encode Global) Global) total
  have prefixNorm : normSquared (reached template inputConstructor «prefix» registers)≤1 := by
    simpa [Subnormalized,reached,initial,O.ordinaryRun_eq_compiled] using
      SmzaRp05ConditionedExecution.CertifiedFor.common_run_subnormalized certified .decsSample normalized
  have bound := Finset.sum_le_sum (s := (Finset.univ : Finset (Branches G.decode Global))) (fun branch _ => branch_bound template inputConstructor ctx dummy «prefix» registers branch
    count reads (by omega))
  change missingSourceMass template inputConstructor «prefix» registers≤_ at bound
  have terminalConserved :
      (∑ branch : Branches G.decode Global,
        normSquared (terminal template inputConstructor «prefix» registers branch)) =
      normSquared (reached template inputConstructor «prefix» registers) := by
    simpa only [terminal] using conserved
  rw [Finset.sum_add_distrib,Finset.sum_add_distrib,←Finset.mul_sum,terminalConserved] at bound
  have roles' : (∑ branch : Branches G.decode Global,∑ role : Role,
      roleMass template inputConstructor ctx dummy role (terminal template inputConstructor «prefix» registers branch)) ≤
      (6*(q:ℝ)^2*(∑ role : Role,(((3*q:Rat)/(2^512:Rat)+N.localLoss role:Rat):ℝ))) *
        normSquared (initial template inputConstructor registers) := by
    calc
      _ = ∑ role : Role,∑ fixed : R.FixedVectors (Counter:=G.Counter) role (G.keyBytes Global),∑ branch : Branches G.decode Global,
          normSquared (workspaceEventProjection (fun _ database => GM.event Global template (fun _ => 0) role fixed database)
            (fiber template inputConstructor role ctx (dummy role) fixed (terminal template inputConstructor «prefix» registers branch))) := by
        unfold roleMass
        rw [Finset.sum_comm]
        apply Finset.sum_congr rfl
        intro role _
        exact Finset.sum_comm
      _ ≤ _ := by simpa [fiber,terminal,reached,initial,O.ordinaryRun_eq_compiled] using roles
  have collisions' : (∑ branch : Branches G.decode Global,
      collisionMass template inputConstructor ctx (dummy .decsSample) (terminal template inputConstructor «prefix» registers branch)) ≤
      (6*(q:ℝ)^2*((q:ℝ)/2^512))*normSquared (initial template inputConstructor registers) := by
    calc
      _ = ∑ fixed : R.FixedVectors (Counter:=G.Counter) .decsSample (G.keyBytes Global),∑ branch : Branches G.decode Global,
        normSquared (workspaceEventProjection (fun _ database => collision template inputConstructor ctx database)
          (fiber template inputConstructor .decsSample ctx (dummy .decsSample) fixed (terminal template inputConstructor «prefix» registers branch))) := by
        unfold collisionMass
        exact Finset.sum_comm
      _ ≤ _ := by
        simpa only [fiber,terminal,reached,initial,O.ordinaryRun_eq_compiled,
          NativePrivateSpendQ58CurrentRoleEventPhysicalMass.contexts,
          NativePrivateSpendQ58CurrentRouteTransport.routeContext,collisionSpec,
          SmzaRp05ActualEventRecertification.event,SmzaRp05ActualEventRecertification.baseEvent,
          SmzaRp05AdaptiveKernelInstantiation.ignoreRetained] using! collisions
  have initNorm : normSquared (initial template inputConstructor registers)≤1 := normalized
  have roleNonnegative : 0≤6*(q:ℝ)^2*(∑ role : Role,
      (((3*q:Rat)/(2^512:Rat)+N.localLoss role:Rat):ℝ)) := by
    apply mul_nonneg (mul_nonneg (by norm_num : (0:ℝ) ≤ 6) (sq_nonneg (q:ℝ)))
    apply Finset.sum_nonneg
    intro role _
    apply (Rat.cast_nonneg (K := ℝ)).mpr
    apply add_nonneg
    · exact div_nonneg (mul_nonneg (by norm_num : (0:Rat) ≤ 3) (Nat.cast_nonneg q))
        (pow_nonneg (by norm_num : (0:Rat) ≤ 2) 512)
    · cases role with
      | decsMatrix =>
        unfold N.localLoss NativePrivateSpendQ58CurrentMatrixDynamicMass.matrixLoss
        exact div_nonneg (by norm_num) (Nat.cast_nonneg _)
      | decsSample =>
        unfold N.localLoss NativePrivateSpendQ58CurrentDecsSampleDensity.loss
        exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
      | piopMatrix =>
        unfold N.localLoss NativePrivateSpendQ58CurrentTracePiopMass.matrixLoss
        exact pow_nonneg (div_nonneg zero_le_one (Nat.cast_nonneg _)) _
      | piopOpening =>
        unfold N.localLoss NativePrivateSpendQ58CurrentTracePiopMass.openingLoss
        exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
  have roleScale := mul_le_mul_of_nonneg_left initNorm roleNonnegative
  have collisionScale := mul_le_mul_of_nonneg_left initNorm
    (show 0≤6*(q:ℝ)^2*((q:ℝ)/2^512) by positivity)
  have debtScale := mul_le_mul_of_nonneg_left prefixNorm (show 0≤20*(q:ℝ)/Fintype.card V by positivity)
  have growth : 0≤(q:ℝ)^3/2^512 := by positivity
  have aggregate : missingSourceMass template inputConstructor «prefix» registers ≤
      6*(q:ℝ)^2*(∑ role : Role,(((3*q:Rat)/(2^512:Rat)+N.localLoss role:Rat):ℝ)) +
      16*(q:ℝ)^3/2^512+20*q/Fintype.card V := by
    exact initialized_aggregate_scalar_bound (q:ℝ) ((2:ℝ)^512) (Fintype.card V)
      bound collisions' roles' collisionScale roleScale debtScale growth
  exact aggregate.trans_lt (current_global_coefficient_below_129 q lifetime)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalInitializedSourceMass
