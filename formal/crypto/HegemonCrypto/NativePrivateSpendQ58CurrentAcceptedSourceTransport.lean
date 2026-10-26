import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceCut
import SmzaRp05OrdinarySoundnessStandardTotal
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceTransport
open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaChallengeStageTargets (Role)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open NativePrivateSpendQ58CurrentCanonicalSourceClassifier
namespace R
export NativePrivateSpendQ58CurrentFiberMassTransport
 (Active FixedVectors actualActiveEquiv actualFixedEquiv actualFixed)
end R
namespace RT
export NativePrivateSpendQ58CurrentRouteTransport (cap routeContext route_predicate fiber_exact)
end RT
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport
 (sourceKeys SourceView activeSourceView sourceProjection source_keys_active_for_each_role current_source_selector_commutes)
end X
namespace K
export NativePrivateSpendQ58CurrentSelectedClaimFailureMass
 (Context sparse selected penalty internal_selector_claims_mass_transport)
end K
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey FixedTable SparseState Memory restrictFiber)
end A
namespace N
export NativePrivateSpendQ58CurrentRoleEventPhysicalMass (contexts roleEvent)
end N
noncomputable section
set_option autoImplicit false
variable {BaseWork:Type}[Fintype BaseWork][DecidableEq BaseWork]
local notation "W"=>SmzaRp05CurrentAdaptiveExecution.Work (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "V"=>VectorOutput G.Counter
variable (p:Program E.Wire) (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
 (rel:NativePrivateSpendQ58CurrentPublicOpening.Relation) (n:Fin (2^32))
local notation "Root"=>root p ns rel n
local notation "S"=>SmzaRp05CurrentAdaptiveExecution.CmsState (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork)
variable (r:Role)
def nativeDB (d:Database (R.Active r (G.keyBytes Root)) (V)):=
 fun k:A.ActiveKey (live p ns rel n r)=>d ((R.actualActiveEquiv r (G.keyBytes Root)).symm k)
def fiber (ctx:SmzaRp05CurrentAdaptiveExecution.Context (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork))
 (dummy:R.Active r (G.keyBytes Root)) (f:R.FixedVectors (Counter:=G.Counter) r (G.keyBytes Root)) (s:S):=
 SmzaRp05ConditionedExecution.fixedFiberToActive (N.contexts Root ctx r) RT.cap dummy f
  (SmzaRp05ConditionedExecution.otherRoleTransform (N.contexts Root ctx r) RT.cap s)
def selector (v:X.SourceView Root→Prop):=
 fun (_:A.Memory (Key:=G.Key Root) (Counter:=G.Counter) (Work:=W)) d=>v (X.activeSourceView Root r (nativeDB p ns rel n r d))
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
    (fixed : A.FixedTable (Counter := Counter) live) :
    A.restrictFiber (Work := Work) live dummy fixed 0 = 0 := by
  funext basis
  simp only [A.restrictFiber, Pi.zero_apply, ite_self]
private theorem current_workspace_projection_zero {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Output] [Fintype Phase] [Fintype Workspace]
    (event : Workspace → Database Input Output → Prop) :
    workspaceEventProjection event (0 : State Input Output Phase Workspace) = 0 := by
  funext basis
  simp only [workspaceEventProjection, Pi.zero_apply, ite_self]
private theorem current_norm_squared_zero {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Output] [Fintype Phase] [Fintype Workspace] :
    normSquared (0 : State Input Output Phase Workspace) = 0 := by
  simp only [normSquared, Pi.zero_apply, Complex.normSq_zero, Finset.sum_const_zero]
private theorem current_zero_projection_bound {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Output] [Fintype Phase] [Fintype Workspace]
    (leftEvent rightEvent : Workspace → Database Input Output → Prop) (factor : ℝ) :
    normSquared (workspaceEventProjection leftEvent (0 : State Input Output Phase Workspace)) ≤
      normSquared (workspaceEventProjection rightEvent (0 : State Input Output Phase Workspace)) +
        factor * normSquared (0 : State Input Output Phase Workspace) := by
  have massZero := current_norm_squared_zero
    (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)
  have leftZero := (congrArg normSquared (current_workspace_projection_zero
    (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace) leftEvent)).trans massZero
  have rightZero := (congrArg normSquared (current_workspace_projection_zero
    (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace) rightEvent)).trans massZero
  have rhsZero : normSquared (workspaceEventProjection rightEvent (0 : State Input Output Phase Workspace)) +
      factor * normSquared (0 : State Input Output Phase Workspace) = 0 := by
    rw [rightZero, massZero, mul_zero, add_zero]
  exact leftZero.le.trans rhsZero.symm.le
private theorem true_projection_mass {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Output] [Fintype Phase] [Fintype Workspace]
    (state : State Input Output Phase Workspace) :
    normSquared (workspaceEventProjection (fun _ _ => True) state) = normSquared state := by
  apply congrArg normSquared
  funext basis
  exact if_pos trivial
omit [DecidableEq BaseWork] in
private theorem cast_mass{l₀ l₁:G.Key Root→Prop} (h:l₀=l₁)
 (e:A.Memory (Key:=G.Key Root) (Counter:=G.Counter) (Work:=W)→Database (A.ActiveKey l₀) (V)→Prop)
 (s:A.SparseState (Counter:=G.Counter) (Work:=W) l₀):
 normSquared (workspaceEventProjection e s)=
 normSquared (workspaceEventProjection
  (fun m d => e m (Eq.mp (congrArg (fun live => Database (A.ActiveKey live) V) h.symm) d))
  (Eq.mp (congrArg (fun live => A.SparseState (Counter := G.Counter) (Work := W) live) h) s)) := by
  cases h
  rfl
private theorem fiber_mass (ctx) (dummy) (f) (s:S) (e:Database (R.Active r (G.keyBytes Root)) (V)→Prop):
 normSquared (workspaceEventProjection (fun _ d=>e d) (fiber p ns rel n r ctx dummy f s))=
 normSquared (workspaceEventProjection (fun _ d=>e (RI.pullDB Root r d))
 (A.restrictFiber (live p ns rel n r) (R.actualActiveEquiv r (G.keyBytes Root) dummy)
 (R.actualFixed r (G.keyBytes Root) f)
 (NativePrivateSpendQ58PartitionTransport.conditioned (live p ns rel n r) (R.actualFixed r (G.keyBytes Root) f) s))):=by
 let h := RT.route_predicate r (G.keyBytes Root)
 have hd : Eq.mp (congrArg (fun live : G.Key Root → Prop => A.ActiveKey live) h) dummy =
     R.actualActiveEquiv r (G.keyBytes Root) dummy := by
  apply Subtype.ext
  exact cast_subtype_val (fun live key => live key) h dummy
 have hf : Eq.mp (congrArg (fun live : G.Key Root → Prop => A.FixedTable (Counter := G.Counter) live) h) f =
     R.actualFixed r (G.keyBytes Root) f := by
  funext key
  change (Eq.mp (congrArg (fun live : G.Key Root → Prop => {key : G.Key Root // ¬live key} → V) h) f) key =
    f ((R.actualFixedEquiv r (G.keyBytes Root)).symm key)
  rw [cast_function_apply (Domain := fun live : G.Key Root → Prop => {key : G.Key Root // ¬live key}) h f key]
  exact congrArg f (Subtype.ext (cast_subtype_val (fun live key => ¬live key) h.symm key))
 have dbcast (d : Database (A.ActiveKey (live p ns rel n r)) V) :
     Eq.mp (congrArg (fun live : G.Key Root → Prop => Database (A.ActiveKey live) V) h.symm) d =
       RI.pullDB Root r d := by
  funext key
  change (Eq.mp (congrArg (fun live : G.Key Root → Prop => A.ActiveKey live → Option V) h.symm) d) key =
    d (R.actualActiveEquiv r (G.keyBytes Root) key)
  rw [cast_function_apply (Domain := fun live : G.Key Root → Prop => A.ActiveKey live) (Value := Option V) h.symm d key]
  exact congrArg d (Subtype.ext (cast_subtype_val (fun live key => live key) h key))
 have fiberEq :
     Eq.mp (congrArg (fun live : G.Key Root → Prop =>
       A.SparseState (Counter := G.Counter) (Work := W) live) h)
       (fiber p ns rel n r ctx dummy f s) =
     A.restrictFiber (live p ns rel n r)
       (Eq.mp (congrArg (fun live : G.Key Root → Prop => A.ActiveKey live) h) dummy)
       (Eq.mp (congrArg (fun live : G.Key Root → Prop => A.FixedTable (Counter := G.Counter) live) h) f)
       (NativePrivateSpendQ58PartitionTransport.conditioned (live p ns rel n r)
         (Eq.mp (congrArg (fun live : G.Key Root → Prop => A.FixedTable (Counter := G.Counter) live) h) f) s) := by
  have retained := RT.fiber_exact ctx r (G.keyBytes Root) dummy f s
  have argsEq := congrArg₂
    (fun (dummy : A.ActiveKey (live p ns rel n r)) (fixed : A.FixedTable (Counter := G.Counter) (live p ns rel n r)) => (dummy, fixed))
    (cast_indexed (Family := fun live : G.Key Root → Prop => A.ActiveKey live) h dummy)
    (cast_indexed (Family := fun live : G.Key Root → Prop => A.FixedTable (Counter := G.Counter) live) h f)
  have resultEq := congrArg
    (fun args : A.ActiveKey (live p ns rel n r) × A.FixedTable (Counter := G.Counter) (live p ns rel n r) =>
      A.restrictFiber (live p ns rel n r) args.1 args.2
        (NativePrivateSpendQ58PartitionTransport.conditioned (live p ns rel n r) args.2 s)) argsEq
  exact retained.trans resultEq
 have mass := cast_mass p ns rel n h (fun _ d => e d) (fiber p ns rel n r ctx dummy f s)
 calc
  _ = normSquared (workspaceEventProjection
      (fun _ d => e (Eq.mp (congrArg (fun live : G.Key Root → Prop => Database (A.ActiveKey live) V) h.symm) d))
      (Eq.mp (congrArg (fun live : G.Key Root → Prop => A.SparseState (Counter := G.Counter) (Work := W) live) h)
        (fiber p ns rel n r ctx dummy f s))) := mass
  _ = _ := by
   have argsEq := congrArg₂
     (fun (dummy : A.ActiveKey (live p ns rel n r)) (fixed : A.FixedTable (Counter := G.Counter) (live p ns rel n r)) => (dummy, fixed)) hd hf
   have stateEq := fiberEq.trans (congrArg
    (fun args : A.ActiveKey (live p ns rel n r) × A.FixedTable (Counter := G.Counter) (live p ns rel n r) =>
      A.restrictFiber (live p ns rel n r) args.1 args.2
        (NativePrivateSpendQ58PartitionTransport.conditioned (live p ns rel n r) args.2 s)) argsEq)
   have eventEq :
       (fun (_ : A.Memory (Key := G.Key Root) (Counter := G.Counter) (Work := W)) d =>
         e (Eq.mp (congrArg (fun live : G.Key Root → Prop => Database (A.ActiveKey live) V) h.symm) d)) =
       (fun _ d => e (RI.pullDB Root r d)) := by
    funext memory database
    exact congrArg e (dbcast database)
   exact congrArg normSquared (congrArg₂ workspaceEventProjection eventEq stateEq)
theorem source_mass (ctx) (dummy) (b:Branches G.decode Root){q finish queries:Nat}
 («prefix»:SmzaRp05OrdinarySoundnessExecution.OrdinaryPrefix (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
 (reg:RegisterBasis (Input:=G.Key Root) (Phase:=V) (Workspace:=W)→ℂ) (v:X.SourceView Root→Prop):
 normSquared (X.sourceProjection Root (fun z _=>v z) (physicalRun (G.encode Root) G.decode Root b
 (SmzaRp05OrdinarySoundnessExecution.ordinaryRun «prefix» (partialRandomOracleState (Output := V) ∅ reg))))=
 ∑f:R.FixedVectors (Counter:=G.Counter) r (G.keyBytes Root),
 normSquared (workspaceEventProjection (selector p ns rel n r v) (fiber p ns rel n r ctx dummy f
 (physicalRun (G.encode Root) G.decode Root b (SmzaRp05OrdinarySoundnessExecution.ordinaryRun «prefix»
 (partialRandomOracleState (Output := V) ∅ reg))))):=by
 have unparsed:∀k∈X.sourceKeys Root,SmzaChallengeStageTargets.parseStageQuery ((N.contexts Root ctx r).keyBytes k)=none:=by
  intro k hk
  have active:=X.source_keys_active_for_each_role Root r k hk
  change NativePrivateSpendQ58CurrentRoleClassifier.RoleActive r
   NativePrivateSpendQ58CurrentGammaFiber.currentRoleCaps (G.keyBytes Root) k at active
  dsimp only [N.contexts, RT.routeContext, NativePrivateSpendQ58CurrentFiberMassTransport.routingTag]
  rw [if_pos active]
  rfl
 have eq:=SmzaRp05OrdinarySoundnessStandardTotal.ordinary_physical_branch_selector_mass_eq_active_fiber_sum
  «prefix» reg (G.encode Root) G.decode Root b (N.contexts Root ctx r) RT.cap dummy (X.sourceKeys Root) unparsed (fun z _=>v z)
 have comm:=congrArg normSquared (X.current_source_selector_commutes Root ctx r (fun z _=>v z)
  (physicalRun (G.encode Root) G.decode Root b (SmzaRp05OrdinarySoundnessExecution.ordinaryRun «prefix»
  (partialRandomOracleState (Output := V) ∅ reg))))
 rw[SmzaRp05ConditionedExecution.other_role_transform_norm_squared] at comm
 dsimp only [X.sourceProjection] at comm
 have joined := comm.symm.trans eq
 refine joined.trans ?_
 apply Finset.sum_congr rfl
 intro f hf
 refine congrArg normSquared ?_
 refine congrArg (fun event => workspaceEventProjection event
  (fiber p ns rel n r ctx dummy f
   (physicalRun (G.encode Root) G.decode Root b
    (SmzaRp05OrdinarySoundnessExecution.ordinaryRun «prefix»
     (partialRandomOracleState (Output := V) ∅ reg))))) ?_
 funext m d
 rfl
theorem choice_mass (ctx) (dummy) (f) (b:Branches G.decode Root) (initial:S) (fb:G.RawDigest)
 (accepted:SmzaRp05PhysicalAcceptedReplayLite.branchResult G.decode Root b=some ()):
 normSquared (workspaceEventProjection (selector p ns rel n r (Choice p ns rel n b r))
 (fiber p ns rel n r ctx dummy f (physicalRun (G.encode Root) G.decode Root b initial)))≤
 normSquared (workspaceEventProjection (fun _ d=>N.roleEvent Root rel fb n r f d)
 (fiber p ns rel n r ctx dummy f (physicalRun (G.encode Root) G.decode Root b initial)))+
 (((2*(AC.activeClaims Root r AC.currentRoleCaps b).toFinset.card:Nat):ℝ)/Fintype.card (V))*
 normSquared (fiber p ns rel n r ctx dummy f (physicalRun (G.encode Root) G.decode Root b initial)):=by
 let c:K.Context Root r W:=⟨R.actualActiveEquiv r (G.keyBytes Root) dummy,R.actualFixed r (G.keyBytes Root) f,b,initial⟩
 have unselectedRaw := fiber_mass p ns rel n r ctx dummy f
  (physicalRun (G.encode Root) G.decode Root b initial) (fun _ => True)
 have unselected :=
  (true_projection_mass (fiber p ns rel n r ctx dummy f
    (physicalRun (G.encode Root) G.decode Root b initial))).symm.trans
   (unselectedRaw.trans (true_projection_mass
    (A.restrictFiber (live p ns rel n r) (R.actualActiveEquiv r (G.keyBytes Root) dummy)
     (R.actualFixed r (G.keyBytes Root) f)
     (NativePrivateSpendQ58PartitionTransport.conditioned (live p ns rel n r)
      (R.actualFixed r (G.keyBytes Root) f) (physicalRun (G.encode Root) G.decode Root b initial)))))
 have leftMass := fiber_mass p ns rel n r ctx dummy f
  (physicalRun (G.encode Root) G.decode Root b initial)
  (fun d => Choice p ns rel n b r (X.activeSourceView Root r (nativeDB p ns rel n r d)))
 have rightMass := fiber_mass p ns rel n r ctx dummy f
  (physicalRun (G.encode Root) G.decode Root b initial)
  (fun d => N.roleEvent Root rel fb n r f d)
 change normSquared (workspaceEventProjection
  (fun _ d => Choice p ns rel n b r (X.activeSourceView Root r (nativeDB p ns rel n r d)))
  (fiber p ns rel n r ctx dummy f (physicalRun (G.encode Root) G.decode Root b initial))) ≤ _
 rw [leftMass, rightMass, unselected]
 have pull:RI.pullFixed Root r (R.actualFixed r (G.keyBytes Root) f)=f:=by funext k;rfl
 have dbpull (d : Database (A.ActiveKey (live p ns rel n r)) V) :
     nativeDB p ns rel n r (RI.pullDB Root r d) = d := by
  funext key
  rfl
 by_cases comp:AC.fixedCompatible Root r AC.currentRoleCaps c.fixed b
 · have bound :=
    K.internal_selector_claims_mass_transport c (fun _ d=>Choice p ns rel n b r (X.activeSourceView Root r d))
    (fun _ d=>N.roleEvent Root rel fb n r (RI.pullFixed Root r c.fixed) (RI.pullDB Root r d))
    (by intro _ d chosen claims;exact chosen_role_inserts p ns rel n b r c.fixed d comp claims fb accepted chosen)
   dsimp (config := { instances := true }) only
    [K.selected, K.sparse, K.penalty,
     NativePrivateSpendQ58CurrentSelectedClaimFailureMass.conditioned,
     NativePrivateSpendQ58CurrentSelectedClaimFailureMass.claims, c,
     live, NativePrivateSpendQ58CurrentSelectedClaimFailureMass.live,
     NativePrivateSpendQ58CurrentSourceSelectorTransport.live, AC.live] at bound
   dsimp (config := { instances := true }) only [live, NativePrivateSpendQ58CurrentSelectedClaimFailureMass.live,
     NativePrivateSpendQ58CurrentSourceSelectorTransport.live, AC.live] at dbpull ⊢
   simpa only [dbpull, pull] using bound
 · have zero:=NativePrivateSpendQ58CurrentConditionedBranchReadback.current_incompatible_conditioned_branch_is_zero
    Root r AC.currentRoleCaps c.fixed b comp initial
   have zeroTyped : NativePrivateSpendQ58PartitionTransport.conditioned (live p ns rel n r) c.fixed
       (physicalRun (G.encode Root) G.decode Root b initial) = 0 := by
    exact zero
   have sparseZero :
       A.restrictFiber (live p ns rel n r) c.dummy c.fixed
         (NativePrivateSpendQ58PartitionTransport.conditioned (live p ns rel n r) c.fixed
           (physicalRun (G.encode Root) G.decode Root b initial)) = 0 := by
    exact (congrArg (A.restrictFiber (live p ns rel n r) c.dummy c.fixed) zeroTyped).trans
      (current_restrict_fiber_zero (live p ns rel n r) c.dummy c.fixed)
   dsimp (config := { instances := true }) only [live, NativePrivateSpendQ58CurrentSelectedClaimFailureMass.live,
     NativePrivateSpendQ58CurrentSourceSelectorTransport.live, AC.live] at sparseZero ⊢
   rw [sparseZero]
   exact current_zero_projection_bound _ _ _
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceTransport
