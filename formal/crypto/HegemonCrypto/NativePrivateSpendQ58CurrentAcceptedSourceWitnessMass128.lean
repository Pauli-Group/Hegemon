import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceWitnessCut
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceInitialized128
open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun branchResult)
open SmzaRp05AdaptivePhysicalReadBound (ReadsAtMost physicalBranchesFintype)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open NativePrivateSpendQ58CurrentCanonicalSourceClassifier
open SmzaChallengeStageTargets (Role)
namespace WC
export NativePrivateSpendQ58CurrentAcceptedSourceWitnessCut (failure accepted_no_source_witness_raw_cut)
end WC
noncomputable section
set_option autoImplicit false
variable{BaseWork:Type}[Fintype BaseWork][DecidableEq BaseWork]
variable (p:Program E.Wire) (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
 (rel:NativePrivateSpendQ58CurrentPublicOpening.Relation) (n:Fin (2^32))
local notation "Root"=>root p ns rel n
local notation "W"=>SmzaRp05CurrentAdaptiveExecution.Work (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "V"=>VectorOutput G.Counter
local notation "Registers"=>RegisterBasis (Input:=G.Key Root) (Phase:=V) (Workspace:=W)→ℂ
local notation "S"=>SmzaRp05CurrentAdaptiveExecution.CmsState (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "Metadata"=>SmzaRp05CurrentAdaptiveExecution.Context (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork)
/-- RAW selected physical mass of accepted branches without the same-source
 satisfying witness carried by the actual native stage/recovery geometry. -/
def noSourceWitnessMass{q finish queries:Nat}
 («prefix»:O.OrdinaryPrefix (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
 (reg:Registers):ℝ:=
 letI:=physicalBranchesFintype G.decode Root
 ∑b:Branches G.decode Root,if branchResult G.decode Root b=some ()
 then normSquared (WC.failure p ns rel n b (terminal p ns rel n «prefix» reg b)) else 0
private theorem witness_active_count (b:Branches G.decode Root) (r:Role) (d:Nat)
 (h:ReadsAtMost G.decode d Root):(AC.activeClaims Root r AC.currentRoleCaps b).toFinset.card≤d:=
 (List.toFinset_card_le _).trans ((List.length_filterMap_le _ _).trans (full_count p ns rel n b d h))
omit [Fintype BaseWork] [DecidableEq BaseWork] in
private theorem witness_collision_inserts (ctx:Metadata) (d:Database (R.Active .decsSample (G.keyBytes Root)) (V))
 (hit:¬SmzaRecordedTracePath.RecordsCollisionFree (records p ns rel n
 (NativePrivateSpendQ58CurrentSourceSelectorTransport.activeSourceView Root .decsSample (B.nativeDB p ns rel n .decsSample d)))):
 collision p ns rel n ctx d:=by
 unfold collision FC.filteredRawCollision
 intro free
 apply hit
 have subset :
   records p ns rel n
     (NativePrivateSpendQ58CurrentSourceSelectorTransport.activeSourceView Root .decsSample
       (B.nativeDB p ns rel n .decsSample d)) ⊆
   V8Smz9CoherentMerkleInstrument.rawRecords
     (R.activeBytes .decsSample (G.keyBytes Root)) (V8Smz9CoherentVectorMerkle.vectorOutputBytes G.zero) d := by
   intro pair member
   rcases pair with ⟨input,output⟩
   obtain ⟨key,v,stored,bytes,out⟩ :=
     (SmzaRawDatabaseRecords.mem_raw_records_iff
       (fun key : {key : G.Key Root // key ∈ X.sourceKeys Root} => G.keyBytes Root key.val)
       (V8Smz9CoherentVectorMerkle.vectorOutputBytes G.zero)
       (NativePrivateSpendQ58CurrentSourceSelectorTransport.activeSourceView Root .decsSample
         (B.nativeDB p ns rel n .decsSample d)) input output).mp member
   apply (SmzaRawDatabaseRecords.mem_raw_records_iff
     (R.activeBytes .decsSample (G.keyBytes Root)) (V8Smz9CoherentVectorMerkle.vectorOutputBytes G.zero) d input output).mpr
   exact ⟨(NativePrivateSpendQ58CurrentFiberMassTransport.actualActiveEquiv
     (Key := G.Key Root) .decsSample (G.keyBytes Root)).symm
     ⟨key.val,NativePrivateSpendQ58CurrentSourceSelectorTransport.source_keys_active_for_each_role Root .decsSample key.val key.property⟩,
     v,stored,bytes,out⟩
 have freeRaw : SmzaRecordedTracePath.RecordsCollisionFree
   (V8Smz9CoherentMerkleInstrument.rawRecords
     (R.activeBytes .decsSample (G.keyBytes Root)) (V8Smz9CoherentVectorMerkle.vectorOutputBytes G.zero) d) := by
   simpa only [FC.filteredRawRecords,O.outside_empty_authorization_identity] using free
 exact SmzaRp04StatementRecordFilter.recordsCollisionFree_mono subset freeRaw
omit [DecidableEq BaseWork] in
private theorem witness_selector_union (b:Branches G.decode Root) (s:S):
 normSquared (X.sourceProjection Root (fun v _=>NativePrivateSpendQ58CurrentAcceptedSourceCut.bad p ns rel n b v) s)≤
 normSquared (X.sourceProjection Root (fun v _=>¬SmzaRecordedTracePath.RecordsCollisionFree (records p ns rel n v)) s)+
 ∑r:Role,normSquared (X.sourceProjection Root (fun v _=>Choice p ns rel n b r v) s):=by
 unfold X.sourceProjection SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection normSquared workspaceEventProjection
 rw[Finset.sum_comm,←Finset.sum_add_distrib]
 apply Finset.sum_le_sum
 intro basis _
 by_cases bad:NativePrivateSpendQ58CurrentAcceptedSourceCut.bad p ns rel n b (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) basis.database)
 · rw[if_pos bad]
   rcases bad with coll|chosen
   · rw[if_pos coll]
     exact le_add_of_nonneg_right (Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _))
   · obtain⟨r,chosen⟩:=chosen
     let values : Role → ℝ := fun role => Complex.normSq
       (if Choice p ns rel n b role
         (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) basis.database)
        then s basis else 0)
     have one : values r ≤ ∑ role : Role, values role := by
       apply Finset.single_le_sum (f := values)
       · intro role _
         dsimp only [values]
         exact Complex.normSq_nonneg _
       · exact Finset.mem_univ r
     dsimp only [values] at one
     rw [if_pos chosen] at one
     exact one.trans (le_add_of_nonneg_left (Complex.normSq_nonneg _))
 · rw[if_neg bad]
   simp only [Complex.normSq_zero]
   exact add_nonneg (Complex.normSq_nonneg _) (Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _))
omit [Fintype BaseWork] [DecidableEq BaseWork] in
private theorem current_true_projection_mass {Input Output Phase Workspace : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Output] [Fintype Phase] [Fintype Workspace]
    (state : State Input Output Phase Workspace) :
    normSquared (workspaceEventProjection (fun _ _ => True) state) = normSquared state := by
  apply congrArg normSquared
  funext basis
  exact if_pos trivial
private theorem no_source_witness_branch_bound (ctx:Metadata) (dummy:(r:Role)→R.Active r (G.keyBytes Root)) (fb:G.RawDigest)
 {q finish queries:Nat} («prefix»:O.OrdinaryPrefix (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
 (reg:Registers) (b:Branches G.decode Root) (d:Nat) (read:ReadsAtMost G.decode d Root) (within:d≤q)
:
 (if branchResult G.decode Root b=some () then normSquared (WC.failure p ns rel n b (terminal p ns rel n «prefix» reg b)) else 0)≤
 collisionMass p ns rel n ctx (dummy .decsSample) (terminal p ns rel n «prefix» reg b)+
 (∑r:Role,roleMass p ns rel n ctx dummy fb r (terminal p ns rel n «prefix» reg b))+
 (20*(q:ℝ)/Fintype.card (V))*normSquared (terminal p ns rel n «prefix» reg b):=by
 let s:=terminal p ns rel n «prefix» reg b
 have mass:0≤normSquared s:=by unfold normSquared;exact Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _)
 have cn:0≤collisionMass p ns rel n ctx (dummy .decsSample) s:=by
  unfold collisionMass
  exact Finset.sum_nonneg (fun _ _=>by unfold normSquared;exact Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _))
 have rn:0≤∑r:Role,roleMass p ns rel n ctx dummy fb r s:=by
  unfold roleMass
  exact Finset.sum_nonneg (fun _ _=>Finset.sum_nonneg (fun _ _=>by unfold normSquared;exact Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _)))
 by_cases accepted:branchResult G.decode Root b=some ()
 · rw[if_pos accepted]
   have cut:=WC.accepted_no_source_witness_raw_cut p ns rel n b
    (reached p ns rel n «prefix» reg) accepted
   have union:=witness_selector_union p ns rel n b s
   have coll:normSquared (X.sourceProjection Root (fun v _=>¬SmzaRecordedTracePath.RecordsCollisionFree (records p ns rel n v)) s)≤
    collisionMass p ns rel n ctx (dummy .decsSample) s:=by
    have collisionSplit := B.source_mass p ns rel n .decsSample ctx (dummy .decsSample) b «prefix» reg
      (fun v => ¬SmzaRecordedTracePath.RecordsCollisionFree (records p ns rel n v))
    change normSquared (X.sourceProjection Root
      (fun v _ => ¬SmzaRecordedTracePath.RecordsCollisionFree (records p ns rel n v)) s) = _ at collisionSplit
    rw [collisionSplit]
    apply Finset.sum_le_sum
    intro f _
    exact SmzaRp05CurrentPhysicalBranchClaims.workspace_event_mass_le_of_inclusion _ _ _
     (by intro _ db hit;exact witness_collision_inserts p ns rel n ctx db hit)
   have choices:∀r:Role,normSquared (X.sourceProjection Root (fun v _=>Choice p ns rel n b r v) s)≤
    roleMass p ns rel n ctx dummy fb r s+(2*(q:ℝ)/Fintype.card (V))*normSquared s:=by
    intro r
    have splitRaw := B.source_mass p ns rel n r ctx (dummy r) b «prefix» reg (fun _ => True)
    change normSquared (workspaceEventProjection (fun _ _ => True) s) =
      ∑ f : R.FixedVectors (Counter := G.Counter) r (G.keyBytes Root),
        normSquared (workspaceEventProjection (fun _ _ => True)
          (B.fiber p ns rel n r ctx (dummy r) f s)) at splitRaw
    have split : normSquared s =
        ∑ f : R.FixedVectors (Counter := G.Counter) r (G.keyBytes Root),
          normSquared (B.fiber p ns rel n r ctx (dummy r) f s) := by
      simpa only [current_true_projection_mass] using! splitRaw
    dsimp only [s, terminal, reached, initial]
    rw [B.source_mass p ns rel n r ctx (dummy r) b «prefix» reg (fun v => Choice p ns rel n b r v)]
    calc
     _≤∑f:R.FixedVectors (Counter:=G.Counter) r (G.keyBytes Root),
      (normSquared (workspaceEventProjection (fun _ db=>N.roleEvent Root rel fb n r f db) (B.fiber p ns rel n r ctx (dummy r) f s))+
      (2*(q:ℝ)/Fintype.card (V))*normSquared (B.fiber p ns rel n r ctx (dummy r) f s)):=by
      apply Finset.sum_le_sum
      intro f _
      apply (B.choice_mass p ns rel n r ctx (dummy r) f b (reached p ns rel n «prefix» reg) fb accepted).trans
      apply add_le_add le_rfl
      apply mul_le_mul_of_nonneg_right
      · apply div_le_div_of_nonneg_right _ (by positivity)
        exact_mod_cast Nat.mul_le_mul_left 2 ((witness_active_count p ns rel n b r d read).trans within)
      · unfold normSquared
        exact Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _)
     _=roleMass p ns rel n ctx dummy fb r s+(2*(q:ℝ)/Fintype.card (V))*normSquared s:=by
      change (∑ f : R.FixedVectors (Counter := G.Counter) r (G.keyBytes Root),
        (normSquared (workspaceEventProjection (fun _ db => N.roleEvent Root rel fb n r f db)
          (B.fiber p ns rel n r ctx (dummy r) f s)) +
         (2*(q:ℝ)/Fintype.card (V))*normSquared (B.fiber p ns rel n r ctx (dummy r) f s))) =
        (∑ f : R.FixedVectors (Counter := G.Counter) r (G.keyBytes Root),
          normSquared (workspaceEventProjection (fun _ db => N.roleEvent Root rel fb n r f db)
            (B.fiber p ns rel n r ctx (dummy r) f s))) +
          (2*(q:ℝ)/Fintype.card (V))*normSquared s
      rw [Finset.sum_add_distrib, ← Finset.mul_sum, ← split]
   have sumChoices:=Finset.sum_le_sum (s := (Finset.univ : Finset Role)) (fun r _=>choices r)
   have count:Fintype.card Role=4:=by decide
   rw[Finset.sum_add_distrib] at sumChoices
   simp only[Finset.sum_const,Finset.card_univ,count,nsmul_eq_mul] at sumChoices
   have countFull:(Q.fullClaims Root b).toFinset.card≤q:=
    (List.toFinset_card_le _).trans ((full_count p ns rel n b d read).trans within)
   have debt:(((2*(Q.fullClaims Root b).toFinset.card:Nat):ℝ)/Fintype.card (V))*normSquared s≤
    (2*(q:ℝ)/Fintype.card (V))*normSquared s:=by
    apply mul_le_mul_of_nonneg_right _ mass
    apply div_le_div_of_nonneg_right _ (by positivity)
    exact_mod_cast Nat.mul_le_mul_left 2 countFull
   have qn:0≤(q:ℝ)/Fintype.card (V):=by positivity
   change normSquared (WC.failure p ns rel n b s) ≤
     normSquared (X.sourceProjection Root
       (fun v _ => NativePrivateSpendQ58CurrentAcceptedSourceCut.bad p ns rel n b v) s) +
       (((2*(Q.fullClaims Root b).toFinset.card:Nat):ℝ)/Fintype.card (V))*normSquared s at cut
   have chosenBound :
       normSquared (X.sourceProjection Root
         (fun v _ => NativePrivateSpendQ58CurrentAcceptedSourceCut.bad p ns rel n b v) s) ≤
       collisionMass p ns rel n ctx (dummy .decsSample) s +
         ((∑r:Role,roleMass p ns rel n ctx dummy fb r s) +
           4*((2*(q:ℝ)/Fintype.card (V))*normSquared s)) :=
     union.trans (add_le_add coll sumChoices)
   have gathered : normSquared (WC.failure p ns rel n b s) ≤
       collisionMass p ns rel n ctx (dummy .decsSample) s +
         ((∑r:Role,roleMass p ns rel n ctx dummy fb r s) +
           4*((2*(q:ℝ)/Fintype.card (V))*normSquared s)) +
         (2*(q:ℝ)/Fintype.card (V))*normSquared s :=
     cut.trans (add_le_add chosenBound debt)
   have budget (collision roles value denominator weight : ℝ)
       (nonnegative : 0 ≤ (value/denominator)*weight) :
       collision + (roles + 4*((2*value/denominator)*weight)) +
         (2*value/denominator)*weight ≤
       collision + roles + (20*value/denominator)*weight := by
     calc
       _ = collision + roles + 10*((value/denominator)*weight) := by ring
       _ ≤ collision + roles + 20*((value/denominator)*weight) :=
         add_le_add (le_refl (collision + roles))
           (mul_le_mul_of_nonneg_right (show (10:ℝ) ≤ 20 by norm_num) nonnegative)
       _ = collision + roles + (20*value/denominator)*weight := by ring
   change normSquared (WC.failure p ns rel n b s) ≤ collisionMass p ns rel n ctx (dummy .decsSample) s +
     (∑r:Role,roleMass p ns rel n ctx dummy fb r s) +
     (20*(q:ℝ)/Fintype.card (V))*normSquared s
   exact gathered.trans (budget
     (collisionMass p ns rel n ctx (dummy .decsSample) s)
     (∑r:Role,roleMass p ns rel n ctx dummy fb r s)
     (q:ℝ) (Fintype.card (V)) (normSquared s) (mul_nonneg qn mass))
 · rw[if_neg accepted]
   exact add_nonneg (add_nonneg cn rn) (mul_nonneg (by positivity) mass)
private theorem witness_mass_below_128_of_point_success
 (metadata:Metadata) (dummy:(r:Role)→R.Active r (G.keyBytes Root)) (fb:G.RawDigest)
 (sample:NativePrivateSpendQ58CurrentDecsSampleDensity.Position) (point:Goldilocks)
 (lookup:SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point)
 {q finish queries:Nat} («prefix»:O.OrdinaryPrefix (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
 (reg:Registers) (normalized:Subnormalized (initial p ns rel n reg))
 (d:Nat) (read:ReadsAtMost G.decode d Root) (support:finish+d≤q) (queriesBound:queries+d≤q)
 (lifetime:q≤3*2^64)
:
 noSourceWitnessMass p ns rel n «prefix» reg<(2:ℝ)^(-128:ℤ):=by
 letI:=physicalBranchesFintype G.decode Root
 let ctx:Metadata:={metadata with authorizedOf:=fun _=>∅}
 have cert:SmzaRp05ConditionedExecution.CertifiedFor (N.contexts Root ctx) (O.compileOrdinary «prefix»):=by
  have contextsEq : O.emptyAuthorizationContexts (N.contexts Root metadata) =
      N.contexts Root ctx := by
    funext role
    rfl
  exact Eq.mp
    (congrArg (fun contexts : Role → Metadata =>
      SmzaRp05ConditionedExecution.CertifiedFor contexts (O.compileOrdinary «prefix»)) contextsEq)
    (O.compileOrdinary_certified (N.contexts Root metadata) «prefix»)
 have total:SmzaRp05RoleReadTotality.StandardOn (Finset.univ:Finset (G.Key Root)).toList
  (reached p ns rel n «prefix» reg):=by
  intro k _
  exact ST.initialized_ordinary_run_standard_total «prefix» reg k
 have totalCompiled:SmzaRp05RoleReadTotality.StandardOn (Finset.univ:Finset (G.Key Root)).toList
  (SmzaRp05ConditionedExecution.PhysicalProgramSkeleton.run (O.compileOrdinary «prefix») (initial p ns rel n reg)):=by
  simpa[reached,initial,O.ordinaryRun_eq_compiled] using total
 have roles:=N.current_four_roles_initialized_weighted_physical_mass Root ctx rel fb n dummy sample point lookup
  cert reg d read (Finset.univ:Finset (G.Key Root)).toList (reads_univ (G.encode Root) Root) support queriesBound totalCompiled
 have collisions:=SmzaRp05ActualEventPhysicalMass.sum_physical_fiber_event_mass_le_certified_prefix
  cert .decsSample RT.cap (dummy .decsSample) (fun f=>collisionSpec p ns rel n ctx q f)
  ((q:ℝ)/2^512) (fun _=>rfl) reg d (G.encode Root) G.decode Root read
  (Finset.univ:Finset (G.Key Root)).toList (reads_univ (G.encode Root) Root) support queriesBound totalCompiled
 have conserved:=SmzaRp05CurrentPhysicalNonchallengeClaims.physical_branch_mass_eq_initial_of_reads_within
  (G.encode Root) G.decode Root (reached p ns rel n «prefix» reg)
  (Finset.univ:Finset (G.Key Root)).toList (reads_univ (G.encode Root) Root) total
 have prefixNorm: normSquared (reached p ns rel n «prefix» reg)≤1:=by
  have result:=SmzaRp05ConditionedExecution.CertifiedFor.common_run_subnormalized cert .decsSample normalized
  simpa[Subnormalized,reached,initial,O.ordinaryRun_eq_compiled] using result
 have bound:=Finset.sum_le_sum (s := (Finset.univ : Finset (Branches G.decode Root))) (fun b _=>no_source_witness_branch_bound p ns rel n ctx dummy fb «prefix» reg b d read (by omega))
 change noSourceWitnessMass p ns rel n «prefix» reg≤_ at bound
 have terminalConserved :
  (∑ b : Branches G.decode Root, normSquared (terminal p ns rel n «prefix» reg b)) =
    normSquared (reached p ns rel n «prefix» reg) := by
   simpa only [terminal] using conserved
 rw[Finset.sum_add_distrib,Finset.sum_add_distrib,←Finset.mul_sum,terminalConserved] at bound
 have count:Fintype.card Role=4:=by decide
 have sumLoss:(∑r:Role,(((3*q:Rat)/(2^512:Rat)+N.localLoss r:Rat):ℝ))=
  12*(q:ℝ)/2^512+(AR.totalLoss:ℝ):=by
  have scale (value denominator extra : ℝ) :
      (4 : ℝ) * (3 * value / denominator) + extra =
        12 * value / denominator + extra := by ring
  simp only[Rat.cast_add,Rat.cast_div,Rat.cast_mul,Rat.cast_natCast,Rat.cast_pow,Rat.cast_ofNat,
   Finset.sum_add_distrib,Finset.sum_const,Finset.card_univ,count,nsmul_eq_mul,AR.totalLoss,Rat.cast_sum]
  exact scale (q:ℝ) (2^512) (∑r:Role,(N.localLoss r:ℝ))
 rw[sumLoss] at roles
 simp only[N.contexts,NativePrivateSpendQ58CurrentRouteTransport.routeContext] at collisions roles
 change _≤(6*(q:ℝ)^2*((q:ℝ)/2^512))*normSquared (initial p ns rel n reg) at collisions
 change _≤(6*(q:ℝ)^2*(12*(q:ℝ)/2^512+(AR.totalLoss:ℝ)))*normSquared (initial p ns rel n reg) at roles
 have localNonnegative:0≤(AR.totalLoss:ℝ):=by
  unfold AR.totalLoss
  rw[Rat.cast_sum]
  exact Finset.sum_nonneg (fun r _ => by
    apply (Rat.cast_nonneg (K := ℝ)).mpr
    cases r with
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
        exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _))
 have numerical:=AR.accepted_arithmetic_with_collision_below_128 G.zero q lifetime
 have initNorm:normSquared (initial p ns rel n reg)≤1:=normalized
 have aggregate:noSourceWitnessMass p ns rel n «prefix» reg≤
  6*(q:ℝ)^2*(AR.totalLoss:ℝ)+88*(q:ℝ)^3/2^512+20*(q:ℝ)/Fintype.card (V):=by
  change noSourceWitnessMass p ns rel n «prefix» reg≤
   (∑b:Branches G.decode Root,collisionMass p ns rel n ctx (dummy .decsSample) (terminal p ns rel n «prefix» reg b))+
   (∑b:Branches G.decode Root,∑r:Role,roleMass p ns rel n ctx dummy fb r (terminal p ns rel n «prefix» reg b))+
   (20*(q:ℝ)/Fintype.card (V))*normSquared (reached p ns rel n «prefix» reg) at bound
  have roles' : (∑b:Branches G.decode Root,∑r:Role,roleMass p ns rel n ctx dummy fb r (terminal p ns rel n «prefix» reg b))≤
   (6*(q:ℝ)^2*(12*(q:ℝ)/2^512+(AR.totalLoss:ℝ)))*normSquared (initial p ns rel n reg):=by
   calc
    _=∑r:Role,∑f:R.FixedVectors (Counter:=G.Counter) r (G.keyBytes Root),∑b:Branches G.decode Root,
     normSquared (workspaceEventProjection (fun _ db=>N.roleEvent Root rel fb n r f db)
      (B.fiber p ns rel n r ctx (dummy r) f (terminal p ns rel n «prefix» reg b))):=by
     unfold roleMass
     rw[Finset.sum_comm]
     apply Finset.sum_congr rfl
     intro r _
     exact Finset.sum_comm
    _≤_:=by
     simpa only [B.fiber,terminal,reached,initial,O.ordinaryRun_eq_compiled,
      N.contexts,NativePrivateSpendQ58CurrentRouteTransport.routeContext] using roles
  have collisions':(∑b:Branches G.decode Root,collisionMass p ns rel n ctx (dummy .decsSample) (terminal p ns rel n «prefix» reg b))≤
   (6*(q:ℝ)^2*((q:ℝ)/2^512))*normSquared (initial p ns rel n reg):=by
   calc
    _=∑f:R.FixedVectors (Counter:=G.Counter) .decsSample (G.keyBytes Root),∑b:Branches G.decode Root,
     normSquared (workspaceEventProjection (fun _ db=>collision p ns rel n ctx db)
      (B.fiber p ns rel n .decsSample ctx (dummy .decsSample) f (terminal p ns rel n «prefix» reg b))):=by
     unfold collisionMass
     exact Finset.sum_comm
    _≤_:=by
     simpa only [B.fiber,terminal,reached,initial,O.ordinaryRun_eq_compiled,
      N.contexts,NativePrivateSpendQ58CurrentRouteTransport.routeContext,collisionSpec,
      SmzaRp05ActualEventRecertification.event,SmzaRp05ActualEventRecertification.baseEvent,
      SmzaRp05AdaptiveKernelInstantiation.ignoreRetained] using! collisions
  have growth:0≤(q:ℝ)^3/2^512:=by positivity
  have first:=mul_le_mul_of_nonneg_left initNorm
   (show 0≤6*(q:ℝ)^2*(12*(q:ℝ)/2^512+(AR.totalLoss:ℝ)) by positivity)
  have second:=mul_le_mul_of_nonneg_left initNorm (show 0≤6*(q:ℝ)^2*((q:ℝ)/2^512) by positivity)
  have debt:=mul_le_mul_of_nonneg_left prefixNorm (show 0≤20*(q:ℝ)/Fintype.card (V) by positivity)
  have totalBound := add_le_add
    (add_le_add (collisions'.trans second) (roles'.trans first)) debt
  have regroup (x loss den card : ℝ) :
      6*x^2*(x/den)+6*x^2*(12*x/den+loss)+20*x/card =
      6*x^2*loss+78*x^3/den+20*x/card := by ring
  have slack : 78*(q:ℝ)^3/2^512 ≤ 88*(q:ℝ)^3/2^512 := by
    simpa only [mul_div_assoc] using
      (mul_le_mul_of_nonneg_right (show (78:ℝ) ≤ 88 by norm_num) growth)
  calc
    _ ≤ 6*(q:ℝ)^2*((q:ℝ)/2^512)+
        6*(q:ℝ)^2*(12*(q:ℝ)/2^512+(AR.totalLoss:ℝ))+
        20*(q:ℝ)/Fintype.card (V) := by
      simpa only [mul_one] using bound.trans totalBound
    _ = 6*(q:ℝ)^2*(AR.totalLoss:ℝ)+78*(q:ℝ)^3/2^512+
        20*(q:ℝ)/Fintype.card (V) :=
      regroup (q:ℝ) (AR.totalLoss:ℝ) (2^512) (Fintype.card (V))
    _ ≤ 6*(q:ℝ)^2*(AR.totalLoss:ℝ)+88*(q:ℝ)^3/2^512+
        20*(q:ℝ)/Fintype.card (V) :=
      add_le_add
        (add_le_add (le_refl (6*(q:ℝ)^2*(AR.totalLoss:ℝ))) slack)
        (le_refl (20*(q:ℝ)/Fintype.card (V)))
 exact aggregate.trans_lt numerical
private theorem witness_map_some{α β:Type} (f:α→Option β) (xs:List α) (ys:List β) (x:α)
 (member:x∈xs) (ok:xs.mapM f=some ys):∃y,f x=some y:=by
 induction xs generalizing ys with
 | nil=>simp at member
 | cons head tail ih=>
  cases h:f head with
  | none=>simp[List.mapM_cons,h] at ok
  | some value=>
   rcases List.mem_cons.mp member with same|later
   · subst x;exact⟨value,h⟩
   · cases rest:tail.mapM f with
     | none=>simp[List.mapM_cons,h,rest] at ok
     | some values=>exact ih values later rest
private theorem witness_stages_have_point (w:E.Wire) (oracle:Oracle) (t:E.Transcript)
 (st:E.ExecutionStages ns rel false n w oracle t) (clean:t.pending=false):
 ∃sample:NativePrivateSpendQ58CurrentDecsSampleDensity.Position,∃point:Goldilocks,
 SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point:=by
 have pcsClean:=NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false ns rel false n w oracle t st clean
 obtain⟨digest,stream,query,hash,raw,decoded,indices,qset⟩:=LI.pcs_has_same_raw_query
  ns st.openingPending w st.decoded st.opening oracle st.pcs st.pcsExecuted pcsClean
 obtain⟨sample,member⟩:=Finset.card_pos.mp (show 0<query.val.card by rw[query.property];decide)
 rw[qset] at member
 have index:sample.val∈st.pcs.indexes:=by
  rw[indices]
  exact List.mem_map.mpr ⟨sample,List.mem_toFinset.mp member,rfl⟩
 obtain⟨_,_,_,_,_,_,points,_⟩:=NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
  ns st.openingPending w st.decoded st.opening oracle st.pcs st.pcsExecuted
 obtain⟨point,success⟩:=witness_map_some (SmzaRp05DecsPointProjection.fieldPoint 13173) st.pcs.indexes st.pcs.decsPoints sample.val index points
 exact⟨sample,point,success⟩
private theorem witness_claims_have_point (b:Branches G.decode Root) (db:Database (G.Key Root) (V))
 (cl:ClaimsDatabaseEvent (Q.fullClaims Root b) db) (a:branchResult G.decode Root b=some ()):
 ∃sample:NativePrivateSpendQ58CurrentDecsSampleDensity.Position,∃point:Goldilocks,
 SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point:=by
 let oracle:=Q.claimOracle Root db (fun _=>0)
 have replay:=Q.current_grouped_claims_replay_actual_program Root b db cl (fun _=>0)
 have run:(Root).eval oracle=some ():=(Program.record_result oracle Root).symm.trans ((congrArg Prod.fst replay).trans a)
 obtain⟨w,_,verified⟩:=SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle p (E.verifierProgram ns rel false n) () run
 obtain⟨t,⟨st⟩,clean,_,_⟩:=E.accepted_execution_has_stages ns rel false n w oracle verified
 exact witness_stages_have_point ns rel n w oracle t st clean
/-- Same initialized ordinary QROM execution and all accepted branches,
 including satisfiable public relations. Private gates may be arbitrary
 database-independent contractions; the adversary cannot assign SHA512 leaf
 cells. This bounds failure of the source-owned satisfying-witness seam; it
 does not construct or assert an efficient extractor. Concrete F1
 native Rust/parser/compiler/platform binding remains separately trusted;
 no verified efficient-extractor contract is asserted. -/
theorem initialized_accepted_no_source_witness_mass_below_128
 (metadata:Metadata) (dummy:(r:Role)→R.Active r (G.keyBytes Root)) (fb:G.RawDigest)
 {q finish queries:Nat} («prefix»:O.OrdinaryPrefix (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
 (reg:Registers) (normalized:Subnormalized (initial p ns rel n reg))
 (d:Nat) (read:ReadsAtMost G.decode d Root) (support:finish+d≤q) (queriesBound:queries+d≤q) (lifetime:q≤3*2^64):
 noSourceWitnessMass p ns rel n «prefix» reg<(2:ℝ)^(-128:ℤ):=by
 by_cases success:∃sample:NativePrivateSpendQ58CurrentDecsSampleDensity.Position,∃point:Goldilocks,
  SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point
 · obtain⟨sample,point,lookup⟩:=success
   exact witness_mass_below_128_of_point_success p ns rel n metadata dummy fb sample point lookup
    «prefix» reg normalized d read support queriesBound lifetime
 · letI:=physicalBranchesFintype G.decode Root
   have zero:∀b:Branches G.decode Root,branchResult G.decode Root b=some ()→
    normSquared (terminal p ns rel n «prefix» reg b)=0:=by
    intro b accepted
    have standard:globalDecompress (terminal p ns rel n «prefix» reg b)=0:=by
     funext basis
     by_contra nonzero
     exact (success (witness_claims_have_point p ns rel n b basis.database
      (NativePrivateSpendQ58CurrentSourceCompletion.physical_full_claims Root b (reached p ns rel n «prefix» reg) basis nonzero) accepted)).elim
    have normEq:normSquared (globalDecompress (terminal p ns rel n «prefix» reg b))=
     normSquared (terminal p ns rel n «prefix» reg b):=by
     unfold globalDecompress
     exact decompress_list_preserves_norm_squared _ _
    rw[standard] at normEq
    simpa[normSquared] using normEq.symm
   have failureZero:∀b:Branches G.decode Root,branchResult G.decode Root b=some ()→
    normSquared (WC.failure p ns rel n b (terminal p ns rel n «prefix» reg b))=0:=by
    intro b accepted
    have le:normSquared (WC.failure p ns rel n b (terminal p ns rel n «prefix» reg b))≤
     normSquared (terminal p ns rel n «prefix» reg b):=by
     change normSquared (workspaceEventProjection
       (fun _ db => ¬SourceWitness p ns rel n b
         (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) db))
       (terminal p ns rel n «prefix» reg b)) ≤
       normSquared (terminal p ns rel n «prefix» reg b)
     simpa only [current_true_projection_mass] using!
      (SmzaRp05CurrentPhysicalBranchClaims.workspace_event_mass_le_of_inclusion
       (fun _ db=>¬SourceWitness p ns rel n b (SmzaRp05ConditionedExecution.xView (X.sourceKeys Root) db))
       (fun _ _=>True) (terminal p ns rel n «prefix» reg b) (by intro _ _ _;trivial))
    rw[zero b accepted] at le
    exact le_antisymm le (by unfold normSquared;exact Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _))
   have massZero:noSourceWitnessMass p ns rel n «prefix» reg=0:=by
    unfold noSourceWitnessMass
    apply Finset.sum_eq_zero
    intro b _
    by_cases accepted:branchResult G.decode Root b=some ()
    · rw[if_pos accepted,failureZero b accepted]
    · rw[if_neg accepted]
   rw[massZero]
   positivity
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceInitialized128
