import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceInitialized128
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
noncomputable section
set_option autoImplicit false
variable{BaseWork:Type}[Fintype BaseWork][DecidableEq BaseWork]
variable (p:Program E.Wire) (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
 (rel:NativePrivateSpendQ58CurrentPublicOpening.Relation) (n:Fin (2^32))
local notation "Root"=>root p ns rel n
local notation "W"=>SmzaRp05CurrentAdaptiveExecution.Work (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "V"=>VectorOutput G.Counter
local notation "Registers"=>RegisterBasis (Input:=G.Key Root) (Phase:=V) (Workspace:=W)→ℂ
local notation "Metadata"=>SmzaRp05CurrentAdaptiveExecution.Context (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork)
private theorem map_some{α β:Type} (f:α→Option β) (xs:List α) (ys:List β) (x:α)
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
private theorem stages_have_point (w:E.Wire) (oracle:Oracle) (t:E.Transcript)
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
 obtain⟨point,success⟩:=map_some (SmzaRp05DecsPointProjection.fieldPoint 13173) st.pcs.indexes st.pcs.decsPoints sample.val index points
 exact⟨sample,point,success⟩
private theorem claims_have_point (b:Branches G.decode Root) (db:Database (G.Key Root) (V))
 (cl:ClaimsDatabaseEvent (Q.fullClaims Root b) db) (a:branchResult G.decode Root b=some ()):
 ∃sample:NativePrivateSpendQ58CurrentDecsSampleDensity.Position,∃point:Goldilocks,
 SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point:=by
 let oracle:=Q.claimOracle Root db (fun _=>0)
 have replay:=Q.current_grouped_claims_replay_actual_program Root b db cl (fun _=>0)
 have run:(Root).eval oracle=some ():=(Program.record_result oracle Root).symm.trans ((congrArg Prod.fst replay).trans a)
 obtain⟨w,_,verified⟩:=SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle p (E.verifierProgram ns rel false n) () run
 obtain⟨t,⟨st⟩,clean,_,_⟩:=E.accepted_execution_has_stages ns rel false n w oracle verified
 exact stages_have_point ns rel n w oracle t st clean
section
open NativePrivateSpendQ58CurrentAcceptedSourceArithmetic
open NativePrivateSpendQ58CurrentFinalCoefficientNumerics
open NativePrivateSpendQ58CurrentRoleEventPhysicalMass (localLoss)

private theorem current_final_total_loss_eq :
    totalLoss = M.matrixLoss+D.loss+P.matrixLoss+P.openingLoss := by
  have roles : (Finset.univ : Finset Role) =
      {.decsMatrix,.decsSample,.piopMatrix,.piopOpening} := by decide
  unfold totalLoss
  rw [roles]
  simp [localLoss, add_assoc]

private theorem current_final_total_loss_nonnegative : (0 : Rat) ≤ totalLoss := by
  rw [current_final_total_loss_eq]
  have matrix : (0 : Rat) ≤ M.matrixLoss := by
    unfold M.matrixLoss
    exact div_nonneg (by norm_num) (Nat.cast_nonneg _)
  have sample : (0 : Rat) ≤ D.loss := by
    unfold D.loss
    exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
  have piopMatrix : (0 : Rat) ≤ P.matrixLoss := by
    unfold P.matrixLoss
    exact pow_nonneg (div_nonneg zero_le_one (Nat.cast_nonneg _)) _
  have opening : (0 : Rat) ≤ P.openingLoss := by
    unfold P.openingLoss
    exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
  exact add_nonneg (add_nonneg (add_nonneg matrix sample) piopMatrix) opening

end

/-- The literal current accepted-invalid initialized endpoint has no supplied
 classifier, event certificate, mass estimate, or point-search-success premise. -/
theorem initialized_accepted_invalid_mass_below_128
 (metadata:Metadata) (dummy:(r:Role)→R.Active r (G.keyBytes Root)) (fb:G.RawDigest)
 {q finish queries:Nat} («prefix»:O.OrdinaryPrefix (Key:=G.Key Root) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
 (reg:Registers) (normalized:Subnormalized (initial p ns rel n reg))
 (d:Nat) (read:ReadsAtMost G.decode d Root) (support:finish+d≤q) (queriesBound:queries+d≤q) (lifetime:q≤3*2^64)
 (invalid:¬∃z:NativePrivateSpendQ58CurrentDecodedRelation.Decoded,
 NativePrivateSpendQ58CurrentPublicOpening.Satisfies rel (NativePrivateSpendQ58CurrentDecodedRelation.decodedValues z)):
 acceptedMass p ns rel n «prefix» reg<(2:ℝ)^(-128:ℤ):=by
 by_cases success:∃sample:NativePrivateSpendQ58CurrentDecsSampleDensity.Position,∃point:Goldilocks,
  SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point
 · obtain⟨sample,point,lookup⟩:=success
   exact initialized_accepted_invalid_mass_below_128_of_point_success p ns rel n metadata dummy fb sample point lookup
    «prefix» reg normalized d read support queriesBound lifetime invalid
 · letI:=physicalBranchesFintype G.decode Root
   let born:=fun b:Branches G.decode Root=>normSquared (terminal p ns rel n «prefix» reg b)
   have each:∀b:Branches G.decode Root,
    (if branchResult G.decode Root b=some () then born b else 0)≤
    (2*(q:ℝ)/Fintype.card (V))*born b:=by
    intro b
    have mass:0≤born b:=by dsimp[born];unfold normSquared;exact Finset.sum_nonneg (fun _ _=>Complex.normSq_nonneg _)
    by_cases a:branchResult G.decode Root b=some ()
    · rw[if_pos a]
      have zero:databaseEventProjection (ClaimsDatabaseEvent (Q.fullClaims Root b)) (terminal p ns rel n «prefix» reg b)=0:=by
       funext basis
       by_cases cl:ClaimsDatabaseEvent (Q.fullClaims Root b) basis.database
       · exact (success (claims_have_point p ns rel n b basis.database cl a)).elim
       · simp[databaseEventProjection,cl]
      have split:=SmzaRp05CurrentKnownClaimsFailureMass.database_event_complement_mass_split
       (ClaimsDatabaseEvent (Q.fullClaims Root b)) (terminal p ns rel n «prefix» reg b)
      rw[zero] at split
      have debt:=NativePrivateSpendQ58CurrentAcceptedSourceCut.unselected_full_claim_failure_le p ns rel n b (reached p ns rel n «prefix» reg)
      have count:(Q.fullClaims Root b).toFinset.card≤q:=(List.toFinset_card_le _).trans ((full_count p ns rel n b d read).trans (by omega))
      have scaled:(((2*(Q.fullClaims Root b).toFinset.card:Nat):ℝ)/Fintype.card (V))*born b≤
       (2*(q:ℝ)/Fintype.card (V))*born b:=by
       apply mul_le_mul_of_nonneg_right _ mass
       apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
       exact_mod_cast Nat.mul_le_mul_left 2 count
      have retained:normSquared (databaseEventProjection (fun db=>¬ClaimsDatabaseEvent (Q.fullClaims Root b) db)
       (terminal p ns rel n «prefix» reg b))=born b:=by simpa[normSquared,born] using split
      change normSquared (databaseEventProjection (fun db=>¬ClaimsDatabaseEvent (Q.fullClaims Root b) db)
       (terminal p ns rel n «prefix» reg b))≤_ at debt
      rw[retained] at debt
      exact debt.trans scaled
    · rw[if_neg a];exact mul_nonneg
        (div_nonneg (mul_nonneg (by norm_num) (Nat.cast_nonneg q)) (Nat.cast_nonneg _)) mass
   have total:SmzaRp05RoleReadTotality.StandardOn (Finset.univ:Finset (G.Key Root)).toList (reached p ns rel n «prefix» reg):=by
    intro k _;exact ST.initialized_ordinary_run_standard_total «prefix» reg k
   have conserved:=SmzaRp05CurrentPhysicalNonchallengeClaims.physical_branch_mass_eq_initial_of_reads_within
    (G.encode Root) G.decode Root (reached p ns rel n «prefix» reg) (Finset.univ:Finset (G.Key Root)).toList (reads_univ (G.encode Root) Root) total
   have normalizedPrefix: normSquared (reached p ns rel n «prefix» reg)≤1:=by
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
    simpa[Subnormalized,reached,initial,O.ordinaryRun_eq_compiled] using
     SmzaRp05ConditionedExecution.CertifiedFor.common_run_subnormalized cert .decsSample normalized
   have sum:=Finset.sum_le_sum (s := (Finset.univ : Finset (Branches G.decode Root))) (fun b _=>each b)
   have terminalConserved : (∑b:Branches G.decode Root, born b) =
       normSquared (reached p ns rel n «prefix» reg) := by
     simpa only [born,terminal] using conserved
   rw[←Finset.mul_sum,terminalConserved] at sum
   have lossNonnegative : (0 : ℝ) ≤
       (NativePrivateSpendQ58CurrentAcceptedSourceArithmetic.totalLoss : ℝ) :=
     (Rat.cast_nonneg (K := ℝ)).mpr current_final_total_loss_nonnegative
   have qNonnegative : (0 : ℝ) ≤ q := Nat.cast_nonneg q
   have quadratic : (0 : ℝ) ≤ (q : ℝ)^2*
       (NativePrivateSpendQ58CurrentAcceptedSourceArithmetic.totalLoss : ℝ) :=
     mul_nonneg (sq_nonneg _) lossNonnegative
   have cubic : (0 : ℝ) ≤ (q : ℝ)^3/(2 : ℝ)^512 :=
     div_nonneg (pow_nonneg qNonnegative _) (pow_nonneg (by norm_num) _)
   have linear : 2*(q : ℝ)/Fintype.card (V) ≤ 20*(q : ℝ)/Fintype.card (V) :=
     div_le_div_of_nonneg_right
       (mul_le_mul_of_nonneg_right (show (2 : ℝ) ≤ 20 by norm_num) qNonnegative)
       (Nat.cast_nonneg _)
   have quadraticNonnegative : (0 : ℝ) ≤ 6*(q : ℝ)^2*
       (NativePrivateSpendQ58CurrentAcceptedSourceArithmetic.totalLoss : ℝ) := by
     simpa only [mul_assoc] using
       mul_nonneg (show (0 : ℝ) ≤ 6 by norm_num) quadratic
   have cubicNonnegative : (0 : ℝ) ≤ 72*(q : ℝ)^3/(2 : ℝ)^512 := by
     simpa only [mul_div_assoc] using
       mul_nonneg (show (0 : ℝ) ≤ 72 by norm_num) cubic
   have arithmeticUpper : 2*(q : ℝ)/Fintype.card (V) ≤
       6*(q : ℝ)^2*(NativePrivateSpendQ58CurrentAcceptedSourceArithmetic.totalLoss : ℝ)+
         72*(q : ℝ)^3/2^512+20*q/Fintype.card (V) :=
     linear.trans (le_add_of_nonneg_left (add_nonneg quadraticNonnegative cubicNonnegative))
   calc
     _ ≤ (2*(q : ℝ)/Fintype.card (V))*normSquared (reached p ns rel n «prefix» reg) := sum
     _ ≤ 2*(q : ℝ)/Fintype.card (V) :=
       mul_le_of_le_one_right
         (div_nonneg (mul_nonneg (by norm_num) qNonnegative) (Nat.cast_nonneg _)) normalizedPrefix
     _ < _ := arithmeticUpper.trans_lt
       (NativePrivateSpendQ58CurrentAcceptedSourceArithmetic.accepted_arithmetic_below_128 G.zero q lifetime)
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceInitialized128
