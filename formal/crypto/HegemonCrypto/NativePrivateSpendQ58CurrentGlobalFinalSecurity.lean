import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalInitializedSourceMass
import HegemonCrypto.NativePrivateSpendCurrentG1CanonicalGameAdapter

/-! Caller-free current global source failure, and explicit CURRENT primitive
composition. The original physical execution/lifetime query budget are kept.
F1 remains the finite actual native/source interpretation of SourceOutcome;
the source theorem does not create that interpretation, an efficient extractor
or a Rust refinement proof. Seven primitive games retain their actual widths,
domains and target shapes. Their total advantage consumes a stated remaining
budget; no bare/RP05 game is renamed, and no primitive receives the SHA512 term.
SOURCE ONLY until exact kernel checks and original-source release review. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalFinalSecurity
open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsQuerySequence HegemonCrypto.FiniteOracleDatabase
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open SmzaRp05AdaptivePhysicalReadBound (ReadsAtMost physicalBranchesFintype)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaChallengeStageTargets (Role)
namespace M
export NativePrivateSpendQ58CurrentGlobalInitializedSourceMass
  (initial reached terminal failure missingSourceMass full_count
   initialized_global_source_mass_below_129_of_point_success)
end M
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter keyBytes encode decode zero)
end G
namespace H
export NativePrivateSpendQ58CurrentGlobalRawLogTransport
  (Stage adaptiveHistoryProgram historyProgram actualTerminalRoot actualTerminalProducer actualTerminalKeys)
end H
namespace GS
export NativePrivateSpendQ58CurrentGlobalSourceSupport (NativeStageInput nativeConstructor)
end GS
namespace S
export NativePrivateSpendQ58CurrentGlobalSourceSelector (canonical missingSource)
end S
namespace GC
export NativePrivateSpendQ58CurrentGlobalSourceClassification
  (actual_accepted_global_history_has_same_source_classifiers observerSourceView)
end GC
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport (sourceKeys sourceProjection)
end X
namespace SC
export NativePrivateSpendQ58CurrentSourceCompletion (SourceClaims complete_source_claims consistent_of_claims)
end SC
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay (claimOracle fullClaims current_grouped_claims_replay_actual_program)
end Q
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire Transcript ExecutionStages verifierProgram accepted_execution_has_stages)
end E
namespace LI
export NativePrivateSpendQ58CurrentDecsLiteralInclusion (pcs_has_same_raw_query)
end LI
namespace O
export SmzaRp05OrdinarySoundnessExecution
  (OrdinaryPrefix compileOrdinary compileOrdinary_certified emptyAuthorizationContexts ordinaryRun_eq_compiled)
end O
namespace N
export NativePrivateSpendQ58CurrentRoleEventPhysicalMass (contexts)
end N
namespace R
export NativePrivateSpendQ58CurrentFiberMassTransport (Active)
end R
namespace ST
export SmzaRp05OrdinarySoundnessStandardTotal (initialized_ordinary_run_standard_total)
end ST
namespace CG
export HegemonCrypto.NativePrivateSpendCurrentG1CanonicalGameAdapter
  (SourceOutcome sourceGameEvent same_execution_current_g1_failure_mass_le_game_sum)
end CG
namespace CC
export NativePrivateSpendQ58CurrentCanonicalSourceClassifier (sourceOracle records)
end CC
namespace RG
export NativePrivateSpendQ58CurrentRecoveryGeometry (RecoveryGeometry)
end RG
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (decodedValues)
end D
namespace Union
export SmzaRoleDomainConditioning (finiteNormSquared eventProjection same_execution_event_union_bound)
end Union
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
local instance sourcePrimeFact : Fact (Nat.Prime HegemonCrypto.NativePrivateSpendLocalSemantics.modulus) :=
  ⟨HegemonCrypto.SmallWood.goldilocks_prime⟩
variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
variable (template : NativePrivateSpendQ58CurrentCausalSourceJoin.SourceTemplate)
    (inputConstructor : Program (List GS.NativeStageInput))
local notation "Ctor" => GS.nativeConstructor template inputConstructor
local notation "Global" => H.adaptiveHistoryProgram Ctor
local notation "V" => VectorOutput G.Counter
local notation "W" => SmzaRp05CurrentAdaptiveExecution.Work (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "Metadata" => SmzaRp05CurrentAdaptiveExecution.Context (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork)
local notation "Registers" => RegisterBasis (Input:=G.Key Global) (Phase:=V) (Workspace:=W) → ℂ
private theorem map_some {α β : Type} (f : α → Option β) (xs : List α) (ys : List β)
    (x : α) (member : x∈xs) (success : xs.mapM f=some ys) : ∃ y,f x=some y := by
  induction xs generalizing ys with
  | nil => simp at member
  | cons head tail ih =>
    cases value : f head with
    | none => simp [List.mapM_cons,value] at success
    | some output =>
      rcases List.mem_cons.mp member with same | later
      · subst x;exact ⟨output,value⟩
      · cases rest : tail.mapM f with
        | none => simp [List.mapM_cons,value,rest] at success
        | some values => exact ih values later rest
private theorem accepted_observer_has_point
    (producer : Program E.Wire) (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce : Fin (2^32))
    (branch : Branches G.decode (producer.bind (E.verifierProgram ns relation false nonce)))
    (database : Database (G.Key (producer.bind (E.verifierProgram ns relation false nonce))) V)
    (claims : ClaimsDatabaseEvent (Q.fullClaims (producer.bind (E.verifierProgram ns relation false nonce)) branch) database)
    (accepted : branchResult G.decode (producer.bind (E.verifierProgram ns relation false nonce)) branch=some ()) :
    ∃ sample : NativePrivateSpendQ58CurrentDecsSampleDensity.Position,∃ point : Goldilocks,
      SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point := by
  let root := producer.bind (E.verifierProgram ns relation false nonce)
  let oracle := Q.claimOracle root database (fun _ => 0)
  have replay := Q.current_grouped_claims_replay_actual_program root branch database claims (fun _ => 0)
  have ordinary : root.eval oracle=some () :=
    (Program.record_result oracle root).symm.trans ((congrArg Prod.fst replay).trans accepted)
  obtain ⟨wire,_produced,verified⟩ := SmzaRp05FinalProgramMiddleExecution.program_bind_success
    oracle producer (E.verifierProgram ns relation false nonce) () ordinary
  obtain ⟨transcript,⟨stages⟩,clean,_,_⟩ := E.accepted_execution_has_stages ns relation false nonce wire oracle verified
  have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
    ns relation false nonce wire oracle transcript stages clean
  obtain ⟨digest,stream,query,_hash,_raw,_decoded,indices,sameSet⟩ := LI.pcs_has_same_raw_query
    ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted pcsClean
  obtain ⟨sample,member⟩ := Finset.card_pos.mp (show 0<query.val.card by rw [query.property];decide)
  rw [sameSet] at member
  have index : sample.val∈stages.pcs.indexes := by
    rw [indices]
    exact List.mem_map.mpr ⟨sample,List.mem_toFinset.mp member,rfl⟩
  obtain ⟨_,_,_,_,_,_,points,_⟩ := NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
    ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted
  obtain ⟨point,lookup⟩ := map_some (SmzaRp05DecsPointProjection.fieldPoint 13173)
    stages.pcs.indexes stages.pcs.decsPoints sample.val index points
  exact ⟨sample,point,lookup⟩

/-- A missing witness on a completely claimed actual accepted branch requires
an actual stage. Empty histories have their vacuous witnesses, so no point
lookup is assumed and no empty-history security behavior is manufactured. -/
private theorem actual_missing_source_claims_have_point
    (branch : Branches G.decode Global) (database : Database (G.Key Global) V)
    (claims : ClaimsDatabaseEvent (Q.fullClaims Global branch) database)
    (accepted : branchResult G.decode Global branch=some ())
    (missing : S.missingSource template inputConstructor branch
      (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database)) :
    ∃ sample : NativePrivateSpendQ58CurrentDecsSampleDensity.Position,∃ point : Goldilocks,
      SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point := by
  let view := SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database
  let full := S.canonical template inputConstructor branch view
  have sources : SC.SourceClaims Global branch view := by
    intro key value member source
    exact claims (key,value) member
  have all : ClaimsDatabaseEvent (Q.fullClaims Global branch) full :=
    SC.complete_source_claims Global branch view 0 sources (SC.consistent_of_claims Global branch database claims)
  obtain ⟨stages,constructed,historyAccepted,classifiers⟩ :=
    GC.actual_accepted_global_history_has_same_source_classifiers Ctor branch full all accepted
  by_cases present : 0<stages.length
  · let i : Fin stages.length := ⟨0,present⟩
    obtain ⟨observer,observerAccepted,_log,observerClaims,_classified⟩ := classifiers i
    exact accepted_observer_has_point (H.actualTerminalProducer Ctor stages i)
      stages[i.val].ns stages[i.val].relation stages[i.val].nonce observer _ observerClaims observerAccepted
  · apply False.elim
    apply missing
    refine ⟨stages,constructed,historyAccepted,?_⟩
    intro i
    have bound := i.isLt
    omega

theorem initialized_global_missing_source_mass_below_129
    (metadata : Metadata) (dummy : (role : Role) → R.Active role (G.keyBytes Global))
    {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) (normalized : Subnormalized (M.initial template inputConstructor registers))
    (count : Nat) (reads : ReadsAtMost G.decode count Global)
    (support : finish+count≤q) (queriesBound : queries+count≤q) (lifetime : q≤3*2^64) :
    M.missingSourceMass template inputConstructor «prefix» registers < (2:ℝ)^(-129:ℤ) := by
  by_cases success : ∃ sample : NativePrivateSpendQ58CurrentDecsSampleDensity.Position,∃ point : Goldilocks,
      SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val=some point
  · obtain ⟨sample,point,lookup⟩ := success
    exact M.initialized_global_source_mass_below_129_of_point_success template inputConstructor
      metadata dummy sample point lookup «prefix» registers normalized count reads support queriesBound lifetime
  · letI := physicalBranchesFintype G.decode Global
    have each : ∀ branch : Branches G.decode Global,
        (if branchResult G.decode Global branch=some () then
          normSquared (M.failure template inputConstructor branch (M.terminal template inputConstructor «prefix» registers branch)) else 0) ≤
        (2*(q:ℝ)/Fintype.card V)*normSquared (M.terminal template inputConstructor «prefix» registers branch) := by
      intro branch
      let state := M.terminal template inputConstructor «prefix» registers branch
      have mass : 0≤normSquared state := by unfold normSquared;exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)
      by_cases accepted : branchResult G.decode Global branch=some ()
      · rw [if_pos accepted]
        have zero : databaseEventProjection (ClaimsDatabaseEvent (Q.fullClaims Global branch))
            (M.failure template inputConstructor branch state)=0 := by
          funext basis
          by_cases claims : ClaimsDatabaseEvent (Q.fullClaims Global branch) basis.database
          · by_cases missing : S.missingSource template inputConstructor branch
                (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) basis.database)
            · exact (success (actual_missing_source_claims_have_point template inputConstructor branch
                basis.database claims accepted missing)).elim
            · simp [M.failure,X.sourceProjection,SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection,
                databaseEventProjection,workspaceEventProjection,missing]
          · simp [databaseEventProjection,claims]
        have split := SmzaRp05CurrentKnownClaimsFailureMass.database_event_complement_mass_split
          (ClaimsDatabaseEvent (Q.fullClaims Global branch)) (M.failure template inputConstructor branch state)
        rw [zero] at split
        have zeroNorm : normSquared (0 : SmzaRp05CurrentAdaptiveExecution.CmsState
            (Key := G.Key Global) (Counter := G.Counter) (BaseWork := BaseWork)) = 0 := by
          simp only [normSquared, Pi.zero_apply, Complex.normSq_zero, Finset.sum_const_zero]
        rw [zeroNorm, zero_add] at split
        have debt : normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims Global branch) state) ≤
            (((2*(Q.fullClaims Global branch).toFinset.card:Nat):ℝ)/Fintype.card V)*normSquared state := by
          apply SmzaRp05CurrentKnownClaimsFailureMass.global_known_claims_failure_mass_le
          intro claim member
          exact SmzaRp05CurrentPhysicalBranchClaimReadback.physical_branch_claim_known_at_standard
            (G.encode Global) G.decode Global branch (M.reached template inputConstructor «prefix» registers) claim member
        have restriction := SmzaRp05CurrentPhysicalBranchClaims.workspace_event_mass_le_of_inclusion
          (fun _ database => ¬ClaimsDatabaseEvent (Q.fullClaims Global branch) database ∧
            S.missingSource template inputConstructor branch (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database))
          (fun _ database => ¬ClaimsDatabaseEvent (Q.fullClaims Global branch) database) state
          (by intro _ _ both;exact both.1)
        have selected : normSquared (databaseEventProjection (fun database => ¬ClaimsDatabaseEvent (Q.fullClaims Global branch) database)
            (M.failure template inputConstructor branch state)) ≤
            normSquared (SmzaRp05PartialReadout.claimFailureProjection (Q.fullClaims Global branch) state) := by
          convert restriction using 1
          · congr 1
            funext basis
            by_cases claims : ClaimsDatabaseEvent (Q.fullClaims Global branch) basis.database <;>
              by_cases missing : S.missingSource template inputConstructor branch (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) basis.database) <;>
              simp [M.failure,X.sourceProjection,SmzaRp05CurrentNonchallengeSelectorTransport.nonchallengeSelectorProjection,
                databaseEventProjection,workspaceEventProjection,claims,missing]
          · rfl
        have fullCount : (Q.fullClaims Global branch).toFinset.card≤q :=
          (List.toFinset_card_le _).trans ((M.full_count template inputConstructor branch count reads).trans (by omega))
        have scaled : (((2*(Q.fullClaims Global branch).toFinset.card:Nat):ℝ)/Fintype.card V)*normSquared state ≤
            (2*(q:ℝ)/Fintype.card V)*normSquared state := by
          apply mul_le_mul_of_nonneg_right _ mass
          apply div_le_div_of_nonneg_right _ (by positivity)
          exact_mod_cast Nat.mul_le_mul_left 2 fullCount
        exact (le_of_eq split.symm).trans (selected.trans (debt.trans scaled))
      · rw [if_neg accepted]
        exact mul_nonneg (by positivity) mass
    have total : SmzaRp05RoleReadTotality.StandardOn (Finset.univ:Finset (G.Key Global)).toList
        (M.reached template inputConstructor «prefix» registers) := by
      intro key _;exact ST.initialized_ordinary_run_standard_total «prefix» registers key
    have conserved := SmzaRp05CurrentPhysicalNonchallengeClaims.physical_branch_mass_eq_initial_of_reads_within
      (G.encode Global) G.decode Global (M.reached template inputConstructor «prefix» registers)
      (Finset.univ:Finset (G.Key Global)).toList (NativePrivateSpendQ58CurrentAcceptedSourceInitialized128.reads_univ (G.encode Global) Global) total
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
    have prefixNorm : normSquared (M.reached template inputConstructor «prefix» registers)≤1 := by
      simpa [Subnormalized,M.reached,M.initial,O.ordinaryRun_eq_compiled] using
        SmzaRp05ConditionedExecution.CertifiedFor.common_run_subnormalized certified .decsSample normalized
    have sum := Finset.sum_le_sum (s := (Finset.univ : Finset (Branches G.decode Global)))
      (fun branch _ => each branch)
    have terminalConserved :
        (∑ branch : Branches G.decode Global,
          normSquared (M.terminal template inputConstructor «prefix» registers branch)) =
        normSquared (M.reached template inputConstructor «prefix» registers) := by
      simpa only [M.terminal] using conserved
    rw [←Finset.mul_sum,terminalConserved] at sum
    have card : (2:ℝ)^512≤Fintype.card V := by
      exact_mod_cast NativePrivateSpendQ58CurrentAcceptedSourceArithmetic.vector_card_lower G.zero
    have qb : (q:ℝ)≤3*2^64 := by exact_mod_cast lifetime
    calc
      _ ≤ (2*(q:ℝ)/Fintype.card V)*normSquared (M.reached template inputConstructor «prefix» registers) := sum
      _ ≤ 2*(q:ℝ)/Fintype.card V :=
        mul_le_of_le_one_right
          (div_nonneg (mul_nonneg (by norm_num : (0:ℝ) ≤ 2) (Nat.cast_nonneg q))
            (Nat.cast_nonneg (Fintype.card V))) prefixNorm
      _ ≤ 2*(3*2^64)/2^512 := by
        have numeratorBound : 2*(q:ℝ) ≤ 2*((3:ℝ)*2^64) :=
          mul_le_mul_of_nonneg_left qb (by norm_num : (0:ℝ) ≤ 2)
        have cardNonnegative : (0:ℝ) ≤ (Fintype.card V:ℝ) :=
          Nat.cast_nonneg (Fintype.card V)
        have upperNumeratorNonnegative : (0:ℝ) ≤ 2*((3:ℝ)*2^64) :=
          mul_nonneg (by norm_num : (0:ℝ) ≤ 2)
            (mul_nonneg (by norm_num : (0:ℝ) ≤ 3)
              (pow_nonneg (by norm_num : (0:ℝ) ≤ 2) 64))
        have denominatorPositive : (0:ℝ) < (2:ℝ)^512 :=
          pow_pos (by norm_num : (0:ℝ) < 2) 512
        exact (div_le_div_of_nonneg_right numeratorBound cardNonnegative).trans
          (div_le_div_of_nonneg_left upperNumeratorNonnegative denominatorPositive card)
      _ < _ := by
        have pow512 : (2:ℝ)^512 = (2:ℝ)^256*(2:ℝ)^256 := by
          simpa only [show (512:Nat)=256+256 from rfl] using (pow_add (2:ℝ) 256 256)
        simp only [pow512]
        norm_num

/-- Retained F1 data readout of THIS canonical branch/source DB, actual stage,
wire and calculated recovery source. RelationCertificate retains current CSR.
Native append/snapshot interpretation is explicit F1 trust; no authorization,
event inclusion, mass bound or efficient-extraction assertion is supplied. -/
def SameSourceOutcome (branch : Branches G.decode Global)
    (basis : Basis (G.Key Global) V V W) (outcome : CG.SourceOutcome) : Prop :=
  let database := S.canonical template inputConstructor branch
    (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) basis.database)
  let oracle := Q.claimOracle Global database (fun _ => 0)
  ∃ (stages : List H.Stage) (constructed : (Ctor).eval oracle=some stages)
    (i : Fin stages.length),
    (H.historyProgram stages).eval oracle=some () ∧
    ∃ observer : Branches G.decode (H.actualTerminalRoot Ctor stages i),
      branchResult G.decode (H.actualTerminalRoot Ctor stages i) observer=some () ∧
      (SmzaRp05PhysicalAcceptedReplayLite.rawLog G.decode (H.actualTerminalRoot Ctor stages i) observer).toFinset=
        (SmzaRp05PhysicalAcceptedReplayLite.rawLog G.decode Global branch).toFinset ∧
      ClaimsDatabaseEvent (Q.fullClaims (H.actualTerminalRoot Ctor stages i) observer)
        (fun key => database (H.actualTerminalKeys Ctor oracle stages constructed i key)) ∧
      let view := GC.observerSourceView Ctor oracle stages constructed i database
      let atOracle := CC.sourceOracle (H.actualTerminalProducer Ctor stages i)
        stages[i.val].ns stages[i.val].relation stages[i.val].nonce observer view
      ∃ wire, ∃ transcript,
        ∃ native : E.ExecutionStages stages[i.val].ns stages[i.val].relation false
          stages[i.val].nonce wire atOracle transcript,
          (H.actualTerminalProducer Ctor stages i).eval atOracle=some wire ∧
          transcript.pending=false ∧
          ∃ geometry : RG.RecoveryGeometry stages[i.val].ns wire native.decoded native.opening native.pcs
              (CC.records (H.actualTerminalProducer Ctor stages i)
                stages[i.val].ns stages[i.val].relation stages[i.val].nonce view),
            outcome.final.source.relation=stages[i.val].relation ∧
            outcome.final.source.packed=D.decodedValues geometry.source ∧
            outcome.snapshot.«public»=(fun j : Fin 77 => (V8SmzaOracleParser.wordAt stages[i.val].ns.binding j.val : Goldilocks))

/-- F1 readout is indexed by the actual original branch/computational basis,
not a free carrier or a second execution. Each returned native outcome must
retain the explicit same-source ordinary-data interpretation above. -/
structure NativeReadout where
  outcome : (branch : Branches G.decode Global) → Basis (G.Key Global) V V W → Option CG.SourceOutcome
  binding : ∀ branch basis value, outcome branch basis=some value →
    SameSourceOutcome template inputConstructor branch basis value

def nativeUnauthorized (readout : NativeReadout (BaseWork:=BaseWork) template inputConstructor)
    (branch : Branches G.decode Global) (basis : Basis (G.Key Global) V V W) : Prop :=
  ∃ outcome,readout.outcome branch basis=some outcome ∧ outcome.unauthorized

def nativeGame (readout : NativeReadout (BaseWork:=BaseWork) template inputConstructor) (kind : Fin 7)
    (branch : Branches G.decode Global) (basis : Basis (G.Key Global) V V W) : Prop :=
  ∃ outcome,readout.outcome branch basis=some outcome ∧ CG.sourceGameEvent kind outcome

def sourceGood {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) (branch : Branches G.decode Global) : Basis (G.Key Global) V V W → ℂ :=
  if branchResult G.decode Global branch=some () then
    workspaceEventProjection (fun _ database => ¬S.missingSource template inputConstructor branch
      (SmzaRp05ConditionedExecution.xView (X.sourceKeys Global) database))
      (M.terminal template inputConstructor «prefix» registers branch)
  else 0

def nativeMass {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) (event : Branches G.decode Global → Basis (G.Key Global) V V W → Prop) : ℝ :=
  letI := physicalBranchesFintype G.decode Global
  ∑ branch : Branches G.decode Global, Union.finiteNormSquared
    (Union.eventProjection (event branch)
      (sourceGood template inputConstructor «prefix» registers branch))

omit [Fintype BaseWork] [DecidableEq BaseWork] in
private theorem native_coverage (readout : NativeReadout template inputConstructor)
    (branch : Branches G.decode Global) (basis : Basis (G.Key Global) V V W)
    (bad : nativeUnauthorized template inputConstructor readout branch basis) :
    ∃ kind : Fin 7,nativeGame template inputConstructor readout kind branch basis := by
  obtain ⟨outcome,read,bad⟩ := bad
  obtain ⟨kind,game⟩ := HegemonCrypto.NativePrivateSpendCurrentG1CanonicalGameAdapter.source_game_coverage outcome bad
  exact ⟨kind,outcome,read,game⟩

/-- One ORIGINAL initialized Born execution/lifetime Q, source-view failure
and seven distinct CURRENT readouts on its same terminal amplitudes.
Seven explicit advantages total at most2^-129; source loss supplies the other
half. Conditional on finite F1 interpretation/current primitive bounds;
no efficient extraction, primitive-security or production-approval claim.
The optional readout measures returned Final outcomes only; its None/ordinary
native-operation completeness and valid trace/Final construction remain F1
interface obligations, not consequences of the numerical bound. -/
theorem initialized_source_and_current_seven_game_mass_below_128
    (metadata : Metadata) (dummy : (role : Role) → R.Active role (G.keyBytes Global))
    {q finish queries : Nat}
    («prefix» : O.OrdinaryPrefix (Key:=G.Key Global) (Counter:=G.Counter) (BaseWork:=BaseWork) (cap:=q) 0 finish queries)
    (registers : Registers) (normalized : Subnormalized (M.initial template inputConstructor registers))
    (count : Nat) (reads : ReadsAtMost G.decode count Global)
    (support : finish+count≤q) (queriesBound : queries+count≤q) (lifetime : q≤3*2^64)
    (readout : NativeReadout template inputConstructor) (advantages : Fin 7 → ℝ)
    (games : ∀ kind : Fin 7,nativeMass template inputConstructor «prefix» registers
      (nativeGame template inputConstructor readout kind)≤advantages kind)
    (remaining : (∑ kind : Fin 7,advantages kind)≤(2:ℝ)^(-129:ℤ)) :
    M.missingSourceMass template inputConstructor «prefix» registers +
      nativeMass template inputConstructor «prefix» registers
        (nativeUnauthorized template inputConstructor readout) < (2:ℝ)^(-128:ℤ) := by
  letI := physicalBranchesFintype G.decode Global
  have source := initialized_global_missing_source_mass_below_129 template inputConstructor
    metadata dummy «prefix» registers normalized count reads support queriesBound lifetime
  have each (branch : Branches G.decode Global) :
      Union.finiteNormSquared
        (Union.eventProjection
          (nativeUnauthorized template inputConstructor readout branch)
          (sourceGood template inputConstructor «prefix» registers branch)) ≤
      ∑ kind : Fin 7,Union.finiteNormSquared
        (Union.eventProjection
          (nativeGame template inputConstructor readout kind branch)
          (sourceGood template inputConstructor «prefix» registers branch)) := by
    have monotone : Union.finiteNormSquared
        (Union.eventProjection
          (nativeUnauthorized template inputConstructor readout branch)
          (sourceGood template inputConstructor «prefix» registers branch)) ≤
        Union.finiteNormSquared
          (Union.eventProjection
            (fun basis => ∃ kind,nativeGame template inputConstructor readout kind branch basis)
            (sourceGood template inputConstructor «prefix» registers branch)) := by
      unfold Union.finiteNormSquared Union.eventProjection
      apply Finset.sum_le_sum
      intro basis _
      by_cases bad : nativeUnauthorized template inputConstructor readout branch basis
      · simp only [if_pos bad,if_pos (native_coverage template inputConstructor readout branch basis bad)]
        exact le_rfl
      · simp only [if_neg bad,Complex.normSq_zero]
        exact Complex.normSq_nonneg _
    exact monotone.trans (Union.same_execution_event_union_bound
      (fun kind basis => nativeGame template inputConstructor readout kind branch basis)
      (sourceGood template inputConstructor «prefix» registers branch))
  have primitive : nativeMass template inputConstructor «prefix» registers
      (nativeUnauthorized template inputConstructor readout)≤∑ kind : Fin 7,advantages kind := by
    unfold nativeMass
    calc
      _ ≤ ∑ branch : Branches G.decode Global,∑ kind : Fin 7,
          Union.finiteNormSquared
            (Union.eventProjection
              (nativeGame template inputConstructor readout kind branch)
              (sourceGood template inputConstructor «prefix» registers branch)) :=
        Finset.sum_le_sum (fun branch _ => each branch)
      _ = ∑ kind : Fin 7,∑ branch : Branches G.decode Global,
          Union.finiteNormSquared
            (Union.eventProjection
              (nativeGame template inputConstructor readout kind branch)
              (sourceGood template inputConstructor «prefix» registers branch)) := Finset.sum_comm
      _ ≤ _ := Finset.sum_le_sum (fun kind _ => games kind)
  have exactBudget : (2:ℝ)^(-129:ℤ)+(2:ℝ)^(-129:ℤ)=(2:ℝ)^(-128:ℤ) := by norm_num
  linarith

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalFinalSecurity
