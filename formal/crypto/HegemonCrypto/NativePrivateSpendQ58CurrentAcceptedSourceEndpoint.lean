import HegemonCrypto.NativePrivateSpendQ58CurrentCanonicalSourceClassifier
import HegemonCrypto.NativePrivateSpendQ58CurrentRoleInsertion
import HegemonCrypto.NativePrivateSpendQ58CurrentMatrixDynamicInsertion
import HegemonCrypto.NativePrivateSpendQ58CurrentSelectedClaimFailureMass
import HegemonCrypto.NativePrivateSpendQ58CurrentSourceRecordExtraction
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCanonicalSourceClassifier
open scoped Classical BigOperators
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult rawLog)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaChallengeStageTargets (Role)
namespace SC
export NativePrivateSpendQ58CurrentSourceCompletion
 (consistent_of_claims same_producer_full_claims replay_native_stages full_claims_agree_on_reads)
end SC
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay (current_grouped_claims_replay_actual_program)
end Q
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims (current_active_claims_complete_full_branch)
end AC
namespace A
export NativePrivateSpendQ58ActiveEventProjection (FixedTable)
end A
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (accepted_execution_has_stages)
end E
namespace AL
export NativePrivateSpendQ58CurrentActualTraceLabel
 (sourceRecords current_claimed_program_source_records_are_in_active_database
  stages_prior_bad_is_impossible_on_collision_free_completed_record stages_current_decs_base_is_in_full_log
  compatible_recorded_decs_base_has_fixed_gamma stored_current_decs_base_determines_claim_gamma
  stages_in_completed_record_identify_literal_source_label)
end AL
namespace FL
export NativePrivateSpendQ58CurrentFullLogReadback (fullRecords stages_pcs_log_subset_full)
end FL
namespace RG
export NativePrivateSpendQ58CurrentRecoveryGeometry
 (MatrixBad SmallSupportBad RecoveryGeometry pcs_execution_has_geometry_or_named_bad_event
  geometry_has_identities_or_literal_lvcs_event)
end RG
namespace LV
export NativePrivateSpendQ58CurrentLvcsEventJoin (CurrentLvcsRootEvent)
end LV
namespace J
export NativePrivateSpendQ58CurrentAcceptedEventJoin (PiopBad)
end J
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded decodedValues candidate)
end D
namespace C
export NativePrivateSpendQ58CurrentPublicOpening (Satisfies)
end C
namespace U
export NativePrivateSpendQ58CurrentDecsSourceJoin
 (Context program oracle records raw activeBytes Stages geometry_identities_give_piop_bad
  stages_decs_hash_and_sample_vector trace_event_is_dynamic_bad)
end U
namespace LI
export NativePrivateSpendQ58CurrentDecsLiteralInclusion
 (pcs_has_same_raw_query coordinates_have_same_query small_support_is_trace_event lvcs_root_is_trace_event)
end LI
namespace RI
export NativePrivateSpendQ58CurrentRoleInsertion (pullFixed pullDB root_matrix native_event_reindex)
end RI
namespace N
export NativePrivateSpendQ58CurrentRoleEventPhysicalMass (roleEvent roleBad stage)
end N
namespace MI
export NativePrivateSpendQ58CurrentMatrixDynamicInsertion (actual_matrix_arm_is_dynamic_bad)
end MI
namespace OV
export NativePrivateSpendQ58CurrentOpeningVectorInsertion
 (Context oracle records raw Stages same_branch_actual_opening_trace actual_opening_arm_is_same_database_dynamic_bad)
end OV
noncomputable section
set_option autoImplicit false
set_option Elab.async false
private theorem current_generic_matrix_event_of_affine {width : Nat}
    (candidate : V8Smz9PiopSoundness.Candidate width)
    (matrix : V8Smz9PiopSoundness.Matrix width)
    (affine : PiopExtraction.AffineBatchAccepts candidate.system
      (V8Smz9PiopSoundness.maskSum candidate) matrix) :
    matrix ∈ NativePrivateSpendQ58CurrentPiopEvents.currentMatrixEvent candidate :=
  Finset.mem_filter.mpr ⟨Finset.mem_univ matrix, affine⟩

private theorem current_context_free_piop_bad
 (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
 (rel : NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce : Fin (2^32))
 (oracle : Oracle) (rc : SmzaRp05FilteredDecoderInstability.RawRecords)
 (w : E.Wire) (t : E.Transcript)
 (st : E.ExecutionStages ns rel false nonce w oracle t)
 (geometry : RG.RecoveryGeometry ns w st.decoded st.opening st.pcs rc)
 (identities : ∀ combination,
  NativePrivateSpendQ58CurrentLvcsEventJoin.actualCombinationPolynomial st.decoded.pcs geometry.heads combination =
  NativePrivateSpendQ58CurrentLvcsEventJoin.combinationPolynomial geometry.source st.opening combination)
 (invalid : ¬∃ source : D.Decoded, C.Satisfies rel (D.decodedValues source)) :
 NativePrivateSpendQ58CurrentAcceptedEventJoin.PiopBad rel geometry.source st.matrix
  (NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (E.finalInput t)) st.opening := by
 have heads := NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_heads_are_lvcs_heads ns st.openingPending w
  st.decoded st.opening oracle st.pcs st.pcsExecuted
 have same : geometry.heads = st.pcs.heads := Option.some.inj (geometry.headsBuilt.symm.trans heads)
 have actual : ∀ combination, NativePrivateSpendQ58CurrentLvcsEventJoin.actualCombinationPolynomial st.decoded.pcs st.pcs.heads combination =
  NativePrivateSpendQ58CurrentLvcsEventJoin.combinationPolynomial geometry.source st.opening combination := by
  intro combination; rw [← same]; exact identities combination
 obtain ⟨witness,nonlinear,linear⟩ := NativePrivateSpendQ58CurrentScalarEventBridge.current_same_execution_scalar_agreement
  ns st.openingPending w st.decoded st.opening oracle st.pcs geometry.source st.decodedEq st.pcsExecuted actual
 have checks := NativePrivateSpendQ58CurrentScalarChecks.current_opened_scalars_derive_piop_checks rel geometry.source
  st.matrix st.opening st.decoded.piop witness nonlinear linear
 have response : NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (E.finalInput t) =
  NativePrivateSpendQ58CurrentPiopRestoration.response rel st.matrix st.opening st.decoded.piop := by
  exact
   (congrArg (fun transcript : E.Transcript => NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (E.finalInput transcript))
     st.reconstructed).symm.trans
    (NativePrivateSpendQ58CurrentPiopRecordJoin.current_final_raw_response rel st.matrix st.opening
      st.decoded.piop st.pcs.hashFpp st.finalPending)
 have satisfied : ¬PiopExtraction.FullySatisfied (D.candidate rel geometry.source).system := by
  intro yes
  exact invalid ⟨geometry.source,NativePrivateSpendQ58CurrentDecodedRelation.fully_satisfied_implies_current_relation rel geometry.source yes⟩
 by_cases affine : PiopExtraction.AffineBatchAccepts (D.candidate rel geometry.source).system
  (V8Smz9PiopSoundness.maskSum (D.candidate rel geometry.source)) st.matrix
 · with_reducible
   unfold NativePrivateSpendQ58CurrentAcceptedEventJoin.PiopBad
   exact Or.inl ⟨satisfied,current_generic_matrix_event_of_affine (D.candidate rel geometry.source) st.matrix affine⟩
 · with_reducible
   unfold NativePrivateSpendQ58CurrentAcceptedEventJoin.PiopBad
   have currentChecks : NativePrivateSpendQ58CurrentPiopEvents.CurrentOpeningChecks (D.candidate rel geometry.source)
     st.matrix (NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (E.finalInput t)) st.opening := by
    exact Eq.mpr
     (congrArg (fun answer : V8Smz9PiopSoundness.ClaimedTranscript =>
       NativePrivateSpendQ58CurrentPiopEvents.CurrentOpeningChecks (D.candidate rel geometry.source) st.matrix answer st.opening)
      response)
     checks
   exact Or.inr ⟨affine,currentChecks⟩

private theorem current_indexed_projection_transport
    {Index : Type} {Family : Index → Type} {Value : Type}
    (project : (index : Index) → Family index → Value)
    {left right : Index} (same : left = right) (value : Family left) :
    project right (same ▸ value) = project left value := by
  cases same
  rfl

variable (prod : Program E.Wire) (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
 (rel : NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce : Fin (2^32))
local notation "Root" => root prod ns rel nonce
variable (branch : Branches G.decode (root prod ns rel nonce))
local notation "View" => X.SourceView Root
local notation "Full" => fullDB prod ns rel nonce branch
local notation "O" => sourceOracle prod ns rel nonce branch
local notation "Live" => live prod ns rel nonce
def records (view : View) := SC.canonicalRecords Root view
def nativeRecords (role : Role)
 (database : Database (A.ActiveKey (Live role)) (VectorOutput G.Counter)) :=
 AL.sourceRecords (rawRecords (fun key : A.ActiveKey (Live role) => G.keyBytes Root key.val)
  (vectorOutputBytes G.zero) database)
include branch
theorem canonical_records (role : Role) (view : View) :
 nativeRecords prod ns rel nonce role (db prod ns rel nonce branch role view) =
 records prod ns rel nonce view := by
 unfold nativeRecords
 have activeRecords := SC.active_source_records (root prod ns rel nonce) role
  (db prod ns rel nonce branch role view)
 dsimp (config := {instances := true}) only
  [live, AC.live, NativePrivateSpendQ58CurrentSourceSelectorTransport.live]
  at activeRecords ⊢
 rw [activeRecords]
 congr 1
 funext key
 simp [X.activeSourceView, db, fullDB,
  NativePrivateSpendQ58CurrentSourceCompletion.completeSourceView, key.property]
theorem source_coverage (role : Role)
 (fixed : A.FixedTable (Counter := G.Counter) (Live role))
 (database : Database (A.ActiveKey (Live role)) (VectorOutput G.Counter))
 (compatible : AC.fixedCompatible Root role AC.currentRoleCaps fixed branch)
 (claims : ClaimsDatabaseEvent (AC.activeClaims Root role AC.currentRoleCaps branch) database)
 (fallback : G.RawDigest) (wire : E.Wire)
 (produced : prod.eval (Q.claimOracle Root (A.merge (Live role) fixed database) fallback) = some wire) :
 AL.sourceRecords (FL.fullRecords ns rel false nonce wire
  (Q.claimOracle Root (A.merge (Live role) fixed database) fallback)) ⊆
 nativeRecords prod ns rel nonce role database := by
 have covered := AL.current_claimed_program_source_records_are_in_active_database
  Root branch role fixed database compatible claims fallback
 intro call member
 obtain ⟨present,unparsed⟩ := Finset.mem_filter.mp member
 exact covered (Finset.mem_filter.mpr ⟨List.mem_toFinset.mpr
  (Program.bind_log_right _ prod _ wire produced (List.mem_toFinset.mp present)),unparsed⟩)
def Arm (branch : Branches G.decode (root prod ns rel nonce))
 (view : View) (wire : E.Wire) (t : E.Transcript)
 (st : E.ExecutionStages ns rel false nonce wire
  (sourceOracle prod ns rel nonce branch view) t) : Role → Prop
 | .decsMatrix => RG.MatrixBad (records prod ns rel nonce view) st.pcs
 | .decsSample => RG.SmallSupportBad (records prod ns rel nonce view) st.pcs ∨
   ∃ geometry : RG.RecoveryGeometry ns wire st.decoded st.opening st.pcs (records prod ns rel nonce view),
    LV.CurrentLvcsRootEvent geometry.source st.opening st.decoded.pcs geometry.heads geometry.coordinates
 | .piopMatrix => ∃ geometry : RG.RecoveryGeometry ns wire st.decoded st.opening st.pcs (records prod ns rel nonce view),
   ¬PiopExtraction.FullySatisfied (D.candidate rel geometry.source).system ∧
    st.matrix ∈ NativePrivateSpendQ58CurrentPiopEvents.currentMatrixEvent (D.candidate rel geometry.source)
 | .piopOpening => ∃ geometry : RG.RecoveryGeometry ns wire st.decoded st.opening st.pcs (records prod ns rel nonce view),
   ¬PiopExtraction.AffineBatchAccepts (D.candidate rel geometry.source).system
    (V8Smz9PiopSoundness.maskSum (D.candidate rel geometry.source)) st.matrix ∧
   NativePrivateSpendQ58CurrentPiopEvents.CurrentOpeningChecks (D.candidate rel geometry.source) st.matrix
    (NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (E.finalInput t)) st.opening
def Choice (branch : Branches G.decode (root prod ns rel nonce))
 (role : Role) (view : View) : Prop :=
 RecordsCollisionFree (records prod ns rel nonce view) ∧
 ∃ wire, prod.eval (sourceOracle prod ns rel nonce branch view) = some wire ∧ ∃ t,
 ∃ st : E.ExecutionStages ns rel false nonce wire
  (sourceOracle prod ns rel nonce branch view) t,
  t.pending = false ∧ (E.finalInput t,wire.hPiop)∈((E.verifierProgram ns rel false nonce wire).record (sourceOracle prod ns rel nonce branch view)).2 ∧ Arm prod ns rel nonce branch view wire t st role
theorem accepted_invalid_chosen_role (view : View)
 (consistent : SC.Consistent (Q.fullClaims Root branch))
 (sources : SC.SourceClaims Root branch view)
 (accepted : branchResult G.decode Root branch = some ())
 (invalid : ¬∃ source : D.Decoded, C.Satisfies rel (D.decodedValues source)) :
 ¬RecordsCollisionFree (records prod ns rel nonce view) ∨
 ∃ role, Choice prod ns rel nonce branch role view := by
 have all := SC.complete_source_claims Root branch view 0 sources consistent
 have replay := Q.current_grouped_claims_replay_actual_program Root branch (Full view) all (fun _ => 0)
 have run : (Root).eval (O view) = some () :=
  (Program.record_result (O view) Root).symm.trans ((congrArg Prod.fst replay).trans accepted)
 obtain ⟨wire,produced,verified⟩ := SmzaRp05FinalProgramMiddleExecution.program_bind_success
  (O view) prod (E.verifierProgram ns rel false nonce) () run
 obtain ⟨t,⟨st⟩,clean,_,finalRecorded⟩ := E.accepted_execution_has_stages ns rel false nonce wire (O view) verified
 by_cases free : RecordsCollisionFree (records prod ns rel nonce view)
 · have covered : AL.sourceRecords (FL.fullRecords ns rel false nonce wire (O view)) ⊆
    records prod ns rel nonce view := by
    have h := source_coverage prod ns rel nonce branch .decsSample
     (fixed prod ns rel nonce branch .decsSample view) (db prod ns rel nonce branch .decsSample view)
     (compatible prod ns rel nonce branch .decsSample view all)
     (selected_claims prod ns rel nonce branch .decsSample view all) (fun _ => 0) wire
     (by simpa only [merge_full, sourceOracle] using produced)
    simpa only [merge_full, canonical_records, sourceOracle] using h
   have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
    ns rel false nonce wire (O view) t st clean
   rcases RG.pcs_execution_has_geometry_or_named_bad_event ns st.openingPending wire st.decoded st.opening
    (O view) st.pcs (records prod ns rel nonce view) st.pcsExecuted pcsClean with prior | matrix | small | ⟨⟨geometry⟩⟩
   · exact (AL.stages_prior_bad_is_impossible_on_collision_free_completed_record
      ns rel false nonce wire (O view) t st clean _ free covered prior).elim
   · exact Or.inr ⟨.decsMatrix,free,wire,produced,t,st,clean,finalRecorded,matrix⟩
   · exact Or.inr ⟨.decsSample,free,wire,produced,t,st,clean,finalRecorded,Or.inl small⟩
   · rcases RG.geometry_has_identities_or_literal_lvcs_event ns wire st.decoded st.opening st.pcs
      (records prod ns rel nonce view) geometry with identities | roots
     · have piop := by
        with_reducible
        exact no_implicit_lambda% (current_context_free_piop_bad ns rel nonce
         (O view) (records prod ns rel nonce view) wire t st geometry identities invalid)
       rcases piop with matrixArm | openingArm
       · exact Or.inr ⟨.piopMatrix,free,wire,produced,t,st,clean,finalRecorded,geometry,matrixArm⟩
       · exact Or.inr ⟨.piopOpening,free,wire,produced,t,st,clean,finalRecorded,geometry,openingArm⟩
     · exact Or.inr ⟨.decsSample,free,wire,produced,t,st,clean,finalRecorded,Or.inr ⟨geometry,roots⟩⟩
 · exact Or.inl free
omit branch
set_option linter.constructorNameAsVariable false in
theorem sample_arm_inserts (c:U.Context) (w:E.Wire) (hw:c.producer.eval (U.oracle c)=some w)
 (t:E.Transcript) (st:U.Stages c w t) (clean:t.pending=false) (free:RecordsCollisionFree (U.records c))
 (final:(E.finalInput t,w.hPiop)∈((E.verifierProgram c.ns c.relation false c.nonce w).record (U.oracle c)).2)
 (arm:RG.SmallSupportBad (U.records c) st.pcs∨∃g:RG.RecoveryGeometry c.ns w st.decoded st.opening st.pcs (U.records c),
  LV.CurrentLvcsRootEvent g.source st.opening st.decoded.pcs g.heads g.coordinates):
 SmzaDynamicDatabaseSoundness.DynamicBad
  (NativePrivateSpendQ58CurrentPrequeryEvents.currentLabel (U.activeBytes c) G.zero 28)
  (fun tr key v=>NativePrivateSpendQ58CurrentDecsDynamicMass.decsSampleBad (U.program c) c.fixed c.fallback c.nonce tr key.val v) c.database:=by
 have pcsClean:=NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
  c.ns c.relation false c.nonce w (U.oracle c) t st clean
 obtain ⟨d,stream,query,hashEq,_raw,decoded,indices,queryEq⟩:=LI.pcs_has_same_raw_query
  c.ns st.openingPending w st.decoded st.opening (U.oracle c) st.pcs st.pcsExecuted pcsClean
 have opening:=(NativePrivateSpendQ58CurrentFixedOpeningReplay.stages_opening_replays_fixed_other_role
  c.producer c.ns c.relation c.nonce .decsSample AC.currentRoleCaps (by decide) (by decide)
  c.fixed c.branch c.database c.compatible c.claims c.fallback w hw t st).2
 rcases arm with small|⟨g,bad⟩
 · obtain ⟨coords,distinct,same,member⟩:=LI.small_support_is_trace_event (U.records c) st.pcs st.opening
    (extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext (U.records c) 28 .decs d) small
   rw[LI.coordinates_have_same_query (List.ofFn stream) st.pcs.indexes query indices queryEq coords distinct same] at member
   have memberTyped : query ∈ NativePrivateSpendQ58CurrentDecsTraceDensity.traceEvent
    (NativePrivateSpendQ58CurrentSourceCandidate.labelFromInputs
     (U.records c) st.pcs.root st.pcs.hashFpp st.pcs.gamma) st.opening
    (extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext (U.records c) 28 .decs d) := by
    dsimp only [NativePrivateSpendQ58CurrentSuccessfulFiber.Query,
     NativePrivateSpendQ58CurrentOrdinaryRecovery.Position,
     SmzaQ38McaSourceBinding.Position, SmzaQ38OracleExtraction.decsDomainSize,
     V8Smz9LogicalOracle.decsDomainSize] at member ⊢
    with_reducible
      exact no_implicit_lambda% member
   have traceRule := by
    with_reducible
      exact no_implicit_lambda% (U.trace_event_is_dynamic_bad c w hw t st free d query hashEq decoded memberTyped final)
   dsimp only [U.program,U.oracle,NativePrivateSpendQ58CurrentDecsSourceJoin.completed,
    NativePrivateSpendQ58CurrentDecsSourceJoin.live,NativePrivateSpendQ58CurrentDecsSourceJoin.caps,
    NativePrivateSpendQ58CurrentFixedOpeningReplay.FullProgram] at traceRule opening ⊢
   with_reducible
     exact no_implicit_lambda% (traceRule opening)
 · have recorded:=(U.stages_decs_hash_and_sample_vector c w hw t st d hashEq).1
   have member := by
     with_reducible
       exact no_implicit_lambda% (LI.lvcs_root_is_trace_event c.ns st.openingPending w st.decoded st.opening (U.oracle c)
        st.pcs st.pcsExecuted (U.records c) free d recorded g bad)
   rw[LI.coordinates_have_same_query (List.ofFn stream) st.pcs.indexes query indices queryEq
    g.coordinates g.distinct g.indicesEq] at member
   have memberTyped : query ∈ NativePrivateSpendQ58CurrentDecsTraceDensity.traceEvent
    (NativePrivateSpendQ58CurrentSourceCandidate.labelFromInputs
     (U.records c) st.pcs.root st.pcs.hashFpp st.pcs.gamma) st.opening
    (extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext (U.records c) 28 .decs d) := by
    dsimp only [NativePrivateSpendQ58CurrentSuccessfulFiber.Query,
     NativePrivateSpendQ58CurrentOrdinaryRecovery.Position,
     SmzaQ38McaSourceBinding.Position, SmzaQ38OracleExtraction.decsDomainSize,
     V8Smz9LogicalOracle.decsDomainSize] at member ⊢
    with_reducible
      exact no_implicit_lambda% member
   have traceRule := by
    with_reducible
      exact no_implicit_lambda% (U.trace_event_is_dynamic_bad c w hw t st free d query hashEq decoded memberTyped final)
   dsimp only [U.program,U.oracle,NativePrivateSpendQ58CurrentDecsSourceJoin.completed,
    NativePrivateSpendQ58CurrentDecsSourceJoin.live,NativePrivateSpendQ58CurrentDecsSourceJoin.caps,
    NativePrivateSpendQ58CurrentFixedOpeningReplay.FullProgram] at traceRule opening ⊢
   with_reducible
     exact no_implicit_lambda% (traceRule opening)
include branch
set_option linter.constructorNameAsVariable false in
theorem chosen_role_inserts (role:Role)
 (fixed:A.FixedTable (Counter:=G.Counter) (Live role))
 (database:Database (A.ActiveKey (Live role)) (VectorOutput G.Counter))
 (comp:AC.fixedCompatible Root role AC.currentRoleCaps fixed branch)
 (claims:ClaimsDatabaseEvent (AC.activeClaims Root role AC.currentRoleCaps branch) database)
 (fallback:G.RawDigest) (accepted:branchResult G.decode Root branch=some ())
 (choice:Choice prod ns rel nonce branch role (X.activeSourceView Root role database)):
 N.roleEvent Root rel fallback nonce role (RI.pullFixed Root role fixed) (RI.pullDB Root role database):=by
 let view:=X.activeSourceView Root role database
 let completed:=A.merge (Live role) fixed database
 have all:=AC.current_active_claims_complete_full_branch Root role AC.currentRoleCaps fixed branch database comp claims
 have src:SC.SourceClaims Root branch view:=by
  intro key value member source
  exact (A.merge_active _ _ _ ⟨key,X.source_keys_active_for_each_role Root role key source⟩).symm.trans (all _ member)
 have coherent:=SC.consistent_of_claims Root branch completed all
 have canonical:=SC.complete_source_claims Root branch view 0 src coherent
 rcases choice with ⟨free,w,produced,t,st,clean,final,arm⟩
 let native:=SC.replay_native_stages prod ns rel false nonce branch (Full view) completed canonical all
  (fun _=>0) fallback w produced t st
 have hw:=SC.same_producer_full_claims prod ns rel false nonce branch (Full view) completed canonical all
  (fun _=>0) fallback w produced
 have same:records prod ns rel nonce view=nativeRecords prod ns rel nonce role database:=
  (SC.active_source_records Root role database).symm
 have agree:=SC.full_claims_agree_on_reads Root branch (Full view) completed canonical all (fun _=>0) fallback
 have logEq:=SmzaRp05CurrentBranchOracleAgreement.record_eq_of_agrees_on_left_reads
  (E.verifierProgram ns rel false nonce w) (O view) (Q.claimOracle Root completed fallback)
  (fun input member=>agree input (Program.bind_log_right _ prod _ w produced member))
 have finalNative:(E.finalInput t,w.hPiop)∈((E.verifierProgram ns rel false nonce w).record
  (Q.claimOracle Root completed fallback)).2:=by
  have logs := congrArg Prod.snd logEq
  rw [← logs]
  exact final
 have pcsClean:=NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
  ns rel false nonce w (Q.claimOracle Root completed fallback) t native clean
 cases role with
 | decsMatrix =>
  let c:NativePrivateSpendQ58CurrentMatrixNativeJoin.Context:=
   {producer:=prod,ns:=ns,relation:=rel,nonce:=nonce,branch:=branch,fixed:=fixed,database:=database,
    compatible:=comp,claims:=claims,accepted:=accepted,fallback:=fallback}
  exact RI.root_matrix c w hw t native pcsClean (records prod ns rel nonce view) same arm
 | decsSample =>
  let c:U.Context:=
   {producer:=prod,ns:=ns,relation:=rel,nonce:=nonce,branch:=branch,fixed:=fixed,database:=database,
    compatible:=comp,claims:=claims,accepted:=accepted,fallback:=fallback}
  apply RI.native_event_reindex
  have sameSample : records prod ns rel nonce view = U.records c := by
   exact same
  have sampleRule := by
   with_reducible
     exact no_implicit_lambda% (sample_arm_inserts c w)
  dsimp only [c,U.program,U.oracle,U.Stages,
   NativePrivateSpendQ58CurrentDecsSourceJoin.completed,
   NativePrivateSpendQ58CurrentDecsSourceJoin.live,NativePrivateSpendQ58CurrentDecsSourceJoin.caps,
   NativePrivateSpendQ58CurrentSourceCompletion.Full,root,live,completed] at sampleRule hw native
  have sampleTail := by
   with_reducible
     exact no_implicit_lambda% (sampleRule hw t native clean)
  have freeSample := sameSample ▸ free
  dsimp only [Arm] at arm
  have armSample := sameSample ▸ arm
  have finalSample := finalNative
  dsimp (config := {failIfUnchanged := false, instances := true}) only
   [c,U.program,U.oracle,U.Stages,NativePrivateSpendQ58CurrentDecsSourceJoin.completed,
    NativePrivateSpendQ58CurrentDecsSourceJoin.live,NativePrivateSpendQ58CurrentDecsSourceJoin.caps,
    U.records,U.raw,U.activeBytes,records,nativeRecords,
    NativePrivateSpendQ58CurrentCanonicalSourceClassifier.sourceOracle,
    NativePrivateSpendQ58CurrentSourceCompletion.Full,root,live,completed]
   at sampleTail freeSample finalSample armSample
  have bad := by
   exact no_implicit_lambda% (sampleTail freeSample finalSample armSample)
  dsimp only [c,U.program,U.oracle,NativePrivateSpendQ58CurrentDecsSourceJoin.completed,
   NativePrivateSpendQ58CurrentDecsSourceJoin.live,NativePrivateSpendQ58CurrentDecsSourceJoin.caps,
   NativePrivateSpendQ58CurrentSourceCompletion.Full,root,live,completed] at bad ⊢
  have bytesEq : U.activeBytes c =
      (fun key : A.ActiveKey (Live .decsSample) => G.keyBytes Root key.val) := by
   funext key
   rfl
  rcases bad with ⟨key, vector, stored, sampleBad⟩
  refine ⟨key, vector, stored, ?_⟩
  have labelBytesAt :
      NativePrivateSpendQ58CurrentPrequeryEvents.currentLabel (U.activeBytes c) G.zero 28 database key =
      NativePrivateSpendQ58CurrentPrequeryEvents.currentLabel
        (fun key : A.ActiveKey (Live .decsSample) => G.keyBytes Root key.val)
        G.zero 28 database key := by
   exact congrArg
     (fun bytes => NativePrivateSpendQ58CurrentPrequeryEvents.currentLabel bytes G.zero 28 database key)
     bytesEq
  dsimp (config := {failIfUnchanged := false, instances := true}) only
   [c,U.program,NativePrivateSpendQ58CurrentDecsSourceJoin.live,
    NativePrivateSpendQ58CurrentDecsSourceJoin.caps,root,live] at labelBytesAt
  rw [labelBytesAt] at sampleBad
  have keyVal :
      ((NativePrivateSpendQ58CurrentFiberMassTransport.actualActiveEquiv
        .decsSample (G.keyBytes Root)).symm key).val = key.val := by
   rfl
  simp only [N.roleBad,N.stage,
   NativePrivateSpendQ58CurrentDecsDynamicMass.fiberBad,
   NativePrivateSpendQ58CurrentRoleInsertion.pull_fixed_exact,keyVal]
  dsimp (config := {failIfUnchanged := false, instances := true}) only
   [c,U.program,U.oracle,U.activeBytes,NativePrivateSpendQ58CurrentDecsSourceJoin.completed,
    NativePrivateSpendQ58CurrentDecsSourceJoin.live,NativePrivateSpendQ58CurrentDecsSourceJoin.caps,
    NativePrivateSpendQ58CurrentSourceCompletion.Full,root,live,completed] at sampleBad ⊢
  with_reducible
    exact no_implicit_lambda% sampleBad
 | piopMatrix =>
  obtain ⟨geometry,matrixArm⟩:=arm
  dsimp (config := {instances := true}) only
    [root, live, NativePrivateSpendQ58CurrentActiveBranchClaims.live]
    at fixed database comp claims ⊢
  let g:RG.RecoveryGeometry ns w native.decoded native.opening native.pcs
    (nativeRecords prod ns rel nonce .piopMatrix database):=same ▸ geometry
  have covered:=source_coverage prod ns rel nonce branch .piopMatrix fixed database comp claims fallback w hw
  obtain ⟨v,recorded,_stored⟩:=canonical_recorded_vector prod ns rel nonce branch view canonical w produced _
   (AL.stages_current_decs_base_is_in_full_log ns rel false nonce w (O view) t st)
  have fixedGamma:=AL.compatible_recorded_decs_base_has_fixed_gamma Root branch .piopMatrix (Or.inl rfl)
   fixed comp native.pcs.root v recorded
  have stored:=Q.current_claims_store_every_branch_vector Root branch completed all _ recorded
  have claimedGamma:=AL.stored_current_decs_base_determines_claim_gamma Root completed fallback native.pcs.root v stored
  have actualGamma:=NativePrivateSpendQ58CurrentSourceCandidate.pcs_execution_gamma_is_label_gamma
   ns native.openingPending w native.decoded native.opening (Q.claimOracle Root completed fallback)
   native.pcs native.pcsExecuted
  have gamma:NativePrivateSpendQ58CurrentGammaFiber.fixedGamma .piopMatrix (G.keyBytes Root) fixed G.decode
   native.pcs.root=some native.pcs.gamma:=fixedGamma.trans (congrArg some (claimedGamma.symm.trans actualGamma))
  obtain ⟨label,_,_⟩:=AL.stages_in_completed_record_identify_literal_source_label .piopMatrix (G.keyBytes Root)
   fixed G.decode ns rel false nonce w (Q.claimOracle Root completed fallback) t native
   (nativeRecords prod ns rel nonce .piopMatrix database) (same ▸ free) covered finalNative gamma
  have calculated:=NativePrivateSpendQ58CurrentSourceCandidate.pcs_execution_candidate_is_label_candidate
   ns native.openingPending w native.decoded native.opening (Q.claimOracle Root completed fallback)
   native.pcs (nativeRecords prod ns rel nonce .piopMatrix database) native.pcsExecuted
  unfold NativePrivateSpendQ58CurrentSourceCandidate.labelAt at calculated
  rw[actualGamma] at calculated
  have candidate:NativePrivateSpendQ58CurrentSourceCandidate.calculatedCandidate
   (NativePrivateSpendQ58CurrentTracePiopMass.fppLabel .piopMatrix (G.keyBytes Root) fixed G.decode
    (extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
     (rawRecords (fun key:A.ActiveKey (Live .piopMatrix)=>G.keyBytes Root key.val) (vectorOutputBytes G.zero) database)
     26 .fpp native.pcs.hashFpp))=some g.source:=by
   rw[← NativePrivateSpendQ58CurrentSourceRecordExtraction.current_source_extract_survives_filtration
    (rawRecords (fun key:A.ActiveKey (Live .piopMatrix)=>G.keyBytes Root key.val)
     (vectorOutputBytes G.zero) database) 26 .fpp native.pcs.hashFpp]
   dsimp only [nativeRecords] at label
   rw[label];exact calculated.trans g.calculated
  apply RI.native_event_reindex
  have bad := by
    have rule := MI.actual_matrix_arm_is_dynamic_bad prod ns rel false nonce
    dsimp (config := {instances := true}) only
      [NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentProgram,
       NativePrivateSpendQ58CurrentMatrixDynamicInsertion.MatrixFixed,
       NativePrivateSpendQ58CurrentMatrixDynamicInsertion.MatrixDatabase,
       NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixLive,
       NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentOracle,
        NativePrivateSpendQ58CurrentSourceCompletion.Full, root,
        NativePrivateSpendQ58CurrentActiveBranchClaims.live] at rule
    have matrixBytes :
        NativePrivateSpendQ58CurrentMatrixDynamicInsertion.activeBytes Root =
          (fun key : A.ActiveKey (Live .piopMatrix) => G.keyBytes Root key.val) := by
      funext key
      rfl
    have matrixRaw :
        NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentRaw Root database =
          rawRecords (fun key : A.ActiveKey (Live .piopMatrix) => G.keyBytes Root key.val)
            (vectorOutputBytes G.zero) database := by
      unfold NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentRaw
      dsimp (config := {instances := true}) only
        [NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixLive,
         root, live, NativePrivateSpendQ58CurrentActiveBranchClaims.live]
      ext pair
      rcases pair with ⟨input, digest⟩
      simp only [SmzaRawDatabaseRecords.mem_raw_records_iff, matrixBytes]
    have matrixRecords :
        AL.sourceRecords
          (NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentRaw Root database) =
          nativeRecords prod ns rel nonce .piopMatrix database := by
      unfold nativeRecords
      exact congrArg AL.sourceRecords matrixRaw
    have matrixExtract :
        extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
          (NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentRaw Root database)
          26 .fpp native.pcs.hashFpp =
          extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
            (rawRecords (fun key : A.ActiveKey (Live .piopMatrix) => G.keyBytes Root key.val)
              (vectorOutputBytes G.zero) database)
            26 .fpp native.pcs.hashFpp := by
      exact congrArg
        (fun raw => extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
          raw 26 .fpp native.pcs.hashFpp) matrixRaw
    have matrixRule := rule branch fixed database comp claims
      fallback w t native hw clean
    rw [matrixRecords] at matrixRule
    rw [matrixExtract] at matrixRule
    have gSource : g.source = geometry.source :=
      current_indexed_projection_transport
        (Family := fun rc => RG.RecoveryGeometry ns w native.decoded native.opening native.pcs rc)
        (fun _ value => value.source) same geometry
    have nativeMatrix : native.matrix = st.matrix := by
      rfl
    have matrixAtGeometry := matrixRule g
    dsimp (config := {instances := true, failIfUnchanged := false}) only
      [root, live, NativePrivateSpendQ58CurrentActiveBranchClaims.live,
       NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixLive]
      at matrixAtGeometry candidate
    have matrixAfterCandidate := matrixAtGeometry candidate
    rw [gSource, nativeMatrix] at matrixAfterCandidate
    with_reducible
      exact no_implicit_lambda% (matrixAfterCandidate matrixArm)
  dsimp (config := {instances := true, failIfUnchanged := false}) only
    [root, live, NativePrivateSpendQ58CurrentMatrixDynamicInsertion.activeBytes,
     NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixLive,
     NativePrivateSpendQ58CurrentActiveBranchClaims.live] at bad ⊢
  dsimp only [NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixDynamicBad] at bad
  rcases bad with ⟨key, vector, stored, pointwise⟩
  refine ⟨key, vector, stored, ?_⟩
  have keyVal :
      ((NativePrivateSpendQ58CurrentFiberMassTransport.actualActiveEquiv
        .piopMatrix (G.keyBytes Root)).symm key).val = key.val := by
    rfl
  dsimp only [N.roleBad, N.stage,
    NativePrivateSpendQ58CurrentFiberMassTransport.matrixEvent]
  rw [NativePrivateSpendQ58CurrentRoleInsertion.pull_fixed_exact]
  rw [keyVal]
  have matrixBytesEq : NativePrivateSpendQ58CurrentMatrixDynamicInsertion.activeBytes Root =
      (fun key : A.ActiveKey (Live .piopMatrix) => G.keyBytes Root key.val) := by
   funext activeKey
   rfl
  have matrixLabelAt := congrArg
    (fun bytes => NativePrivateSpendQ58CurrentPrequeryEvents.currentLabel bytes G.zero 26 database key)
    matrixBytesEq
  have matrixPredicateAt := congrArg
    (fun label => NativePrivateSpendQ58CurrentTracePiopMass.matrixBad rel (G.keyBytes Root) fixed G.decode
      NativePrivateSpendQ58CurrentClaimMatrixReadback.matrixSelect label key.val vector)
    matrixLabelAt
  dsimp (config := {instances := true}) only
    [root,live,NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixLive,
     NativePrivateSpendQ58CurrentActiveBranchClaims.live]
    at matrixBytesEq matrixLabelAt matrixPredicateAt pointwise ⊢
  with_reducible
    exact no_implicit_lambda% (Eq.mp matrixPredicateAt pointwise)
 | piopOpening =>
  obtain ⟨geometry,failure,checked⟩:=arm
  dsimp (config := {instances := true}) only
    [live, NativePrivateSpendQ58CurrentActiveBranchClaims.live]
    at fixed database comp claims ⊢
  let c:OV.Context:=
   {producer:=prod,ns:=ns,relation:=rel,pending:=false,nonce:=nonce,branch:=branch,fixed:=fixed,
    database:=database,compatible:=comp,claims:=claims,accepted:=accepted,fallback:=fallback}
  apply RI.native_event_reindex
  have openingFree : RecordsCollisionFree
    (nativeRecords prod ns rel nonce .piopOpening database) := same ▸ free
  let openingGeometry : RG.RecoveryGeometry ns w native.decoded native.opening native.pcs
    (nativeRecords prod ns rel nonce .piopOpening database) := same ▸ geometry
  have openingBytesEq :
    NativePrivateSpendQ58CurrentOpeningVectorInsertion.activeBytes c =
      (fun key : A.ActiveKey (Live .piopOpening) => G.keyBytes Root key.val) := by
    funext key
    rfl
  have openingRaw : OV.raw c =
      rawRecords (fun key : A.ActiveKey (Live .piopOpening) => G.keyBytes Root key.val)
        (vectorOutputBytes G.zero) database := by
    unfold OV.raw
    dsimp (config := {instances := true}) only
      [c, NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.live,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.caps,
       root, live, NativePrivateSpendQ58CurrentActiveBranchClaims.live]
      at openingBytesEq ⊢
    ext pair
    rcases pair with ⟨input, digest⟩
    simp only [SmzaRawDatabaseRecords.mem_raw_records_iff, openingBytesEq]
  have openingRecords : OV.records c =
      nativeRecords prod ns rel nonce .piopOpening database := by
    unfold OV.records nativeRecords
    exact congrArg AL.sourceRecords openingRaw
  have openingRule := OV.actual_opening_arm_is_same_database_dynamic_bad c w
  rw [openingRecords] at openingRule
  have openingProduced := hw
  let openingStages := native
  have openingFailure := failure
  have openingChecked := checked
  dsimp (config := {instances := true}) only
    [c, NativePrivateSpendQ58CurrentOpeningVectorInsertion.Stages,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.oracle,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.completed,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.live,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.activeBytes,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.fullBytes,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.caps,
     NativePrivateSpendQ58CurrentSourceCompletion.Full,
     NativePrivateSpendQ58CurrentRoleInsertion.Fixed,
     NativePrivateSpendQ58CurrentRoleInsertion.DB,
     NativePrivateSpendQ58CurrentActiveBranchClaims.live,
     completed, root, live]
    at openingRule openingProduced openingStages openingFree openingFailure openingChecked
  have openingAfterStages := by
    with_reducible
      exact no_implicit_lambda% (openingRule openingProduced t openingStages)
  dsimp only [openingStages] at openingAfterStages
  have openingGeometrySource : openingGeometry.source = geometry.source :=
    current_indexed_projection_transport
      (Family := fun rc => RG.RecoveryGeometry ns w native.decoded native.opening native.pcs rc)
      (fun _ value => value.source) same geometry
  have openingMatrixProjection : native.matrix = st.matrix := by
    rfl
  have openingOpeningProjection : native.opening = st.opening := by
    rfl
  have openingAfterGeometry := by
    exact no_implicit_lambda% (openingAfterStages openingFree openingGeometry)
  rw [openingGeometrySource, openingMatrixProjection, openingOpeningProjection] at openingAfterGeometry
  have bad := by
    exact no_implicit_lambda% (openingAfterGeometry openingFailure openingChecked)
  rcases bad with ⟨openingKey, openingVector, openingStored, openingHit⟩
  refine ⟨openingKey, openingVector, openingStored, ?_⟩
  have openingKeyVal :
    ((NativePrivateSpendQ58CurrentFiberMassTransport.actualActiveEquiv
      .piopOpening (G.keyBytes Root)).symm openingKey).val = openingKey.val := by
    rfl
  unfold N.roleBad
  dsimp only [N.stage]
  unfold NativePrivateSpendQ58CurrentFiberMassTransport.openingEvent
  rw [NativePrivateSpendQ58CurrentRoleInsertion.pull_fixed_exact, openingKeyVal]
  have openingLabelAt := congrArg
    (fun bytes => NativePrivateSpendQ58CurrentPrequeryEvents.currentLabel bytes G.zero 27 database openingKey)
    openingBytesEq
  have openingPredicateAt := congrArg
    (fun label => NativePrivateSpendQ58CurrentTracePiopMass.openingBad rel (G.keyBytes Root) fixed G.decode
      NativePrivateSpendQ58CurrentClaimMatrixReadback.matrixSelect
      NativePrivateSpendQ58CurrentOpeningVectorInsertion.openingSelect label openingKey.val openingVector)
    openingLabelAt
  dsimp (config := {instances := true, failIfUnchanged := false}) only
    [c, NativePrivateSpendQ58CurrentOpeningVectorInsertion.fullBytes,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.live,
     NativePrivateSpendQ58CurrentOpeningVectorInsertion.caps,
     root, live, NativePrivateSpendQ58CurrentSourceCompletion.Full,
     NativePrivateSpendQ58CurrentActiveBranchClaims.live]
    at openingHit openingBytesEq openingLabelAt openingPredicateAt ⊢
  with_reducible
    exact no_implicit_lambda% (Eq.mp openingPredicateAt openingHit)
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCanonicalSourceClassifier
