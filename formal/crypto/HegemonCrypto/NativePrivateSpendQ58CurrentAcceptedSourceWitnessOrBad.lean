import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceFinal128
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCanonicalSourceClassifier
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaRecordedTracePath (RecordsCollisionFree)
open SmzaChallengeStageTargets (Role)
namespace LV
export NativePrivateSpendQ58CurrentLvcsEventJoin (actualCombinationPolynomial combinationPolynomial)
end LV
noncomputable section
set_option autoImplicit false
private theorem current_matrix_event_of_affine {width : Nat}
    (candidate : V8Smz9PiopSoundness.Candidate width)
    (matrix : V8Smz9PiopSoundness.Matrix width)
    (affine : PiopExtraction.AffineBatchAccepts candidate.system
      (V8Smz9PiopSoundness.maskSum candidate) matrix) :
    matrix ∈ NativePrivateSpendQ58CurrentPiopEvents.currentMatrixEvent candidate :=
  Finset.mem_filter.mpr ⟨Finset.mem_univ matrix, affine⟩

variable (p:Program E.Wire) (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
 (rel:NativePrivateSpendQ58CurrentPublicOpening.Relation) (n:Fin (2^32))
local notation "Root"=>root p ns rel n
variable (b:Branches G.decode (root p ns rel n))
local notation "View"=>X.SourceView Root
local notation "OracleAt"=>sourceOracle p ns rel n b
/-- The witness is the source recovered from this very canonical current
 accepted stage trace, with its recovery and polynomial identities retained. -/
def SourceWitness (v:View):Prop:=
 ∃w,p.eval (OracleAt v)=some w∧∃t,∃st:E.ExecutionStages ns rel false n w (OracleAt v) t,
 t.pending=false∧∃g:RG.RecoveryGeometry ns w st.decoded st.opening st.pcs (records p ns rel n v),
 (∀i,LV.actualCombinationPolynomial st.decoded.pcs g.heads i=LV.combinationPolynomial g.source st.opening i)∧
 PiopExtraction.FullySatisfied (D.candidate rel g.source).system∧C.Satisfies rel (D.decodedValues g.source)
private theorem identities_piop (w:E.Wire) (o:Oracle) (t:E.Transcript) (st:E.ExecutionStages ns rel false n w o t)
 (rc:SmzaRp05FilteredDecoderInstability.RawRecords) (g:RG.RecoveryGeometry ns w st.decoded st.opening st.pcs rc)
 (ids:∀i,LV.actualCombinationPolynomial st.decoded.pcs g.heads i=LV.combinationPolynomial g.source st.opening i)
 (unsat:¬PiopExtraction.FullySatisfied (D.candidate rel g.source).system):
 J.PiopBad rel g.source st.matrix (NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (E.finalInput t)) st.opening:=by
 have heads:=NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_heads_are_lvcs_heads ns st.openingPending w
  st.decoded st.opening o st.pcs st.pcsExecuted
 have same:g.heads=st.pcs.heads:=Option.some.inj (g.headsBuilt.symm.trans heads)
 have actual:∀i,LV.actualCombinationPolynomial st.decoded.pcs st.pcs.heads i=LV.combinationPolynomial g.source st.opening i:=by
  intro i;rw[←same];exact ids i
 obtain⟨wit,nonlinear,linear⟩:=NativePrivateSpendQ58CurrentScalarEventBridge.current_same_execution_scalar_agreement
  ns st.openingPending w st.decoded st.opening o st.pcs g.source st.decodedEq st.pcsExecuted actual
 have checks:=NativePrivateSpendQ58CurrentScalarChecks.current_opened_scalars_derive_piop_checks
  rel g.source st.matrix st.opening st.decoded.piop wit nonlinear linear
 have response:NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (E.finalInput t)=
  NativePrivateSpendQ58CurrentPiopRestoration.response rel st.matrix st.opening st.decoded.piop:=by
  exact (congrArg
    (fun value : E.Transcript => NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (E.finalInput value))
    st.reconstructed).symm.trans
      (NativePrivateSpendQ58CurrentPiopRecordJoin.current_final_raw_response rel st.matrix st.opening
        st.decoded.piop st.pcs.hashFpp st.finalPending)
 by_cases affine:PiopExtraction.AffineBatchAccepts (D.candidate rel g.source).system
  (V8Smz9PiopSoundness.maskSum (D.candidate rel g.source)) st.matrix
 · with_reducible
   unfold J.PiopBad
   refine Or.inl ?_
   refine ⟨unsat, ?_⟩
   exact current_matrix_event_of_affine (D.candidate rel g.source) st.matrix affine
 · apply Or.inr
   refine⟨affine,?_⟩
   rw[response];exact checks
/-- Unconditional same-source witness OR one literal current bad-event arm.
 Public relation satisfiability is unrestricted; no extraction/assignment
 certificate is supplied by the caller. -/
theorem accepted_source_witness_or_chosen_role (v:View)
 (co:SC.Consistent (Q.fullClaims Root b)) (src:SC.SourceClaims Root b v)
 (a:branchResult G.decode Root b=some ()):
 ¬RecordsCollisionFree (records p ns rel n v)∨(∃r,Choice p ns rel n b r v)∨SourceWitness p ns rel n b v:=by
 have all:=SC.complete_source_claims Root b v 0 src co
 have replay:=Q.current_grouped_claims_replay_actual_program Root b (fullDB p ns rel n b v) all (fun _=>0)
 have run:(Root).eval (OracleAt v)=some ():=(Program.record_result (OracleAt v) Root).symm.trans ((congrArg Prod.fst replay).trans a)
 obtain⟨w,produced,verified⟩:=SmzaRp05FinalProgramMiddleExecution.program_bind_success (OracleAt v) p (E.verifierProgram ns rel false n) () run
 obtain⟨t,⟨st⟩,clean,_,final⟩:=E.accepted_execution_has_stages ns rel false n w (OracleAt v) verified
 by_cases free:RecordsCollisionFree (records p ns rel n v)
 · have choose (r:Role) (arm:Arm p ns rel n b v w t st r):
    ¬RecordsCollisionFree (records p ns rel n v)∨(∃r,Choice p ns rel n b r v)∨SourceWitness p ns rel n b v:=
    Or.inr (Or.inl ⟨r,free,w,produced,t,st,clean,final,arm⟩)
   have covered:AL.sourceRecords (FL.fullRecords ns rel false n w (OracleAt v))⊆records p ns rel n v:=by
    have h:=source_coverage p ns rel n b .decsSample (fixed p ns rel n b .decsSample v) (db p ns rel n b .decsSample v)
     (compatible p ns rel n b .decsSample v all) (selected_claims p ns rel n b .decsSample v all) (fun _=>0) w
     (by simpa only[merge_full,sourceOracle] using produced)
    simpa only[merge_full,canonical_records,sourceOracle] using h
   have pcsClean:=NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false ns rel false n w (OracleAt v) t st clean
   rcases RG.pcs_execution_has_geometry_or_named_bad_event ns st.openingPending w st.decoded st.opening (OracleAt v)
    st.pcs (records p ns rel n v) st.pcsExecuted pcsClean with prior|matrix|small|⟨⟨g⟩⟩
   · exact (AL.stages_prior_bad_is_impossible_on_collision_free_completed_record ns rel false n w (OracleAt v) t st clean _ free covered prior).elim
   · exact choose .decsMatrix matrix
   · exact choose .decsSample (Or.inl small)
   · rcases RG.geometry_has_identities_or_literal_lvcs_event ns w st.decoded st.opening st.pcs (records p ns rel n v) g with ids|roots
     · by_cases satisfied:PiopExtraction.FullySatisfied (D.candidate rel g.source).system
       · exact Or.inr (Or.inr ⟨w,produced,t,st,clean,g,ids,satisfied,
          NativePrivateSpendQ58CurrentDecodedRelation.fully_satisfied_implies_current_relation rel g.source satisfied⟩)
       · rcases identities_piop ns rel n w (OracleAt v) t st (records p ns rel n v) g ids satisfied with ma|op
         · exact choose .piopMatrix ⟨g,ma⟩
         · exact choose .piopOpening ⟨g,op⟩
     · exact choose .decsSample (Or.inr ⟨g,roots⟩)
 · exact Or.inl free
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCanonicalSourceClassifier
