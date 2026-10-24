import HegemonCrypto.NativePrivateSpendQ58CurrentFixedOpeningReplay
import HegemonCrypto.NativePrivateSpendQ58CurrentActualTraceLabel
import HegemonCrypto.NativePrivateSpendQ58CurrentClaimMatrixReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentSameDatabaseEventJoin
import HegemonCrypto.NativePrivateSpendQ58CurrentDecsDynamicMass
import HegemonCrypto.NativePrivateSpendQ58CurrentDecsLiteralInclusion
/-! Actual pending=false accepted branch to DECS28/raw14 event. SOURCE ONLY. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsSourceJoin
open SmzaRp05ExecutableMerkleVerifier(Program Oracle)
open SmzaRp05ExecutableChallengeStage
(FieldWord scan returnedWords pendingFailure field_loop_executes_scan)
open SmzaRp05PhysicalAcceptedReplayLite(Branches answerLog rawLog branchResult)
open HegemonCrypto.FiniteOracleDatabase(Database)
open HegemonCrypto.CmsOracleDatabaseBridge(ClaimsDatabaseEvent)
open HegemonCrypto.CmsCompressedOracle(Basis)
open V8Smz9CoherentVectorMerkle(VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument(rawRecords)
open V8Smz9RawCounterCompiler(digestCallCap)
open V8Smz9CappedRawSampler(FieldOutput sourceFieldSize)
open SmzaRp04RawRoleSampling(selectedRawBlocks rawFieldSample)
open SmzaRp05FilteredDecoderInstability(RawRecords)
open SmzaRecordedTracePath(RecordsCollisionFree)
open V8Smz9CoherentMerkleGeometry(extract)
open SmzaDynamicDatabaseSoundness(DynamicBad)
open V8Smz9PiopSoundness(maskSum)
open SmzaChallengeStageTargets(Role)
open scoped Classical
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
(Wire Opening Transcript ExecutionStages decodeOpeningWords fieldKeys fieldXof openingAttempt canonicalOpening
 queryProgram queryResult decsInput pcsProgram matrixProgram reconstruct finalInput verifierProgram accepted_execution_has_stages)
end E
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
(RawInput RawDigest Counter Key encode decode frame zero keyBytes key_bytes_injective nonceValue
 frame_is_literal_current recorded_current_base_parser stored_current_vector_answers_every_counter)
end G
namespace B
export NativePrivateSpendQ58CurrentActiveBranchClaims
(live activeClaims fixedCompatible current_active_claims_replay_same_program
 current_active_claims_complete_full_branch current_recorded_active_claim_is_selected)
end B
namespace A
export NativePrivateSpendQ58ActiveEventProjection(ActiveKey merge)
end A
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay
(claimOracle fullClaims current_claims_store_every_branch_vector)
end Q
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier
(RoleActive parseCurrentStageQuery canonicalCurrentQueryBytes other_bounded_role_is_fixed
 fixed_vector_at_nonce_eq_actual_cell)
end C
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope(rawNext)
end F
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber(currentRoleCaps fixedGamma gammaFromVector)
end GF
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate
(labelAt labelFromInputs calculatedCandidate stages_transcript_execution stages_verifier_has_pre_matrix_log
 pcs_execution_gamma_is_label_gamma pcs_execution_candidate_is_label_candidate)
end S
namespace AL
export NativePrivateSpendQ58CurrentActualTraceLabel
(sourceRecords current_claimed_program_source_records_are_in_active_database
 stages_current_decs_base_is_in_full_log stored_current_decs_base_determines_claim_gamma
 compatible_recorded_decs_base_has_fixed_gamma stages_in_completed_record_identify_literal_source_label
 current_source_valid_input_is_unparsed)
end AL
namespace TM
export NativePrivateSpendQ58CurrentTracePiopMass(child childDigest traceInput fppLabel fixedMatrix openingBad)
end TM
namespace FR
export NativePrivateSpendQ58CurrentFixedOpeningReplay
(attemptedOpening opening_attempt_exact canonical_opening_first_valid16 FirstValid16)
end FR
namespace MR
export NativePrivateSpendQ58CurrentClaimMatrixReadback
(base matrixSelect matrix_base_in_full_log stored_matrix_decodes_execution)
end MR
namespace R
export NativePrivateSpendQ58CurrentRawPiopDensity
(currentOpeningFieldEquiv currentOpeningDecoder rawCurrentOpeningOutput)
end R
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents(currentLabel sourceTrace queryTarget queryStage)
end P
namespace PR
export NativePrivateSpendQ58CurrentPiopRecordJoin(rawResponse)
end PR
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation(candidate)
end D
namespace RG
export NativePrivateSpendQ58CurrentRecoveryGeometry(RecoveryGeometry)
end RG
namespace PE
export NativePrivateSpendQ58CurrentPiopEvents(CurrentOpeningChecks currentOpeningEvent)
end PE
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
private theorem current_matrix_event_of_affine {width : Nat}
    (candidate : V8Smz9PiopSoundness.Candidate width)
    (matrix : V8Smz9PiopSoundness.Matrix width)
    (affine : PiopExtraction.AffineBatchAccepts candidate.system
      (V8Smz9PiopSoundness.maskSum candidate) matrix) :
    matrix ∈ NativePrivateSpendQ58CurrentPiopEvents.currentMatrixEvent candidate :=
  Finset.mem_filter.mpr ⟨Finset.mem_univ matrix, affine⟩

abbrev caps:=GF.currentRoleCaps
structure Context where
 producer : Program E.Wire
 ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace
 relation : NativePrivateSpendQ58CurrentPublicOpening.Relation
 nonce : Fin (2^32)
 branch : Branches G.decode (producer.bind (E.verifierProgram ns relation false nonce))
 fixed : NativePrivateSpendQ58PartitionTransport.FixedTable (Counter := G.Counter)
  (B.live (producer.bind (E.verifierProgram ns relation false nonce)) .decsSample caps)
 database : Database (A.ActiveKey
  (B.live (producer.bind (E.verifierProgram ns relation false nonce)) .decsSample caps)) (VectorOutput G.Counter)
 compatible : B.fixedCompatible (producer.bind (E.verifierProgram ns relation false nonce))
  .decsSample caps fixed branch
 claims : ClaimsDatabaseEvent (B.activeClaims (producer.bind (E.verifierProgram ns relation false nonce))
  .decsSample caps branch) database
 accepted : branchResult G.decode (producer.bind (E.verifierProgram ns relation false nonce)) branch = some ()
 fallback : G.RawDigest
def program (c : Context) := c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce)
def live (c : Context) := B.live (program c) .decsSample caps
def completed (c : Context) := A.merge (live c) c.fixed c.database
def oracle (c : Context) := Q.claimOracle (program c) (completed c) c.fallback
def activeBytes (c : Context) : A.ActiveKey (live c) → G.RawInput := fun key => G.keyBytes (program c) key.val
def raw (c : Context) : RawRecords := rawRecords (activeBytes c) (vectorOutputBytes G.zero) c.database
def records (c : Context) := AL.sourceRecords (raw c)
abbrev Stages (c : Context) (w : E.Wire) (t : E.Transcript) :=
 E.ExecutionStages c.ns c.relation false c.nonce w (oracle c) t
private theorem same_verifier_record_vector (c : Context) (w : E.Wire)
 (produced : c.producer.eval (oracle c) = some w) (x : G.RawInput)
 (member : (x,oracle c x) ∈ ((E.verifierProgram c.ns c.relation false c.nonce w).record (oracle c)).2) :
 ∃ v, (x,v) ∈ answerLog G.decode (program c) c.branch ∧ completed c (G.encode (program c) x) = some v := by
 have replay := B.current_active_claims_replay_same_program (program c) .decsSample caps
  c.fixed c.branch c.database c.compatible c.claims c.fallback
 have all := B.current_active_claims_complete_full_branch (program c) .decsSample caps
  c.fixed c.branch c.database c.compatible c.claims
 have inRaw : (x,oracle c x) ∈ rawLog G.decode (program c) c.branch := by
  have logEq := congrArg Prod.snd replay
  dsimp only [Prod.snd] at logEq
  rw [← logEq]
  exact Program.bind_log_right (oracle c) c.producer _ w produced member
 obtain ⟨call,recorded,same⟩ := List.mem_map.mp inRaw
 have inputEq := congrArg Prod.fst same
 rcases call with ⟨actual,v⟩
 dsimp only at inputEq
 subst actual
 exact ⟨v,recorded,Q.current_claims_store_every_branch_vector (program c) c.branch (completed c) all (x,v) recorded⟩
namespace LI
export NativePrivateSpendQ58CurrentDecsLiteralInclusion
 (literalBytes literalWords recorded_decs_trace pcs_literal_payload actualRawBlocks pcs_execution_event_or_recovery)
end LI
namespace DM
export NativePrivateSpendQ58CurrentDecsDynamicMass (sampleSelect decsSampleBad)
end DM
namespace FO
export NativePrivateSpendQ58CurrentFixedOpeningReplay
 (current_accepted_decs_sample_branch_has_fixed_opening fixedOpening)
end FO
namespace FL
export NativePrivateSpendQ58CurrentFullLogReadback
 (fullRecords pcs_execution_has_actual_log_parts stages_pcs_log_subset_full)
end FL
namespace J
export NativePrivateSpendQ58CurrentAcceptedEventJoin (PiopBad)
end J
namespace LV
export NativePrivateSpendQ58CurrentLvcsEventJoin (actualCombinationPolynomial combinationPolynomial)
end LV
namespace DD
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded decodedValues fully_satisfied_implies_current_relation)
end DD
namespace PUB
export NativePrivateSpendQ58CurrentPublicOpening (Satisfies)
end PUB
namespace DS
export NativePrivateSpendQ58CurrentDecsTraceDensity (traceEvent)
end DS
namespace SF
export NativePrivateSpendQ58CurrentSuccessfulFiber (rawDecoder Query)
end SF
open SmzaRp05PcsWireProjection (fieldWordsToGoldilocks)

/-- Direct sample-role proof; the DECS matrix remains an inactive bounded role. -/
theorem compatible_sample_decs_base_has_fixed_gamma {Result : Type}
 (p : Program Result) (b : Branches G.decode p)
 (fixed : NativePrivateSpendQ58PartitionTransport.FixedTable (Counter := G.Counter) (B.live p .decsSample caps))
 (compat : B.fixedCompatible p .decsSample caps fixed b) (root : G.RawDigest) (v : VectorOutput G.Counter)
 (recorded : (G.frame .decsMatrix root ⟨0,by decide⟩ G.zero,v) ∈ answerLog G.decode p b) :
 GF.fixedGamma .decsSample (G.keyBytes p) fixed G.decode root = some (GF.gammaFromVector G.decode root v) := by
 have parsed := G.recorded_current_base_parser p b .decsMatrix root ⟨0,by decide⟩ G.zero v recorded
 have inactive : ¬B.live p .decsSample caps (G.encode p (G.frame .decsMatrix root ⟨0,by decide⟩ G.zero)) :=
  C.other_bounded_role_is_fixed .decsSample caps (G.keyBytes p) _ ⟨.decsMatrix,root,0,0⟩ parsed
   (by change Role.decsMatrix ≠ Role.decsSample; decide)
   (by change 0 < GF.currentRoleCaps .decsMatrix; decide)
 have same := compat (G.frame .decsMatrix root ⟨0,by decide⟩ G.zero,v) recorded inactive
 have cell := C.fixed_vector_at_nonce_eq_actual_cell .decsSample caps (G.keyBytes p) (G.key_bytes_injective p)
  fixed ⟨G.encode p (G.frame .decsMatrix root ⟨0,by decide⟩ G.zero),inactive⟩ ⟨.decsMatrix,root,0,0⟩ parsed rfl
 have sameCell : fixed
   ⟨G.encode p (G.frame .decsMatrix root ⟨0,by decide⟩ G.zero),inactive⟩ = v := by
  simpa only [Prod.fst,Prod.snd] using same
 have fixedVector : NativePrivateSpendQ58CurrentRoleClassifier.fixedVectorAtNonce .decsSample caps
   (G.keyBytes p) fixed .decsMatrix root 0 = some v :=
  cell.trans (congrArg some sameCell)
 simpa only [GF.fixedGamma,Option.map_some] using
  congrArg (Option.map (GF.gammaFromVector G.decode root)) fixedVector

def sampleBase (d : G.RawDigest) := G.frame .decsSample d ⟨0,by decide⟩ G.zero
private theorem stored_sample_blocks {Result : Type} (p : Program Result)
 (db : Database (G.Key p) (VectorOutput G.Counter)) (fallback d : G.RawDigest)
 (v : VectorOutput G.Counter) (stored : db (G.encode p (sampleBase d)) = some v) :
 selectedRawBlocks DM.sampleSelect v = LI.actualRawBlocks (Q.claimOracle p db fallback) d := by
 let basis : Basis (G.Key p) (VectorOutput G.Counter) (VectorOutput G.Counter) PUnit :=
  { input := G.encode p [], phase := 0, workspace := PUnit.unit, database := db }
 have oracleEq : Q.claimOracle p db fallback =
   SmzaRp05PhysicalAcceptedReplayLite.basisOracle (G.encode p) G.decode basis fallback := by
  funext raw
  unfold Q.claimOracle SmzaRp05PhysicalAcceptedReplayLite.basisOracle
  dsimp only [basis]
  cases db (G.encode p raw) <;> rfl
 have basisStored :
   basis.database (G.encode p (G.frame .decsSample d ⟨0,by decide⟩ G.zero)) = some v := by
  simpa only [basis,sampleBase] using stored
 funext i
 have answer := G.stored_current_vector_answers_every_counter p basis .decsSample d ⟨0,by decide⟩ v basisStored
  (DM.sampleSelect i) fallback
 have selectVal : (DM.sampleSelect i).val = i.val := rfl
 have literal : G.frame .decsSample d ⟨0,by decide⟩ (DM.sampleSelect i) =
   C.canonicalCurrentQueryBytes ⟨.decsSample,d,0,i.val⟩ := by
  simpa only [G.nonceValue,if_neg (by decide : Role.decsSample ≠ Role.piopOpening),selectVal] using
   G.frame_is_literal_current .decsSample d ⟨0,by decide⟩ (DM.sampleSelect i)
 rw [literal] at answer
 rw [oracleEq]
 simpa only [LI.actualRawBlocks,selectedRawBlocks] using answer.symm

private theorem sample_base_in_query (pending : Bool) (d : G.RawDigest) (o : Oracle) :
 (sampleBase d,o (sampleBase d)) ∈ ((E.queryProgram pending d).record o).2 := by
 have first : (sampleBase d,o (sampleBase d)) ∈ ((E.fieldXof .decsSample 80 d).record o).2 := by
  unfold sampleBase
  rw [G.frame_is_literal_current]
  change (C.canonicalCurrentQueryBytes ⟨.decsSample,d,0,0⟩,o (C.canonicalCurrentQueryBytes ⟨.decsSample,d,0,0⟩)) ∈ _ :: _
  exact List.mem_cons_self
 unfold E.queryProgram
 exact Program.bind_log_left o (E.fieldXof .decsSample 80 d) _
  (scan o 80 [] (E.fieldKeys .decsSample 80 d)) (field_loop_executes_scan o 80 [] _) first

private theorem source_coverage (c : Context) (w : E.Wire) (produced : c.producer.eval (oracle c) = some w) :
 AL.sourceRecords (FL.fullRecords c.ns c.relation false c.nonce w (oracle c)) ⊆ records c := by
 have all := AL.current_claimed_program_source_records_are_in_active_database (program c) c.branch
  .decsSample c.fixed c.database c.compatible c.claims c.fallback
 intro call member
 obtain ⟨present,unparsed⟩ := Finset.mem_filter.mp member
 exact no_implicit_lambda% (all (Finset.mem_filter.mpr
  ⟨List.mem_toFinset.mpr (Program.bind_log_right (oracle c) c.producer _ w produced
   (List.mem_toFinset.mp present)),unparsed⟩))

private theorem pcs_coverage (c : Context) (w : E.Wire) (produced : c.producer.eval (oracle c) = some w)
 (t : E.Transcript) (st : Stages c w t) :
 AL.sourceRecords (NativePrivateSpendQ58CurrentActualTraceLabel.pcsRecords c.ns st.openingPending w
  st.decoded st.opening (oracle c)) ⊆ records c := by
 have covered := source_coverage c w produced
 have included := FL.stages_pcs_log_subset_full c.ns c.relation false c.nonce w (oracle c) t st
 intro call member
 obtain ⟨present,unparsed⟩ := Finset.mem_filter.mp member
 exact covered (Finset.mem_filter.mpr ⟨List.mem_toFinset.mpr (included (List.mem_toFinset.mp present)),unparsed⟩)

/-- Actual DECS hash request and selected base parser/storage/readback. -/
theorem stages_decs_hash_and_sample_vector (c : Context) (w : E.Wire)
 (produced : c.producer.eval (oracle c) = some w) (t : E.Transcript) (st : Stages c w t) (d : G.RawDigest)
 (hashEq : oracle c (E.decsInput w.hPiop st.pcs.heads (st.decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)) = d) :
 (E.decsInput w.hPiop st.pcs.heads (st.decoded.pcs.rcombiTails.map fieldWordsToGoldilocks),d) ∈ records c ∧
 ∃ v, ∃ active : live c (G.encode (program c) (sampleBase d)),
  C.parseCurrentStageQuery (G.keyBytes (program c) (G.encode (program c) (sampleBase d))) = some ⟨.decsSample,d,0,0⟩ ∧
  c.database ⟨G.encode (program c) (sampleBase d),active⟩ = some v ∧
  selectedRawBlocks DM.sampleSelect v = LI.actualRawBlocks (oracle c) d := by
 obtain ⟨actual,parts⟩ := FL.pcs_execution_has_actual_log_parts c.ns st.openingPending w st.decoded st.opening
  (oracle c) st.pcs st.pcsExecuted
 have recordedHash : (E.decsInput w.hPiop st.pcs.heads (st.decoded.pcs.rcombiTails.map fieldWordsToGoldilocks),actual) ∈
  ((E.pcsProgram c.ns st.openingPending w st.decoded st.opening).record (oracle c)).2 := by
  rw [parts]
  simp only [List.mem_append,List.mem_singleton]
  exact Or.inl (Or.inl (Or.inl (Or.inl True.intro)))
 have same : actual = d := (Program.recorded_call (oracle c) _ _ recordedHash).trans hashEq
 subst actual
 have edge := (LI.pcs_literal_payload c.ns st.openingPending w st.decoded st.opening (oracle c) st.pcs st.pcsExecuted).2
 have retained := pcs_coverage c w produced t st (Finset.mem_filter.mpr ⟨List.mem_toFinset.mpr recordedHash,
  AL.current_source_valid_input_is_unparsed .decs _ (by simp [edge])⟩)
 have inPcs : (sampleBase d,oracle c (sampleBase d)) ∈
  ((E.pcsProgram c.ns st.openingPending w st.decoded st.opening).record (oracle c)).2 := by
  rw [parts]
  simp only [List.mem_append]
  have first := sample_base_in_query st.openingPending d (oracle c)
  exact Or.inl (Or.inl (Or.inl (Or.inr first)))
 obtain ⟨v,recorded,stored⟩ := same_verifier_record_vector c w produced _
  (FL.stages_pcs_log_subset_full c.ns c.relation false c.nonce w (oracle c) t st inPcs)
 have parsed := G.recorded_current_base_parser (program c) c.branch .decsSample d ⟨0,by decide⟩ G.zero v recorded
 have active : live c (G.encode (program c) (sampleBase d)) := by
  change C.RoleActive .decsSample caps (G.keyBytes (program c))
   (G.encode (program c) (G.frame .decsSample d ⟨0,by decide⟩ G.zero))
  unfold C.RoleActive
  rw [parsed]
  exact Or.inl rfl
 have full : (G.encode (program c) (sampleBase d),v) ∈ Q.fullClaims (program c) c.branch := by
  rw [Q.fullClaims,SmzaRp05PhysicalAcceptedReplayLite.branch_claims_eq_answer_log]
  exact List.mem_map.mpr ⟨_,recorded,rfl⟩
 have chosen := B.current_recorded_active_claim_is_selected (program c) .decsSample caps c.branch _ full active
 exact ⟨retained,v,active,parsed,c.claims _ chosen,stored_sample_blocks (program c) (completed c) c.fallback d v stored⟩

/-- Recorded DECS28 child is PIOP27; child-child FPP26 determines the source label. -/
theorem stages_literal_decs_trace (c : Context) (w : E.Wire) (produced : c.producer.eval (oracle c) = some w)
 (t : E.Transcript) (st : Stages c w t) (free : RecordsCollisionFree (records c)) (d : G.RawDigest)
 (recorded : (E.decsInput w.hPiop st.pcs.heads (st.decoded.pcs.rcombiTails.map fieldWordsToGoldilocks),d) ∈ records c)
 (finalRecorded : (E.finalInput t,w.hPiop) ∈ ((E.verifierProgram c.ns c.relation false c.nonce w).record (oracle c)).2) :
 TM.childDigest (extract F.rawNext (raw c) 28 .decs d) = w.hPiop ∧
 TM.fppLabel .decsSample (G.keyBytes (program c)) c.fixed G.decode
  (TM.child (TM.child (extract F.rawNext (raw c) 28 .decs d) 0) 0) =
  S.labelFromInputs (records c) st.pcs.root st.pcs.hashFpp st.pcs.gamma := by
 have covered := source_coverage c w produced
 obtain ⟨v,has,stored⟩ := same_verifier_record_vector c w produced _
  (AL.stages_current_decs_base_is_in_full_log c.ns c.relation false c.nonce w (oracle c) t st)
 have fixed := compatible_sample_decs_base_has_fixed_gamma (program c) c.branch c.fixed c.compatible st.pcs.root v has
 have claimed := AL.stored_current_decs_base_determines_claim_gamma (program c) (completed c) c.fallback st.pcs.root v stored
 have actual := S.pcs_execution_gamma_is_label_gamma c.ns st.openingPending w st.decoded st.opening
  (oracle c) st.pcs st.pcsExecuted
 have gamma : GF.fixedGamma .decsSample (G.keyBytes (program c)) c.fixed G.decode st.pcs.root = some st.pcs.gamma :=
  fixed.trans (congrArg some (claimed.symm.trans actual))
 obtain ⟨_,label,_⟩ := AL.stages_in_completed_record_identify_literal_source_label .decsSample
  (G.keyBytes (program c)) c.fixed G.decode c.ns c.relation false c.nonce w (oracle c) t st
  (records c) free covered finalRecorded gamma
 have trace := LI.recorded_decs_trace c.ns st.openingPending w st.decoded st.opening (oracle c) st.pcs
  st.pcsExecuted (records c) free d recorded
 have erase := NativePrivateSpendQ58CurrentComplementReadback.current_extract_erases_challenge_records (raw c) 28 .decs d
 delta program at *
 dsimp only [records,AL.sourceRecords] at erase trace label ⊢
 rw [← erase,trace]
 constructor
 · have payload := (LI.pcs_literal_payload c.ns st.openingPending w st.decoded st.opening (oracle c) st.pcs st.pcsExecuted).1
   simp only [TM.childDigest,TM.traceInput,SmzaRecordedTracePath.readPath,payload,Option.map_some,Option.getD_some,
     LI.literalBytes,LI.literalWords,List.flatMap_append,SmzaRp05CurrentDecsFrameReadback.digest_words_encode_exact,
     SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append]
 · simpa only [TM.child,List.getD_cons_zero] using label

-- The finite-type constructor-name style check timed out at whnf in C190.
-- Scope only this style check; proof checking and all other linters remain active.
set_option linter.constructorNameAsVariable false in
-- This retained matcher is pinned by the source graph; scope only its auxiliary-name style check.
set_option linter.auxLemma false in
/-- Same raw14 decoder and calculated Opening yield the same DB dynamic event. -/
theorem trace_event_is_dynamic_bad (c : Context) (w : E.Wire) (produced : c.producer.eval (oracle c) = some w)
 (t : E.Transcript) (st : Stages c w t) (free : RecordsCollisionFree (records c)) (d : G.RawDigest) (query : SF.Query)
 (hashEq : oracle c (E.decsInput w.hPiop st.pcs.heads (st.decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)) = d)
 (decoded : SF.rawDecoder (LI.actualRawBlocks (oracle c) d) = some query)
 (member : query ∈ DS.traceEvent (S.labelFromInputs (records c) st.pcs.root st.pcs.hashFpp st.pcs.gamma)
  st.opening (extract F.rawNext (records c) 28 .decs d))
 (finalRecorded : (E.finalInput t,w.hPiop) ∈ ((E.verifierProgram c.ns c.relation false c.nonce w).record (oracle c)).2)
 (opening : FO.fixedOpening (program c) .decsSample caps c.fixed c.fallback c.nonce w.hPiop = some st.opening) :
 DynamicBad (P.currentLabel (activeBytes c) G.zero 28)
  (fun trace key v => DM.decsSampleBad (program c) c.fixed c.fallback c.nonce trace key.val v) c.database := by
 obtain ⟨recorded,v,active,parsed,stored,blocks⟩ := stages_decs_hash_and_sample_vector c w produced t st d hashEq
 obtain ⟨target,label⟩ := stages_literal_decs_trace c w produced t st free d recorded finalRecorded
 let key : A.ActiveKey (live c) := ⟨G.encode (program c) (sampleBase d),active⟩
 have traceLabel : P.currentLabel (activeBytes c) G.zero 28 c.database key = extract F.rawNext (raw c) 28 .decs d := by
  have parsedKey : C.parseCurrentStageQuery (activeBytes c key) = some ⟨.decsSample,d,0,0⟩ := by
   dsimp only [activeBytes,key]
   exact parsed
  have targetPair : P.queryTarget (activeBytes c key) = (.decs,d) := by
   unfold P.queryTarget
   rw [parsedKey]
   rfl
  unfold P.currentLabel P.sourceTrace
  rw [targetPair]
  rfl
 have erase := NativePrivateSpendQ58CurrentComplementReadback.current_extract_erases_challenge_records (raw c) 28 .decs d
 refine ⟨key,v,stored,?_⟩
 rw [traceLabel]
 unfold DM.decsSampleBad
 delta live at *
 delta program at *
 with_reducible
  have targetOpening :
    FO.fixedOpening (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce)) .decsSample caps c.fixed c.fallback c.nonce
     (TM.childDigest (extract F.rawNext (raw c) 28 .decs d)) =
    FO.fixedOpening (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce)) .decsSample caps c.fixed c.fallback c.nonce w.hPiop := by
   with_reducible
    exact congrArg (α := G.RawDigest) (β := Option E.Opening)
     (fun digest : G.RawDigest =>
      FO.fixedOpening (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce)) .decsSample caps c.fixed c.fallback c.nonce digest) target
  have fixedOpeningAtTrace :
    FO.fixedOpening (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce)) .decsSample caps c.fixed c.fallback c.nonce
     (TM.childDigest (extract F.rawNext (raw c) 28 .decs d)) = some st.opening := by
   with_reducible
    exact targetOpening.trans opening
  let atOpening : Option E.Opening → Prop := fun result =>
   _root_.HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsDynamicMass.decsSampleBad.match_1
    (fun _ => Prop) result (fun _ => False) (fun actualOpening =>
     (∃ parsedQuery : SmzaChallengeStageTargets.StageQuery,
       C.parseCurrentStageQuery (G.keyBytes (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce)) key.val) = some parsedQuery ∧
       parsedQuery.role = .decsSample ∧ parsedQuery.nonce = 0 ∧ parsedQuery.counter = 0) ∧
     ∃ sampledQuery : SF.Query,
       SF.rawDecoder (selectedRawBlocks DM.sampleSelect v) = some sampledQuery ∧
       sampledQuery ∈ DS.traceEvent
        (TM.fppLabel .decsSample (G.keyBytes (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce))) c.fixed G.decode
         (TM.child (TM.child (extract F.rawNext (raw c) 28 .decs d) 0) 0))
        actualOpening (extract F.rawNext (raw c) 28 .decs d))
  have atSome : atOpening (some st.opening) := by
   dsimp only [atOpening]
   refine ⟨⟨⟨.decsSample,d,0,0⟩,(by dsimp only [key]; dsimp only [program]; exact parsed),rfl,rfl,rfl⟩,query,?_,?_⟩
   · rw [blocks]; exact decoded
   · rw [label,← erase]
     dsimp only [records,AL.sourceRecords] at member ⊢
     exact member
  have openingPredicateEq :
    atOpening (FO.fixedOpening
     (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce))
     .decsSample caps c.fixed c.fallback c.nonce
     (TM.childDigest (extract F.rawNext (raw c) 28 .decs d))) =
    atOpening (some st.opening) := by
   exact @congrArg (Option E.Opening) Prop
    (FO.fixedOpening (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce))
     .decsSample caps c.fixed c.fallback c.nonce
     (TM.childDigest (extract F.rawNext (raw c) 28 .decs d)))
    (some st.opening) atOpening fixedOpeningAtTrace
  have transported : atOpening (FO.fixedOpening
    (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce))
    .decsSample caps c.fixed c.fallback c.nonce
    (TM.childDigest (extract F.rawNext (raw c) 28 .decs d))) := by
   exact Eq.mpr openingPredicateEq atSome
  dsimp only [atOpening,caps] at transported
  dsimp only []
  exact transported

/-- Returned recovery identities derive scalar restoration and actual PIOP failure. -/
theorem geometry_identities_give_piop_bad (c : Context) (w : E.Wire) (t : E.Transcript) (st : Stages c w t)
 (geometry : RG.RecoveryGeometry c.ns w st.decoded st.opening st.pcs (records c))
 (identities : ∀ combination, LV.actualCombinationPolynomial st.decoded.pcs geometry.heads combination =
  LV.combinationPolynomial geometry.source st.opening combination)
 (invalid : ¬∃ source : DD.Decoded, PUB.Satisfies c.relation (DD.decodedValues source)) :
 J.PiopBad c.relation geometry.source st.matrix (PR.rawResponse (E.finalInput t)) st.opening := by
 have heads := NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_heads_are_lvcs_heads c.ns st.openingPending w
  st.decoded st.opening (oracle c) st.pcs st.pcsExecuted
 have same : geometry.heads = st.pcs.heads := Option.some.inj (geometry.headsBuilt.symm.trans heads)
 have actual : ∀ combination, LV.actualCombinationPolynomial st.decoded.pcs st.pcs.heads combination =
  LV.combinationPolynomial geometry.source st.opening combination := by
  intro combination; rw [← same]; exact identities combination
 obtain ⟨witness,nonlinear,linear⟩ := NativePrivateSpendQ58CurrentScalarEventBridge.current_same_execution_scalar_agreement
  c.ns st.openingPending w st.decoded st.opening (oracle c) st.pcs geometry.source st.decodedEq st.pcsExecuted actual
 have checks := NativePrivateSpendQ58CurrentScalarChecks.current_opened_scalars_derive_piop_checks c.relation geometry.source
  st.matrix st.opening st.decoded.piop witness nonlinear linear
 have response : PR.rawResponse (E.finalInput t) =
  NativePrivateSpendQ58CurrentPiopRestoration.response c.relation st.matrix st.opening st.decoded.piop := by
  exact
   (congrArg (fun transcript : E.Transcript => PR.rawResponse (E.finalInput transcript))
     st.reconstructed).symm.trans
    (NativePrivateSpendQ58CurrentPiopRecordJoin.current_final_raw_response c.relation st.matrix st.opening
      st.decoded.piop st.pcs.hashFpp st.finalPending)
 have satisfied : ¬PiopExtraction.FullySatisfied (D.candidate c.relation geometry.source).system := by
  intro yes
  exact invalid ⟨geometry.source,DD.fully_satisfied_implies_current_relation c.relation geometry.source yes⟩
 by_cases affine : PiopExtraction.AffineBatchAccepts (D.candidate c.relation geometry.source).system
  (maskSum (D.candidate c.relation geometry.source)) st.matrix
 · with_reducible
   unfold J.PiopBad
   exact Or.inl ⟨satisfied,current_matrix_event_of_affine (D.candidate c.relation geometry.source) st.matrix affine⟩
 · with_reducible
   unfold J.PiopBad
   have currentChecks : PE.CurrentOpeningChecks (D.candidate c.relation geometry.source)
     st.matrix (PR.rawResponse (E.finalInput t)) st.opening := by
    exact Eq.mpr
     (congrArg (fun answer : V8Smz9PiopSoundness.ClaimedTranscript =>
       PE.CurrentOpeningChecks (D.candidate c.relation geometry.source) st.matrix answer st.opening)
      response)
     checks
   exact Or.inr ⟨affine,currentChecks⟩

-- The endpoint finite-type constructor-name style check timed out at whnf in C195.
set_option linter.constructorNameAsVariable false in
/-- Only actual accepted branch data and relation invalidity are endpoint premises. -/
theorem accepted_invalid_decs_sample_has_literal_event (c : Context)
 (invalid : ¬∃ source : DD.Decoded, PUB.Satisfies c.relation (DD.decodedValues source)) :
 ∃ w, c.producer.eval (oracle c) = some w ∧
 (¬RecordsCollisionFree (records c) ∨
  DynamicBad (P.currentLabel (activeBytes c) G.zero 28)
   (fun trace key v => DM.decsSampleBad (program c) c.fixed c.fallback c.nonce trace key.val v) c.database ∨
  ∃ t, ∃ st : Stages c w t,
   NativePrivateSpendQ58CurrentRecoveryGeometry.MatrixBad (records c) st.pcs ∨
   ∃ geometry : RG.RecoveryGeometry c.ns w st.decoded st.opening st.pcs (records c),
    J.PiopBad c.relation geometry.source st.matrix (PR.rawResponse (E.finalInput t)) st.opening) := by
 obtain ⟨w,produced,t,st,clean,_fixedExecuted,calculated,_first⟩ :=
  FO.current_accepted_decs_sample_branch_has_fixed_opening c.producer c.ns c.relation c.nonce
   c.fixed c.branch c.database c.compatible c.claims c.accepted c.fallback
 change Stages c w t at st
 change FO.fixedOpening (program c) .decsSample caps c.fixed c.fallback c.nonce w.hPiop = some st.opening at calculated
 change c.producer.eval (oracle c) = some w at produced
 refine ⟨w,produced,?_⟩
 by_cases free : RecordsCollisionFree (records c)
 · have replay := B.current_active_claims_replay_same_program (program c) .decsSample caps
     c.fixed c.branch c.database c.compatible c.claims c.fallback
   have ordinary : (program c).eval (oracle c) = some () :=
     (Program.record_result (oracle c) (program c)).symm.trans
       ((congrArg Prod.fst replay).trans c.accepted)
   obtain ⟨otherWire,otherProduced,verifierAccepted⟩ :=
     SmzaRp05FinalProgramMiddleExecution.program_bind_success (oracle c) c.producer
       (E.verifierProgram c.ns c.relation false c.nonce) () ordinary
   have wireEq : otherWire = w := Option.some.inj (otherProduced.symm.trans produced)
   subst otherWire
   obtain ⟨other,⟨otherStages⟩,_clean,_digest,finalRecorded⟩ := E.accepted_execution_has_stages
     c.ns c.relation false c.nonce w (oracle c) verifierAccepted
   have same : other = t := Option.some.inj
     ((S.stages_transcript_execution c.ns c.relation false c.nonce w (oracle c) other otherStages).symm.trans
       (S.stages_transcript_execution c.ns c.relation false c.nonce w (oracle c) t st))
   subst other
   have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
     c.ns c.relation false c.nonce w (oracle c) t st clean
   obtain ⟨d,query,hashEq,decoded,event⟩ := LI.pcs_execution_event_or_recovery c.ns st.openingPending w st.decoded
     st.opening (oracle c) st.pcs st.pcsExecuted (records c) free (pcs_coverage c w produced t st) pcsClean
   with_reducible
     rcases event with prior | matrix | sample | ⟨geometry,identities⟩
     · have notPrior := NativePrivateSpendQ58CurrentActualTraceLabel.stages_prior_bad_is_impossible_on_collision_free_completed_record
         c.ns c.relation false c.nonce w (oracle c) t st clean (records c) free (source_coverage c w produced)
       unfold Not at notPrior
       exact False.elim (notPrior prior)
     · exact Or.inr (Or.inr ⟨t,st,Or.inl matrix⟩)
     · exact Or.inr (Or.inl (trace_event_is_dynamic_bad c w produced t st free d query hashEq decoded sample
         finalRecorded calculated))
     · exact Or.inr (Or.inr ⟨t,st,Or.inr ⟨geometry,geometry_identities_give_piop_bad c w t st geometry identities invalid⟩⟩)
 · with_reducible
   exact Or.inl free
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsSourceJoin
