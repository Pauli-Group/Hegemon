import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceEndpoint
import HegemonCrypto.NativePrivateSpendQ58CurrentSourceRecordExtraction
import SmzaRawDatabaseRecords

/-! Retain the stored counter-zero key and actual digest already constructed by
current PIOP insertion. The four-role dispatcher uses the same native replay,
claims, database and literal bad events as the frozen predecessor. DECS arms
remain unchanged. There is no supplied target/public/event inclusion, no new
physical execution, probability premise or lifetime query account. SOURCE ONLY.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixDynamicInsertion
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRp04RawRoleSampling (selectedRawBlocks)
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
variable (producer : Program E.Wire) (ns : M.Namespace) (relation : U.Relation)
variable (pending : Bool) (nonce : Fin (2^32))
local notation "program" => currentProgram producer ns relation pending nonce
/-- The actual matrix base query remains visible alongside its original bad predicate. -/
theorem actual_matrix_arm_is_targeted_bad
    (branch : Branches G.decode program) (fixed : MatrixFixed program)
    (database : MatrixDatabase program)
    (compatible : AC.fixedCompatible program .piopMatrix GF.currentRoleCaps fixed branch)
    (claims : ClaimsDatabaseEvent
      (AC.activeClaims program .piopMatrix GF.currentRoleCaps branch) database)
    (fallback : G.RawDigest) (wire : E.Wire) (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire
      (currentOracle program fixed database fallback) transcript)
    (produced : producer.eval (currentOracle program fixed database fallback) = some wire)
    (clean : transcript.pending = false)
    (geometry : R.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs
      (L.sourceRecords (currentRaw program database)))
    (calculated : S.calculatedCandidate (TM.fppLabel .piopMatrix (G.keyBytes program) fixed G.decode
      (extract F.rawNext (currentRaw program database) 26 .fpp stages.pcs.hashFpp)) = some geometry.source)
    (matrixArm : ¬ PiopExtraction.FullySatisfied (D.candidate relation geometry.source).system ∧
      stages.matrix ∈ PI.currentMatrixEvent (D.candidate relation geometry.source)) :
    ∃ key : A.ActiveKey (matrixLive program), ∃ vector,
      database key = some vector ∧
      C.parseCurrentStageQuery (activeBytes program key) =
        some ⟨.piopMatrix, stages.pcs.hashFpp, 0, 0⟩ ∧
      TM.matrixBad relation (G.keyBytes program) fixed G.decode MR.matrixSelect
        (P.currentLabel (activeBytes program) G.zero 26 database key) key.val vector := by
  obtain ⟨vector, active, recorded, parsed, stored, decoded⟩ :=
    exact_stages_matrix_vector producer ns relation pending nonce branch fixed database
      compatible claims fallback wire transcript stages produced clean
  have label := recorded_matrix_base_has_actual_fpp_label program database stages.pcs.hashFpp active parsed
  refine ⟨⟨G.encode program (MR.base stages.pcs.hashFpp), active⟩, vector, stored, parsed, ?_⟩
  change TM.matrixBad relation (G.keyBytes program) fixed G.decode MR.matrixSelect
    (P.currentLabel (activeBytes program) G.zero 26 database
      ⟨G.encode program (MR.base stages.pcs.hashFpp), active⟩)
    (G.encode program (MR.base stages.pcs.hashFpp)) vector
  rw [label]
  unfold TM.matrixBad
  rw [calculated]
  have conjunctionRight {left right : Prop} (proof : left ∧ right) : right := proof.2
  constructor
  · refine ⟨⟨.piopMatrix, stages.pcs.hashFpp, 0, 0⟩, ?_, ?_, ?_⟩
    · exact parsed
    · rfl
    · rfl
  · constructor
    · exact matrixArm.1
    · refine ⟨stages.matrix, ?_, ?_⟩
      · exact decoded
      · with_reducible
          exact no_implicit_lambda% (@conjunctionRight
              (¬ PiopExtraction.FullySatisfied (D.candidate relation geometry.source).system)
              (stages.matrix ∈ PI.currentMatrixEvent (D.candidate relation geometry.source))
              matrixArm)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixDynamicInsertion

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOpeningVectorInsertion
open SmzaRp05ExecutableMerkleVerifier (Program)
open HegemonCrypto.FiniteOracleDatabase (Database)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8Smz9PiopSoundness (maskSum)
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
/-- The actual first-valid opening base remains visible alongside its original bad predicate. -/
theorem actual_opening_arm_is_targeted_bad (c : Context) (w : E.Wire)
      (hw : c.producer.eval (oracle c) = some w) (t : E.Transcript) (st : Stages c w t)
      (free : RecordsCollisionFree (records c))
      (geom : RG.RecoveryGeometry c.ns w st.decoded st.opening st.pcs (records c))
      (failure : ¬PiopExtraction.AffineBatchAccepts (D.candidate c.relation geom.source).system
      (maskSum (D.candidate c.relation geom.source)) st.matrix)
      (checked : PE.CurrentOpeningChecks (D.candidate c.relation geom.source) st.matrix
      (PR.rawResponse (E.finalInput t)) st.opening) :
    ∃ key : A.ActiveKey (live c), ∃ vector,
      c.database key = some vector ∧
      C.parseCurrentStageQuery (activeBytes c key) =
        some ⟨.piopOpening, w.hPiop, c.nonce.val, 0⟩ ∧
      TM.openingBad c.relation (fullBytes c) c.fixed G.decode MR.matrixSelect openingSelect
        (P.currentLabel (activeBytes c) G.zero 27 c.database key) key.val vector := by
  obtain ⟨nonceBound, v, active, _recorded, parsed, hs, decoded⟩ :=
    same_branch_selected_opening_vector c w hw t st
  let key : A.ActiveKey (live c) := ⟨code c (openingBase w.hPiop c.nonce), active⟩
  have label : P.currentLabel (activeBytes c) G.zero 27 c.database key =
      extract F.rawNext (raw c) 27 .piop w.hPiop := by
    unfold P.currentLabel
    change P.sourceTrace 27 (raw c) (fullBytes c (code c (openingBase w.hPiop c.nonce))) = _
    unfold P.sourceTrace P.queryTarget
    rw [parsed]
    rfl
  obtain ⟨candidate, target, frame⟩ := same_branch_actual_opening_trace c w hw t st free geom
  have matrix := same_branch_matrix_is_fixed_matrix c w hw t st
  refine ⟨key, v, hs, parsed, ?_⟩
  rw [label]
  unfold TM.openingBad
  rw [candidate, target, matrix]
  refine ⟨⟨⟨.piopOpening, w.hPiop, c.nonce.val, 0⟩, parsed, rfl, nonceBound, rfl⟩,
    failure, st.opening, decoded, ?_⟩
  apply Finset.mem_filter.mpr
  refine ⟨Finset.mem_univ _, ?_⟩
  rw [frame]
  exact checked
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOpeningVectorInsertion

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCanonicalSourceClassifier.RetainedTarget
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree)
open SmzaDynamicDatabaseSoundness (DynamicBad)
open SmzaChallengeStageTargets (Role)
open V8Smz9CoherentMerkleGeometry (extract)
namespace FT
export NativePrivateSpendQ58CurrentFiberMassTransport (Active FixedVectors activeBytes actualActiveEquiv)
end FT
namespace CP
export NativePrivateSpendQ58CurrentRoleClassifier (parseCurrentStageQuery)
end CP
namespace PP
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel)
end PP
namespace MI
export NativePrivateSpendQ58CurrentMatrixDynamicInsertion (actual_matrix_arm_is_targeted_bad)
end MI
namespace OV
export NativePrivateSpendQ58CurrentOpeningVectorInsertion (actual_opening_arm_is_targeted_bad)
end OV
noncomputable section
set_option autoImplicit false
set_option Elab.async false
variable {Result : Type}

/-- The original routed bad event, with its SAME stored key and parsed actual target. -/
def TargetedRoleEvent (program : Program Result)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (fallback : G.RawDigest)
    (nonce : Fin (2^32)) (role : Role)
    (fixed : FT.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (database : Database (FT.Active role (G.keyBytes program)) (VectorOutput G.Counter))
    (target : G.RawDigest) (scanNonce : Nat) : Prop :=
  ∃ key, ∃ vector, database key = some vector ∧
    CP.parseCurrentStageQuery (FT.activeBytes role (G.keyBytes program) key) =
      some ⟨role, target, scanNonce, 0⟩ ∧
    N.roleBad program relation fallback nonce role fixed
      (PP.currentLabel (FT.activeBytes role (G.keyBytes program)) G.zero (N.stage role) database key)
      key vector

theorem targeted_role_event_is_original (program : Program Result)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (fallback : G.RawDigest)
    (nonce : Fin (2^32)) (role : Role)
    (fixed : FT.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (database : Database (FT.Active role (G.keyBytes program)) (VectorOutput G.Counter))
    (target : G.RawDigest) (scanNonce : Nat)
    (hit : TargetedRoleEvent program relation fallback nonce role fixed database target scanNonce) :
    N.roleEvent program relation fallback nonce role fixed database := by
  rcases hit with ⟨key, vector, stored, _parsed, bad⟩
  exact ⟨key, vector, stored, bad⟩

private theorem target_raw_exact (program : Program Result) (role : Role)
    (database : Database (A.ActiveKey (AC.live program role AC.currentRoleCaps)) (VectorOutput G.Counter)) :
    rawRecords (FT.activeBytes role (G.keyBytes program)) (vectorOutputBytes G.zero)
      (RI.pullDB program role database) =
    rawRecords (fun key : A.ActiveKey (AC.live program role AC.currentRoleCaps) => G.keyBytes program key.val)
      (vectorOutputBytes G.zero) database := by
  ext pair
  rcases pair with ⟨input, digest⟩
  simp only [SmzaRawDatabaseRecords.mem_raw_records_iff]
  constructor
  · rintro ⟨key, vector, stored, bytes, output⟩
    exact ⟨FT.actualActiveEquiv role (G.keyBytes program) key, vector, stored, bytes, output⟩
  · rintro ⟨key, vector, stored, bytes, output⟩
    refine ⟨(FT.actualActiveEquiv role (G.keyBytes program)).symm key, vector, ?_, bytes, output⟩
    simpa only [RI.pullDB, Equiv.apply_symm_apply] using stored

/-- The predecessor's coordinate transport also preserves the constructed parser witness. -/
theorem native_targeted_event_reindex (program : Program Result)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (fallback : G.RawDigest)
    (nonce : Fin (2^32)) (role : Role)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live program role AC.currentRoleCaps))
    (database : Database (A.ActiveKey (AC.live program role AC.currentRoleCaps)) (VectorOutput G.Counter))
    (target : G.RawDigest) (scanNonce : Nat)
    (hit : ∃ key, ∃ vector, database key = some vector ∧
      CP.parseCurrentStageQuery (G.keyBytes program key.val) = some ⟨role, target, scanNonce, 0⟩ ∧
      N.roleBad program relation fallback nonce role (RI.pullFixed program role fixed)
        (PP.currentLabel (fun key : A.ActiveKey (AC.live program role AC.currentRoleCaps) =>
          G.keyBytes program key.val) G.zero (N.stage role) database key)
        ((FT.actualActiveEquiv role (G.keyBytes program)).symm key) vector) :
    TargetedRoleEvent program relation fallback nonce role (RI.pullFixed program role fixed)
      (RI.pullDB program role database) target scanNonce := by
  rcases hit with ⟨key, vector, stored, parsed, bad⟩
  refine ⟨(FT.actualActiveEquiv role (G.keyBytes program)).symm key, vector, ?_, parsed, ?_⟩
  · simpa only [RI.pullDB, Equiv.apply_symm_apply] using stored
  · have label :
      PP.currentLabel (FT.activeBytes role (G.keyBytes program)) G.zero (N.stage role)
        (RI.pullDB program role database) ((FT.actualActiveEquiv role (G.keyBytes program)).symm key) =
      PP.currentLabel (fun key : A.ActiveKey (AC.live program role AC.currentRoleCaps) =>
        G.keyBytes program key.val) G.zero (N.stage role) database key := by
      unfold PP.currentLabel NativePrivateSpendQ58CurrentPrequeryEvents.sourceTrace
      rw [target_raw_exact program role database]
      rfl
    rw [label]
    exact bad

private theorem target_indexed_projection_transport
    {Index : Type} {Family : Index → Type} {Value : Type}
    (project : (index : Index) → Family index → Value)
    {left right : Index} (same : left = right) (value : Family left) :
    project right (same ▸ value) = project left value := by
  cases same
  rfl

variable (prod : Program E.Wire) (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (rel : NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce : Fin (2^32))
local notation "Root" => root prod ns rel nonce
local notation "Live" => live prod ns rel nonce
variable (branch : Branches (Output := VectorOutput G.Counter) (Result := Unit) G.decode
    (prod.bind (E.verifierProgram ns rel false nonce)))
local notation "Full" => fullDB prod ns rel nonce branch
local notation "O" => sourceOracle prod ns rel nonce branch

/-- Only the two PIOP alternatives require target retention; DECS conclusions
are the exact original role events. All targets below come from actual stages. -/
def InsertionAt (role : Role)
    (fixed : A.FixedTable (Counter := G.Counter) (Live role))
    (database : Database (A.ActiveKey (Live role)) (VectorOutput G.Counter))
    (fallback : G.RawDigest) (wire : E.Wire) (t : E.Transcript)
    (st : E.ExecutionStages ns rel false nonce wire
      (Q.claimOracle Root (A.merge (Live role) fixed database) fallback) t) : Prop :=
  match role with
  | .decsMatrix => N.roleEvent Root rel fallback nonce .decsMatrix
      (RI.pullFixed Root .decsMatrix fixed) (RI.pullDB Root .decsMatrix database)
  | .decsSample => N.roleEvent Root rel fallback nonce .decsSample
      (RI.pullFixed Root .decsSample fixed) (RI.pullDB Root .decsSample database)
  | .piopMatrix => TargetedRoleEvent Root rel fallback nonce .piopMatrix
      (RI.pullFixed Root .piopMatrix fixed) (RI.pullDB Root .piopMatrix database) st.pcs.hashFpp 0
  | .piopOpening => TargetedRoleEvent Root rel fallback nonce .piopOpening
      (RI.pullFixed Root .piopOpening fixed) (RI.pullDB Root .piopOpening database) wire.hPiop nonce.val

/-- Native replay data are retained so the causal consumer can derive public
labels from these SAME stages, source records and stored base key. -/
def ActualInsertion (role : Role)
    (fixed : A.FixedTable (Counter := G.Counter) (Live role))
    (database : Database (A.ActiveKey (Live role)) (VectorOutput G.Counter))
    (fallback : G.RawDigest) : Prop :=
  ∃ wire, prod.eval (Q.claimOracle Root (A.merge (Live role) fixed database) fallback) = some wire ∧
    ∃ t, ∃ st : E.ExecutionStages ns rel false nonce wire
      (Q.claimOracle Root (A.merge (Live role) fixed database) fallback) t,
      t.pending = false ∧ RecordsCollisionFree (nativeRecords prod ns rel nonce role database) ∧
      AL.sourceRecords (FL.fullRecords ns rel false nonce wire
        (Q.claimOracle Root (A.merge (Live role) fixed database) fallback)) ⊆
        nativeRecords prod ns rel nonce role database ∧
      (E.finalInput t, wire.hPiop) ∈ ((E.verifierProgram ns rel false nonce wire).record
        (Q.claimOracle Root (A.merge (Live role) fixed database) fallback)).2 ∧
      InsertionAt prod ns rel nonce role fixed database fallback wire t st
include branch in
theorem chosen_role_inserts_retaining_actual_target (role : Role)
    (fixed : A.FixedTable (Counter := G.Counter) (Live role))
    (database : Database (A.ActiveKey (Live role)) (VectorOutput G.Counter))
    (comp : AC.fixedCompatible Root role AC.currentRoleCaps fixed branch)
    (claims : ClaimsDatabaseEvent (AC.activeClaims Root role AC.currentRoleCaps branch) database)
    (fallback : G.RawDigest) (accepted : branchResult G.decode Root branch = some ())
    (choice : Choice prod ns rel nonce branch role (X.activeSourceView Root role database)) :
    ActualInsertion prod ns rel nonce role fixed database fallback := by
  let view := X.activeSourceView Root role database
  let completed := A.merge (Live role) fixed database
  have all := AC.current_active_claims_complete_full_branch Root role AC.currentRoleCaps fixed branch database comp claims
  have src : SC.SourceClaims Root branch view := by
    intro key value member source
    exact (A.merge_active _ _ _ ⟨key, X.source_keys_active_for_each_role Root role key source⟩).symm.trans (all _ member)
  have coherent := SC.consistent_of_claims Root branch completed all
  have canonical := SC.complete_source_claims Root branch view 0 src coherent
  have original := chosen_role_inserts prod ns rel nonce branch role fixed database comp claims fallback accepted choice
  rcases choice with ⟨free, w, produced, t, st, clean, final, arm⟩
  let native := SC.replay_native_stages prod ns rel false nonce branch (Full view) completed canonical all
    (fun _ => 0) fallback w produced t st
  have hw := SC.same_producer_full_claims prod ns rel false nonce branch (Full view) completed canonical all
    (fun _ => 0) fallback w produced
  have same : records prod ns rel nonce view = nativeRecords prod ns rel nonce role database := 
    (SC.active_source_records Root role database).symm
  have agree := SC.full_claims_agree_on_reads Root branch (Full view) completed canonical all (fun _ => 0) fallback
  have logEq := SmzaRp05CurrentBranchOracleAgreement.record_eq_of_agrees_on_left_reads
    (E.verifierProgram ns rel false nonce w) (O view) (Q.claimOracle Root completed fallback)
    (fun input member => agree input (Program.bind_log_right _ prod _ w produced member))
  have finalNative : (E.finalInput t, w.hPiop)∈((E.verifierProgram ns rel false nonce w).record
    (Q.claimOracle Root completed fallback)).2 := by
    rw [←congrArg Prod.snd logEq]; exact final
  have coveredAll := source_coverage prod ns rel nonce branch role fixed database comp claims fallback w hw
  refine ⟨w, hw, t, native, clean, same ▸ free, coveredAll, finalNative, ?_⟩
  cases role with
  | decsMatrix => exact original
  | decsSample => exact original
  | piopMatrix => 
    change TargetedRoleEvent Root rel fallback nonce .piopMatrix
      (RI.pullFixed Root .piopMatrix fixed) (RI.pullDB Root .piopMatrix database) native.pcs.hashFpp 0
    obtain ⟨geometry, matrixArm⟩ := arm
    let g : RG.RecoveryGeometry ns w native.decoded native.opening native.pcs
        (nativeRecords prod ns rel nonce .piopMatrix database) := same ▸ geometry
    have covered := source_coverage prod ns rel nonce branch .piopMatrix fixed database comp claims fallback w hw
    obtain ⟨v, recorded, _stored⟩ := canonical_recorded_vector prod ns rel nonce branch view canonical w produced _
      (AL.stages_current_decs_base_is_in_full_log ns rel false nonce w (O view) t st)
    have fixedGamma := AL.compatible_recorded_decs_base_has_fixed_gamma Root branch .piopMatrix (Or.inl rfl)
      fixed comp native.pcs.root v recorded
    have stored := Q.current_claims_store_every_branch_vector Root branch completed all _ recorded
    have claimedGamma := AL.stored_current_decs_base_determines_claim_gamma Root completed fallback native.pcs.root v stored
    have actualGamma := NativePrivateSpendQ58CurrentSourceCandidate.pcs_execution_gamma_is_label_gamma
      ns native.openingPending w native.decoded native.opening (Q.claimOracle Root completed fallback)
      native.pcs native.pcsExecuted
    have gamma : NativePrivateSpendQ58CurrentGammaFiber.fixedGamma .piopMatrix (G.keyBytes Root) fixed G.decode
      native.pcs.root = some native.pcs.gamma := fixedGamma.trans (congrArg some (claimedGamma.symm.trans actualGamma))
    obtain ⟨label, _, _⟩ := AL.stages_in_completed_record_identify_literal_source_label .piopMatrix (G.keyBytes Root)
      fixed G.decode ns rel false nonce w (Q.claimOracle Root completed fallback) t native
      (nativeRecords prod ns rel nonce .piopMatrix database) (same ▸ free) covered finalNative gamma
    have calculated := NativePrivateSpendQ58CurrentSourceCandidate.pcs_execution_candidate_is_label_candidate
      ns native.openingPending w native.decoded native.opening (Q.claimOracle Root completed fallback)
      native.pcs (nativeRecords prod ns rel nonce .piopMatrix database) native.pcsExecuted
    unfold NativePrivateSpendQ58CurrentSourceCandidate.labelAt at calculated
    rw [actualGamma] at calculated
    have candidate : NativePrivateSpendQ58CurrentSourceCandidate.calculatedCandidate
      (NativePrivateSpendQ58CurrentTracePiopMass.fppLabel .piopMatrix (G.keyBytes Root) fixed G.decode
        (extract NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
          (rawRecords (fun key : A.ActiveKey (Live .piopMatrix) => G.keyBytes Root key.val) (vectorOutputBytes G.zero) database)
          26 .fpp native.pcs.hashFpp)) = some g.source := by
      rw [← NativePrivateSpendQ58CurrentSourceRecordExtraction.current_source_extract_survives_filtration
        (rawRecords (fun key : A.ActiveKey (Live .piopMatrix) => G.keyBytes Root key.val)
            (vectorOutputBytes G.zero) database) 26 .fpp native.pcs.hashFpp]
      dsimp only [nativeRecords] at label
      rw [label]; exact calculated.trans g.calculated
    apply native_targeted_event_reindex
    have bad := by
      have matrixRule := @MI.actual_matrix_arm_is_targeted_bad prod ns rel false nonce
      dsimp (config := {instances := true}) only
        [NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentProgram,
         NativePrivateSpendQ58CurrentMatrixDynamicInsertion.MatrixFixed,
         NativePrivateSpendQ58CurrentMatrixDynamicInsertion.MatrixDatabase,
         NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixLive,
         NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentOracle,
         NativePrivateSpendQ58CurrentMatrixDynamicInsertion.activeBytes,
         NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentRaw, root, live]
        at matrixRule
      have matrixAtGeometry := matrixRule branch fixed database comp claims
        fallback w t native hw clean g
      dsimp (config := {instances := true, failIfUnchanged := false}) only
        [nativeRecords, root, live,
         NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixLive,
         NativePrivateSpendQ58CurrentMatrixDynamicInsertion.currentRaw,
         NativePrivateSpendQ58CurrentMatrixDynamicInsertion.activeBytes]
        at matrixAtGeometry candidate
      have matrixAfterCandidate := matrixAtGeometry candidate
      have gSource : g.source = geometry.source :=
        target_indexed_projection_transport
          (Family := fun prior => RG.RecoveryGeometry ns w native.decoded native.opening native.pcs prior)
          (fun _ value => value.source) same geometry
      have nativeMatrix : native.matrix = st.matrix := by rfl
      rw [gSource, nativeMatrix] at matrixAfterCandidate
      with_reducible
        exact no_implicit_lambda% (matrixAfterCandidate matrixArm)
    simpa (config := {unfoldPartialApp := true, instances := true})
      [root, NativePrivateSpendQ58CurrentSourceCompletion.Full,
       NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixLive,
       N.roleBad, N.stage, NativePrivateSpendQ58CurrentMatrixDynamicInsertion.matrixDynamicBad,
       NativePrivateSpendQ58CurrentMatrixDynamicInsertion.activeBytes,
       NativePrivateSpendQ58CurrentFiberMassTransport.matrixEvent,
       NativePrivateSpendQ58CurrentFiberMassTransport.actualActiveEquiv, RI.pullFixed,
       NativePrivateSpendQ58CurrentFiberMassTransport.actualFixed] using bad
  | piopOpening => 
    change TargetedRoleEvent Root rel fallback nonce .piopOpening
      (RI.pullFixed Root .piopOpening fixed) (RI.pullDB Root .piopOpening database) w.hPiop nonce.val
    obtain ⟨geometry, failure, checked⟩ := arm
    let c : OV.Context := 
      {producer := prod, ns := ns, relation := rel, pending := false, nonce := nonce, branch := branch, fixed := fixed, 
        database := database, compatible := comp, claims := claims, accepted := accepted, fallback := fallback}
    have nativeFree : RecordsCollisionFree
        (nativeRecords prod ns rel nonce .piopOpening database) := same ▸ free
    let nativeGeometry : RG.RecoveryGeometry ns w native.decoded native.opening native.pcs
        (nativeRecords prod ns rel nonce .piopOpening database) := same ▸ geometry
    have openingProduced : c.producer.eval (OV.oracle c) = some w := by
      dsimp only [c, NativePrivateSpendQ58CurrentOpeningVectorInsertion.oracle,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.completed, NativePrivateSpendQ58CurrentOpeningVectorInsertion.live,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog, NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify]
      dsimp only [completed, live,
        NativePrivateSpendQ58CurrentSourceCompletion.Full] at hw
      exact hw
    let openingStages : OV.Stages c w t := by
      dsimp only [OV.Stages, c,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.oracle, NativePrivateSpendQ58CurrentOpeningVectorInsertion.completed,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.live, NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify]
      dsimp only [completed, live,
        NativePrivateSpendQ58CurrentSourceCompletion.Full] at native
      exact native
    have openingFree : RecordsCollisionFree (OV.records c) := by
      dsimp only [c, NativePrivateSpendQ58CurrentOpeningVectorInsertion.records,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.raw, NativePrivateSpendQ58CurrentOpeningVectorInsertion.activeBytes,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.fullBytes, NativePrivateSpendQ58CurrentOpeningVectorInsertion.live,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog, NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify]
      dsimp only [nativeRecords, live] at nativeFree
      exact nativeFree
    let openingGeometry : RG.RecoveryGeometry c.ns w openingStages.decoded
        openingStages.opening openingStages.pcs (OV.records c) := by
      dsimp only [openingStages, c,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.oracle, NativePrivateSpendQ58CurrentOpeningVectorInsertion.completed,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.live, NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify, NativePrivateSpendQ58CurrentOpeningVectorInsertion.records,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.raw, NativePrivateSpendQ58CurrentOpeningVectorInsertion.activeBytes,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.fullBytes, NativePrivateSpendQ58CurrentOpeningVectorInsertion.live,
        NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog, NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify]
      dsimp only [nativeRecords, live] at nativeGeometry
      exact nativeGeometry
    have openingSource : openingGeometry.source = geometry.source := by
      change nativeGeometry.source = geometry.source
      exact target_indexed_projection_transport
        (Family := fun prior => RG.RecoveryGeometry ns w native.decoded native.opening native.pcs prior)
        (fun _ value => value.source) same geometry
    have openingMatrix : openingStages.matrix = st.matrix := by rfl
    have openingVector : openingStages.opening = st.opening := by rfl
    have openingFailure : ¬ PiopExtraction.AffineBatchAccepts
        (NativePrivateSpendQ58CurrentDecodedRelation.candidate c.relation openingGeometry.source).system
        (V8Smz9PiopSoundness.maskSum
          (NativePrivateSpendQ58CurrentDecodedRelation.candidate c.relation openingGeometry.source))
        openingStages.matrix := by
      rw [openingSource, openingMatrix]
      exact failure
    have openingChecked : NativePrivateSpendQ58CurrentPiopEvents.CurrentOpeningChecks
        (NativePrivateSpendQ58CurrentDecodedRelation.candidate c.relation openingGeometry.source)
        openingStages.matrix (NativePrivateSpendQ58CurrentPiopRecordJoin.rawResponse (E.finalInput t))
        openingStages.opening := by
      rw [openingSource, openingMatrix, openingVector]
      exact checked
    apply native_targeted_event_reindex
    with_reducible
      have bad := no_implicit_lambda% (@OV.actual_opening_arm_is_targeted_bad
        c w openingProduced t openingStages openingFree openingGeometry openingFailure openingChecked)
    dsimp (config := {instances := true, failIfUnchanged := false}) only
      [c, root, live, NativePrivateSpendQ58CurrentActiveBranchClaims.live,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.caps,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.activeBytes,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.fullBytes,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.live,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify] at bad ⊢
    simpa (config := {unfoldPartialApp := true, instances := true})
      [NativePrivateSpendQ58CurrentOpeningVectorInsertion.live,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.prog,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.verify,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.caps,
       NativePrivateSpendQ58CurrentActiveBranchClaims.live,
       N.roleBad, N.stage, NativePrivateSpendQ58CurrentOpeningVectorInsertion.activeBytes,
       NativePrivateSpendQ58CurrentOpeningVectorInsertion.fullBytes,
       NativePrivateSpendQ58CurrentFiberMassTransport.openingEvent,
       NativePrivateSpendQ58CurrentFiberMassTransport.actualActiveEquiv, RI.pullFixed,
       NativePrivateSpendQ58CurrentFiberMassTransport.actualFixed] using bad
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCanonicalSourceClassifier.RetainedTarget
