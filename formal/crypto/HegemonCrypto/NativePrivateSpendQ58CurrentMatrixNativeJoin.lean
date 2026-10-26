import HegemonCrypto.NativePrivateSpendQ58CurrentMatrixRawOrder
import HegemonCrypto.NativePrivateSpendQ58CurrentDecsLiteralInclusion
import HegemonCrypto.NativePrivateSpendQ58CurrentActualTraceLabel
import SmzaRp05CurrentRawSampleReadback
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixNativeJoin
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableChallengeStage
(FieldWord scan returnedWords field_loop_executes_scan pendingFailure zeroWord)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog rawLog branchResult)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsCompressedOracle (Basis)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9CappedRawSampler (FieldOutput sourceFieldSize)
open SmzaRp04RawRoleSampling (selectedRawBlocks rawFieldSample totalEquivDecoder)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaDynamicDatabaseSoundness (DynamicBad)
open V8Smz9RuntimeRandomness (idealFieldCoinEquivGoldilocks)
open SmzaRp05DecsResponseProjection (decodeFieldRow)
namespace CM
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end CM
namespace CP
export NativePrivateSpendQ58CurrentPublicOpening (Relation)
end CP
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
(Wire Transcript ExecutionStages DecodedFields Opening PcsOutput decsInput verifierProgram pcsProgram fieldKeys fieldXof gammaRows accepted_execution_has_stages)
end E
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
(Counter RawInput RawDigest Key zero encode decode frame keyBytes
    frame_is_literal_current recorded_current_base_parser stored_current_vector_answers_every_counter)
end G
namespace B
export NativePrivateSpendQ58CurrentActiveBranchClaims
(live fixedCompatible activeClaims current_active_claims_replay_same_program
    current_active_claims_complete_full_branch current_recorded_active_claim_is_selected)
end B
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey merge)
end A
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay
(claimOracle fullClaims current_claims_store_every_branch_vector)
end Q
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (parseCurrentStageQuery canonicalCurrentQueryBytes RoleActive)
end C
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end GF
namespace AL
export NativePrivateSpendQ58CurrentActualTraceLabel
(sourceRecords pcsRecords current_claimed_program_source_records_are_in_active_database
    stages_current_decs_base_is_in_full_log stages_prior_bad_is_impossible_on_collision_free_completed_record)
end AL
namespace FL
export NativePrivateSpendQ58CurrentFullLogReadback (fullRecords stages_pcs_log_subset_full)
end FL
namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport (actualCoefficients stages_pcs_pending_false)
end L
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (labelData labelMasks labelFromInputs)
end S
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel sourceTrace queryTarget queryStage)
end P
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext)
end F
namespace R
export NativePrivateSpendQ58CurrentRecoveryGeometry (MatrixBad RecoveryGeometry)
end R
namespace MR
export NativePrivateSpendQ58CurrentMatrixRawOrder
(fieldEquiv field_equiv_current_coordinate current_coordinate_value rawOutput vectorOutput vectorBad)
end MR
namespace MM
export NativePrivateSpendQ58CurrentMatrixDynamicMass (traceLabel matrixBad)
end MM
namespace LI
export NativePrivateSpendQ58CurrentDecsLiteralInclusion (pcs_execution_event_or_recovery actualRawBlocks)
end LI
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
abbrev caps:=GF.currentRoleCaps
structure Context where
  producer:Program E.Wire
  ns:CM.Namespace
  relation:CP.Relation
  nonce:Fin (2^32)
  branch:Branches G.decode (producer.bind (E.verifierProgram ns relation false nonce))
  fixed:NativePrivateSpendQ58PartitionTransport.FixedTable (Counter:=G.Counter)
      (B.live (producer.bind (E.verifierProgram ns relation false nonce)) .decsMatrix caps)
  database:Database (A.ActiveKey
      (B.live (producer.bind (E.verifierProgram ns relation false nonce)) .decsMatrix caps)) (VectorOutput G.Counter)
  compatible:B.fixedCompatible (producer.bind (E.verifierProgram ns relation false nonce)) .decsMatrix caps fixed branch
  claims:ClaimsDatabaseEvent (B.activeClaims
      (producer.bind (E.verifierProgram ns relation false nonce)) .decsMatrix caps branch) database
  accepted:branchResult G.decode (producer.bind (E.verifierProgram ns relation false nonce)) branch=some ()
  fallback:G.RawDigest
def prog (c:Context):=c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce)
def live (c:Context):=B.live (prog c) .decsMatrix caps
def full (c:Context):=A.merge (live c) c.fixed c.database
def oracle (c:Context):=Q.claimOracle (prog c) (full c) c.fallback
def bytes (c:Context):A.ActiveKey (live c)→G.RawInput:=fun key => G.keyBytes (prog c) key.val
def raw (c:Context):RawRecords:=rawRecords (bytes c) (vectorOutputBytes G.zero) c.database
def records (c:Context):=AL.sourceRecords (raw c)
abbrev Stages (c:Context) (w:E.Wire) (t:E.Transcript) :=
  E.ExecutionStages c.ns c.relation false c.nonce w (oracle c) t
def base (root:G.RawDigest):=G.frame .decsMatrix root ⟨0,by decide⟩ G.zero
def select:Fin (digestCallCap 700)↪G.Counter where
  toFun i:=⟨i.val,i.isLt.trans_le (by decide)⟩
  inj':=by intro i j same;exact Fin.ext (congrArg (fun counter : G.Counter => counter.val) same)
private def keys (root:G.RawDigest):=fun i:Fin (digestCallCap 700) =>
  G.frame .decsMatrix root ⟨0,by decide⟩ (select i)
private theorem keys_current (root:G.RawDigest) :
  E.fieldKeys .decsMatrix 700 root=List.ofFn (keys root):=by
  have enumeration {α:Type} {n:Nat} (f:Nat→α) :
    List.ofFn (fun i:Fin n => f i.val)=(List.range n).map f:=by
    rw [List.ofFn_eq_pmap];simp only [List.pmap_eq_map]
  have same:keys root=(fun i:Fin (digestCallCap 700) => C.canonicalCurrentQueryBytes ⟨.decsMatrix,root,0,i.val⟩):=by
    funext i
    have counterVal : (select i).val = i.val := rfl
    simpa only [keys, NativePrivateSpendQ58CurrentConstructorGrouping.nonceValue,
        if_neg (by decide : SmzaChallengeStageTargets.Role.decsMatrix ≠ SmzaChallengeStageTargets.Role.piopOpening),
        counterVal] using
        (G.frame_is_literal_current .decsMatrix root ⟨0, by decide⟩ (select i))
  have listed := enumeration (n := digestCallCap 700)
      (fun counter : Nat => C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, counter⟩)
  rw [same,listed]
  rfl
theorem stored_blocks {Result:Type} (p:Program Result)
(db:Database (G.Key p) (VectorOutput G.Counter)) (fallback root:G.RawDigest) (v:VectorOutput G.Counter)
(stored:db (G.encode p (base root))=some v) :
  selectedRawBlocks select v=fun i => Q.claimOracle p db fallback (keys root i):=by
  let basis:Basis (G.Key p) (VectorOutput G.Counter) (VectorOutput G.Counter) PUnit :=
    { input:=G.encode p [],phase:=0,workspace:=PUnit.unit,database:=db }
  have oracleEq : Q.claimOracle p db fallback =
          SmzaRp05PhysicalAcceptedReplayLite.basisOracle (G.encode p) G.decode basis fallback := by
    funext rawInput
    unfold Q.claimOracle SmzaRp05PhysicalAcceptedReplayLite.basisOracle
    dsimp only [basis]
    cases db (G.encode p rawInput) <;> rfl
  have basisStored :
          basis.database (G.encode p (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero)) = some v := by
    simpa only [basis,base] using stored
  funext i
  symm
  have answered := G.stored_current_vector_answers_every_counter p basis .decsMatrix root
      ⟨0, by decide⟩ v basisStored (select i) fallback
  rw [oracleEq]
  simpa only [keys,selectedRawBlocks] using answered
private theorem fin_equiv_value (n : Nat) [NeZero n] (word : Fin n) :
    (ZMod.finEquiv n word).val = word.val := by
  cases n with
  | zero => exact Fin.elim0 word
  | succ n => rfl

private theorem coin_cast (w:FieldWord):idealFieldCoinEquivGoldilocks w=(w.val:Goldilocks):=by
  letI:NeZero V8Smz9RuntimeRandomness.fieldModulus:=⟨by decide⟩
  change (ZMod.finEquiv V8Smz9RuntimeRandomness.fieldModulus) w=(w.val:ZMod V8Smz9RuntimeRandomness.fieldModulus)
  apply ZMod.val_injective
  rw [fin_equiv_value, ZMod.val_natCast]
  change w.val = w.val % SmzaRp05ExecutableChallengeStage.modulus
  exact (Nat.mod_eq_of_lt w.isLt).symm
private theorem of_fn_getD {α : Type} {n : Nat}
    (values : Fin n → α) (index : Fin n) (fallback : α) :
    (List.ofFn values).getD index.val fallback = values index := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_ofFn, dif_pos index.isLt, Option.getD_some]

private theorem field_word_gamma_coordinate
    (words : Fin 700 → FieldWord) (column : Fin 140) (row : Fin 5) :
    L.actualCoefficients (E.gammaRows (@List.ofFn FieldWord 700 words)) column row =
      ((words (finProdFinEquiv (row, column))).val : Goldilocks) := by
  have bounded : 140 * row.val + column.val < 700 := by
    have r := row.isLt
    have c := column.isLt
    omega
  have coordinate : finProdFinEquiv (row, column) =
      (⟨140 * row.val + column.val, bounded⟩ : Fin 700) :=
    Fin.ext (MR.current_coordinate_value column row)
  unfold L.actualCoefficients E.gammaRows decodeFieldRow
  rw [of_fn_getD _ row []]
  rw [List.map_ofFn, of_fn_getD _ column 0]
  dsimp only [Function.comp]
  rw [of_fn_getD words (⟨140 * row.val + column.val, bounded⟩ : Fin 700) zeroWord]
  rw [coordinate]

theorem coins_coefficients (coins:FieldOutput sourceFieldSize 700) :
  MR.fieldEquiv coins=L.actualCoefficients (E.gammaRows (List.ofFn coins)):=by
  funext column row
  exact (MR.field_equiv_current_coordinate coins column row).trans
    ((coin_cast (coins (finProdFinEquiv (row, column)))).trans
      (field_word_gamma_coordinate (coins : Fin 700 → FieldWord) column row).symm)
theorem stored_decodes {Result:Type} (p:Program Result)
(db:Database (G.Key p) (VectorOutput G.Counter)) (fallback:G.RawDigest) (v:VectorOutput G.Counter)
(ns:CM.Namespace) (pending:Bool)
(wire:E.Wire) (fields:E.DecodedFields)
(opening:E.Opening)
(output:E.PcsOutput)
(stored:db (G.encode p (base output.root))=some v)
(executed:(E.pcsProgram ns pending wire fields opening).eval (Q.claimOracle p db fallback)=some output)
(clean:output.pending=false):MR.vectorOutput select v=some (L.actualCoefficients output.gamma):=by
  let o:=Q.claimOracle p db fallback
  obtain ⟨_,sampledPending,sampled,_,_,_,_,_,_,_,gammaExecuted,gammaEq,_,_,pendingEq⟩ :=
    NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts ns pending wire fields opening o output executed
  obtain ⟨_,words,finished⟩:=SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words
    sampledPending sampled (pendingEq.trans clean)
  have gamma:E.gammaRows words=output.gamma:=by
    simpa only [finished,returnedWords,Option.getD_some] using gammaEq
  have scanEq:scan o 700 [] (E.fieldKeys .decsMatrix 700 output.root)=some words:=by
    exact (Option.some.inj ((field_loop_executes_scan o 700 [] _).symm.trans gammaExecuted)).trans finished
  rw [keys_current] at scanEq
  have mapped:=(SmzaRp05CurrentRawSampleReadback.source_scan_eq_raw_field_sample 700 (keys output.root) o).symm.trans scanEq
  rw [← stored_blocks p db fallback output.root v stored] at mapped
  cases sampledEq:rawFieldSample (digestCallCap 700) 700 (selectedRawBlocks select v) with
  | none => simp only [sampledEq,Option.map_none] at mapped;cases mapped
  | some coins =>
    have mappedSome := mapped
    simp only [sampledEq, Option.map_some] at mappedSome
    have same : @List.ofFn FieldWord 700 coins = words := Option.some.inj mappedSome
    unfold MR.vectorOutput MR.rawOutput
    rw [sampledEq]
    change some (MR.fieldEquiv coins)=some (L.actualCoefficients output.gamma)
    have coefficients := coins_coefficients coins
    change MR.fieldEquiv coins = L.actualCoefficients
      (E.gammaRows (@List.ofFn FieldWord 700 coins)) at coefficients
    have rows : E.gammaRows (@List.ofFn FieldWord 700 coins) = output.gamma :=
      (congrArg E.gammaRows same).trans gamma
    exact congrArg some (coefficients.trans (congrArg L.actualCoefficients rows))
private theorem record_vector (c:Context) (w:E.Wire) (produced:c.producer.eval (oracle c)=some w)
(x:G.RawInput) (member:(x,oracle c x)∈((E.verifierProgram c.ns c.relation false c.nonce w).record (oracle c)).2) :
  ∃ v,(x,v)∈answerLog G.decode (prog c) c.branch∧full c (G.encode (prog c) x)=some v:=by
  have replay:=B.current_active_claims_replay_same_program (prog c) .decsMatrix caps
    c.fixed c.branch c.database c.compatible c.claims c.fallback
  have all:=B.current_active_claims_complete_full_branch (prog c) .decsMatrix caps
    c.fixed c.branch c.database c.compatible c.claims
  have member':(x,oracle c x)∈rawLog G.decode (prog c) c.branch:=by
    have logEq := congrArg Prod.snd replay
    dsimp only [Prod.snd] at logEq
    rw [← logEq]
    exact Program.bind_log_right (oracle c) c.producer _ w produced member
  obtain ⟨call,recorded,same⟩:=List.mem_map.mp member'
  have inputEq:=congrArg Prod.fst same
  rcases call with ⟨actual,v⟩
  dsimp only at inputEq
  subst actual
  have stored : full c (G.encode (prog c) x) = some v := by
    dsimp only [prog, full, live] at all recorded ⊢
    with_reducible
      exact Q.current_claims_store_every_branch_vector (Result := Unit)
        (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce)) c.branch
        (A.merge (B.live (c.producer.bind (E.verifierProgram c.ns c.relation false c.nonce))
          .decsMatrix caps) c.fixed c.database) all
        ((x, v) : G.RawInput × VectorOutput G.Counter) recorded
  dsimp only [prog, full, live] at recorded stored
  refine ⟨v, ?_, ?_⟩
  · dsimp only [prog]
    with_reducible exact recorded
  · dsimp only [full, live, prog]
    with_reducible exact stored
private theorem sources (c:Context) (w:E.Wire) (produced:c.producer.eval (oracle c)=some w) :
  AL.sourceRecords (FL.fullRecords c.ns c.relation false c.nonce w (oracle c))⊆records c:=by
  have all:=AL.current_claimed_program_source_records_are_in_active_database (prog c) c.branch
    .decsMatrix c.fixed c.database c.compatible c.claims c.fallback
  intro call member
  obtain ⟨present,unparsed⟩:=Finset.mem_filter.mp member
  exact all (Finset.mem_filter.mpr ⟨List.mem_toFinset.mpr (Program.bind_log_right (oracle c) c.producer _ w produced
    (List.mem_toFinset.mp present)),unparsed⟩)
theorem matrix_root_event (rec:RawRecords)
(output:E.PcsOutput) (bad:R.MatrixBad rec output) :
  MM.matrixBad (S.labelData (MM.traceLabel (extract F.rawNext rec 25 .root output.root)))
  (S.labelMasks (MM.traceLabel (extract F.rawNext rec 25 .root output.root))) (L.actualCoefficients output.gamma):=bad
theorem matrix_dynamic (c:Context) (w:E.Wire) (produced:c.producer.eval (oracle c)=some w)
(t:E.Transcript) (st:Stages c w t) (clean:st.pcs.pending=false) (bad:R.MatrixBad (records c) st.pcs) :
  DynamicBad (P.currentLabel (bytes c) G.zero 25)
  (fun trace key vector => MR.vectorBad (G.keyBytes (prog c)) select trace key.val vector) c.database:=by
  obtain ⟨v,recorded,stored⟩:=record_vector c w produced _
    (AL.stages_current_decs_base_is_in_full_log c.ns c.relation false c.nonce w (oracle c) t st)
  have parsed : C.parseCurrentStageQuery
      (G.keyBytes (prog c) (G.encode (prog c) (base st.pcs.root))) =
      some ⟨.decsMatrix, st.pcs.root, 0, 0⟩ := by
    unfold base
    exact G.recorded_current_base_parser (prog c) c.branch .decsMatrix st.pcs.root
      (0 : Fin (2 ^ 32)) G.zero v recorded
  have active:live c (G.encode (prog c) (base st.pcs.root)):=by
    unfold live B.live C.RoleActive
    rw [parsed]
    exact Or.inl rfl
  have claimed:(G.encode (prog c) (base st.pcs.root),v)∈Q.fullClaims (prog c) c.branch:=by
    rw [Q.fullClaims,SmzaRp05PhysicalAcceptedReplayLite.branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨_,recorded,rfl⟩
  have chosen:=B.current_recorded_active_claim_is_selected (prog c) .decsMatrix caps c.branch _ claimed active
  let key:A.ActiveKey (live c):=⟨G.encode (prog c) (base st.pcs.root),active⟩
  have label:P.currentLabel (bytes c) G.zero 25 c.database key=extract F.rawNext (raw c) 25 .root st.pcs.root:=by
    have parsedKey : C.parseCurrentStageQuery (bytes c key) =
        some ⟨.decsMatrix, st.pcs.root, 0, 0⟩ := parsed
    have target : P.queryTarget (bytes c key) = (.root, st.pcs.root) := by
      unfold P.queryTarget
      rw [parsedKey]
      rfl
    unfold P.currentLabel P.sourceTrace
    rw [target]
    rfl
  have decoded:=stored_decodes (prog c) (full c) c.fallback v
    c.ns st.openingPending w st.decoded st.opening st.pcs stored st.pcsExecuted clean
  have erase:=NativePrivateSpendQ58CurrentComplementReadback.current_extract_erases_challenge_records (raw c) 25 .root st.pcs.root
  refine ⟨key,v,c.claims _ chosen,?_⟩
  rw [label]
  refine ⟨⟨⟨.decsMatrix,st.pcs.root,0,0⟩,parsed,rfl,rfl⟩,L.actualCoefficients st.pcs.gamma,decoded,?_⟩
  rw [← erase]
  exact matrix_root_event (records c) st.pcs bad
namespace V
export NativePrivateSpendQ58CurrentLvcsEventJoin (actualCombinationPolynomial combinationPolynomial)
end V
namespace U
export NativePrivateSpendQ58CurrentSuccessfulFiber (Query rawDecoder)
end U
namespace D
export NativePrivateSpendQ58CurrentDecsTraceDensity (traceEvent)
end D
def Remaining (c:Context) (w:E.Wire) (t:E.Transcript) (st:Stages c w t):Prop :=
(∃ d:G.RawDigest,∃ query:U.Query,
    oracle c (E.decsInput w.hPiop st.pcs.heads
    (st.decoded.pcs.rcombiTails.map SmzaRp05PcsWireProjection.fieldWordsToGoldilocks))=d ∧
    U.rawDecoder (LI.actualRawBlocks (oracle c) d)=some query ∧
    query∈D.traceEvent (S.labelFromInputs (records c)
      st.pcs.root st.pcs.hashFpp st.pcs.gamma) st.opening (extract F.rawNext (records c) 28 .decs d)) ∨
  ∃ geometry:R.RecoveryGeometry c.ns w st.decoded st.opening st.pcs (records c),
    ∀ combination,V.actualCombinationPolynomial st.decoded.pcs geometry.heads combination =
      V.combinationPolynomial geometry.source st.opening combination
theorem accepted_decs_matrix_has_literal_event (c:Context) :
  ∃ w,c.producer.eval (oracle c)=some w∧(¬RecordsCollisionFree (records c) ∨
    ∃ t,∃ st:Stages c w t,t.pending=false ∧
    (DynamicBad (P.currentLabel (bytes c) G.zero 25)
      (fun trace key vector => MR.vectorBad (G.keyBytes (prog c)) select trace key.val vector) c.database ∨
        Remaining c w t st)):=by
  have replay:=B.current_active_claims_replay_same_program (prog c) .decsMatrix caps
    c.fixed c.branch c.database c.compatible c.claims c.fallback
  have ordinary:(prog c).eval (oracle c)=some () :=
    (Program.record_result (oracle c) _).symm.trans ((congrArg Prod.fst replay).trans c.accepted)
  obtain ⟨w,produced,accepted⟩:=SmzaRp05FinalProgramMiddleExecution.program_bind_success (oracle c)
    c.producer (E.verifierProgram c.ns c.relation false c.nonce) () ordinary
  obtain ⟨t,⟨st⟩,clean,_,_⟩:=E.accepted_execution_has_stages c.ns c.relation false c.nonce w (oracle c) accepted
  refine ⟨w,produced,?_⟩
  by_cases free:RecordsCollisionFree (records c)
  · have covered:=sources c w produced
    have pcsCovered:AL.sourceRecords (AL.pcsRecords c.ns st.openingPending w st.decoded st.opening (oracle c))⊆records c:=by
      intro call member
      obtain ⟨present,unparsed⟩:=Finset.mem_filter.mp member
      exact covered (Finset.mem_filter.mpr ⟨List.mem_toFinset.mpr
        (FL.stages_pcs_log_subset_full c.ns c.relation false c.nonce w (oracle c) t st (List.mem_toFinset.mp present)),unparsed⟩)
    have pcsClean:=L.stages_pcs_pending_false c.ns c.relation false c.nonce w (oracle c) t st clean
    obtain ⟨d,query,hashEq,decoded,event⟩:=LI.pcs_execution_event_or_recovery c.ns st.openingPending w st.decoded
      st.opening (oracle c) st.pcs st.pcsExecuted (records c) free pcsCovered pcsClean
    refine Or.inr ⟨t,st,clean,?_⟩
    rcases event with prior | matrix | remainder
    · exact (AL.stages_prior_bad_is_impossible_on_collision_free_completed_record
          c.ns c.relation false c.nonce w (oracle c) t st clean (records c) free covered prior).elim
    · exact Or.inl (matrix_dynamic c w produced t st pcsClean matrix)
    · cases remainder
      · with_reducible
          refine Or.inr ?_
          unfold Remaining
          refine Or.inl ⟨(d : G.RawDigest), (query : U.Query), ?_, ?_, ?_⟩
          · exact (hashEq : oracle c (E.decsInput w.hPiop st.pcs.heads
              (st.decoded.pcs.rcombiTails.map SmzaRp05PcsWireProjection.fieldWordsToGoldilocks)) = d)
          · exact (decoded : U.rawDecoder (LI.actualRawBlocks (oracle c) d) = some query)
          · assumption
      · with_reducible
          refine Or.inr ?_
          unfold Remaining
          apply Or.inr
          assumption
  · exact Or.inl free
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixNativeJoin
