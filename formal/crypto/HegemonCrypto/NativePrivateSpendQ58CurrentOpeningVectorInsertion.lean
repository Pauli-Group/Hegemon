import HegemonCrypto.NativePrivateSpendQ58CurrentFixedOpeningReplay
import HegemonCrypto.NativePrivateSpendQ58CurrentActualTraceLabel
import HegemonCrypto.NativePrivateSpendQ58CurrentClaimMatrixReadback
/-! Same accepted branch derives current opening vector, fixed matrix and
PIOP27 trace insertion. Source only; no compiler, probability or G3 PASS. -/

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOpeningVectorInsertion
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableChallengeStage
  (FieldWord scan returnedWords pendingFailure field_loop_executes_scan)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog rawLog branchResult)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsCompressedOracle (Basis)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9CappedRawSampler (FieldOutput sourceFieldSize)
open SmzaRp04RawRoleSampling (selectedRawBlocks rawFieldSample)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaDynamicDatabaseSoundness (DynamicBad)
open V8Smz9PiopSoundness (maskSum)
open SmzaChallengeStageTargets (Role)
open scoped Classical

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Wire Opening Transcript ExecutionStages decodeOpeningWords fieldKeys fieldXof openingAttempt canonicalOpening
  queryProgram queryResult matrixProgram reconstruct finalInput verifierProgram accepted_execution_has_stages)

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
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey merge)

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
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext)

end F

namespace GF
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps fixedGamma gammaFromVector)

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
export NativePrivateSpendQ58CurrentTracePiopMass (child childDigest traceInput fppLabel fixedMatrix openingBad)

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
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel sourceTrace queryTarget queryStage)

end P

namespace PR
export NativePrivateSpendQ58CurrentPiopRecordJoin (rawResponse)

end PR

namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (candidate)

end D

namespace RG
export NativePrivateSpendQ58CurrentRecoveryGeometry (RecoveryGeometry)

end RG

namespace PE
export NativePrivateSpendQ58CurrentPiopEvents (CurrentOpeningChecks currentOpeningEvent)

end PE

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev caps := GF.currentRoleCaps

/-- Only data from the same accepted producer/verifier branch and its actual
active claims are supplied. All vector and trace readback is derived below. -/
structure Context where
  producer : Program E.Wire
  ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace
  relation : NativePrivateSpendQ58CurrentPublicOpening.Relation
  pending : Bool
  nonce : Fin (2 ^ 32)
  branch : Branches G.decode (producer.bind (E.verifierProgram ns relation pending nonce))
  fixed : NativePrivateSpendQ58PartitionTransport.FixedTable (Counter := G.Counter)
      (B.live (producer.bind (E.verifierProgram ns relation pending nonce)) .piopOpening caps)
  database : Database (A.ActiveKey
      (B.live (producer.bind (E.verifierProgram ns relation pending nonce)) .piopOpening caps))
      (VectorOutput G.Counter)
  compatible : B.fixedCompatible (producer.bind (E.verifierProgram ns relation pending nonce))
    .piopOpening caps fixed branch
  claims : ClaimsDatabaseEvent (B.activeClaims (producer.bind (E.verifierProgram ns relation pending nonce))
    .piopOpening caps branch) database
  accepted : branchResult G.decode (producer.bind (E.verifierProgram ns relation pending nonce)) branch = some ()
  fallback : G.RawDigest

def verify (c : Context) := E.verifierProgram c.ns c.relation c.pending c.nonce

def prog (c : Context) := c.producer.bind (verify c)

def live (c : Context) := B.live (prog c) .piopOpening caps

def completed (c : Context) := A.merge (live c) c.fixed c.database

def oracle (c : Context) := Q.claimOracle (prog c) (completed c) c.fallback

def fullBytes (c : Context) := G.keyBytes (prog c)

def code (c : Context) := G.encode (prog c)

def activeBytes (c : Context) : A.ActiveKey (live c) → G.RawInput := fun key => fullBytes c key.val

def raw (c : Context) : RawRecords := rawRecords (activeBytes c) (vectorOutputBytes G.zero) c.database

def records (c : Context) := AL.sourceRecords (raw c)

abbrev Stages (c : Context) (w : E.Wire) (t : E.Transcript) :=
  E.ExecutionStages c.ns c.relation c.pending c.nonce w (oracle c) t

def openingBase (d : G.RawDigest) (nonce : Fin (2 ^ 32)) := G.frame .piopOpening d nonce G.zero

/-- The current six-field sampler consumes exactly five raw counters. -/
def openingSelect : Fin (digestCallCap 6) ↪ G.Counter where
  toFun i := ⟨i.val, by
    have small := i.isLt
    change i.val < 5 at small
    omega⟩
  inj' := by intro left right same; exact Fin.ext (congrArg (fun counter : G.Counter => counter.val) same)

private def openingKeys (d : G.RawDigest) (nonce : Fin (2 ^ 32)) :=
  fun i : Fin (digestCallCap 6) => G.frame .piopOpening d nonce (openingSelect i)

private theorem keysCurrent (d : G.RawDigest) (nonce : Fin (2 ^ 32)) :
    E.fieldKeys .piopOpening 6 d nonce.val = List.ofFn (openingKeys d nonce) := by
  have enumeration {α : Type} {n : Nat} (f : Nat → α) :
      List.ofFn (fun i : Fin n => f i.val) = (List.range n).map f := by
    rw [List.ofFn_eq_pmap]; simp only [List.pmap_eq_map]
  have same : openingKeys d nonce =
      (fun i : Fin (digestCallCap 6) => C.canonicalCurrentQueryBytes ⟨.piopOpening, d, nonce.val, i.val⟩) := by
    funext i
    have counterVal : (openingSelect i).val = i.val := rfl
    simpa only [openingKeys, G.nonceValue, if_true, counterVal] using
      (G.frame_is_literal_current .piopOpening d nonce (openingSelect i))
  have listed := enumeration (n := digestCallCap 6)
    (fun counter : Nat => C.canonicalCurrentQueryBytes ⟨.piopOpening, d, nonce.val, counter⟩)
  rw [same, listed]
  rfl

private theorem blocksStored {Result : Type} (p : Program Result)
      (db : Database (G.Key p) (VectorOutput G.Counter)) (fallback d : G.RawDigest)
      (nonce : Fin (2 ^ 32)) (v : VectorOutput G.Counter)
      (hs : db (G.encode p (openingBase d nonce)) = some v) :
    selectedRawBlocks openingSelect v = fun i => Q.claimOracle p db fallback (openingKeys d nonce i) := by
  let basis : Basis (G.Key p) (VectorOutput G.Counter) (VectorOutput G.Counter) PUnit :=
    { input := G.encode p [], phase := 0, workspace := PUnit.unit, database := db }
  have oracleEq : Q.claimOracle p db fallback =
      SmzaRp05PhysicalAcceptedReplayLite.basisOracle (G.encode p) G.decode basis fallback := by
    funext rawInput
    unfold Q.claimOracle SmzaRp05PhysicalAcceptedReplayLite.basisOracle
    dsimp only [basis]
    cases db (G.encode p rawInput) <;> rfl
  have basisStored :
      basis.database (G.encode p (G.frame .piopOpening d nonce G.zero)) = some v := by
    simpa only [basis, openingBase] using hs
  funext i
  symm
  have answered := G.stored_current_vector_answers_every_counter p basis .piopOpening d nonce v basisStored
    (openingSelect i) fallback
  rw [oracleEq]
  simpa only [openingKeys, selectedRawBlocks] using answered

private theorem current_tuple_decode (coins : FieldOutput sourceFieldSize 6) :
    E.decodeOpeningWords (List.ofFn coins) = R.currentOpeningDecoder coins := by
  have points : V8Smz9HonestOpeningSchedule.sourcePointVector (List.ofFn coins) = R.currentOpeningFieldEquiv coins := by
    funext i
    simp only [V8Smz9HonestOpeningSchedule.sourcePointVector, List.getD_eq_getElem?_getD,
      List.getElem?_ofFn, i.isLt, dif_pos, Option.getD_some]
    symm
    change (ZMod.finEquiv sourceFieldSize) (coins i) = ((coins i).val : ZMod sourceFieldSize)
    apply ZMod.val_injective
    have valueEq : ((ZMod.finEquiv sourceFieldSize) (coins i)).val = (coins i).val := rfl
    exact valueEq.trans
      (ZMod.val_natCast_of_lt (n := sourceFieldSize) (a := (coins i).val) (coins i).isLt).symm
  have decoderPoints : V8Smz9HonestOpeningSchedule.sourcePointVector
      (@List.ofFn FieldWord 6 coins) = R.currentOpeningFieldEquiv coins := points
  unfold E.decodeOpeningWords R.currentOpeningDecoder
  by_cases valid : NativePrivateSpendQ58CurrentChronologicalRequest.currentOpeningAdmissible
      (R.currentOpeningFieldEquiv coins)
  · have leftValid : (@List.ofFn FieldWord 6 coins).length = 6 ∧
        NativePrivateSpendQ58CurrentChronologicalRequest.currentOpeningAdmissible
          (V8Smz9HonestOpeningSchedule.sourcePointVector (@List.ofFn FieldWord 6 coins)) := by
      refine ⟨List.length_ofFn (f := (coins : Fin 6 → FieldWord)), ?_⟩
      rw [decoderPoints]
      exact valid
    rw [dif_pos leftValid, dif_pos valid]
    apply congrArg some
    apply Subtype.ext
    exact decoderPoints
  · have leftInvalid : ¬((@List.ofFn FieldWord 6 coins).length = 6 ∧
        NativePrivateSpendQ58CurrentChronologicalRequest.currentOpeningAdmissible
          (V8Smz9HonestOpeningSchedule.sourcePointVector (@List.ofFn FieldWord 6 coins))) := by
      intro guarded
      apply valid
      rw [← decoderPoints]
      exact guarded.2
    rw [dif_neg leftInvalid, dif_neg valid]

theorem stored_opening_decodes_clean_attempt {Result : Type} (p : Program Result)
      (db : Database (G.Key p) (VectorOutput G.Counter)) (fallback d : G.RawDigest)
      (nonce : Fin (2 ^ 32)) (v : VectorOutput G.Counter)
      (hs : db (G.encode p (openingBase d nonce)) = some v)
      (pending g : Bool) (a : E.Opening)
      (executed : (E.openingAttempt pending d nonce.val).eval (Q.claimOracle p db fallback) =
      some (some a, g)) (clean : g = false) :
    R.rawCurrentOpeningOutput (selectedRawBlocks openingSelect v) = some a := by
  let o := Q.claimOracle p db fallback
  have pair := Option.some.inj ((FR.opening_attempt_exact pending d nonce.val o).symm.trans executed)
  obtain ⟨_, words, sampled⟩ := SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words pending
      (scan o 6 [] (E.fieldKeys .piopOpening 6 d nonce.val)) ((congrArg Prod.snd pair).trans clean)
  have decoded : E.decodeOpeningWords words = some a := by
    simpa only [FR.attemptedOpening, sampled, returnedWords, Option.getD_some] using congrArg Prod.fst pair
  rw [keysCurrent] at sampled
  have readback := SmzaRp05CurrentRawSampleReadback.source_scan_eq_raw_field_sample 6 (openingKeys d nonce) o
  have mapped := readback.symm.trans sampled
  rw [← blocksStored p db fallback d nonce v hs] at mapped
  cases rawEq : rawFieldSample (digestCallCap 6) 6 (selectedRawBlocks openingSelect v) with
  | none => simp only [rawEq, Option.map_none] at mapped; cases mapped
  | some fields =>
      have mappedSome := mapped
      simp only [rawEq, Option.map_some] at mappedSome
      have wordsEq : @List.ofFn FieldWord 6 fields = words := Option.some.inj mappedSome
      rw [← wordsEq, current_tuple_decode] at decoded
      simpa only [R.rawCurrentOpeningOutput, rawEq, Option.bind_some] using decoded

private theorem baseInAttempt (pending : Bool) (d : G.RawDigest)
      (nonce : Fin (2 ^ 32)) (o : Oracle) :
      (openingBase d nonce, o (openingBase d nonce)) ∈ ((E.openingAttempt pending d nonce.val).record o).2 := by
  have first : (openingBase d nonce, o (openingBase d nonce)) ∈
      ((E.fieldXof .piopOpening 6 d nonce.val).record o).2 := by
    unfold openingBase
    rw [G.frame_is_literal_current]
    change (C.canonicalCurrentQueryBytes ⟨.piopOpening, d, nonce.val, 0⟩,
      o (C.canonicalCurrentQueryBytes ⟨.piopOpening, d, nonce.val, 0⟩)) ∈ _
    change _ ∈ _ :: _
    exact List.mem_cons_self
  unfold E.openingAttempt
  exact Program.bind_log_left o (E.fieldXof .piopOpening 6 d nonce.val) _
      (scan o 6 [] (E.fieldKeys .piopOpening 6 d nonce.val)) (field_loop_executes_scan o 6 [] _) first

theorem selected_opening_base_is_in_canonical_log (pending : Bool) (nonce : Fin (2 ^ 32))
      (d : G.RawDigest) (o : Oracle) (a : E.Opening) (g : Bool)
      (executed : (E.canonicalOpening pending nonce d).eval o = some (a, g)) :
      (openingBase d nonce, o (openingBase d nonce)) ∈ ((E.canonicalOpening pending nonce d).record o).2 := by
  unfold E.canonicalOpening at executed ⊢
  obtain ⟨chosen, scanned, continued⟩ := SmzaRp05FinalProgramMiddleExecution.program_bind_success o
      (NativePrivateSpendQ58CurrentExecutableVerifier.openingScan d (List.range 16) pending) _ (a, g) executed
  rcases chosen with ⟨expected, firstOpening, scanPending⟩
  by_cases equal : nonce.val = expected
  · simp only [if_pos equal] at continued
    obtain ⟨pair, repeated, _returned⟩ := SmzaRp05FinalProgramMiddleExecution.program_bind_success o
      (E.openingAttempt scanPending d nonce.val) _ (a, g) continued
    refine no_implicit_lambda% (Program.bind_log_right o _ _ (expected, firstOpening, scanPending) scanned ?_)
    simp only [if_pos equal]
    exact Program.bind_log_left o (E.openingAttempt scanPending d nonce.val) _ pair repeated
      (baseInAttempt scanPending d nonce o)
  · simp only [if_neg equal, Program.eval] at continued; cases continued

private theorem recordVector (c : Context) (w : E.Wire)
      (hw : c.producer.eval (oracle c) = some w) (x : G.RawInput)
      (member : (x, oracle c x) ∈ ((verify c w).record (oracle c)).2) :
    ∃ v, (x, v) ∈ answerLog G.decode (prog c) c.branch ∧
      completed c (code c x) = some v := by
  have replay := B.current_active_claims_replay_same_program (prog c) .piopOpening caps
    c.fixed c.branch c.database c.compatible c.claims c.fallback
  have all := B.current_active_claims_complete_full_branch (prog c) .piopOpening caps
    c.fixed c.branch c.database c.compatible c.claims
  have inRaw : (x, oracle c x) ∈ rawLog G.decode (prog c) c.branch := by
    have logEq := congrArg Prod.snd replay
    dsimp only [Prod.snd] at logEq
    rw [← logEq]
    exact Program.bind_log_right (oracle c) c.producer _ w hw member
  obtain ⟨call, hc, same⟩ := List.mem_map.mp inRaw
  have inputEq := congrArg Prod.fst same
  rcases call with ⟨actual, v⟩
  dsimp only at inputEq
  subst actual
  have stored :
      (A.merge (B.live (prog c) .piopOpening caps) c.fixed c.database)
        (G.encode (prog c) x) = some v := by
    dsimp only [prog, verify] at all hc ⊢
    with_reducible
      exact Q.current_claims_store_every_branch_vector (Result := Unit)
        (c.producer.bind (E.verifierProgram c.ns c.relation c.pending c.nonce)) c.branch
        (A.merge (B.live (c.producer.bind (E.verifierProgram c.ns c.relation c.pending c.nonce))
          .piopOpening caps) c.fixed c.database) all
        ((x, v) : G.RawInput × VectorOutput G.Counter) hc
  dsimp only [prog, verify] at hc stored
  refine ⟨v, ?_, ?_⟩
  · dsimp only [prog, verify]
    with_reducible exact hc
  · dsimp only [completed, live, code, prog, verify]
    with_reducible exact stored

private theorem stageFacts (c : Context) (w : E.Wire)
      (hw : c.producer.eval (oracle c) = some w) (t : E.Transcript) (st : Stages c w t) :
    t.pending = false ∧ (E.finalInput t, w.hPiop) ∈
      ((verify c w).record (oracle c)).2 := by
  have replay := B.current_active_claims_replay_same_program (prog c) .piopOpening caps
    c.fixed c.branch c.database c.compatible c.claims c.fallback
  have ordinary : (prog c).eval (oracle c) = some () :=
      (Program.record_result (oracle c) _).symm.trans ((congrArg Prod.fst replay).trans c.accepted)
  change (c.producer.bind (verify c)).eval (oracle c) = some () at ordinary
  rw [Program.eval_bind, hw, Option.bind_some] at ordinary
  obtain ⟨other, ⟨otherStages⟩, clean, _digest, hc⟩ := E.accepted_execution_has_stages
    c.ns c.relation c.pending c.nonce w (oracle c) ordinary
  have otherRun := S.stages_transcript_execution c.ns c.relation c.pending c.nonce w (oracle c) other otherStages
  have thisRun := S.stages_transcript_execution c.ns c.relation c.pending c.nonce w (oracle c) t st
  have same : other = t := Option.some.inj (otherRun.symm.trans thisRun)
  subst other
  exact ⟨clean, hc⟩

private theorem query_clean (pending : Bool) (d : G.RawDigest) (o : Oracle)
      (indices : List Nat) (g : Bool)
      (executed : (E.queryProgram pending d).eval o = some (indices, g))
      (clean : g = false) : pending = false := by
  unfold E.queryProgram at executed
  obtain ⟨sampled, _sampled, returned⟩ := SmzaRp05FinalProgramMiddleExecution.program_bind_success o
      (E.fieldXof .decsSample 80 d) _ (indices, g) executed
  change E.queryResult pending sampled = some (indices, g) at returned
  have selectedFlag (selected : List Nat) (flag : Bool)
      (result : (if selected.length = 58 then some (selected, flag) else none) =
        some (indices, g)) : flag = g := by
    by_cases enough : selected.length = 58
    · rw [if_pos enough] at result
      exact congrArg Prod.snd (Option.some.inj result)
    · rw [if_neg enough] at result
      cases result
  have flagEq : pendingFailure pending sampled = g := selectedFlag
    ((NativePrivateSpendQ58CurrentChronologicalRequest.sortedCurrentIndices
      (returnedWords 80 sampled)).map Fin.val)
    (pendingFailure pending sampled) returned
  exact (SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words pending sampled
    (flagEq.trans clean)).1

theorem accepted_stages_opening_pending_false (c : Context) (w : E.Wire)
      (hw : c.producer.eval (oracle c) = some w) (t : E.Transcript) (st : Stages c w t) :
    st.openingPending = false := by
  have clean := (stageFacts c w hw t st).1
  have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
    c.ns c.relation c.pending c.nonce w (oracle c) t st clean
  obtain ⟨d, sampledPending, sampled, _, _, query, _, _, _, _, _, _, _, _, pendingEq⟩ :=
    NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
      c.ns st.openingPending w st.decoded st.opening (oracle c) st.pcs st.pcsExecuted
  have queryClean := (SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words sampledPending sampled
      (pendingEq.trans pcsClean)).1
  exact query_clean st.openingPending d (oracle c) st.pcs.indexes sampledPending query queryClean

/-- Literal first-valid16 selection, current base parser and active storage. -/
theorem same_branch_selected_opening_vector (c : Context) (w : E.Wire)
      (hw : c.producer.eval (oracle c) = some w) (t : E.Transcript) (st : Stages c w t) :
    c.nonce.val < 16 ∧ ∃ v, ∃ active : live c (code c (openingBase w.hPiop c.nonce)),
      (openingBase w.hPiop c.nonce, v) ∈ answerLog G.decode (prog c) c.branch ∧
      C.parseCurrentStageQuery (fullBytes c (code c (openingBase w.hPiop c.nonce))) =
        some ⟨.piopOpening, w.hPiop, c.nonce.val, 0⟩ ∧
      c.database ⟨code c (openingBase w.hPiop c.nonce), active⟩ = some v ∧
      R.rawCurrentOpeningOutput (selectedRawBlocks openingSelect v) = some st.opening := by
  have first := FR.canonical_opening_first_valid16 c.pending c.nonce w.hPiop (oracle c)
    st.opening st.openingPending st.openingExecuted
  obtain ⟨before, after, scanPending, order, _prior, _selected, repeated⟩ := first
  have nonceBound : c.nonce.val < 16 := List.mem_range.mp (by rw [order]; simp)
  have selectedBase := selected_opening_base_is_in_canonical_log c.pending c.nonce w.hPiop (oracle c)
    st.opening st.openingPending st.openingExecuted
  have inVerifier : (openingBase w.hPiop c.nonce, oracle c (openingBase w.hPiop c.nonce)) ∈
      ((verify c w).record (oracle c)).2 := by
    dsimp only [verify]
    rw [S.stages_verifier_has_pre_matrix_log c.ns c.relation c.pending c.nonce w (oracle c) t st]
    exact List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inl selectedBase)))
  obtain ⟨v, hc, hs⟩ := recordVector c w hw _ inVerifier
  have parsed : C.parseCurrentStageQuery (fullBytes c (code c (openingBase w.hPiop c.nonce))) =
      some ⟨.piopOpening, w.hPiop, c.nonce.val, 0⟩ := by
    simpa only [fullBytes, code, openingBase, G.nonceValue, if_true] using G.recorded_current_base_parser (prog c) c.branch
      .piopOpening w.hPiop c.nonce G.zero v hc
  have active : live c (code c (openingBase w.hPiop c.nonce)) := by
    have parsedActive := parsed
    dsimp only [fullBytes] at parsedActive
    dsimp only [live, B.live]
    unfold C.RoleActive
    rw [parsedActive]
    exact Or.inl rfl
  have full : (code c (openingBase w.hPiop c.nonce), v) ∈ Q.fullClaims (prog c) c.branch := by
    rw [Q.fullClaims, SmzaRp05PhysicalAcceptedReplayLite.branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨_, hc, rfl⟩
  have chosen := B.current_recorded_active_claim_is_selected (prog c) .piopOpening caps c.branch _ full active
  exact ⟨nonceBound, v, active, hc, parsed, c.claims _ chosen,
    stored_opening_decodes_clean_attempt (prog c) (completed c) c.fallback w.hPiop c.nonce v hs
      scanPending st.openingPending st.opening repeated (accepted_stages_opening_pending_false c w hw t st)⟩

/-- Opaque conversion on abstract cells and decoders. Instantiations retain
an existing decoder equality without a rewrite motive over concrete carriers. -/
private theorem bind_decoded_some {Input Output : Type}
    (cell : Option Input) (decode : Input → Option Output)
    (value : Input) (result : Output)
    (cellEq : cell = some value) (decoded : decode value = some result) :
    cell.bind decode = some result := by
  exact (congrArg (fun entry : Option Input => entry.bind decode) cellEq).trans decoded

/-- The same recorded matrix vector is inactive under the opening role. -/
theorem same_branch_matrix_is_fixed_matrix (c : Context) (w : E.Wire)
      (hw : c.producer.eval (oracle c) = some w) (t : E.Transcript) (st : Stages c w t) :
    TM.fixedMatrix (fullBytes c) c.fixed MR.matrixSelect st.pcs.hashFpp = some st.matrix := by
  obtain ⟨v, hc, hs⟩ := recordVector c w hw _
      (MR.matrix_base_in_full_log c.ns c.relation c.pending c.nonce w (oracle c) t st)
  have parsed := G.recorded_current_base_parser (prog c) c.branch .piopMatrix st.pcs.hashFpp
      ⟨0, Nat.two_pow_pos 32⟩ G.zero v hc
  have inactive : ¬live c (code c (MR.base st.pcs.hashFpp)) := C.other_bounded_role_is_fixed
    .piopOpening caps (fullBytes c) _ ⟨.piopMatrix, st.pcs.hashFpp, 0, 0⟩ parsed
      (by change Role.piopMatrix ≠ Role.piopOpening; decide)
      (by change 0 < 840376; exact Nat.zero_lt_succ 840375)
  have fixedEq := c.compatible (MR.base st.pcs.hashFpp, v) hc inactive
  have cell := C.fixed_vector_at_nonce_eq_actual_cell .piopOpening caps (fullBytes c)
      (G.key_bytes_injective (prog c)) c.fixed ⟨code c (MR.base st.pcs.hashFpp), inactive⟩
      ⟨.piopMatrix, st.pcs.hashFpp, 0, 0⟩ parsed rfl
  have finalClean : st.finalPending = false := by
    have equal := congrArg (fun value : E.Transcript => value.pending) st.reconstructed
    simpa only [E.reconstruct] using equal.trans (stageFacts c w hw t st).1
  have fixedStored : c.fixed ⟨code c (MR.base st.pcs.hashFpp), inactive⟩ = v := fixedEq
  have cellStored := cell.trans (congrArg some fixedStored)
  exact bind_decoded_some
    (NativePrivateSpendQ58CurrentRoleClassifier.fixedVectorAtNonce
      .piopOpening caps (fullBytes c) c.fixed .piopMatrix st.pcs.hashFpp 0)
    (fun vector => SmzaRp04RawRoleSampling.rawPiopMatrixOutput 1344594
      (selectedRawBlocks MR.matrixSelect vector))
    v st.matrix cellStored
    (MR.stored_matrix_decodes_execution (prog c) (completed c) c.fallback st.pcs.hashFpp v hs
      st.pcs.pending st.finalPending st.matrix st.matrixExecuted finalClean)

/-- Source coverage comes from the same active claims. Challenge erasure
identifies the raw PIOP27 trace and its FPP26 calculated label. -/
theorem same_branch_actual_opening_trace (c : Context) (w : E.Wire)
      (hw : c.producer.eval (oracle c) = some w) (t : E.Transcript) (st : Stages c w t)
      (free : RecordsCollisionFree (records c))
      (geom : RG.RecoveryGeometry c.ns w st.decoded st.opening st.pcs (records c)) :
    S.calculatedCandidate (TM.fppLabel .piopOpening (fullBytes c) c.fixed G.decode
      (TM.child (extract F.rawNext (raw c) 27 .piop w.hPiop) 0)) = some geom.source ∧
    TM.childDigest (extract F.rawNext (raw c) 27 .piop w.hPiop) = st.pcs.hashFpp ∧
    TM.traceInput (extract F.rawNext (raw c) 27 .piop w.hPiop) = E.finalInput t := by
  have finalRecorded := (stageFacts c w hw t st).2
  have allSources := AL.current_claimed_program_source_records_are_in_active_database (prog c) c.branch
    .piopOpening c.fixed c.database c.compatible c.claims c.fallback
  have covered : AL.sourceRecords (NativePrivateSpendQ58CurrentFullLogReadback.fullRecords
      c.ns c.relation c.pending c.nonce w (oracle c)) ⊆ records c := by
    intro call member
    obtain ⟨present, unparsed⟩ := Finset.mem_filter.mp member
    exact no_implicit_lambda% (allSources (Finset.mem_filter.mpr
      ⟨List.mem_toFinset.mpr (Program.bind_log_right (oracle c) c.producer _ w hw
        (List.mem_toFinset.mp present)), unparsed⟩))
  obtain ⟨v, hc, hs⟩ := recordVector c w hw _
      (AL.stages_current_decs_base_is_in_full_log c.ns c.relation c.pending c.nonce w (oracle c) t st)
  have fixedGamma := AL.compatible_recorded_decs_base_has_fixed_gamma (prog c) c.branch .piopOpening
      (Or.inr rfl) c.fixed c.compatible st.pcs.root v hc
  have claimedGamma := AL.stored_current_decs_base_determines_claim_gamma (prog c) (completed c) c.fallback
    st.pcs.root v hs
  have actualGamma := S.pcs_execution_gamma_is_label_gamma c.ns st.openingPending w st.decoded
    st.opening (oracle c) st.pcs st.pcsExecuted
  have gamma : GF.fixedGamma .piopOpening (fullBytes c) c.fixed G.decode st.pcs.root = some st.pcs.gamma :=
    fixedGamma.trans (congrArg some (claimedGamma.symm.trans actualGamma))
  obtain ⟨_fppLabel, openingLabel, target⟩ := AL.stages_in_completed_record_identify_literal_source_label
    .piopOpening (fullBytes c) c.fixed G.decode c.ns c.relation c.pending c.nonce w (oracle c)
      t st (records c) free covered finalRecorded gamma
  have calculated := S.pcs_execution_candidate_is_label_candidate c.ns st.openingPending w st.decoded
    st.opening (oracle c) st.pcs (records c) st.pcsExecuted
  unfold S.labelAt at calculated
  rw [actualGamma] at calculated
  have erase : extract F.rawNext (records c) 27 .piop w.hPiop =
      extract F.rawNext (raw c) 27 .piop w.hPiop := by
    simpa only [records, AL.sourceRecords] using
      NativePrivateSpendQ58CurrentComplementReadback.current_extract_erases_challenge_records
        (raw c) 27 .piop w.hPiop
  have unparsed := AL.current_source_valid_input_is_unparsed .piop (E.finalInput t)
      (by simp [NativePrivateSpendQ58CurrentSourceTraceReadback.current_final_frame_has_literal_fpp_edge t])
  have finalPresent := covered (Finset.mem_filter.mpr ⟨List.mem_toFinset.mpr finalRecorded, unparsed⟩)
  have finalTrace := NativePrivateSpendQ58CurrentSourceTraceReadback.recorded_current_piop_trace_readback
      (records c) free t w.hPiop finalPresent
  refine ⟨?_, ?_, ?_⟩
  · rw [← erase, openingLabel]; exact calculated.trans geom.calculated
  · rw [← erase]; exact target
  · rw [← erase, finalTrace]; rfl

/-- An actual current opening arm inserts into the literal sparse database
with FULL grouped-key bytes for the fixed matrix and opening predicates. -/
theorem actual_opening_arm_is_same_database_dynamic_bad (c : Context) (w : E.Wire)
      (hw : c.producer.eval (oracle c) = some w) (t : E.Transcript) (st : Stages c w t)
      (free : RecordsCollisionFree (records c))
      (geom : RG.RecoveryGeometry c.ns w st.decoded st.opening st.pcs (records c))
      (failure : ¬PiopExtraction.AffineBatchAccepts (D.candidate c.relation geom.source).system
      (maskSum (D.candidate c.relation geom.source)) st.matrix)
      (checked : PE.CurrentOpeningChecks (D.candidate c.relation geom.source) st.matrix
      (PR.rawResponse (E.finalInput t)) st.opening) :
    DynamicBad (P.currentLabel (activeBytes c) G.zero 27)
      (fun trace key v => TM.openingBad c.relation (fullBytes c) c.fixed G.decode
        MR.matrixSelect openingSelect trace key.val v) c.database := by
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
  refine ⟨key, v, hs, ?_⟩
  rw [label]
  change TM.openingBad c.relation (fullBytes c) c.fixed G.decode
    MR.matrixSelect openingSelect (extract F.rawNext (raw c) 27 .piop w.hPiop) key.val v
  unfold TM.openingBad
  rw [candidate, target, matrix]
  refine ⟨⟨⟨.piopOpening, w.hPiop, c.nonce.val, 0⟩, parsed, rfl, nonceBound, rfl⟩,
    failure, st.opening, decoded, ?_⟩
  refine no_implicit_lambda% (Finset.mem_filter.mpr ⟨Finset.mem_univ _, ?_⟩)
  rw [frame]
  exact checked

end

end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOpeningVectorInsertion
