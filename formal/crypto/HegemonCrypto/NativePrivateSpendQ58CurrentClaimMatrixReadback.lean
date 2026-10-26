import HegemonCrypto.NativePrivateSpendQ58CurrentActiveBranchClaims
import HegemonCrypto.NativePrivateSpendQ58CurrentSourceCandidate
import SmzaRp05CurrentRawSampleReadback
import SmzaRp04RawRoleSampling
/-! Source-only current matrix readback; no kernel or G3 mass receipt. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentClaimMatrixReadback
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05ExecutableMerkleVerifier
open SmzaRp05ExecutableChallengeStage
 (FieldWord scan fieldLoop field_loop_executes_scan returnedWords pendingFailure zeroWord)
open SmzaRp05PhysicalAcceptedReplayLite
open V8Smz9CoherentVectorMerkle
open V8Smz9RawCounterCompiler
open V8Smz9CappedRawSampler
open V8Smz9PiopSoundness
open SmzaRp04RawRoleSampling
open V8Smz9RuntimeFieldLayout
open V8Smz9RuntimeRandomness
open SmzaChallengeStageTargets (Role)
open NativePrivateSpendQ58CurrentConstructorGrouping
open NativePrivateSpendQ58CurrentExecutableVerifier
open NativePrivateSpendQ58CurrentClaimReplay
open NativePrivateSpendQ58CurrentActiveBranchClaims
open NativePrivateSpendQ58CurrentRoleClassifier (RoleActive parseCurrentStageQuery canonicalCurrentQueryBytes)
open NativePrivateSpendQ58ActiveEventProjection (ActiveKey merge)
open NativePrivateSpendQ58PartitionTransport (FixedTable)
noncomputable section
open scoped Classical
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
def base (d:RawDigest):= frame .piopMatrix d ⟨0, by decide⟩ zero
def matrixSelect:Fin (digestCallCap (5 * 1344594))↪Counter where
 toFun i:= ⟨i.val, by
  have h:= i.isLt
  change i.val < 840376 at h
  exact h⟩
 inj':= by intro i j h; exact Fin.ext (congrArg Fin.val h)
private def keys (d:RawDigest) :
  Fin (digestCallCap (5 * 1344594))→V8SmzaOracleParser.RawInput:=
 fun i => frame .piopMatrix d ⟨0, by decide⟩ (matrixSelect i)
private theorem keys_current (d:RawDigest) :
  fieldKeys .piopMatrix 6722970 d=List.ofFn (keys d):= by
 have enumeration {α:Type} {n:Nat} (f:Nat→α) :
   List.ofFn (fun i:Fin n => f i.val)=(List.range n).map f:= by
  rw [List.ofFn_eq_pmap]
  simp only [List.pmap_eq_map]
 have same:keys d=(fun i:Fin (digestCallCap (5 * 1344594)) =>
   canonicalCurrentQueryBytes ⟨.piopMatrix, d, 0, i.val⟩):= by
  funext i
  have counterVal : (matrixSelect i).val = i.val := rfl
  simpa only [keys, nonceValue,
    if_neg (by decide : Role.piopMatrix ≠ Role.piopOpening), counterVal] using
    (frame_is_literal_current .piopMatrix d ⟨0, by decide⟩ (matrixSelect i))
 have listed := enumeration (n := digestCallCap (5 * 1344594))
   (fun counter : Nat => canonicalCurrentQueryBytes ⟨.piopMatrix, d, 0, counter⟩)
 rw [same, listed]
 rfl
theorem stored_matrix_blocks {Result:Type}
  (p:Program Result) (db:Database (Key p) (VectorOutput Counter))
  (h d:RawDigest) (v:VectorOutput Counter)
  (stored:db (encode p (base d))=some v) :
  selectedRawBlocks matrixSelect v =
   (fun i => claimOracle p db h (keys d i)):= by
 let b:Basis (Key p) (VectorOutput Counter) (VectorOutput Counter) PUnit:=
  { input:= encode p [], phase:= 0, workspace:= PUnit.unit, database:= db }
 have oracleEq : claimOracle p db h = basisOracle (encode p) decode b h := by
  funext raw
  unfold claimOracle basisOracle
  dsimp only [b]
  cases db (encode p raw) <;> rfl
 have basisStored :
     b.database (encode p (frame .piopMatrix d ⟨0, by decide⟩ zero)) = some v := by
  simpa only [b, base] using stored
 funext i
 symm
 have answered := stored_current_vector_answers_every_counter p b .piopMatrix d
   ⟨0, by decide⟩ v basisStored (matrixSelect i) h
 rw [oracleEq]
 simpa only [keys, selectedRawBlocks] using answered
private def output (words:List FieldWord) (width:Nat) :
  FieldOutput sourceFieldSize (5 * width):= fun i => words.getD i.val zeroWord
private theorem output_inverse (width:Nat) (v:FieldOutput sourceFieldSize (5 * width)) :
  output (List.ofFn v) width=v:= by
 funext i
 simp only [output, List.getD_eq_getElem?_getD, List.getElem?_ofFn,
  i.isLt, dif_pos, Option.getD_some]
private theorem fin_cast (n:Nat) [NeZero n] (w:Fin n) :
  (ZMod.finEquiv n) w=(w.val:ZMod n):= by
 cases n with
 | zero => exact (NeZero.ne 0 rfl).elim
 | succ n =>
  apply ZMod.val_injective
  change w.val=((w.val:ZMod (n + 1)).val)
  simp [ZMod.val_natCast, Nat.mod_eq_of_lt w.isLt]
private theorem coin_cast (w:FieldWord) :
  idealFieldCoinEquivGoldilocks w=w.val:= by
 letI:NeZero V8Smz9RuntimeRandomness.fieldModulus:= ⟨by decide⟩
 change (ZMod.finEquiv V8Smz9RuntimeRandomness.fieldModulus) w =
  (w.val:ZMod V8Smz9RuntimeRandomness.fieldModulus)
 exact fin_cast V8Smz9RuntimeRandomness.fieldModulus w
private theorem words_matrix (width:Nat) (words:List FieldWord) :
  matrixFieldEquiv width (output words width) =
   SmzaRp05PiopMatrixStage.matrixFromWords width words:= by
 funext row column
 simp [matrixFieldEquiv, output, SmzaRp05PiopMatrixStage.matrixFromWords,
  matrixEquiv, idealFieldCoinEquivGoldilocks, V8Smz9RuntimeRandomness.fieldModulus]
 rw [Nat.mul_comm width row.val, Nat.add_comm]
 exact coin_cast (words.getD (row.val * width + column.val) zeroWord)
private theorem matrix_eq_of_equal_words (width : Nat)
    (fields : FieldOutput sourceFieldSize (5 * width))
    (words : List FieldWord) (matrix : Matrix width)
    (wordsEq : List.ofFn fields = words)
    (matrixEq : SmzaRp05PiopMatrixStage.matrixFromWords width words = matrix) :
    matrixFieldEquiv width fields = matrix := by
  have inverse : output (List.ofFn fields) width = fields :=
    output_inverse width fields
  have restored : matrixFieldEquiv width fields =
      matrixFieldEquiv width (output (List.ofFn fields) width) :=
    congrArg (fun values : FieldOutput sourceFieldSize (5 * width) =>
      matrixFieldEquiv width values) inverse.symm
  have decoded : matrixFieldEquiv width (output (List.ofFn fields) width) =
      SmzaRp05PiopMatrixStage.matrixFromWords width (List.ofFn fields) :=
    words_matrix width (List.ofFn fields)
  have sameWords : SmzaRp05PiopMatrixStage.matrixFromWords width (List.ofFn fields) =
      SmzaRp05PiopMatrixStage.matrixFromWords width words :=
    congrArg (SmzaRp05PiopMatrixStage.matrixFromWords width) wordsEq
  exact restored.trans (decoded.trans (sameWords.trans matrixEq))

theorem stored_matrix_decodes_execution {Result:Type}
  (p:Program Result) (db:Database (Key p) (VectorOutput Counter))
  (h d:RawDigest) (v:VectorOutput Counter)
  (stored:db (encode p (base d))=some v)
  (f g:Bool) (m:Matrix 1344594)
  (executed:(matrixProgram f d).eval (claimOracle p db h) =
   some (m, g)) (clean:g=false) :
  rawPiopMatrixOutput 1344594 (selectedRawBlocks matrixSelect v)=some m:= by
 let o:= claimOracle p db h
 let next : Option (List FieldWord) → Program (Matrix 1344594 × Bool) :=
   fun sampled => .done (some
     (SmzaRp05PiopMatrixStage.matrixFromWords 1344594 (returnedWords 6722970 sampled),
       pendingFailure f sampled))
 have executedBind : ((fieldXof .piopMatrix 6722970 d).bind next).eval o =
     some (m, g) := by
  unfold matrixProgram at executed
  with_reducible
    exact executed
 obtain ⟨sample, run, finished⟩ := by
  with_reducible
    exact SmzaRp05FinalProgramMiddleExecution.program_bind_success o
      (fieldXof .piopMatrix 6722970 d) next (m, g) executedBind
 change some (SmzaRp05PiopMatrixStage.matrixFromWords 1344594
  (returnedWords 6722970 sample), pendingFailure f sample) =
   some (m, g) at finished
 have pair:= Option.some.inj finished
 obtain ⟨_, words, eq⟩:=
  SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words f sample
   ((congrArg Prod.snd pair).trans clean)
 have matEq:SmzaRp05PiopMatrixStage.matrixFromWords 1344594 words=m:= by
  simpa only [eq, returnedWords, Option.getD_some] using congrArg Prod.fst pair
 have scanEq:scan o 6722970 [] (fieldKeys .piopMatrix 6722970 d)=some words:= by
  have loop:= field_loop_executes_scan o 6722970 [] (fieldKeys .piopMatrix 6722970 d)
  exact (Option.some.inj (loop.symm.trans run)).trans eq
 rw [keys_current] at scanEq
 have readback:= SmzaRp05CurrentRawSampleReadback.source_scan_eq_raw_field_sample
  6722970 (keys d) o
 have sampleMap:= readback.symm.trans scanEq
 rw [← stored_matrix_blocks p db h d v stored] at sampleMap
 cases rawEq:rawFieldSample (digestCallCap (5 * 1344594)) 6722970
   (selectedRawBlocks matrixSelect v) with
 | none => simp only [rawEq, Option.map_none] at sampleMap; cases sampleMap
 | some fields =>
  have wordsEq:List.ofFn fields=words:= by
   dsimp only [SmzaRp05ExecutableChallengeStage.FieldWord,
     SmzaRp05ExecutableChallengeStage.modulus, sourceFieldSize, fieldModulus,
     Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]
     at rawEq sampleMap ⊢
   exact Option.some.inj (by
     simpa only [rawEq, Option.map_some] using sampleMap)
  unfold rawPiopMatrixOutput
  rw [rawEq]
  change some (matrixFieldEquiv 1344594 fields)=some m
  apply congrArg some
  with_reducible
    exact matrix_eq_of_equal_words 1344594 fields words m wordsEq matEq
private theorem range_map_head_tail {α : Type} (n : Nat) (f : Nat → α) :
    (List.range (n + 1)).map f = f 0 :: ((List.range (n + 1)).map f).tail := by
  simp only [List.range_succ_eq_map, List.map_cons, List.tail_cons]

theorem matrix_base_in_field_log (o:Oracle) (d:RawDigest) :
  (base d, o (base d))∈((fieldXof .piopMatrix 6722970 d).record o).2:= by
 let rest:= (fieldKeys .piopMatrix 6722970 d).tail
 have ks:fieldKeys .piopMatrix 6722970 d =
   canonicalCurrentQueryBytes ⟨.piopMatrix, d, 0, 0⟩::rest:= by
  have cap : SmzaRp05ExecutableChallengeStage.callCap 6722970 = 840375 + 1 := by decide
  have head := range_map_head_tail 840375
    (fun counter : Nat => canonicalCurrentQueryBytes ⟨.piopMatrix, d, 0, counter⟩)
  with_reducible
    simpa only [rest, fieldKeys, cap] using head
 unfold base
 rw [frame_is_literal_current]
 change (canonicalCurrentQueryBytes ⟨.piopMatrix, d, 0, 0⟩,
  o (canonicalCurrentQueryBytes ⟨.piopMatrix, d, 0, 0⟩)) ∈
  ((fieldLoop 6722970 [] (fieldKeys .piopMatrix 6722970 d)).record o).2
 rw [ks]
 change _∈_::_
 exact List.mem_cons_self
theorem matrix_base_in_full_log
  (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
  (r:NativePrivateSpendQ58CurrentPublicOpening.Relation)
  (f:Bool) (nonce:Fin (2^32)) (w:Wire) (o:Oracle)
  (t:Transcript) (st:ExecutionStages ns r f nonce w o t) :
  (base st.pcs.hashFpp, o (base st.pcs.hashFpp)) ∈
   ((verifierProgram ns r f nonce w).record o).2:= by
 have sample:= field_loop_executes_scan o 6722970 []
  (fieldKeys .piopMatrix 6722970 st.pcs.hashFpp)
 rw [NativePrivateSpendQ58CurrentSourceCandidate.stages_verifier_has_pre_matrix_log
  ns r f nonce w o t st]
 apply List.mem_append.mpr
 apply Or.inr
 apply List.mem_append.mpr
 apply Or.inl
 unfold matrixProgram
 rw [Program.record_bind_success o (fieldXof .piopMatrix 6722970 st.pcs.hashFpp) _ _ sample]
 simpa only [Prod.snd, Program.record, List.append_nil] using
  matrix_base_in_field_log o st.pcs.hashFpp
theorem accepted_active_branch_matrix
  (prod:Program Wire) (ns:NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
  (r:NativePrivateSpendQ58CurrentPublicOpening.Relation)
  (f:Bool) (nonce:Fin (2^32)) (caps:Role→Nat)
  (branch:Branches decode (prod.bind (verifierProgram ns r f nonce)))
  (fixed:FixedTable (Counter:= Counter)
   (live (prod.bind (verifierProgram ns r f nonce)) .piopMatrix caps))
  (db:Database (ActiveKey
   (live (prod.bind (verifierProgram ns r f nonce)) .piopMatrix caps))
   (VectorOutput Counter))
  (compat:fixedCompatible (prod.bind (verifierProgram ns r f nonce))
   .piopMatrix caps fixed branch)
  (claims:ClaimsDatabaseEvent (activeClaims
   (prod.bind (verifierProgram ns r f nonce)) .piopMatrix caps branch) db)
  (accept:branchResult decode (prod.bind (verifierProgram ns r f nonce)) branch=some ())
  (h:RawDigest) :
  let p:= prod.bind (verifierProgram ns r f nonce)
  let o:= claimOracle p (merge (live p .piopMatrix caps) fixed db) h
  ∃ w, prod.eval o=some w∧
   ∃ t, ∃ st:ExecutionStages ns r f nonce w o t,
    t.pending=false∧
    ∃ v, ∃ active:live p .piopMatrix caps (encode p (base st.pcs.hashFpp)),
     (base st.pcs.hashFpp, v)∈answerLog decode p branch∧
     parseCurrentStageQuery (keyBytes p (encode p (base st.pcs.hashFpp))) =
      some ⟨.piopMatrix, st.pcs.hashFpp, 0, 0⟩∧
     db ⟨encode p (base st.pcs.hashFpp), active⟩=some v∧
     rawPiopMatrixOutput 1344594 (selectedRawBlocks matrixSelect v)=some st.matrix:= by
 let p:= prod.bind (verifierProgram ns r f nonce)
 let merged:= merge (live p .piopMatrix caps) fixed db
 let o:= claimOracle p merged h
 have replay:= current_active_claims_replay_same_program p .piopMatrix caps
  fixed branch db compat claims h
 have allClaims:= current_active_claims_complete_full_branch p .piopMatrix caps
  fixed branch db compat claims
 have run:p.eval o=some ():=
  (Program.record_result o p).symm.trans ((congrArg Prod.fst replay).trans accept)
 obtain ⟨w, produced, verifierAccepted⟩:= SmzaRp05FinalProgramMiddleExecution.program_bind_success
  o prod (verifierProgram ns r f nonce) () run
 obtain ⟨t, ⟨st⟩, clean, _, _⟩:=
  accepted_execution_has_stages ns r f nonce w o verifierAccepted
 have parts:= Program.record_bind_success o prod (verifierProgram ns r f nonce) w produced
 have rawMem:(base st.pcs.hashFpp, o (base st.pcs.hashFpp))∈rawLog decode p branch:= by
  have logEq := congrArg Prod.snd replay
  dsimp only [Prod.snd] at logEq
  have partsEq := congrArg Prod.snd parts
  dsimp only [Prod.snd] at partsEq
  rw [← logEq, partsEq]
  exact List.mem_append.mpr (Or.inr
   (matrix_base_in_full_log ns r f nonce w o t st))
 obtain ⟨call, mem, same⟩:= List.mem_map.mp rawMem
 have inputEq:= congrArg Prod.fst same
 rcases call with ⟨input, v⟩
 dsimp only at inputEq
 subst input
 have parse : parseCurrentStageQuery (keyBytes p (encode p (base st.pcs.hashFpp))) =
   some ⟨.piopMatrix, st.pcs.hashFpp, 0, 0⟩ := by
  simpa only [base, nonceValue,
    if_neg (by decide : Role.piopMatrix ≠ Role.piopOpening)] using
    (recorded_current_base_parser p branch .piopMatrix st.pcs.hashFpp
      ⟨0, by decide⟩ zero v mem)
 have active:live p .piopMatrix caps (encode p (base st.pcs.hashFpp)):= by
  unfold live RoleActive
  rw [parse]
  exact Or.inl rfl
 have member:(encode p (base st.pcs.hashFpp), v)∈fullClaims p branch:= by
  rw [fullClaims, SmzaRp05PhysicalAcceptedReplayLite.branch_claims_eq_answer_log]
  exact List.mem_map.mpr ⟨_, mem, rfl⟩
 have chosen:= current_recorded_active_claim_is_selected p .piopMatrix caps branch _ member active
 have stored:= current_claims_store_every_branch_vector p branch merged allClaims _ mem
 have finalClean:st.finalPending=false:= by
  have samePending:= congrArg Transcript.pending st.reconstructed
  simpa only [reconstruct] using samePending.trans clean
 exact ⟨w, produced, t, st, clean, v, active, mem, parse, claims _ chosen,
  stored_matrix_decodes_execution p merged h st.pcs.hashFpp v stored
   st.pcs.pending st.finalPending st.matrix st.matrixExecuted finalClean⟩
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentClaimMatrixReadback

