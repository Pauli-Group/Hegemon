import HegemonCrypto.NativePrivateSpendQ58CurrentLeafErasure
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAdapters
/-! Literal original SMZD request, independently constructed from the source
columns/masks, all2^23 raw taped leaves,23 Merkle levels and actual selectors.
It is NOT defined as the public simulator. The trusted source interpretation
is the same contract as PR205; no Rust/OS/P2P refinement is introduced. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOriginalRequest
open HegemonCrypto.CanonicalBytes
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9HiddenLeafQrom
open V8Smz9CurrentPrivacyComposition
open V8Smz9CurrentPrivacyGame (uniformAverage)
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule V8Smz9RawCounterCompiler
open V8Smz9MixedMaskCompiler
open NativePrivateSpendQ58CurrentLeafInput NativePrivateSpendQ58CurrentTranscriptInput
open NativePrivateSpendQ58CurrentSelectedLeaf NativePrivateSpendQ58CurrentChronologicalRequest
open NativePrivateSpendQ58CurrentCosetSelector NativePrivateSpendQ58CurrentCoinObservation
open NativePrivateSpendQ58CurrentInitializedPublic
open scoped Classical ENNReal
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option stderrAsMessages false
abbrev CByte := HegemonCrypto.CanonicalBytes.Byte
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: CByte"
abbrev Raw (bound : Nat) := CurrentFullRawInput bound
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: Raw"
abbrev GS (bound : Nat) (Work : Type) [Fintype Work] :=
 V8Smz9HonestWholeViewGames.GameState (Input := Raw bound) (Work := Work)
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: GS"
namespace SC
export NativePrivateSpendQ58Compff01SourceColumns
 (SourceData sourceCurrentColumns extendedRowPolynomial)
end SC
namespace OC
export NativePrivateSpendQ58Compff01OpeningContinuation
 (Heads stackedHeads earlier fullSubset combinationHeads)
end OC
namespace RB
export NativePrivateSpendQ58CurrentRowBoundary
 (CurrentCoins CurrentValues Gamma)
end RB
abbrev OriginalCoins := RB.CurrentCoins
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: OriginalCoins"
def originalCoinSource : V8Smz9HonestWholeViewGames.RandomSource where
 Coins := OriginalCoins
 finite := inferInstance
 inhabited := inferInstance
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: originalCoinSource"
def originalData (values : RB.CurrentValues)
  (coins : OriginalCoins) : SC.SourceData :=
 sourceData values coins.1 coins.2.2.1 coins.2.1
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: originalData"
def originalHeads (values : RB.CurrentValues)
  (coins : OriginalCoins) : OC.Heads :=
 OC.stackedHeads
  (SC.sourceCurrentColumns (originalData values coins))
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: originalHeads"
def originalPayload (descriptor : Descriptor)
  (values : RB.CurrentValues) (coins : OriginalCoins)
  (index : Index) : Fin 1176 → CByte :=
 let point := pointForIndex descriptor index
 leafPayload
  (fun row => (SC.extendedRowPolynomial
   (originalHeads values coins) coins.2.2.2.1 row).eval point)
  (fun repetition => (V8Smz9EagerPrivacy.coefficientPolynomial
   (coins.2.2.2.2 repetition)).eval point)
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: originalPayload"
variable {Work : Type} [Fintype Work]
def originalLeafBatch {bound : Nat}
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) :
  (count : Nat) → (Fin count → Index) →
   (Fin count → Fin 1176 → CByte) →
   ((Fin count → LeafTape) → (Fin count → DigestRegister) →
    MixedProgram (Raw bound) Work) → MixedProgram (Raw bound) Work
 | 0, _indices, _payloads, next => next Fin.elim0 Fin.elim0
 | count + 1, indices, payloads, next =>
   currentLeaf bound statement salt (payloads 0) (indices 0) fun tape output =>
    originalLeafBatch statement salt count (fun index => indices index.succ)
     (fun index => payloads index.succ) fun tapes outputs =>
      next (Fin.cons tape tapes) (Fin.cons output outputs)
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: originalLeafBatch"
def currentUpdates {bound : Nat} : (count : Nat) →
  (Fin count → Raw bound) → (Fin count → DigestRegister) →
   (Raw bound → DigestRegister) → Raw bound → DigestRegister
 | 0, _inputs, _outputs, oracle => oracle
 | count + 1, inputs, outputs, oracle =>
   currentUpdates count (fun index => inputs index.succ) (fun index => outputs index.succ)
    (Function.update oracle (inputs 0) (outputs 0))
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: currentUpdates"
theorem original_batch_randomized {bound : Nat}
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte)
  (count : Nat) (indices : Fin count → Index)
  (payloads : Fin count → Fin 1176 → CByte)
  (next : (Fin count → LeafTape) → (Fin count → DigestRegister) →
   MixedProgram (Raw bound) Work)
  (oracle : Raw bound → DigestRegister)
  (state : GS bound Work) :
  run true (originalLeafBatch statement salt count indices payloads next) oracle state =
   uniformAverage (fun tapes : Fin count → LeafTape =>
    uniformAverage (fun labels : Fin count → DigestRegister =>
     run true (next tapes labels)
      (currentUpdates count (fun index => .inl
       (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
        (payloads index) (indices index) (tapes index))) labels oracle) state)) := by
 induction count generalizing oracle with
 | zero =>
   have tapes : ∀ xs : Fin 0 → LeafTape, xs = Fin.elim0 := fun _ => Subsingleton.elim _ _
   have labels : ∀ xs : Fin 0 → DigestRegister, xs = Fin.elim0 := fun _ => Subsingleton.elim _ _
   simp only [originalLeafBatch, currentUpdates, tapes, labels, uniform_average_const]
 | succ count ih =>
   simp only [originalLeafBatch, currentLeaf, run, leafSampler]
   conv_rhs => rw [V8Smz9HonestLeafBatch.uniform_average_fin_cons count]
   apply congrArg uniformAverage
   funext tape
   simp_rw [ih]
   rw [uniform_average_comm]
   apply congrArg uniformAverage
   funext tapes
   conv_rhs => rw [V8Smz9HonestLeafBatch.uniform_average_fin_cons count]
   apply congrArg uniformAverage
   funext output
   apply congrArg uniformAverage
   funext outputs
   simp only [ite_true, Function.update_self, currentUpdates, Fin.cons_zero, Fin.cons_succ]
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: original_batch_randomized"
theorem current_updates_nonleaf {bound : Nat} (count : Nat)
  (inputs : Fin count → CurrentLeafInput) (labels : Fin count → DigestRegister)
  (oracle : Raw bound → DigestRegister) (input : CurrentOtherRawInput bound) :
  currentUpdates count (fun index => .inl (inputs index)) labels oracle (.inr input) = oracle (.inr input) := by
 induction count generalizing oracle with
 | zero => rfl
 | succ count ih =>
   rw [currentUpdates, ih]
   exact Function.update_of_ne (by simp) _ _
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: current_updates_nonleaf"
theorem source_nonleaf_deferral {bound : Nat} {Result : Type}
  (count : Nat) (inputs : Fin count → CurrentLeafInput) (labels : Fin count → DigestRegister)
  (program : V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) Result)
  (next : Result → MixedProgram (Raw bound) Work)
  (oracle : Raw bound → DigestRegister)
  (state : GS bound Work) :
  run true (compileNonleaf program next)
   (currentUpdates count (fun index => .inl (inputs index)) labels oracle) state =
   run true (next (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input)) program))
    (currentUpdates count (fun index => .inl (inputs index)) labels oracle) state := by
 rw [compile_nonleaf_executes]
 have same : (fun input : CurrentOtherRawInput bound =>
   currentUpdates count (fun index => .inl (inputs index)) labels oracle (.inr input)) =
    (fun input => oracle (.inr input)) := by
  funext input
  exact current_updates_nonleaf count inputs labels oracle input
 rw [same]
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: source_nonleaf_deferral"
def currentParentLevel (bound : Nat) (largeEnough : 1264811 ≤ bound) :
  (count : Nat) → (Fin (2 * count) → DigestRegister) →
   V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) (Fin count → DigestRegister)
 | 0, _labels => .done Fin.elim0
 | count + 1, labels =>
   .read (currentCounterKey bound SmallWoodTranscript.merkleNodeDomain
    (sourceDigestWords (labels ⟨0, by omega⟩) ++ sourceDigestWords (labels ⟨1, by omega⟩))
    (by
      rw [List.length_append, source_digest_word_count, source_digest_word_count]
      have role : SmallWoodTranscript.merkleNodeDomain.length = 36 := by decide
      rw [role]; omega)
    (by
      rw [List.length_append, source_digest_word_count, source_digest_word_count]
      have role : SmallWoodTranscript.merkleNodeDomain.length = 36 := by decide
      rw [role]; decide) ⟨0, by norm_num⟩) fun parent =>
    V8Smz9HonestRequestSchedule.NonleafProgram.bind
     (currentParentLevel bound largeEnough count (fun index => labels ⟨index.val + 2, by omega⟩))
     (fun parents => .done (Fin.cons parent parents))
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: currentParentLevel"
def currentMerkleLevels (bound : Nat) (largeEnough : 1264811 ≤ bound) :
  (depth : Nat) → (Fin (2 ^ depth) → DigestRegister) →
   V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) (DigestRegister × List (List DigestRegister))
 | 0, labels => .done (labels ⟨0, by norm_num⟩, [List.ofFn labels])
 | depth + 1, labels =>
   V8Smz9HonestRequestSchedule.NonleafProgram.bind
    (currentParentLevel bound largeEnough (2 ^ depth)
     (fun index => labels ⟨index.val, by simpa only [pow_succ, Nat.mul_comm] using index.isLt⟩))
    (fun parents => V8Smz9HonestRequestSchedule.NonleafProgram.bind (currentMerkleLevels bound largeEnough depth parents)
     (fun result => .done (result.1, List.ofFn labels :: result.2)))
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: currentMerkleLevels"
structure CommitPrefix where
 hashMt : DigestRegister
 gamma : RB.Gamma
 pendingFailure : Bool
 layers : List (List DigestRegister)
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: CommitPrefix"
def saltWords (salt : Fin 32 → CByte) : List Nat :=
 List.ofFn fun word : Fin 4 => decodeLE (((List.ofFn salt).drop (8 * word.val)).take 8)
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: saltWords"
def currentCommitPrefix (bound : Nat) (largeEnough : 1264811 ≤ bound)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (labels : Index → DigestRegister) : V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) CommitPrefix :=
 V8Smz9HonestRequestSchedule.NonleafProgram.bind (currentMerkleLevels bound largeEnough 23 labels) fun tree =>
  let words := saltWords salt ++ sourceDigestWords tree.1 ++ List.ofFn (fun index => (binding index).val)
  .read (currentCounterKey bound SmallWoodTranscript.merkleRootDomain words
   (by
     simp only [words, saltWords, List.length_append, List.length_ofFn, source_digest_word_count]
     have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
     rw [role]; omega)
   (by
     simp only [words, saltWords, List.length_append, List.length_ofFn, source_digest_word_count]
     have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
     rw [role]; decide) ⟨0, by norm_num⟩) fun hashMt =>
   V8Smz9HonestRequestSchedule.NonleafProgram.bind
    (currentFieldXof bound SmallWoodTranscript.decsCoefficientDomain (sourceDigestWords hashMt)
     (by
       rw [source_digest_word_count]
       have role : SmallWoodTranscript.decsCoefficientDomain.length = 41 := by decide
       rw [role]; omega)
     (by
       rw [source_digest_word_count]
       have role : SmallWoodTranscript.decsCoefficientDomain.length = 41 := by decide
       rw [role]; decide) 700 (by norm_num)) fun sampled =>
     .done ⟨hashMt, (fun repetition row =>
      ((sourceReturnedWords 700 sampled).getD (repetition.val * 140 + row.val) 0).val),
       sourcePendingFailure false sampled, tree.2⟩
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: currentCommitPrefix"
def actualTranscript (relation : PublicRelation) (values : RB.CurrentValues)
  (coins : OriginalCoins) («prefix» : PiopPrefix) : Q :=
 (fun repetition => NativePrivateSpendQ58CurrentPublicOpening.nonlinearResponse relation
  (prefixGamma «prefix» repetition) (sourceWitness values coins.1) (coins.2.1.1 repetition),
 fun repetition => NativePrivateSpendQ58CurrentPublicOpening.linearResponse relation
  (prefixGamma «prefix» repetition) (sourceWitness values coins.1) (coins.2.1.2 repetition))
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: actualTranscript"
def actualDecsReply (values : RB.CurrentValues)
  (coins : OriginalCoins) («prefix» : CommitPrefix) : D :=
 NativePrivateSpendQ58CurrentPublicOpening.sourceDecsResponse (originalHeads values coins)
  coins.2.2.2.1 «prefix».gamma coins.2.2.2.2
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: actualDecsReply"
def originalAfterSelection {bound : Nat} (descriptor : Descriptor)
  (values : RB.CurrentValues) (coins : OriginalCoins)
  (_statement : Fin 616 → CByte)
  (_salt : Fin 32 → CByte)
  (tapes : Index → LeafTape) (_labels : Index → DigestRegister)
  (reply : D) («prefix» : PiopPrefix) (transcript : Q) (digest : DigestRegister)
  (nonce : Fin 16) (points : Fin 6 → Goldilocks)
  (fields : NativePrivateSpendQ58CurrentPublicOpening.PublicFields)
  (selection : DecsSelection)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 match selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates) with
 | none => next (.error "fixed DECS sampler exhausted its candidate pool")
 | some selected =>
   let targets := selectedTargets descriptor selected
   let earlier := OC.earlier points coins.2.2.2.1
   let later := OC.fullSubset
    (originalHeads values coins) targets.val coins.2.2.2.1
   next (scopeReturn selection.pendingFailure (.ok ⟨reply, «prefix», transcript, digest, nonce,
    points, fields, earlier, later, selected.val, fun opening => tapes (selected.val opening)⟩))
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: originalAfterSelection"
def originalAfterOpening {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation)
  (values : RB.CurrentValues) (coins : OriginalCoins)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte)
  (tapes : Index → LeafTape) (labels : Index → DigestRegister)
  (reply : D) («prefix» : PiopPrefix) (transcript : Q) (digest : DigestRegister)
  (choice : OpeningChoice)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 match choice.selected with
 | none => next (.error "smallwood opening nonce trial limit exhausted")
 | some (nonce, words) =>
   let points := sourcePointVector words
   let fields := NativePrivateSpendQ58CurrentPublicOpening.sourceFields relation
    (prefixGamma «prefix») (originalData values coins) points
   let earlier := OC.earlier points coins.2.2.2.1
   let heads := OC.combinationHeads points
    (originalHeads values coins)
   compileNonleaf (currentDecsSelection bound largeEnough digest heads earlier choice.pendingFailure)
    (fun selection => originalAfterSelection descriptor values coins statement salt tapes labels
     reply «prefix» transcript digest nonce points fields selection next)
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: originalAfterOpening"
def originalAfterCommit {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation)
  (values : RB.CurrentValues) (coins : OriginalCoins)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (tapes : Index → LeafTape) (labels : Index → DigestRegister) (commit : CommitPrefix)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 let reply := actualDecsReply values coins commit
 compileNonleaf (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure) fun «prefix» =>
  let transcript := actualTranscript relation values coins «prefix»
  .honestRead (.inr (finalKey bound (by omega) (sourceDigestPrefix «prefix».hashFpp) transcript)) fun digest =>
   compileNonleaf (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
    (fun choice => originalAfterOpening largeEnough descriptor relation values coins statement salt
     tapes labels reply «prefix» transcript digest choice next)
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: originalAfterCommit"
def originalRequest {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (relation : PublicRelation) (values : RB.CurrentValues)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (next : Option ((Index → DigestRegister) × CommitPrefix) →
   Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 match currentDescriptor with
 | none => next none (.error "smallwood strict-ZK DECS coset search exhausted")
 | some descriptor =>
   .random originalCoinSource fun coins =>
    originalLeafBatch statement salt 8388608 id (originalPayload descriptor values coins) fun tapes labels =>
     compileNonleaf (currentCommitPrefix bound largeEnough salt binding labels) fun commit =>
      originalAfterCommit largeEnough descriptor relation values coins statement salt binding
       tapes labels commit (next (some (labels, commit)))
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: originalRequest"
theorem protected_original_source_expansion {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (constructed : currentDescriptor = some descriptor)
  (relation : PublicRelation) (values : RB.CurrentValues)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (next : Option ((Index → DigestRegister) × CommitPrefix) →
   Except String PublicResult → MixedProgram (Raw bound) Work)
  (oracle : Raw bound → DigestRegister)
  (state : GS bound Work) :
  run true (originalRequest largeEnough relation values statement salt binding next) oracle state =
   uniformAverage (fun coins : OriginalCoins =>
    uniformAverage (fun tapes : Index → LeafTape =>
     uniformAverage (fun labels : Index → DigestRegister =>
      run true (originalAfterCommit largeEnough descriptor relation values coins statement salt binding
       tapes labels (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
        (currentCommitPrefix bound largeEnough salt binding labels))
       (next (some (labels, V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
        (currentCommitPrefix bound largeEnough salt binding labels)))))
       (currentUpdates 8388608 (fun index => .inl
        (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
         (originalPayload descriptor values coins index) index (tapes index))) labels oracle) state))) := by
 simp only [originalRequest, constructed, originalCoinSource]
 rw [run]
 apply congrArg uniformAverage
 funext coins
 rw [original_batch_randomized]
 apply congrArg uniformAverage
 funext tapes
 apply congrArg uniformAverage
 funext labels
 exact source_nonleaf_deferral 8388608 _ labels _ _ oracle state
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: protected_original_source_expansion"
def frozenCaller {bound : Nat} (futureMode : Bool)
  (caller : Except String PublicResult → MixedProgram (Raw bound) Work)
  (outcome : Except String PublicResult) : MixedProgram (Raw bound) Work :=
 fixedProgram futureMode (compile (caller outcome) [])
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: frozenCaller"
theorem frozen_caller_executes {bound : Nat} (requestMode futureMode : Bool)
  (caller : Except String PublicResult → MixedProgram (Raw bound) Work)
  (outcome : Except String PublicResult) (oracle : Raw bound → DigestRegister)
  (state : GS bound Work) :
  run requestMode (frozenCaller futureMode caller outcome) oracle state =
   run futureMode (caller outcome) oracle state := by
 rw [frozenCaller, fixed_program_execution, compile_executes, effective_empty]
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: frozen_caller_executes"
theorem fixed_future_mass {bound : Nat} (future : Bool)
  (program : V8Smz9HonestWholeViewGames.Program (Raw bound) Work) (cap : ℝ≥0∞) :
  InputMassAtMost cap (fixedProgram future program) := by
 induction program with
 | finish _ => trivial
 | gate _ _ ih => exact ih
 | quantumQuery _ ih => exact ih
 | honestRead _ _ ih => exact ih
 | instrument _ _ ih => exact ih
 | random _ _ ih => exact ih
 | freshInput _ _ ih =>
   cases future <;> simp only [fixedProgram, Bool.false_eq_true, if_false, if_true,
    sampledRead, fixedFresh, InputMassAtMost] <;> exact ih
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: fixed_future_mass"
theorem original_batch_mass {bound : Nat}
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (count : Nat) (indices : Fin count → Index) (payloads : Fin count → Fin 1176 → CByte)
  (next : (Fin count → LeafTape) → (Fin count → DigestRegister) → MixedProgram (Raw bound) Work)
  (remaining : ∀ tapes labels, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next tapes labels)) :
  InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (originalLeafBatch statement salt count indices payloads next) := by
 induction count with
 | zero => exact remaining _ _
 | succ count ih =>
   apply current_leaf_preserves_mass
   intro tape label
   exact ih _ _ _ (fun tapes labels => remaining _ _)
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: original_batch_mass"
theorem original_request_mass {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (relation : PublicRelation) (values : RB.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (next : Option ((Index → DigestRegister) × CommitPrefix) → Except String PublicResult → MixedProgram (Raw bound) Work)
  (remaining : ∀ context result, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next context result)) :
  InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
   (originalRequest largeEnough relation values statement salt binding next) := by
  unfold originalRequest
  split
  · exact remaining _ _
  ·
    rename_i descriptor descriptorCase
    intro coins
    change OriginalCoins at coins
    have openingMass (tapes : Index → LeafTape) (labels : Index → DigestRegister)
        (commit : CommitPrefix) (reply : D) («prefix» : PiopPrefix) (transcript : Q)
        (digest : DigestRegister) (choice : OpeningChoice) :
        InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
          (originalAfterOpening largeEnough descriptor relation values coins statement salt
            tapes labels reply «prefix» transcript digest choice (next (some (labels, commit)))) := by
      rcases choice with ⟨selectedChoice, pendingFailure⟩
      cases selectedChoice with
      | none =>
          dsimp only [originalAfterOpening]
          exact remaining (some (labels, commit)) (.error "smallwood opening nonce trial limit exhausted")
      | some selectedValue =>
          rcases selectedValue with ⟨nonce, words⟩
          dsimp only [originalAfterOpening]
          with_reducible
            exact compile_nonleaf_mass (Work := Work) (bound := bound) (Result := DecsSelection)
              (currentDecsSelection bound largeEnough digest
                (OC.combinationHeads (sourcePointVector words) (originalHeads values coins))
                (OC.earlier (sourcePointVector words) coins.2.2.2.1) pendingFailure)
              (fun selection => originalAfterSelection descriptor values coins statement salt
                tapes labels reply «prefix» transcript digest nonce (sourcePointVector words)
                (NativePrivateSpendQ58CurrentPublicOpening.sourceFields relation
                  (prefixGamma «prefix») (originalData values coins) (sourcePointVector words))
                selection (next (some (labels, commit))))
              (fun selection => by
                unfold originalAfterSelection
                split <;> exact remaining _ _)
    let commitContinuation (tapes : Index → LeafTape) (labels : Index → DigestRegister)
        (commit : CommitPrefix) : MixedProgram (Raw bound) Work :=
      originalAfterCommit largeEnough descriptor relation values coins statement salt binding
        tapes labels commit (next (some (labels, commit)))
    have commitMass (tapes : Index → LeafTape) (labels : Index → DigestRegister)
        (commit : CommitPrefix) :
        InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (commitContinuation tapes labels commit) := by
      dsimp only [commitContinuation, originalAfterCommit]
      with_reducible
        exact compile_nonleaf_mass (Work := Work) (bound := bound) (Result := PiopPrefix)
          (piopPrefix bound (by omega) commit.hashMt binding
            (actualDecsReply values coins commit) commit.pendingFailure)
          (fun «prefix» => .honestRead
            (.inr (finalKey bound (by omega) (sourceDigestPrefix «prefix».hashFpp)
              (actualTranscript relation values coins «prefix»)))
            (fun digest => compileNonleaf
              (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
              (fun choice => originalAfterOpening largeEnough descriptor relation values coins
                statement salt tapes labels (actualDecsReply values coins commit) «prefix»
                (actualTranscript relation values coins «prefix») digest choice
                (next (some (labels, commit))))))
          (fun «prefix» => by
            unfold InputMassAtMost
            change ∀ digest : DigestRegister, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
              (compileNonleaf
                (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
                (fun choice => originalAfterOpening largeEnough descriptor relation values coins
                  statement salt tapes labels (actualDecsReply values coins commit) «prefix»
                  (actualTranscript relation values coins «prefix») digest choice
                  (next (some (labels, commit)))))
            intro digest
            with_reducible
              exact compile_nonleaf_mass (Work := Work) (bound := bound) (Result := OpeningChoice)
                (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
                (fun choice => originalAfterOpening largeEnough descriptor relation values coins
                  statement salt tapes labels (actualDecsReply values coins commit) «prefix»
                  (actualTranscript relation values coins «prefix») digest choice
                  (next (some (labels, commit))))
                (openingMass tapes labels commit (actualDecsReply values coins commit) «prefix»
                  (actualTranscript relation values coins «prefix») digest))
    have leafContinuationMass (tapes : Index → LeafTape) (labels : Index → DigestRegister) :
        InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
          (compileNonleaf (currentCommitPrefix bound largeEnough salt binding labels)
            (commitContinuation tapes labels)) := by
      with_reducible
        exact compile_nonleaf_mass (Work := Work) (bound := bound) (Result := CommitPrefix)
          (currentCommitPrefix bound largeEnough salt binding labels)
          (commitContinuation tapes labels) (commitMass tapes labels)
    with_reducible
      exact original_batch_mass (Work := Work) (bound := bound)
        statement salt 8388608 id (originalPayload descriptor values coins)
        (fun tapes labels => compileNonleaf
          (currentCommitPrefix bound largeEnough salt binding labels)
          (commitContinuation tapes labels))
        leafContinuationMass
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_DONE: original_request_mass"
#eval IO.eprintln "ORIGINAL_REQUEST_DECL_EOF"
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOriginalRequest
