import HegemonCrypto.NativePrivateSpendQ58CurrentOpeningFiber
import Q38OpenedTapeConditioningR5
import Lean.Elab.Tactic
import Lean.Meta.Sym.AlphaShareCommon
import Lean.Util.Sorry
namespace Lean.Elab.Tactic.Q58AlphaShare
open Lean Meta Elab Tactic

private def sharePair (target proof : Expr) : Expr × Expr :=
  let action : Lean.Meta.Sym.AlphaShareCommonM (Expr × Expr) := do
    let target ← Lean.Meta.Sym.shareCommonAlpha target
    let proof ← Lean.Meta.Sym.shareCommonAlpha proof
    pure (target, proof)
  action.run' {}

elab "q58_alpha_share" body:tacticSeq : tactic => withMainContext do
  let originalGoals ← getGoals
  let goal ← getMainGoal
  let saved ← saveState
  try
    let target ← goal.getType
    let temporary ← mkFreshExprMVar (some target) .syntheticOpaque
    setGoals [temporary.mvarId!]
    withoutRecover <| evalTactic body
    unless (← getUnsolvedGoals).isEmpty do
      throwError "q58_alpha_share: the unchanged proof left unsolved goals"
    Term.synthesizeSyntheticMVarsNoPostponing
    let target ← instantiateMVars target
    let proof ← instantiateMVars temporary
    if target.hasMVar || proof.hasMVar then
      throwError "q58_alpha_share: residual expression or level metavariables"
    if proof.hasSorry then
      throwError "q58_alpha_share: sorry is forbidden"
    let (_, sharedProof) := sharePair target proof
    setGoals originalGoals
    closeMainGoal `q58_alpha_share sharedProof
  catch ex =>
    let messages ← Core.getMessageLog
    saved.restore
    Core.setMessageLog messages
    throw ex
elab "q58_default_bridge" body:tacticSeq : tactic =>
  Lean.Meta.withTransparency .default (Lean.Elab.Tactic.evalTactic body)

end Lean.Elab.Tactic.Q58AlphaShare

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCompletePublicJoin
open V8Smz9CurrentPrivacyGame
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9HiddenLeafQrom
open V8Smz9CurrentPrivacyComposition V8Smz9HonestOpeningSchedule V8Smz9MixedMaskCompiler
open V8Smz9HiddenPatch V8Smz9MeasuredOracleHybrid
open NativePrivateSpendQ58CurrentLeafInput NativePrivateSpendQ58CurrentSelectedLeaf
open NativePrivateSpendQ58CurrentChronologicalRequest NativePrivateSpendQ58CurrentCosetSelector
open NativePrivateSpendQ58CurrentCoinObservation NativePrivateSpendQ58CurrentInitializedPublic
open NativePrivateSpendQ58CurrentOriginalRequest NativePrivateSpendQ58CurrentOpeningFiber
open NativePrivateSpendQ58CurrentLeafErasure
open scoped Classical ENNReal
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option stderrAsMessages false
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: CByte"
abbrev CByte := HegemonCrypto.CanonicalBytes.Byte
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: Raw"
abbrev Raw (bound : Nat) := CurrentFullRawInput bound
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: GS"
abbrev GS (bound : Nat) (Work : Type) [Fintype Work] :=
 V8Smz9HonestWholeViewGames.GameState (Input := Raw bound) (Work := Work)
variable {Work : Type} [Fintype Work]
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: FullTapes"
abbrev FullTapes := Index → LeafTape
private def functionRandomSource (A B : Type) [decA : DecidableEq A]
    [finA : Fintype A] [finB : Fintype B] [nonemptyB : Nonempty B] :
    V8Smz9HonestWholeViewGames.RandomSource where
 Coins := A → B
 finite := @Pi.instFintype A (fun _ : A => B) decA finA (fun _ : A => finB)
 inhabited := ⟨fun _ : A => Classical.choice nonemptyB⟩
private theorem double_average_congr {A B : Type*} [Fintype A] [Nonempty A]
  [Fintype B] [Nonempty B] (left right : A → B → ℝ)
  (same : ∀ a b, left a b = right a b) :
  uniformAverage (fun a : A => uniformAverage (fun b : B => left a b)) =
   uniformAverage (fun a : A => uniformAverage (fun b : B => right a b)) := by
 apply congrArg uniformAverage
 funext a
 apply congrArg uniformAverage
 funext b
 exact same a b
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: publicTranscriptSource"
def publicTranscriptSource : V8Smz9HonestWholeViewGames.RandomSource where
 Coins := Q
 finite := inferInstance
 inhabited := inferInstance
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: publicFullTapeSource"
def publicFullTapeSource : V8Smz9HonestWholeViewGames.RandomSource where
 Coins := FullTapes
 finite := inferInstance
 inhabited := inferInstance
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: originalResponse"
def originalResponse {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (oracle : Raw bound → DigestRegister) (relation : PublicRelation)
  (values : B.CurrentValues) (binding : Fin 77 → Goldilocks) (commit : CommitPrefix)
  (coins : OriginalCoins) : Response :=
 sourceResponse bound (by omega) oracle relation values commit.hashMt binding commit.gamma
  commit.pendingFailure (coins.1, coins.2.2.1, coins.2.2.2.1) (coins.2.1, coins.2.2.2.2)
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: original_response_is_mask_stage"
theorem original_response_is_mask_stage {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (oracle : Raw bound → DigestRegister) (relation : PublicRelation)
  (values : B.CurrentValues) (binding : Fin 77 → Goldilocks) (commit : CommitPrefix)
  (coins : OriginalCoins) :
  originalResponse largeEnough oracle relation values binding commit coins =
   (B.maskStage (currentSourceModel bound (by omega) oracle relation values commit.hashMt
    binding commit.gamma commit.pendingFailure) coins).1 := by
 exact source_response_is_mask_forward bound (by omega) oracle relation values commit.hashMt
  binding commit.gamma commit.pendingFailure _ _
private theorem original_response_is_actual_tuple {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (old : Raw bound → DigestRegister) (relation : PublicRelation) (values : B.CurrentValues)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (coins : OriginalCoins) :
  originalResponse largeEnough old relation values binding commit coins =
   (actualDecsReply values coins commit,
    actualTranscript relation values coins
     (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
      (piopPrefix bound (by omega) commit.hashMt binding (actualDecsReply values coins commit)
       commit.pendingFailure))) := by
 with_reducible
  dsimp only [originalResponse, sourceResponse, actualDecsReply, actualTranscript,
   originalHeads, originalData]
private abbrev responsePrefixValue {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix)
  (old : Raw bound → DigestRegister)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) : PiopPrefix :=
 V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
  (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure)
private abbrev responseDigestValue {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (old : Raw bound → DigestRegister) («prefix» : PiopPrefix) (transcript : Q) : DigestRegister :=
 old (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
  (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript))
private abbrev responseChoiceValue {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (old : Raw bound → DigestRegister) («prefix» : PiopPrefix) (digest : DigestRegister) : OpeningChoice :=
 V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
  (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
private structure CertifiedOpeningValues where
 reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse
 prefixValue : PiopPrefix
 transcript : Q
 digest : DigestRegister
 choice : OpeningChoice

private def literalOpening {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (old : Raw bound → DigestRegister) (relation : PublicRelation) (values : B.CurrentValues)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (coins : OriginalCoins) :
  CertifiedOpeningValues :=
 let reply := actualDecsReply values coins commit
 let pref := responsePrefixValue largeEnough binding commit old reply
 let transcript := actualTranscript relation values coins pref
 let digest := responseDigestValue largeEnough old pref transcript
 let choice := responseChoiceValue largeEnough old pref digest
 ⟨reply, pref, transcript, digest, choice⟩

private opaque certifiedOpening {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (old : Raw bound → DigestRegister) (relation : PublicRelation) (values : B.CurrentValues)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (coins : OriginalCoins) :
  { computed : CertifiedOpeningValues //
    computed = literalOpening largeEnough old relation values binding commit coins } :=
 ⟨literalOpening largeEnough old relation values binding commit coins, rfl⟩

private def choiceSourceScalar {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) (coins : OriginalCoins) (tapes : FullTapes)
  (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (choice : OpeningChoice) : ℝ :=
    match choice.selected with
    | none => run randomized (next (.error "smallwood opening nonce trial limit exhausted")) old state
    | some (nonce, words) => run randomized
      (sourceOpeningFiber largeEnough descriptor relation values statement salt binding commit response
       «prefix» digest nonce (sourcePointVector words) choice.pendingFailure labels tapes
       (coins.1, coins.2.2.1) coins.2.2.2.1 old next) old state
private theorem choiceSourceScalar_unfold {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) (coins : OriginalCoins) (tapes : FullTapes)
  (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (choice : OpeningChoice) :
  choiceSourceScalar largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes response «prefix» digest choice =
  (match choice.selected with
    | none => run randomized (next (.error "smallwood opening nonce trial limit exhausted")) old state
    | some (nonce, words) => run randomized
      (sourceOpeningFiber largeEnough descriptor relation values statement salt binding commit response
       «prefix» digest nonce (sourcePointVector words) choice.pendingFailure labels tapes
       (coins.1, coins.2.2.1) coins.2.2.2.1 old next) old state) := by
 unfold choiceSourceScalar
 rfl

private def selected_frame_right_value {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) : OriginalCoins → FullTapes → ℝ :=
  fun coins : OriginalCoins => fun tapes : FullTapes =>
    let response := originalResponse largeEnough old relation values binding commit coins
    let «prefix» := responsePrefixValue largeEnough binding commit old response.1
    let digest := responseDigestValue largeEnough old «prefix» response.2
    let choice := responseChoiceValue largeEnough old «prefix» digest
    choiceSourceScalar largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes response «prefix» digest choice
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: clearedSourceValue"
def clearedSourceValue {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (oracle : Raw bound → DigestRegister)
  (state : GS bound Work) : ℝ :=
 uniformAverage (fun coins : OriginalCoins => uniformAverage (fun tapes : FullTapes =>
  selected_frame_right_value largeEnough descriptor relation values statement salt binding commit labels
   next randomized oracle state coins tapes))
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: clearedPublicAfterDecs"
def clearedPublicAfterDecs {bound : Nat} (descriptor : Descriptor) (relation : PublicRelation)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (commit : CommitPrefix)
  (labels : Index → DigestRegister) (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks)
  (distinct : Function.Injective points) (fields : O.PublicFields)
  (earlier : CurrentEarlier) (selection : DecsSelection)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 match selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates) with
 | none => next (.error "fixed DECS sampler exhausted its candidate pool")
 | some selected =>
   .random publicLaterSource fun later => .random publicFullTapeSource fun tapes =>
    let targets := selectedTargets descriptor selected
    let visible := fun opening => tapes (selected.val opening)
    selectedWrites
     (publicSelectedLeaves statement salt response.1 commit.gamma points distinct
      (O.publicHeads relation fields points) earlier later targets.val selected.val visible)
     (fun opening => labels (selected.val opening))
     (next (scopeReturn selection.pendingFailure (.ok ⟨response.1, «prefix», response.2, digest,
      nonce, points, fields, earlier, later, selected.val, visible⟩)))
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: clearedPublicAfterOpening"
def clearedPublicAfterOpening {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (commit : CommitPrefix)
  (labels : Index → DigestRegister) (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (choice : OpeningChoice)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 match choice.selected with
 | none => next (.error "smallwood opening nonce trial limit exhausted")
 | some (nonce, words) =>
   if accepted : currentOpeningAdmissible (sourcePointVector words) then
    .random publicScalarSource fun observed =>
     let fields := observedPublicFields (prefixGamma «prefix») response.2 observed
     .random publicEarlierSource fun earlier =>
      compileNonleaf (currentDecsSelection bound largeEnough digest
       (O.publicHeads relation fields (sourcePointVector words)) earlier choice.pendingFailure)
       (fun selection => clearedPublicAfterDecs descriptor relation statement salt commit labels
        response «prefix» digest nonce (sourcePointVector words) accepted.1 fields earlier selection next)
   else next (.error "smallwood opening nonce trial limit exhausted")
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: clearedPublicRequest"
def clearedPublicRequest {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 .random publicReplySource fun reply =>
  compileNonleaf (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure) fun «prefix» =>
   .random publicTranscriptSource fun transcript =>
    .honestRead (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega) (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript)) fun digest =>
     compileNonleaf (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
      (fun choice => clearedPublicAfterOpening largeEnough descriptor relation statement salt commit
       labels (reply, transcript) «prefix» digest choice next)
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: public_opening_value_is_fiber_average"
theorem public_opening_value_is_fiber_average {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (commit : CommitPrefix)
  (labels : Index → DigestRegister) (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (choice : OpeningChoice) (nonce : Fin 16) (words : List FieldWord)
  (selected : choice.selected = some (nonce, words))
  (accepted : currentOpeningAdmissible (sourcePointVector words))
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (oracle : Raw bound → DigestRegister)
  (state : GS bound Work) :
  run randomized (clearedPublicAfterOpening largeEnough descriptor relation statement salt commit labels
   response «prefix» digest choice next) oracle state =
  uniformAverage (fun tapes : FullTapes => uniformAverage (fun observed : Original =>
   uniformAverage (fun earlier : CurrentEarlier => uniformAverage (fun later : CurrentLater =>
    run randomized (publicOpeningFiber largeEnough descriptor relation statement salt commit response
     «prefix» digest nonce (sourcePointVector words) accepted.1 choice.pendingFailure labels tapes
     observed earlier later oracle next) oracle state)))) := by
 have distinct : Function.Injective (sourcePointVector words) := accepted.1
 let publicView : Original → CurrentEarlier → FullTapes → CurrentLater → ℝ :=
  fun observed earlier tapes later =>
   run randomized (publicOpeningFiber largeEnough descriptor relation statement salt commit response
    «prefix» digest nonce (sourcePointVector words) distinct choice.pendingFailure labels tapes
    observed earlier later oracle next) oracle state
 with_reducible
  unfold clearedPublicAfterOpening
  simp only [selected, dif_pos accepted, V8Smz9MixedMaskCompiler.run, publicScalarSource, publicEarlierSource,
   compile_nonleaf_executes]
  calc
   _ = uniformAverage (fun observed : Original => uniformAverage (fun earlier : CurrentEarlier =>
    uniformAverage (fun tapes : FullTapes => uniformAverage (publicView observed earlier tapes)))) := by
    apply congrArg uniformAverage
    funext observed
    apply congrArg uniformAverage
    funext earlier
    dsimp only [publicView]
    let selection := actualPublicSelection largeEnough oracle relation «prefix» response digest
     (sourcePointVector words) choice.pendingFailure observed earlier
    cases sampledCase : selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates) with
    | none =>
      dsimp only [selection, actualPublicSelection] at sampledCase
      simp only [clearedPublicAfterDecs, publicOpeningFiber, actualPublicSelection, sampledCase]
      let k : ℝ := V8Smz9MixedMaskCompiler.run randomized
       (next (.error "fixed DECS sampler exhausted its candidate pool")) oracle state
      change k = uniformAverage (fun _ : FullTapes => uniformAverage (fun _ : CurrentLater => k))
      exact ((congrArg (fun value : ℝ => uniformAverage (fun _ : FullTapes => value))
       (uniform_average_const (A := CurrentLater) k)).trans
        (uniform_average_const (A := FullTapes) k)).symm
    | some certificate =>
      dsimp only [selection, actualPublicSelection] at sampledCase
      simp only [clearedPublicAfterDecs, publicOpeningFiber, actualPublicSelection, sampledCase,
       V8Smz9MixedMaskCompiler.run, publicLaterSource, publicFullTapeSource]
      simpa only [publicView, publicOpeningFiber, actualPublicSelection, sampledCase] using
       (uniform_average_comm
        (fun (later : CurrentLater) (tapes : FullTapes) => publicView observed earlier tapes later))
   _ = uniformAverage (fun observed : Original => uniformAverage (fun tapes : FullTapes =>
    uniformAverage (fun earlier : CurrentEarlier => uniformAverage (publicView observed earlier tapes)))) := by
    apply congrArg uniformAverage
    funext observed
    exact uniform_average_comm
     (fun (earlier : CurrentEarlier) (tapes : FullTapes) => uniformAverage (publicView observed earlier tapes))
   _ = _ := uniform_average_comm
    (fun (observed : Original) (tapes : FullTapes) =>
     uniformAverage (fun earlier : CurrentEarlier => uniformAverage (publicView observed earlier tapes)))
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: cleared_source_game_is_public"
theorem cleared_source_game_is_public {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (valid : O.Satisfies relation values)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (oracle : Raw bound → DigestRegister)
  (state : GS bound Work) :
  clearedSourceValue largeEnough descriptor relation values statement salt binding commit labels
   next randomized oracle state =
  run randomized (clearedPublicRequest largeEnough descriptor relation statement salt binding commit labels next)
   oracle state := by
 let model := currentSourceModel bound (by omega) oracle relation values commit.hashMt
  binding commit.gamma commit.pendingFailure
 let sourceView : OriginalCoins → FullTapes → ℝ := fun coins tapes =>
  let response := originalResponse largeEnough oracle relation values binding commit coins
  let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
   (piopPrefix bound (by omega) commit.hashMt binding response.1 commit.pendingFailure)
  let digest := oracle (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega) (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) response.2))
  let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
   (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
  match choice.selected with
  | none => run randomized (next (.error "smallwood opening nonce trial limit exhausted")) oracle state
  | some (nonce, words) => run randomized
    (sourceOpeningFiber largeEnough descriptor relation values statement salt binding commit response
     «prefix» digest nonce (sourcePointVector words) choice.pendingFailure labels tapes
     (coins.1, coins.2.2.1) coins.2.2.2.1 oracle next) oracle state
 have sourceWitnessProjection (response : Response) (source : Original × Tail) :
   ((B.maskStage model).symm (response, source)).1 = source.1.1 := rfl
 have sourcePcsProjection (response : Response) (source : Original × Tail) :
   ((B.maskStage model).symm (response, source)).2.2.1 = source.1.2 := rfl
 have sourceTailProjection (response : Response) (source : Original × Tail) :
   ((B.maskStage model).symm (response, source)).2.2.2.1 = source.2 := rfl
 have responseRoundtrip (response : Response) (source : Original × Tail) :
   originalResponse largeEnough oracle relation values binding commit
    ((B.maskStage model).symm (response, source)) = response :=
  (original_response_is_mask_stage largeEnough oracle relation values binding commit
   ((B.maskStage model).symm (response, source))).trans
    (congrArg (fun pair : Response × (Original × Tail) => pair.1)
     ((B.maskStage model).apply_symm_apply (response, source)))
 have rhsProduct := @V8Smz9HonestLeafBatch.uniform_average_product
  NativePrivateSpendQ58CurrentRowBoundary.D NativePrivateSpendQ58CurrentRowBoundary.Q
  NativePrivateSpendQ58CurrentInitializedPublic.publicReplySource.finite
  NativePrivateSpendQ58CurrentInitializedPublic.publicReplySource.inhabited
  NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource.finite
  NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource.inhabited
  (fun (reply : NativePrivateSpendQ58CurrentRowBoundary.D)
    (transcript : NativePrivateSpendQ58CurrentRowBoundary.Q) =>
   let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
    (fun input => oracle (.inr input))
    (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure)
   let digest := oracle (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
    (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript))
   let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
    (fun input => oracle (.inr input))
    (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
   run randomized (clearedPublicAfterOpening largeEnough descriptor relation statement salt commit
    labels (reply, transcript) «prefix» digest choice next) oracle state)
 dsimp only [NativePrivateSpendQ58CurrentInitializedPublic.publicReplySource,
  NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource] at rhsProduct
 have randomExec (source : V8Smz9HonestWholeViewGames.RandomSource)
   (continuation : source.Coins → MixedProgram (Raw bound) Work) :
   run randomized (.random source continuation) oracle state =
    @uniformAverage source.Coins source.finite source.inhabited
     (fun coins : source.Coins => run randomized (continuation coins) oracle state) := by
  rfl
 have readExec (input : CurrentOtherRawInput bound)
   (continuation : DigestRegister → MixedProgram (Raw bound) Work) :
   run randomized (.honestRead (.inr input) continuation) oracle state =
    run randomized (continuation (oracle (.inr input))) oracle state := by
  rfl
 let afterChoice (reply : NativePrivateSpendQ58CurrentRowBoundary.D)
   («prefix» : PiopPrefix) (transcript : NativePrivateSpendQ58CurrentRowBoundary.Q)
   (digest : DigestRegister) : OpeningChoice → MixedProgram (Raw bound) Work := fun choice =>
  clearedPublicAfterOpening largeEnough descriptor relation statement salt commit labels
   (reply, transcript) «prefix» digest choice next
 let afterRead (reply : NativePrivateSpendQ58CurrentRowBoundary.D)
   («prefix» : PiopPrefix) (transcript : NativePrivateSpendQ58CurrentRowBoundary.Q) :
   DigestRegister → MixedProgram (Raw bound) Work := fun digest =>
  compileNonleaf (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
   (afterChoice reply «prefix» transcript digest)
 let afterPiop (reply : NativePrivateSpendQ58CurrentRowBoundary.D) :
   PiopPrefix → MixedProgram (Raw bound) Work := fun «prefix» =>
  .random NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource fun transcript =>
   .honestRead (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
    (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript))
    (afterRead reply «prefix» transcript)
 have requestExec :
   run randomized (clearedPublicRequest largeEnough descriptor relation statement salt binding commit labels next)
    oracle state =
   @uniformAverage NativePrivateSpendQ58CurrentRowBoundary.D
    NativePrivateSpendQ58CurrentInitializedPublic.publicReplySource.finite
    NativePrivateSpendQ58CurrentInitializedPublic.publicReplySource.inhabited
    (fun reply : NativePrivateSpendQ58CurrentRowBoundary.D =>
     @uniformAverage NativePrivateSpendQ58CurrentRowBoundary.Q
      NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource.finite
      NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource.inhabited
      (fun transcript : NativePrivateSpendQ58CurrentRowBoundary.Q =>
       let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
        (fun input => oracle (.inr input))
        (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure)
       let digest := oracle (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
        (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript))
       let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
        (fun input => oracle (.inr input))
        (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
       run randomized (clearedPublicAfterOpening largeEnough descriptor relation statement salt commit
        labels (reply, transcript) «prefix» digest choice next) oracle state)) := by
  delta clearedPublicRequest
  rewrite [randomExec NativePrivateSpendQ58CurrentInitializedPublic.publicReplySource
   (fun reply => compileNonleaf
    (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure) (afterPiop reply))]
  apply congrArg (@uniformAverage NativePrivateSpendQ58CurrentRowBoundary.D
   NativePrivateSpendQ58CurrentInitializedPublic.publicReplySource.finite
   NativePrivateSpendQ58CurrentInitializedPublic.publicReplySource.inhabited)
  funext reply
  let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
   (fun input => oracle (.inr input))
   (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure)
  rewrite [compile_nonleaf_executes randomized
   (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure)
   (afterPiop reply) oracle state]
  dsimp only [afterPiop]
  rewrite [randomExec NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource
   (fun transcript => .honestRead
    (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
     (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript))
    (afterRead reply «prefix» transcript))]
  apply congrArg (@uniformAverage NativePrivateSpendQ58CurrentRowBoundary.Q
   NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource.finite
   NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource.inhabited)
  funext transcript
  let digest := oracle (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
   (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript))
  rewrite [readExec (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
   (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript)
   (afterRead reply «prefix» transcript)]
  dsimp only [afterRead]
  exact compile_nonleaf_executes randomized
   (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
   (afterChoice reply «prefix» transcript digest) oracle state
 dsimp only [NativePrivateSpendQ58CurrentInitializedPublic.publicReplySource,
  NativePrivateSpendQ58CurrentCompletePublicJoin.publicTranscriptSource] at requestExec
 have responseAverageCongr (leftFinite rightFinite : Fintype Response)
   (leftNonempty rightNonempty : Nonempty Response) (left right : Response → ℝ)
   (same : ∀ response, left response = right response) :
   @uniformAverage Response leftFinite leftNonempty left =
    @uniformAverage Response rightFinite rightNonempty right := by
  have finiteEq : leftFinite = rightFinite := Subsingleton.elim _ _
  have inhabitedEq : leftNonempty = rightNonempty := Subsingleton.elim _ _
  cases finiteEq
  cases inhabitedEq
  exact congrArg (@uniformAverage Response leftFinite leftNonempty) (funext same)
 with_reducible
  unfold clearedSourceValue selected_frame_right_value choiceSourceScalar
  change uniformAverage (fun coins : OriginalCoins => uniformAverage (sourceView coins)) = _
  rewrite [← uniform_average_equiv (B.maskStage model).symm
   (fun coins : OriginalCoins => uniformAverage (sourceView coins))]
  let responseSourceView : Response → (Original × Tail) → ℝ :=
   fun response source => uniformAverage
    (sourceView ((B.maskStage model).symm (response, source)))
  change uniformAverage (fun pair : Response × (Original × Tail) =>
   responseSourceView pair.1 pair.2) = _
  rewrite [V8Smz9HonestLeafBatch.uniform_average_product responseSourceView]
  dsimp only [responseSourceView, sourceView]
  simp only [responseRoundtrip, sourceWitnessProjection, sourcePcsProjection, sourceTailProjection]
  rewrite [requestExec]
  rewrite [← rhsProduct]
  refine responseAverageCongr _ _ _ _ _ _ ?_
  intro response
  let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
   (piopPrefix bound (by omega) commit.hashMt binding response.1 commit.pendingFailure)
  let digest := oracle (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega) (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) response.2))
  let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
   (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
  cases selected : choice.selected with
  | none =>
    dsimp only [choice, digest, «prefix»] at selected
    simp only [clearedPublicAfterOpening, selected]
    let k : ℝ := V8Smz9MixedMaskCompiler.run randomized
     (next (.error "smallwood opening nonce trial limit exhausted")) oracle state
    change uniformAverage (fun _ : Original × Tail => uniformAverage (fun _ : FullTapes => k)) = k
    exact (congrArg (fun value : ℝ => uniformAverage (fun _ : Original × Tail => value))
     (uniform_average_const (A := FullTapes) k)).trans
      (uniform_average_const (A := Original × Tail) k)
  | some pair =>
    rcases pair with ⟨nonce, words⟩
    have accepted : currentOpeningAdmissible (sourcePointVector words) :=
     selected_guard_redundant (by omega) digest «prefix».pendingFailure
      (fun input => oracle (.inr input)) nonce words selected
    rewrite [public_opening_value_is_fiber_average largeEnough descriptor relation statement salt commit
     labels response «prefix» digest choice nonce words selected accepted next randomized oracle state]
    rewrite [uniform_average_comm]
    apply congrArg uniformAverage
    funext tapes
    exact opening_fiber_game_equality largeEnough descriptor relation values valid statement salt binding
     commit response oracle digest nonce (sourcePointVector words) accepted choice.pendingFailure
     labels tapes next randomized state
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: LiteralSourceFrame"
structure LiteralSourceFrame where
 opened : Finset Index
 outcome : FullTapes → Except String PublicResult
 retains_visible (known : FullTapes)
  (fresh : V8SmzaLeafFrameHybrid.Unopened openedᶜ → LeafTape) :
  outcome (V8SmzaLeafFrameHybrid.completeTapes openedᶜ known fresh) = outcome known
private def literalFrameForChoice {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (coins : OriginalCoins) (oracle : Raw bound → DigestRegister)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) («prefix» : PiopPrefix) (transcript : Q)
  (digest : DigestRegister) (choice : OpeningChoice) : LiteralSourceFrame :=
 match choice.selected with
 | none => ⟨∅, fun _ => .error "smallwood opening nonce trial limit exhausted", by intro known fresh; rfl⟩
 | some (nonce, words) =>
   let points := sourcePointVector words
   let fields := O.sourceFields relation (prefixGamma «prefix») (originalData values coins) points
   let heads := originalHeads values coins
   let earlier := C.earlier points coins.2.2.2.1
   let selection := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
    (currentDecsSelection bound largeEnough digest (C.combinationHeads points heads) earlier choice.pendingFailure)
   match selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates) with
   | none => ⟨∅, fun _ => .error "fixed DECS sampler exhausted its candidate pool", by intro known fresh; rfl⟩
   | some selected => ⟨Finset.univ.image selected.val, fun tapes =>
     scopeReturn selection.pendingFailure (.ok ⟨reply, «prefix», transcript, digest, nonce, points,
      fields, earlier, C.fullSubset heads (selectedTargets descriptor selected).val coins.2.2.2.1,
      selected.val, fun opening => tapes (selected.val opening)⟩), by
       intro known fresh
       with_reducible
        apply congrArg (fun visible : Fin 58 → LeafTape =>
         scopeReturn selection.pendingFailure (.ok (⟨reply, «prefix», transcript, digest, nonce, points,
          fields, earlier, C.fullSubset heads (selectedTargets descriptor selected).val coins.2.2.2.1,
          selected.val, visible⟩ : PublicResult)))
        funext opening
        exact V8SmzaLeafFrameHybrid.complete_preserves_opened
         (Finset.univ.image selected.val)ᶜ known fresh (selected.val opening)
         (by simp only [Finset.mem_compl, not_not];
             exact Finset.mem_image.mpr ⟨opening, Finset.mem_univ _, rfl⟩)⟩
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: literalSourceFrame"
def literalSourceFrame {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (coins : OriginalCoins)
  (oracle : Raw bound → DigestRegister) : LiteralSourceFrame :=
 let reply := actualDecsReply values coins commit
 let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
  (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure)
 let transcript := actualTranscript relation values coins «prefix»
 let digest := oracle (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega) (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript))
 let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
  (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
 literalFrameForChoice largeEnough descriptor relation values coins oracle reply «prefix» transcript digest choice
private theorem literal_source_frame_is_choice {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (coins : OriginalCoins)
  (oracle : Raw bound → DigestRegister) :
  literalSourceFrame largeEnough descriptor relation values binding commit coins oracle =
   let reply := actualDecsReply values coins commit
   let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
    (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure)
   let transcript := actualTranscript relation values coins «prefix»
   let digest := oracle (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
    (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript))
   let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
    (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
   literalFrameForChoice largeEnough descriptor relation values coins oracle reply «prefix» transcript digest choice := by
 delta literalSourceFrame
 rfl
private def frameForCertificate
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues) (coins : OriginalCoins)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) («prefix» : PiopPrefix) (transcript : Q)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks) (pending : Bool)
  (certificate : Option { indices : Fin 58 → Index // Function.Injective indices }) : LiteralSourceFrame :=
 let data := originalData values coins
 let fields := O.sourceFields relation (prefixGamma «prefix») data points
 let heads := originalHeads values coins
 let earlier := C.earlier points coins.2.2.2.1
 match certificate with
 | none => ⟨∅, fun _ => .error "fixed DECS sampler exhausted its candidate pool", by intro known fresh; rfl⟩
 | some selected => ⟨Finset.univ.image selected.val, fun tapes =>
   scopeReturn pending (.ok ⟨reply, «prefix», transcript, digest, nonce, points,
    fields, earlier, C.fullSubset heads (selectedTargets descriptor selected).val coins.2.2.2.1,
    selected.val, fun opening => tapes (selected.val opening)⟩), by
     intro known fresh
     with_reducible
      apply congrArg (fun visible : Fin 58 → LeafTape =>
       scopeReturn pending (.ok (⟨reply, «prefix», transcript, digest, nonce, points,
        fields, earlier, C.fullSubset heads (selectedTargets descriptor selected).val coins.2.2.2.1,
        selected.val, visible⟩ : PublicResult)))
      funext opening
      exact V8SmzaLeafFrameHybrid.complete_preserves_opened
       (Finset.univ.image selected.val)ᶜ known fresh (selected.val opening)
       (by simp only [Finset.mem_compl, not_not];
           exact Finset.mem_image.mpr ⟨opening, Finset.mem_univ _, rfl⟩)⟩
private theorem literal_frame_is_certificate {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues) (coins : OriginalCoins)
  (old : Raw bound → DigestRegister)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) («prefix» : PiopPrefix) (transcript : Q)
  (digest : DigestRegister) (choice : OpeningChoice) (nonce : Fin 16) (words : List FieldWord)
  (choiceEq : choice.selected = some (nonce, words)) :
  literalFrameForChoice largeEnough descriptor relation values coins old reply «prefix» transcript digest choice =
   let points := sourcePointVector words
   let heads := originalHeads values coins
   let earlier := C.earlier points coins.2.2.2.1
   let selection := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
    (currentDecsSelection bound largeEnough digest (C.combinationHeads points heads) earlier choice.pendingFailure)
   frameForCertificate descriptor relation values coins reply «prefix» transcript digest nonce points selection.pendingFailure
    (selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates)) := by
 delta literalFrameForChoice frameForCertificate
 rewrite [choiceEq]
 rfl
private theorem frame_certificate_card_le
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues) (coins : OriginalCoins)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) («prefix» : PiopPrefix) (transcript : Q)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks) (pending : Bool)
  (certificate : Option { indices : Fin 58 → Index // Function.Injective indices }) :
  (frameForCertificate descriptor relation values coins reply «prefix» transcript digest nonce points
   pending certificate).opened.card ≤ 58 := by
 cases certificate with
 | none => simp only [frameForCertificate, Finset.card_empty]; omega
 | some selected =>
   dsimp only [frameForCertificate]
   exact (Finset.card_image_le).trans (by simp)
private theorem certificate_opened_card_le
  (certificate : Option { indices : Fin 58 → Index // Function.Injective indices }) :
  (match certificate with
   | none => (∅ : Finset Index)
   | some selected => Finset.univ.image selected.val).card ≤ 58 := by
 cases certificate with
 | none => simp only [Finset.card_empty]; omega
 | some selected => exact (Finset.card_image_le).trans (by simp)
private theorem literal_frame_choice_card_le {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (coins : OriginalCoins) (oracle : Raw bound → DigestRegister)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) («prefix» : PiopPrefix) (transcript : Q)
  (digest : DigestRegister) (choice : OpeningChoice) :
  (literalFrameForChoice largeEnough descriptor relation values coins oracle reply
   «prefix» transcript digest choice).opened.card ≤ 58 := by
 cases choiceEq : choice.selected with
 | none => simp only [literalFrameForChoice, choiceEq, Finset.card_empty]; omega
 | some chosen =>
   rcases chosen with ⟨nonce, words⟩
   rewrite [literal_frame_is_certificate largeEnough descriptor relation values coins oracle reply
    «prefix» transcript digest choice nonce words choiceEq]
   let points := sourcePointVector words
   let heads := originalHeads values coins
   let earlier := C.earlier points coins.2.2.2.1
   let selection := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
    (currentDecsSelection bound largeEnough digest (C.combinationHeads points heads) earlier choice.pendingFailure)
   change (frameForCertificate descriptor relation values coins reply «prefix» transcript digest nonce points
    selection.pendingFailure (selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates))).opened.card ≤ 58
   exact frame_certificate_card_le descriptor relation values coins reply «prefix» transcript digest nonce points
    selection.pendingFailure (selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates))
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: literal_frame_opened_card_le"
theorem literal_frame_opened_card_le {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (coins : OriginalCoins)
  (oracle : Raw bound → DigestRegister) :
  (literalSourceFrame largeEnough descriptor relation values binding commit coins oracle).opened.card ≤ 58 := by
 rewrite [literal_source_frame_is_choice largeEnough descriptor relation values binding commit coins oracle]
 let reply := actualDecsReply values coins commit
 let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
  (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure)
 let transcript := actualTranscript relation values coins «prefix»
 let digest := oracle (.inr (NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
  (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript))
 let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
  (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
 change (literalFrameForChoice largeEnough descriptor relation values coins oracle reply
  «prefix» transcript digest choice).opened.card ≤ 58
 exact literal_frame_choice_card_le largeEnough descriptor relation values coins oracle
  reply «prefix» transcript digest choice
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: literal_frame_retains_visible"
theorem literal_frame_retains_visible
  (frame : LiteralSourceFrame) (known : FullTapes)
  (fresh : V8SmzaLeafFrameHybrid.Unopened frame.openedᶜ → LeafTape) :
  frame.outcome (V8SmzaLeafFrameHybrid.completeTapes frame.openedᶜ known fresh) = frame.outcome known := by
 exact LiteralSourceFrame.retains_visible frame known fresh
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: source_overlay_partition"
theorem source_overlay_partition {bound : Nat}
  (old : Raw bound → DigestRegister) (labels : Index → DigestRegister)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte) (opened : Finset Index) (known : FullTapes)
  (fresh : V8SmzaLeafFrameHybrid.Unopened openedᶜ → LeafTape) :
  let full := V8SmzaLeafFrameHybrid.completeTapes openedᶜ known fresh
  currentSourceOverlay old labels statement salt payload Finset.univ full =
   currentSourceOverlay (currentSourceOverlay old labels statement salt payload opened known)
    labels statement salt payload openedᶜ full := by
 dsimp only
 let full := V8SmzaLeafFrameHybrid.completeTapes openedᶜ known fresh
 have openedSame : currentSourcePatch statement salt payload opened full =
   currentSourcePatch statement salt payload opened known := by
  unfold currentSourcePatch
  apply Finset.image_congr
  intro index member
  change NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index
    (V8SmzaLeafFrameHybrid.completeTapes openedᶜ known fresh index) =
   NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index (known index)
  have outside : index ∉ openedᶜ := by
   intro complement
   exact (Finset.mem_compl.mp complement) member
  exact congrArg (fun tape : LeafTape =>
   NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index tape)
    (V8SmzaLeafFrameHybrid.complete_preserves_opened openedᶜ known fresh index outside)
 have union : currentSourcePatch statement salt payload Finset.univ full =
   currentSourcePatch statement salt payload opened known ∪
    currentSourcePatch statement salt payload openedᶜ full := by
  rw [← openedSame]
  simp only [currentSourcePatch, ← Finset.image_union, Finset.union_compl]
 funext input
 cases input with
 | inr input => rfl
 | inl input =>
   change (if input ∈ currentSourcePatch statement salt payload Finset.univ full then
      labels (indexProjection input) else old (.inl input)) =
    (if input ∈ currentSourcePatch statement salt payload openedᶜ full then
      labels (indexProjection input) else
       if input ∈ currentSourcePatch statement salt payload opened known then
        labels (indexProjection input) else old (.inl input))
   have unionMem :
       input ∈ currentSourcePatch statement salt payload Finset.univ full ↔
         input ∈ currentSourcePatch statement salt payload opened known ∨
         input ∈ currentSourcePatch statement salt payload openedᶜ full := by
     rw [union, Finset.mem_union]
   by_cases a : input ∈ currentSourcePatch statement salt payload opened known
   ·
     have all : input ∈ currentSourcePatch statement salt payload Finset.univ full :=
       unionMem.mpr (Or.inl a)
     by_cases b : input ∈ currentSourcePatch statement salt payload openedᶜ full
     · rw [if_pos all, if_pos b]
     · rw [if_pos all, if_neg b, if_pos a]
   ·
     by_cases b : input ∈ currentSourcePatch statement salt payload openedᶜ full
     ·
       have all : input ∈ currentSourcePatch statement salt payload Finset.univ full :=
         unionMem.mpr (Or.inr b)
       rw [if_pos all, if_pos b]
     ·
       have noAll : input ∉ currentSourcePatch statement salt payload Finset.univ full := by
         intro member
         cases unionMem.mp member with
         | inl openedMember => exact a openedMember
         | inr unopenedMember => exact b unopenedMember
       rw [if_neg noAll, if_neg b, if_neg a]
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: current_updates_of_function"
theorem current_updates_of_function {bound : Nat} (count : Nat)
  (inputs : Fin count → Raw bound)
  (answer : Raw bound → DigestRegister)
  (old : Raw bound → DigestRegister) (input : Raw bound) :
  currentUpdates count inputs (fun index => answer (inputs index)) old input =
   if ∃ index, inputs index = input then answer input else old input := by
  induction count generalizing old with
  | zero =>
      simp only [currentUpdates, Fin.exists_fin_zero, if_false]
  | succ count ih =>
      rw [currentUpdates]
      rw [ih (fun index => inputs index.succ)
        (Function.update old (inputs 0) (answer (inputs 0)))]
      by_cases tail : ∃ index : Fin count, inputs index.succ = input
      ·
        have all : ∃ index : Fin (count + 1), inputs index = input :=
          let ⟨index, same⟩ := tail
          ⟨index.succ, same⟩
        rw [if_pos tail, if_pos all]
      ·
        by_cases head : inputs 0 = input
        ·
          have all : ∃ index : Fin (count + 1), inputs index = input := ⟨0, head⟩
          rw [if_neg tail, if_pos all, ← head, Function.update_self]
        ·
          have all : ¬ ∃ index : Fin (count + 1), inputs index = input := by
            rintro ⟨index, same⟩
            cases index using Fin.cases with
            | zero => exact head same
            | succ index => exact tail ⟨index, same⟩
          rw [if_neg tail, if_neg all]
          exact Function.update_of_ne (Ne.symm head) _ _
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: sequential_source_updates_are_full_overlay"
theorem sequential_source_updates_are_full_overlay {bound : Nat}
  (old : Raw bound → DigestRegister) (labels : Index → DigestRegister)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte) (tapes : FullTapes) :
  currentUpdates 8388608 (fun index => .inl
   (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index (tapes index)))
   labels old = currentSourceOverlay old labels statement salt payload Finset.univ tapes := by
 let answer : Raw bound → DigestRegister :=
  Sum.elim (fun input => labels (indexProjection input)) (fun input => old (.inr input))
 have outputs : labels = fun index => answer (.inl
   (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index (tapes index))) := by
  funext index
  simp only [answer, Sum.elim_inl, source_leaf_index]
 conv_lhs => rw [outputs]
 funext input
 rw [current_updates_of_function]
 cases input with
 | inl input =>
   simp only [currentSourceOverlay, currentSourcePatch, Finset.mem_image, Finset.mem_univ,
    true_and, answer, Sum.elim_inl, Sum.inl.injEq]
 | inr input =>
   have no : ¬ ∃ index : Index, (Sum.inl
    (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index (tapes index)) :
    Raw bound) = .inr input := by simp
   rw [if_neg no]
   rfl
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: full_overlay_nonleaf_fold"
theorem full_overlay_nonleaf_fold {bound : Nat} {Result : Type}
  (randomized : Bool) (program : V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) Result)
  (next : Result → MixedProgram (Raw bound) Work)
  (old : Raw bound → DigestRegister) (labels : Index → DigestRegister)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte) (tapes : FullTapes)
  (state : GS bound Work) :
  run randomized (compileNonleaf program next)
   (currentSourceOverlay old labels statement salt payload Finset.univ tapes) state =
  run randomized (next (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input)) program))
   (currentSourceOverlay old labels statement salt payload Finset.univ tapes) state := by
 rw [compile_nonleaf_executes]
 rfl
private theorem full_overlay_honest_read_fold {bound : Nat}
  (randomized : Bool) (input : CurrentOtherRawInput bound)
  (next : DigestRegister → MixedProgram (Raw bound) Work)
  (old : Raw bound → DigestRegister) (labels : Index → DigestRegister)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte) (tapes : FullTapes)
  (state : GS bound Work) :
  run randomized (.honestRead (.inr input) next)
   (currentSourceOverlay old labels statement salt payload Finset.univ tapes) state =
  run randomized (next (old (.inr input)))
   (currentSourceOverlay old labels statement salt payload Finset.univ tapes) state := by
 rfl
private theorem original_opening_is_literal_choice {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues) (coins : OriginalCoins)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) («prefix» : PiopPrefix) (transcript : Q)
  (digest : DigestRegister) (choice : OpeningChoice) (labels : Index → DigestRegister) (tapes : FullTapes)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister) (state : GS bound Work) :
  run randomized (originalAfterOpening largeEnough descriptor relation values coins statement salt
   tapes labels reply «prefix» transcript digest choice next)
   (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) Finset.univ tapes) state =
  run randomized (next ((literalFrameForChoice largeEnough descriptor relation values coins old
   reply «prefix» transcript digest choice).outcome tapes))
   (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) Finset.univ tapes) state := by
 cases choiceEq : choice.selected with
 | none => simp only [originalAfterOpening, literalFrameForChoice, choiceEq]
 | some chosen =>
   rcases chosen with ⟨nonce, words⟩
   simp only [originalAfterOpening, literalFrameForChoice, choiceEq]
   rewrite [full_overlay_nonleaf_fold]
   let points := sourcePointVector words
   let heads := originalHeads values coins
   let earlier := C.earlier points coins.2.2.2.1
   let selection := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
    (currentDecsSelection bound largeEnough digest (C.combinationHeads points heads) earlier choice.pendingFailure)
   cases certificateEq : selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates) with
   | none =>
     dsimp only [selection, points, heads, earlier] at certificateEq
     simp only [originalAfterSelection, certificateEq]
   | some selected =>
     dsimp only [selection, points, heads, earlier] at certificateEq
     simp only [originalAfterSelection, certificateEq]
private theorem scalar_eq_chain_nine {α : Type}
  (a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 : α)
  (h0 : a0 = a1) (h1 : a1 = a2) (h2 : a2 = a3)
  (h3 : a3 = a4) (h4 : a4 = a5) (h5 : a5 = a6)
  (h6 : a6 = a7) (h7 : a7 = a8) (h8 : a8 = a9) : a0 = a9 := by
 exact h0.trans (h1.trans (h2.trans (h3.trans (h4.trans
  (h5.trans (h6.trans (h7.trans h8)))))))
private def staged_nonleaf_read_nonleaf {bound : Nat} {Prefix Choice : Type}
  (piopProgram : V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) Prefix)
  (readInput : Prefix → CurrentOtherRawInput bound)
  (openingProgram : Prefix → DigestRegister →
   V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) Choice)
  (finish : Prefix → DigestRegister → Choice → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 compileNonleaf piopProgram fun «prefix» =>
  .honestRead (.inr (readInput «prefix»)) fun digest =>
   compileNonleaf (openingProgram «prefix» digest) (finish «prefix» digest)
private theorem staged_nonleaf_read_nonleaf_executes {bound : Nat} {Prefix Choice : Type}
  (randomized : Bool)
  (piopProgram : V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) Prefix)
  (readInput : Prefix → CurrentOtherRawInput bound)
  (openingProgram : Prefix → DigestRegister →
   V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) Choice)
  (finish : Prefix → DigestRegister → Choice → MixedProgram (Raw bound) Work)
  (old : Raw bound → DigestRegister) (labels : Index → DigestRegister)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte) (tapes : FullTapes)
  (state : GS bound Work) :
  let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
   (fun input => old (.inr input)) piopProgram
  let digest := old (.inr (readInput «prefix»))
  let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
   (fun input => old (.inr input)) (openingProgram «prefix» digest)
  run randomized (staged_nonleaf_read_nonleaf piopProgram readInput openingProgram finish)
    (currentSourceOverlay old labels statement salt payload Finset.univ tapes) state =
   run randomized (finish «prefix» digest choice)
    (currentSourceOverlay old labels statement salt payload Finset.univ tapes) state := by
 dsimp only []
 delta staged_nonleaf_read_nonleaf
 let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
  (fun input => old (.inr input)) piopProgram
 let digest := old (.inr (readInput «prefix»))
 have piopEq := full_overlay_nonleaf_fold (Work := Work) randomized piopProgram
  (fun «prefix» => .honestRead (.inr (readInput «prefix»)) fun digest =>
   compileNonleaf (openingProgram «prefix» digest) (finish «prefix» digest))
  old labels statement salt payload tapes state
 have digestEq := full_overlay_honest_read_fold (Work := Work) randomized (readInput «prefix»)
  (fun digest => compileNonleaf (openingProgram «prefix» digest) (finish «prefix» digest))
  old labels statement salt payload tapes state
 have openingEq := full_overlay_nonleaf_fold (Work := Work) randomized
  (openingProgram «prefix» digest) (finish «prefix» digest)
  old labels statement salt payload tapes state
 exact piopEq.trans (digestEq.trans openingEq)
private def original_commit_stage_program {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (coins : OriginalCoins) (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (binding : Fin 77 → Goldilocks) (tapes : FullTapes) (labels : Index → DigestRegister)
  (commit : CommitPrefix)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 let reply := actualDecsReply values coins commit
 staged_nonleaf_read_nonleaf
  (piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure)
  (fun «prefix» => NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
   (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp)
   (actualTranscript relation values coins «prefix»))
  (fun «prefix» digest => currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
  (fun «prefix» digest choice => originalAfterOpening largeEnough descriptor relation values coins
   statement salt tapes labels reply «prefix» (actualTranscript relation values coins «prefix»)
   digest choice next)
private theorem original_commit_stage_program_eq {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (coins : OriginalCoins) (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (binding : Fin 77 → Goldilocks) (tapes : FullTapes) (labels : Index → DigestRegister)
  (commit : CommitPrefix)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  originalAfterCommit largeEnough descriptor relation values coins statement salt binding
    tapes labels commit next =
   original_commit_stage_program largeEnough descriptor relation values coins statement salt binding
    tapes labels commit next := by
 delta originalAfterCommit original_commit_stage_program staged_nonleaf_read_nonleaf
 rfl
private theorem original_commit_stage_run_eq {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (coins : OriginalCoins) (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (binding : Fin 77 → Goldilocks) (tapes : FullTapes) (labels : Index → DigestRegister)
  (commit : CommitPrefix)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister) (state : GS bound Work) :
  run randomized (originalAfterCommit largeEnough descriptor relation values coins statement salt
    binding tapes labels commit next)
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins)
     Finset.univ tapes) state =
   run randomized (original_commit_stage_program largeEnough descriptor relation values coins
    statement salt binding tapes labels commit next)
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins)
     Finset.univ tapes) state := by
 exact congrArg (fun program : MixedProgram (Raw bound) Work => run randomized program
  (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins)
   Finset.univ tapes) state)
  (original_commit_stage_program_eq largeEnough descriptor relation values coins statement salt
   binding tapes labels commit next)
private theorem original_commit_named_stages_execute {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (coins : OriginalCoins) (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (binding : Fin 77 → Goldilocks) (tapes : FullTapes) (labels : Index → DigestRegister)
  (commit : CommitPrefix)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister) (state : GS bound Work) :
  let reply := actualDecsReply values coins commit
  let piopProgram := piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure
  let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
   (fun input => old (.inr input)) piopProgram
  let transcript := actualTranscript relation values coins «prefix»
  let digestInput := NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
   (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript
  let digest := old (.inr digestInput)
  let openingProgram := currentChooseOpening bound (by omega) digest «prefix».pendingFailure
  let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret
   (fun input => old (.inr input)) openingProgram
  run randomized (original_commit_stage_program largeEnough descriptor relation values coins
    statement salt binding tapes labels commit next)
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins)
     Finset.univ tapes) state =
   run randomized (originalAfterOpening largeEnough descriptor relation values coins statement salt
    tapes labels reply «prefix» transcript digest choice next)
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins)
     Finset.univ tapes) state := by
 dsimp only []
 delta original_commit_stage_program
 exact staged_nonleaf_read_nonleaf_executes (Work := Work) (Prefix := PiopPrefix)
  (Choice := OpeningChoice) randomized
  (piopPrefix bound (by omega) commit.hashMt binding (actualDecsReply values coins commit)
   commit.pendingFailure)
  (fun «prefix» => NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
   (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp)
   (actualTranscript relation values coins «prefix»))
  (fun «prefix» digest => currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
  (fun «prefix» digest choice => originalAfterOpening largeEnough descriptor relation values coins
   statement salt tapes labels (actualDecsReply values coins commit) «prefix»
   (actualTranscript relation values coins «prefix») digest choice next)
  old labels statement salt (originalPayload descriptor values coins) tapes state
private theorem frame_outcome_run_congr {bound : Nat}
  (left right : LiteralSourceFrame) (same : left = right) (tapes : FullTapes)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (oracle : Raw bound → DigestRegister) (state : GS bound Work) :
  run randomized (next (left.outcome tapes)) oracle state =
   run randomized (next (right.outcome tapes)) oracle state := by
 exact congrArg (fun frame : LiteralSourceFrame =>
  run randomized (next (frame.outcome tapes)) oracle state) same
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: original_after_commit_is_literal_frame"
theorem original_after_commit_is_literal_frame {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (coins : OriginalCoins) (labels : Index → DigestRegister) (tapes : FullTapes)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) :
  run randomized (originalAfterCommit largeEnough descriptor relation values coins statement salt binding
   tapes labels commit next)
   (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) Finset.univ tapes) state =
  run randomized (next ((literalSourceFrame largeEnough descriptor relation values binding commit coins old).outcome tapes))
   (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) Finset.univ tapes) state := by
 let reply := actualDecsReply values coins commit
 let piopProgram := piopPrefix bound (by omega) commit.hashMt binding reply commit.pendingFailure
 let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input)) piopProgram
 let transcript := actualTranscript relation values coins «prefix»
 let digestInput := NativePrivateSpendQ58CurrentTranscriptInput.finalKey bound (by omega)
  (V8Smz9HonestRequestSchedule.sourceDigestPrefix «prefix».hashFpp) transcript
 let digest := old (.inr digestInput)
 let openingProgram := currentChooseOpening bound (by omega) digest «prefix».pendingFailure
 let choice := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input)) openingProgram
 let payload := originalPayload descriptor values coins
 let overlay := currentSourceOverlay old labels statement salt payload Finset.univ tapes
 with_reducible
  exact (original_commit_stage_run_eq (Work := Work) largeEnough descriptor relation values
   coins statement salt binding tapes labels commit next randomized old state).trans
   ((original_commit_named_stages_execute (Work := Work) largeEnough descriptor relation values
     coins statement salt binding tapes labels commit next randomized old state).trans
    ((original_opening_is_literal_choice (Work := Work) largeEnough descriptor relation values coins
      statement salt reply «prefix» transcript digest choice labels tapes next randomized old state).trans
     (congrArg (fun frame : LiteralSourceFrame =>
       run randomized (next (frame.outcome tapes)) overlay state)
       (literal_source_frame_is_choice largeEnough descriptor relation values binding commit coins old)).symm))
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: currentSelectUnopened"
def currentSelectUnopened (unopened : Finset Index) (anchor : V8SmzaLeafFrameHybrid.Unopened unopened)
  (input : CurrentLeafInput) : V8SmzaLeafFrameHybrid.Unopened unopened :=
 if member : indexProjection input ∈ unopened then ⟨indexProjection input, member⟩ else anchor
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: current_conditioned_patch_subset"
theorem current_conditioned_patch_subset
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte)
  (unopened : Finset Index) (anchor : V8SmzaLeafFrameHybrid.Unopened unopened)
  (known : FullTapes) (fresh : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape) :
  currentSourcePatch statement salt payload unopened
   (V8SmzaLeafFrameHybrid.completeTapes unopened known fresh) ⊆
   indexedSupport (currentSelectUnopened unopened anchor) tapeProjection fresh := by
 intro input member
 simp only [indexedSupport, Finset.mem_filter, Finset.mem_univ, true_and]
 exact V8SmzaLeafFrameHybrid.image_restricted_projection unopened anchor
  (fun index tape => NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index tape)
  indexProjection tapeProjection
  (fun index tape => source_leaf_index statement salt (payload index) index tape)
  (fun index tape => source_leaf_tape statement salt (payload index) index tape)
  (V8SmzaLeafFrameHybrid.completeTapes unopened known fresh) fresh
  (fun index member => by simp only [V8SmzaLeafFrameHybrid.completeTapes, dif_pos member]) input member
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: conditioned_current_unopened_erasure"
theorem conditioned_current_unopened_erasure {bound : Nat}
  (randomized : Bool)
  (program : V8Smz9HonestWholeViewGames.Program (Raw bound) Work)
  (old : Raw bound → DigestRegister) (labels : Index → DigestRegister)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte)
  (unopened : Finset Index) (anchor : V8SmzaLeafFrameHybrid.Unopened unopened)
  (known : FullTapes)
  (state : GS bound Work)
  (normalized : ‖state‖ = 1) :
  |uniformAverage (fun fresh : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape =>
   V8Smz9HonestWholeViewGames.run randomized program
    (currentSourceOverlay old labels statement salt payload unopened
     (V8SmzaLeafFrameHybrid.completeTapes unopened known fresh)) state) -
   V8Smz9HonestWholeViewGames.run randomized program old state| ≤
   4 * (V8Smz9HonestWholeViewGames.queryCount program : ℝ) / (2 ^ 256 : ℝ) := by
 let select := currentSelectUnopened unopened anchor
 let support := indexedSupport
  (Sum.elim select (fun _ : CurrentOtherRawInput bound => anchor))
  (Sum.elim tapeProjection (fun _ : CurrentOtherRawInput bound => (0 : LeafTape)))
 have supportBound (input : Raw bound) :
   supportCount support input ≤
    (Fintype.card (V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape) : ℝ) * (2 ^ 512 : ℝ)⁻¹ :=
  (indexed_leaf_tape_support_count
   (Sum.elim select (fun _ : CurrentOtherRawInput bound => anchor))
   (Sum.elim tapeProjection (fun _ : CurrentOtherRawInput bound => (0 : LeafTape))) input).le
 have same (fresh : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape)
   (input : Raw bound) (outside : input ∉ support fresh) :
   old input = currentSourceOverlay old labels statement salt payload unopened
    (V8SmzaLeafFrameHybrid.completeTapes unopened known fresh) input := by
  cases input with
  | inl input =>
    have outsideLeaf : input ∉ indexedSupport select tapeProjection fresh := by
     simpa only [support, indexedSupport, Finset.mem_filter, Finset.mem_univ, true_and,
      Sum.elim_inl] using outside
    have outsideSource := outside_of_subset _ _
     (current_conditioned_patch_subset statement salt payload unopened anchor known fresh) input outsideLeaf
    simp only [currentSourceOverlay, if_neg outsideSource]
  | inr input => rfl
 have hybrid := measured_program_hidden_patch_bound randomized program support (2 ^ 512 : ℝ)⁻¹
  (by positivity) (inv_le_one_of_one_le₀ (one_le_pow₀ (by norm_num))) supportBound old
  (fun fresh => currentSourceOverlay old labels statement salt payload unopened
   (V8SmzaLeafFrameHybrid.completeTapes unopened known fresh)) same state
 have averaged := V8Smz9MeasuredRunContinuity.average_difference_abs_le
  (fun fresh : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape =>
   V8Smz9HonestWholeViewGames.run randomized program
    (currentSourceOverlay old labels statement salt payload unopened
     (V8SmzaLeafFrameHybrid.completeTapes unopened known fresh)) state)
  (fun _ : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape =>
   V8Smz9HonestWholeViewGames.run randomized program old state)
 rw [uniform_average_const] at averaged
 simpa only [queryLoss, normalized, one_pow, mul_one,
  V8Smz9MeasuredSourceHiddenPatch.sqrt_source_tape_cap, div_eq_mul_inv]
   using averaged.trans hybrid
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: opened_overlay_retains_visible"
theorem opened_overlay_retains_visible {bound : Nat}
  (old : Raw bound → DigestRegister) (labels : Index → DigestRegister)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte) (opened : Finset Index) (known : FullTapes)
  (fresh : V8SmzaLeafFrameHybrid.Unopened openedᶜ → LeafTape) :
  currentSourceOverlay old labels statement salt payload opened
   (V8SmzaLeafFrameHybrid.completeTapes openedᶜ known fresh) =
   currentSourceOverlay old labels statement salt payload opened known := by
 have same : currentSourcePatch statement salt payload opened
   (V8SmzaLeafFrameHybrid.completeTapes openedᶜ known fresh) =
   currentSourcePatch statement salt payload opened known := by
  unfold currentSourcePatch
  apply Finset.image_congr
  intro index member
  change NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index
    (V8SmzaLeafFrameHybrid.completeTapes openedᶜ known fresh index) =
   NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index (known index)
  have outside : index ∉ openedᶜ := by
   intro complement
   exact (Finset.mem_compl.mp complement) member
  exact congrArg (fun tape : LeafTape =>
   NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload index) index tape)
    (V8SmzaLeafFrameHybrid.complete_preserves_opened openedᶜ known fresh index outside)
 funext input
 cases input <;> simp only [currentSourceOverlay, same]
private theorem literal_frame_overlay_erasure_bound {bound : Nat}
  (frame : LiteralSourceFrame) (small : frame.opened.card ≤ 58)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) (normalized : ‖state‖ = 1) (queries : Nat)
  (queryBound : ∀ tapes : FullTapes,
   V8Smz9HonestWholeViewGames.queryCount (compile (next (frame.outcome tapes)) []) ≤ queries) :
  |uniformAverage (fun tapes : FullTapes => run randomized (next (frame.outcome tapes))
    (currentSourceOverlay old labels statement salt payload Finset.univ tapes) state) -
   uniformAverage (fun tapes : FullTapes => run randomized (next (frame.outcome tapes))
    (currentSourceOverlay old labels statement salt payload frame.opened tapes) state)| ≤
    4 * (queries : ℝ) / (2 ^ 256 : ℝ) := by
 let unopened := frame.openedᶜ
 have nonempty : unopened.Nonempty := by
  apply Finset.card_pos.mp
  rw [Finset.card_compl]
  have count := small
  have all : Fintype.card Index = 8388608 := by
   change Fintype.card (Fin 8388608) = 8388608
   exact Fintype.card_fin 8388608
  rw [all]
  omega
 let anchor : V8SmzaLeafFrameHybrid.Unopened unopened :=
  ⟨nonempty.choose, nonempty.choose_spec⟩
 let «split» := V8SmzaLeafFrameHybrid.tapeSplit unopened
 let known (visible : V8SmzaLeafFrameHybrid.Opened unopened → LeafTape) : FullTapes :=
  «split».symm (visible, fun _ => 0)
 have complete (visible : V8SmzaLeafFrameHybrid.Opened unopened → LeafTape)
   (fresh : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape) :
   «split».symm (visible, fresh) = V8SmzaLeafFrameHybrid.completeTapes unopened (known visible) fresh := by
  rw [V8SmzaLeafFrameHybrid.complete_is_split_reconstruction]
  simp only [known, «split», Equiv.apply_symm_apply]
 have splitAverage (value : FullTapes → ℝ) : uniformAverage value =
   uniformAverage (fun visible : V8SmzaLeafFrameHybrid.Opened unopened → LeafTape =>
    uniformAverage (fun fresh : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape =>
     value («split».symm (visible, fresh)))) :=
  (uniform_average_equiv «split».symm value).symm.trans
   (V8Smz9HonestLeafBatch.uniform_average_product
    (fun visible fresh => value («split».symm (visible, fresh))))
 rewrite [splitAverage (fun tapes : FullTapes => run randomized (next (frame.outcome tapes))
   (currentSourceOverlay old labels statement salt payload Finset.univ tapes) state),
  splitAverage (fun tapes : FullTapes => run randomized (next (frame.outcome tapes))
   (currentSourceOverlay old labels statement salt payload frame.opened tapes) state)]
 have fullTransport :
   uniformAverage (fun visible : V8SmzaLeafFrameHybrid.Opened unopened → LeafTape =>
    uniformAverage (fun fresh : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape =>
     run randomized (next (frame.outcome («split».symm (visible, fresh))))
      (currentSourceOverlay old labels statement salt payload Finset.univ
       («split».symm (visible, fresh))) state)) =
   uniformAverage (fun visible : V8SmzaLeafFrameHybrid.Opened unopened → LeafTape =>
    uniformAverage (fun fresh : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape =>
     run randomized (next (frame.outcome (known visible)))
      (currentSourceOverlay
       (currentSourceOverlay old labels statement salt payload frame.opened (known visible))
       labels statement salt payload unopened
       (V8SmzaLeafFrameHybrid.completeTapes unopened (known visible) fresh)) state)) := by
  apply double_average_congr
  intro visible fresh
  exact congrArg₂ (fun outcome oracle => run randomized (next outcome) oracle state)
   ((congrArg frame.outcome (complete visible fresh)).trans
    (literal_frame_retains_visible frame (known visible) fresh))
   ((congrArg (currentSourceOverlay old labels statement salt payload Finset.univ)
     (complete visible fresh)).trans
    (source_overlay_partition old labels statement salt payload frame.opened (known visible) fresh))
 have openedTransport :
   uniformAverage (fun visible : V8SmzaLeafFrameHybrid.Opened unopened → LeafTape =>
    uniformAverage (fun fresh : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape =>
     run randomized (next (frame.outcome («split».symm (visible, fresh))))
      (currentSourceOverlay old labels statement salt payload frame.opened
       («split».symm (visible, fresh))) state)) =
   uniformAverage (fun visible : V8SmzaLeafFrameHybrid.Opened unopened → LeafTape =>
    uniformAverage (fun _ : V8SmzaLeafFrameHybrid.Unopened unopened → LeafTape =>
     run randomized (next (frame.outcome (known visible)))
      (currentSourceOverlay old labels statement salt payload frame.opened (known visible)) state)) := by
  apply double_average_congr
  intro visible fresh
  exact congrArg₂ (fun outcome oracle => run randomized (next outcome) oracle state)
   ((congrArg frame.outcome (complete visible fresh)).trans
    (literal_frame_retains_visible frame (known visible) fresh))
   ((congrArg (currentSourceOverlay old labels statement salt payload frame.opened)
     (complete visible fresh)).trans
    (opened_overlay_retains_visible old labels statement salt payload frame.opened (known visible) fresh))
 rewrite [fullTransport, openedTransport]
 simp only [uniform_average_const]
 apply uniform_average_difference_le
 intro visible
 let program := compile (next (frame.outcome (known visible))) []
 let base := currentSourceOverlay old labels statement salt payload
  frame.opened (known visible)
 have erased := conditioned_current_unopened_erasure randomized program base labels statement salt
  payload unopened anchor (known visible) state normalized
 simp only [program, compile_executes, effective_empty] at erased
 apply erased.trans
 have castBound : (V8Smz9HonestWholeViewGames.queryCount program : ℝ) ≤ queries :=
  by exact_mod_cast queryBound (known visible)
 exact div_le_div_of_nonneg_right (mul_le_mul_of_nonneg_left castBound (by norm_num)) (by positivity)
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: source_frame_erasure_bound"
theorem source_frame_erasure_bound {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (coins : OriginalCoins) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work)
  (normalized : ‖state‖ = 1) (queries : Nat)
  (queryBound : ∀ tapes : FullTapes,
   V8Smz9HonestWholeViewGames.queryCount (compile (next
    ((literalSourceFrame largeEnough descriptor relation values binding commit coins old).outcome tapes)) []) ≤ queries) :
  let frame := literalSourceFrame largeEnough descriptor relation values binding commit coins old
  |uniformAverage (fun tapes : FullTapes => run randomized
    (originalAfterCommit largeEnough descriptor relation values coins statement salt binding tapes labels commit next)
    (currentUpdates 8388608 (fun index => .inl
     (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
      (originalPayload descriptor values coins index) index (tapes index))) labels old) state) -
   uniformAverage (fun tapes : FullTapes => run randomized (next (frame.outcome tapes))
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) frame.opened tapes) state)| ≤
    4 * (queries : ℝ) / (2 ^ 256 : ℝ) := by
 dsimp only
 simp_rw [sequential_source_updates_are_full_overlay, original_after_commit_is_literal_frame]
 exact literal_frame_overlay_erasure_bound
  (literalSourceFrame largeEnough descriptor relation values binding commit coins old)
  (literal_frame_opened_card_le largeEnough descriptor relation values binding commit coins old)
  statement salt (originalPayload descriptor values coins) labels next randomized old state
  normalized queries queryBound
private theorem actual_erasure_average_bound {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (old : Raw bound → DigestRegister) (state : GS bound Work) (normalized : ‖state‖ = 1)
  (queries : Nat) (queryBound : ∀ result,
   V8Smz9HonestWholeViewGames.queryCount (compile (next result) []) ≤ queries) :
  |uniformAverage (fun coins : OriginalCoins => uniformAverage (fun tapes : FullTapes => run true
    (originalAfterCommit largeEnough descriptor relation values coins statement salt binding
     tapes labels commit next)
    (currentUpdates 8388608 (fun index => .inl
     (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
      (originalPayload descriptor values coins index) index (tapes index))) labels old) state)) - uniformAverage (fun coins : OriginalCoins => uniformAverage (fun tapes : FullTapes =>
    let frame := literalSourceFrame largeEnough descriptor relation values binding commit coins old
    run true (next (frame.outcome tapes)) (currentSourceOverlay old labels statement salt
     (originalPayload descriptor values coins) frame.opened tapes) state))| ≤ 4 * (queries : ℝ) / (2 ^ 256 : ℝ) := by
 with_reducible
  exact uniform_average_difference_le
   (fun coins : OriginalCoins => uniformAverage (fun tapes : FullTapes => run true
    (originalAfterCommit largeEnough descriptor relation values coins statement salt binding tapes labels commit next)
    (currentUpdates 8388608 (fun index => .inl
     (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
      (originalPayload descriptor values coins index) index (tapes index))) labels old) state))
   (fun coins : OriginalCoins => uniformAverage (fun tapes : FullTapes =>
    let frame := literalSourceFrame largeEnough descriptor relation values binding commit coins old
    run true (next (frame.outcome tapes)) (currentSourceOverlay old labels statement salt
     (originalPayload descriptor values coins) frame.opened tapes) state))
   (4 * (queries : ℝ) / (2 ^ 256 : ℝ))
   (fun coins => source_frame_erasure_bound largeEnough descriptor relation values statement salt binding
    commit coins labels next true old state normalized queries (fun tapes => queryBound ((literalSourceFrame largeEnough descriptor relation values binding commit coins old).outcome tapes)))
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: finite_writes_execution"
theorem finite_writes_execution {bound : Nat} (randomized : Bool) (count : Nat)
  (inputs : Fin count → Raw bound) (answers : Fin count → DigestRegister)
  (next : MixedProgram (Raw bound) Work)
  (old : Raw bound → DigestRegister)
  (state : GS bound Work) :
  run randomized ((List.ofFn fun index => (inputs index, answers index)).foldr
   (fun entry rest => .write entry.1 entry.2 rest) next) old state =
   run randomized next (currentUpdates count inputs answers old) state := by
  induction count generalizing old with
  | zero =>
      simp only [List.ofFn_zero, List.foldr_nil, currentUpdates]
  | succ count ih =>
      rw [List.ofFn_succ, List.foldr_cons]
      rw [V8Smz9MixedMaskCompiler.run, currentUpdates]
      exact ih (fun index => inputs index.succ) (fun index => answers index.succ)
        (Function.update old (inputs 0) (answers 0))
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: selected_source_writes_execute"
theorem selected_source_writes_execute {bound : Nat} (randomized : Bool)
  (old : Raw bound → DigestRegister) (labels : Index → DigestRegister)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (payload : Index → Fin 1176 → CByte) (indices : Fin 58 → Index) (tapes : FullTapes)
  (next : MixedProgram (Raw bound) Work)
  (state : GS bound Work) :
  run randomized (selectedWrites (fun opening =>
   NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload (indices opening))
    (indices opening) (tapes (indices opening))) (fun opening => labels (indices opening)) next) old state =
  run randomized next
   (currentSourceOverlay old labels statement salt payload (Finset.univ.image indices) tapes) state := by
 let leaves : Fin 58 → CurrentLeafInput := fun opening =>
   NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
     (payload (indices opening)) (indices opening) (tapes (indices opening))
 let answers : Fin 58 → DigestRegister := fun opening => labels (indices opening)
 let lift : CurrentLeafInput × DigestRegister → Raw bound × DigestRegister :=
   fun entry => (.inl entry.1, entry.2)
 have mapped :
     List.ofFn (fun opening : Fin 58 => ((.inl (leaves opening) : Raw bound), answers opening)) =
       (List.ofFn (fun opening : Fin 58 => (leaves opening, answers opening))).map lift := by
   exact (List.map_ofFn (f := fun opening : Fin 58 => (leaves opening, answers opening))
     (g := lift)).symm
 have foldEq : selectedWrites leaves answers next =
     (List.ofFn (fun opening : Fin 58 => ((.inl (leaves opening) : Raw bound), answers opening))).foldr
       (fun entry rest => .write entry.1 entry.2 rest) next := by
   unfold selectedWrites
   rw [mapped, List.foldr_map]
 rw [foldEq, finite_writes_execution]
 apply congrArg (fun oracle : Raw bound → DigestRegister => run randomized next oracle state)
 dsimp only [leaves, answers]
 let answer : Raw bound → DigestRegister :=
  Sum.elim (fun input => labels (indexProjection input)) (fun input => old (.inr input))
 have outputs : (fun opening => labels (indices opening)) = fun opening => answer (.inl
   (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload (indices opening))
    (indices opening) (tapes (indices opening)))) := by
  funext opening
  simp only [answer, Sum.elim_inl, source_leaf_index]
 conv_lhs => rw [outputs]
 funext input
 rw [current_updates_of_function]
 cases input with
 | inr input => simp [currentSourceOverlay]
 | inl input =>
   have member : (∃ opening : Fin 58,
     NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt (payload (indices opening))
      (indices opening) (tapes (indices opening)) = input) ↔
     input ∈ currentSourcePatch statement salt payload (Finset.univ.image indices) tapes := by
    simp only [currentSourcePatch, Finset.mem_image, Finset.mem_univ, true_and]
    constructor
    ·
      rintro ⟨opening, same⟩
      exact ⟨indices opening, ⟨opening, rfl⟩, same⟩
    ·
      rintro ⟨index, ⟨opening, rfl⟩, same⟩
      exact ⟨opening, same⟩
   simp only [Sum.inl.injEq, currentSourceOverlay, answer, Sum.elim_inl, member]
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: recovered_actual_original_coins"
theorem recovered_actual_original_coins {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (old : Raw bound → DigestRegister) (relation : PublicRelation)
  (values : B.CurrentValues) (binding : Fin 77 → Goldilocks) (commit : CommitPrefix)
  (coins : OriginalCoins) :
  recoveredCoins (currentSourceModel bound (by omega) old relation values commit.hashMt binding
   commit.gamma commit.pendingFailure) (originalResponse largeEnough old relation values binding commit coins)
   (coins.1, coins.2.2.1) coins.2.2.2.1 = coins := by
 rw [recovered_coins_are_mask_inverse, original_response_is_mask_stage]
 exact (B.maskStage _).symm_apply_apply coins
private def selected_frame_left_value {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) : OriginalCoins → FullTapes → ℝ :=
  fun coins : OriginalCoins => fun tapes : FullTapes =>
    let frame := literalSourceFrame largeEnough descriptor relation values binding commit coins old
    run randomized (next (frame.outcome tapes))
     (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) frame.opened tapes) state
private theorem selected_frame_left_value_function {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) :
  (fun coins : OriginalCoins => fun tapes : FullTapes =>
    let frame := literalSourceFrame largeEnough descriptor relation values binding commit coins old
    run randomized (next (frame.outcome tapes))
     (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) frame.opened tapes) state) =
  selected_frame_left_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state := by
 rfl
private def sourceFiberRecoveredBody {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte)
  (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks) (pending : Bool)
  (labels : Index → DigestRegister) (tapes : Index → LeafTape)
  (tails : Tail) (coins : OriginalCoins)
  (oracle : Raw bound → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 let data := originalData values coins
 let heads := originalHeads values coins
 let fields := O.sourceFields relation (prefixGamma «prefix») data points
 let earlier := C.earlier points tails
 let selection := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
  (currentDecsSelection bound largeEnough digest (C.combinationHeads points heads) earlier pending)
 match selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates) with
 | none => next (.error "fixed DECS sampler exhausted its candidate pool")
 | some selected =>
   let targets := selectedTargets descriptor selected
   let later := C.fullSubset heads targets.val tails
   let visible := fun opening => tapes (selected.val opening)
   selectedWrites
    (sourceSelectedLeaves statement salt heads tails coins.2.2.2.2 targets.val selected.val visible)
    (fun opening => labels (selected.val opening))
    (next (scopeReturn selection.pendingFailure (.ok ⟨response.1, «prefix», response.2, digest,
     nonce, points, fields, earlier, later, selected.val, visible⟩)))
private theorem source_fiber_is_recovered_body {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks) (pending : Bool)
  (labels : Index → DigestRegister) (tapes : Index → LeafTape)
  (original : Original) (tails : Tail)
  (oracle : Raw bound → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  sourceOpeningFiber largeEnough descriptor relation values statement salt binding commit response «prefix» digest nonce points pending labels tapes original tails oracle next =
  sourceFiberRecoveredBody largeEnough descriptor relation values statement salt response «prefix» digest nonce points pending labels tapes tails
   (recoveredCoins (currentSourceModel bound (by omega) oracle relation values commit.hashMt binding commit.gamma commit.pendingFailure) response original tails) oracle next := by
 delta sourceOpeningFiber sourceFiberRecoveredBody
 rfl
private def programForCertificate {bound : Nat}
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues) (coins : OriginalCoins)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks) (pending : Bool)
  (labels : Index → DigestRegister) (tapes : FullTapes)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (certificate : Option { indices : Fin 58 → Index // Function.Injective indices }) : MixedProgram (Raw bound) Work :=
 let data := originalData values coins
 let fields := O.sourceFields relation (prefixGamma «prefix») data points
 let heads := originalHeads values coins
 let earlier := C.earlier points coins.2.2.2.1
 match certificate with
 | none => next (.error "fixed DECS sampler exhausted its candidate pool")
 | some selected =>
   let targets := selectedTargets descriptor selected
   let later := C.fullSubset heads targets.val coins.2.2.2.1
   let visible := fun opening => tapes (selected.val opening)
   selectedWrites
    (sourceSelectedLeaves statement salt heads coins.2.2.2.1 coins.2.2.2.2 targets.val selected.val visible)
    (fun opening => labels (selected.val opening))
    (next (scopeReturn pending (.ok ⟨response.1, «prefix», response.2, digest,
     nonce, points, fields, earlier, later, selected.val, visible⟩)))
private theorem recovered_body_is_certificate {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues) (coins : OriginalCoins)
  (old : Raw bound → DigestRegister)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks) (pending : Bool)
  (labels : Index → DigestRegister) (tapes : FullTapes)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  sourceFiberRecoveredBody largeEnough descriptor relation values statement salt response «prefix» digest nonce points pending
   labels tapes coins.2.2.2.1 coins old next =
   let heads := originalHeads values coins
   let earlier := C.earlier points coins.2.2.2.1
   let selection := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
    (currentDecsSelection bound largeEnough digest (C.combinationHeads points heads) earlier pending)
   programForCertificate descriptor relation values coins statement salt response «prefix» digest nonce points
    selection.pendingFailure labels tapes next (selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates)) := by
 delta sourceFiberRecoveredBody programForCertificate
 rfl
private theorem certificate_execution {bound : Nat}
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues) (coins : OriginalCoins)
  (old : Raw bound → DigestRegister)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) («prefix» : PiopPrefix) (transcript : Q)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks) (pending : Bool)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (labels : Index → DigestRegister) (tapes : FullTapes)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (state : GS bound Work)
  (certificate : Option { indices : Fin 58 → Index // Function.Injective indices }) :
  (let frame := frameForCertificate descriptor relation values coins reply «prefix» transcript digest nonce points pending certificate
   run randomized (next (frame.outcome tapes))
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) frame.opened tapes) state) =
  run randomized (programForCertificate descriptor relation values coins statement salt (reply, transcript) «prefix» digest nonce points
   pending labels tapes next certificate) old state := by
 cases certificate with
 | none =>
   dsimp only [frameForCertificate, programForCertificate]
   have emptyOverlay : currentSourceOverlay old labels statement salt
     (originalPayload descriptor values coins) ∅ tapes = old := by
    funext input
    cases input with
    | inl input =>
      simp only [currentSourceOverlay, currentSourcePatch, Finset.image_empty, Finset.notMem_empty, if_false]
    | inr input => rfl
   exact congrArg (fun oracle => run randomized
    (next (.error "fixed DECS sampler exhausted its candidate pool")) oracle state) emptyOverlay
 | some selected =>
   dsimp only [frameForCertificate, programForCertificate]
   let heads := originalHeads values coins
   let fields := O.sourceFields relation (prefixGamma «prefix») (originalData values coins) points
   let earlier := C.earlier points coins.2.2.2.1
   have inputsEq : sourceSelectedLeaves statement salt heads coins.2.2.2.1 coins.2.2.2.2
     (selectedTargets descriptor selected).val selected.val (fun opening => tapes (selected.val opening)) =
    (fun opening => sourceLeafInput statement salt (originalPayload descriptor values coins (selected.val opening))
     (selected.val opening) (tapes (selected.val opening))) := by
    dsimp only [heads, sourceSelectedLeaves, originalPayload, selectedTargets] ; rfl
   let selectedNext := next (scopeReturn pending (.ok (⟨reply, «prefix», transcript, digest, nonce, points,
    fields, earlier, C.fullSubset heads (selectedTargets descriptor selected).val coins.2.2.2.1,
    selected.val, fun opening => tapes (selected.val opening)⟩ : PublicResult)))
   have programEq := congrArg (fun inputs : Fin 58 → CurrentLeafInput =>
    selectedWrites inputs (fun opening => labels (selected.val opening)) selectedNext) inputsEq
   have runEq := congrArg (fun program : MixedProgram (Raw bound) Work => run randomized program old state) programEq
   exact (selected_source_writes_execute randomized old labels statement salt
    (originalPayload descriptor values coins) selected.val tapes selectedNext state).symm.trans runEq.symm
private theorem literal_frame_choice_execution {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (coins : OriginalCoins) (old : Raw bound → DigestRegister)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse)
  («prefix» : PiopPrefix) (transcript : Q)
  (digest : DigestRegister) (choice : OpeningChoice)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (labels : Index → DigestRegister) (tapes : FullTapes)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (state : GS bound Work) :
  (let frame := literalFrameForChoice largeEnough descriptor relation values coins old reply «prefix» transcript digest choice
   run randomized (next (frame.outcome tapes))
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) frame.opened tapes) state) =
  (match choice.selected with
   | none => run randomized (next (.error "smallwood opening nonce trial limit exhausted")) old state
   | some (nonce, words) => run randomized
     (sourceFiberRecoveredBody largeEnough descriptor relation values statement salt (reply, transcript) «prefix» digest nonce
      (sourcePointVector words) choice.pendingFailure labels tapes coins.2.2.2.1 coins old next) old state) := by
 cases choiceEq : choice.selected
 case none =>
  simp only [literalFrameForChoice, choiceEq]
  have emptyOverlay : currentSourceOverlay old labels statement salt
    (originalPayload descriptor values coins) ∅ tapes = old := by
   funext input
   cases input with
   | inl input =>
     simp only [currentSourceOverlay, currentSourcePatch, Finset.image_empty, Finset.notMem_empty, if_false]
   | inr input => rfl
  exact congrArg (fun oracle => run randomized
   (next (.error "smallwood opening nonce trial limit exhausted")) oracle state) emptyOverlay
 case some chosen =>
  rcases chosen with ⟨nonce, words⟩
  let points := sourcePointVector words
  let heads := originalHeads values coins
  let earlier := C.earlier points coins.2.2.2.1
  let selection := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
   (currentDecsSelection bound largeEnough digest (C.combinationHeads points heads) earlier choice.pendingFailure)
  have frameEq := literal_frame_is_certificate largeEnough descriptor relation values coins old
   reply «prefix» transcript digest choice nonce words choiceEq
  have programEq := recovered_body_is_certificate largeEnough descriptor relation values coins old
   statement salt (reply, transcript) «prefix» digest nonce points choice.pendingFailure labels tapes next
  have frameScalarEq := congrArg (fun frame : LiteralSourceFrame =>
   run randomized (next (frame.outcome tapes))
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) frame.opened tapes) state) frameEq
  have programScalarEq := congrArg (fun program : MixedProgram (Raw bound) Work =>
   run randomized program old state) programEq
  exact frameScalarEq.trans ((certificate_execution descriptor relation values coins old reply «prefix» transcript digest
   nonce points selection.pendingFailure statement salt labels tapes next randomized state
   (selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates))).trans programScalarEq.symm)
private def selected_frame_response_value {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) (coins : OriginalCoins) (tapes : FullTapes)
  (response : Response) : ℝ :=
    let «prefix» := responsePrefixValue largeEnough binding commit old response.1
    let digest := responseDigestValue largeEnough old «prefix» response.2
    let choice := responseChoiceValue largeEnough old «prefix» digest
    choiceSourceScalar largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes response «prefix» digest choice
private theorem selected_frame_right_value_as_response_value {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) (coins : OriginalCoins) (tapes : FullTapes) :
  selected_frame_right_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes =
  selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
   (originalResponse largeEnough old relation values binding commit coins) := by
 rfl
private theorem recovered_actual_response_coins {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (old : Raw bound → DigestRegister) (relation : PublicRelation) (values : B.CurrentValues)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (coins : OriginalCoins) :
  recoveredCoins (currentSourceModel bound (by omega) old relation values commit.hashMt binding
   commit.gamma commit.pendingFailure)
   (actualDecsReply values coins commit,
    actualTranscript relation values coins
     (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
      (piopPrefix bound (by omega) commit.hashMt binding (actualDecsReply values coins commit)
       commit.pendingFailure)))
   (coins.1, coins.2.2.1) coins.2.2.2.1 = coins := by
 let recover : Response → OriginalCoins := fun response =>
  recoveredCoins (currentSourceModel bound (by omega) old relation values commit.hashMt binding
   commit.gamma commit.pendingFailure) response (coins.1, coins.2.2.1) coins.2.2.2.1
 have originalRecovery : recover (originalResponse largeEnough old relation values binding commit coins) = coins :=
  recovered_actual_original_coins largeEnough old relation values binding commit coins
 have responseTransport :
   recover (originalResponse largeEnough old relation values binding commit coins) =
   recover (actualDecsReply values coins commit,
    actualTranscript relation values coins
     (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
      (piopPrefix bound (by omega) commit.hashMt binding (actualDecsReply values coins commit)
       commit.pendingFailure))) :=
  congrArg recover (original_response_is_actual_tuple largeEnough old relation values binding commit coins)
 exact responseTransport.symm.trans originalRecovery

private theorem recovered_choice_run_is_opening {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (choice : OpeningChoice)
  (labels : Index → DigestRegister) (tapes : FullTapes) (coins : OriginalCoins)
  (old : Raw bound → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (state : GS bound Work)
  (recoveredEq :
    recoveredCoins (currentSourceModel bound (by omega) old relation values commit.hashMt binding
     commit.gamma commit.pendingFailure) response (coins.1, coins.2.2.1) coins.2.2.2.1 = coins) :
  (match choice.selected with
   | none => run randomized (next (.error "smallwood opening nonce trial limit exhausted")) old state
   | some (nonce, words) => run randomized
     (sourceFiberRecoveredBody largeEnough descriptor relation values statement salt
      response «prefix» digest nonce (sourcePointVector words)
      choice.pendingFailure labels tapes coins.2.2.2.1 coins old next) old state) =
  choiceSourceScalar largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes response «prefix» digest choice := by
 rw [choiceSourceScalar_unfold]
 with_reducible
  cases choiceEq : choice.selected
  case none => rfl
  case some chosen =>
   rcases chosen with ⟨nonce, words⟩
   let points := sourcePointVector words
   let body := sourceFiberRecoveredBody (Work := Work) largeEnough descriptor relation values statement salt response «prefix» digest nonce points choice.pendingFailure labels tapes coins.2.2.2.1
   have fiberProgramEq :=
    (source_fiber_is_recovered_body largeEnough descriptor relation values statement salt binding commit response «prefix» digest nonce points choice.pendingFailure labels tapes (coins.1, coins.2.2.1) coins.2.2.2.1 old next).trans
     (congrArg (fun recovered : OriginalCoins => body recovered old next) recoveredEq)
   exact (congrArg (fun program : MixedProgram (Raw bound) Work => run randomized program old state) fiberProgramEq).symm

private theorem frame_transport_to_choice_source {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (coins : OriginalCoins)
  (reply : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse)
  («prefix» : PiopPrefix) (transcript : Q) (digest : DigestRegister) (choice : OpeningChoice)
  (labels : Index → DigestRegister) (tapes : FullTapes)
  (old : Raw bound → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (state : GS bound Work) (frame : LiteralSourceFrame)
  (frameEq : frame = literalFrameForChoice largeEnough descriptor relation values coins old
    reply «prefix» transcript digest choice)
  (recoveredEq : recoveredCoins (currentSourceModel bound (by omega) old relation values
    commit.hashMt binding commit.gamma commit.pendingFailure) (reply, transcript)
    (coins.1, coins.2.2.1) coins.2.2.2.1 = coins) :
  run randomized (next (frame.outcome tapes))
   (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) frame.opened tapes) state =
  choiceSourceScalar largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes (reply, transcript) «prefix» digest choice := by
 with_reducible
  have frameScalarEq := congrArg (fun sourceFrame : LiteralSourceFrame =>
   run randomized (next (sourceFrame.outcome tapes))
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) sourceFrame.opened tapes) state) frameEq
  have executionEq := literal_frame_choice_execution largeEnough descriptor relation values coins old
   reply «prefix» transcript digest choice statement salt labels tapes next randomized state
  have choiceRunEq := recovered_choice_run_is_opening largeEnough descriptor relation values
   statement salt binding commit (reply, transcript) «prefix» digest choice labels tapes coins old
   next randomized state recoveredEq
  exact frameScalarEq.trans (executionEq.trans choiceRunEq)

private theorem selected_frame_response_value_function {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) (coins : OriginalCoins) (tapes : FullTapes)
  : (fun response : Response =>
    let «prefix» := responsePrefixValue largeEnough binding commit old response.1
    let digest := responseDigestValue largeEnough old «prefix» response.2
    let choice := responseChoiceValue largeEnough old «prefix» digest
    choiceSourceScalar largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes response «prefix» digest choice) =
   selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes := by
 rfl

private theorem certified_opening_frame {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (coins : OriginalCoins)
  (old : Raw bound → DigestRegister) :
  literalSourceFrame largeEnough descriptor relation values binding commit coins old =
   let computed := (certifiedOpening largeEnough old relation values binding commit coins).val
   literalFrameForChoice largeEnough descriptor relation values coins old
    computed.reply computed.prefixValue computed.transcript computed.digest computed.choice := by
 let frameOf : CertifiedOpeningValues → LiteralSourceFrame := fun computed =>
  literalFrameForChoice largeEnough descriptor relation values coins old
   computed.reply computed.prefixValue computed.transcript computed.digest computed.choice
 have literalEq :=
  literal_source_frame_is_choice largeEnough descriptor relation values binding commit coins old
 have certificateEq := congrArg frameOf
  (certifiedOpening largeEnough old relation values binding commit coins).property
 dsimp only [frameOf, literalOpening, responsePrefixValue, responseDigestValue,
  responseChoiceValue] at certificateEq
 exact literalEq.trans certificateEq.symm

private theorem certified_opening_recovery {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (old : Raw bound → DigestRegister) (relation : PublicRelation) (values : B.CurrentValues)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (coins : OriginalCoins) :
  let computed := (certifiedOpening largeEnough old relation values binding commit coins).val
  recoveredCoins (currentSourceModel bound (by omega) old relation values commit.hashMt binding
   commit.gamma commit.pendingFailure) (computed.reply, computed.transcript)
   (coins.1, coins.2.2.1) coins.2.2.2.1 = coins := by
 let recoveryOf : CertifiedOpeningValues → OriginalCoins := fun computed =>
  recoveredCoins (currentSourceModel bound (by omega) old relation values commit.hashMt binding
   commit.gamma commit.pendingFailure) (computed.reply, computed.transcript)
   (coins.1, coins.2.2.1) coins.2.2.2.1
 have literalEq :
   recoveryOf (literalOpening largeEnough old relation values binding commit coins) = coins :=
  recovered_actual_response_coins largeEnough old relation values binding commit coins
 have certificateEq := congrArg recoveryOf
  (certifiedOpening largeEnough old relation values binding commit coins).property
 exact certificateEq.trans literalEq

private theorem literal_opening_scalar_is_response {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work)
  (coins : OriginalCoins) (tapes : FullTapes) :
  (let computed := literalOpening largeEnough old relation values binding commit coins
   choiceSourceScalar largeEnough descriptor relation values statement salt binding commit labels
    next randomized old state coins tapes (computed.reply, computed.transcript)
    computed.prefixValue computed.digest computed.choice) =
  selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
   (actualDecsReply values coins commit,
    actualTranscript relation values coins
     (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
      (piopPrefix bound (by omega) commit.hashMt binding (actualDecsReply values coins commit)
       commit.pendingFailure))) := by
 with_reducible
  dsimp only [literalOpening, responsePrefixValue, responseDigestValue, responseChoiceValue,
   selected_frame_response_value]

private theorem certified_opening_scalar_is_response {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work)
  (coins : OriginalCoins) (tapes : FullTapes) :
  (let computed := (certifiedOpening largeEnough old relation values binding commit coins).val
   choiceSourceScalar largeEnough descriptor relation values statement salt binding commit labels
    next randomized old state coins tapes (computed.reply, computed.transcript)
    computed.prefixValue computed.digest computed.choice) =
  selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
   (actualDecsReply values coins commit,
    actualTranscript relation values coins
     (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
      (piopPrefix bound (by omega) commit.hashMt binding (actualDecsReply values coins commit)
       commit.pendingFailure))) := by
 let scalarOf : CertifiedOpeningValues → ℝ := fun computed =>
  choiceSourceScalar largeEnough descriptor relation values statement salt binding commit labels
   next randomized old state coins tapes (computed.reply, computed.transcript)
   computed.prefixValue computed.digest computed.choice
 have certificateEq := congrArg scalarOf
  (certifiedOpening largeEnough old relation values binding commit coins).property
 exact certificateEq.trans
  (literal_opening_scalar_is_response largeEnough descriptor relation values statement salt binding
   commit labels next randomized old state coins tapes)

private theorem selected_frame_actual_value_is_source {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work)
  (coins : OriginalCoins) (tapes : FullTapes) :
  selected_frame_left_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes =
  selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
   (actualDecsReply values coins commit,
    actualTranscript relation values coins
     (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
      (piopPrefix bound (by omega) commit.hashMt binding (actualDecsReply values coins commit)
       commit.pendingFailure))) := by
 q58_alpha_share
  with_reducible
   let computed := (certifiedOpening largeEnough old relation values binding commit coins).val
   have leftEq := congrFun
    (congrFun (selected_frame_left_value_function largeEnough descriptor relation values
     statement salt binding commit labels next randomized old state) coins) tapes
   have frameEq := certified_opening_frame largeEnough descriptor relation values binding commit coins old
   have recoveredEq := certified_opening_recovery largeEnough old relation values binding commit coins
   have transportEq := frame_transport_to_choice_source largeEnough descriptor relation values
    statement salt binding commit coins computed.reply computed.prefixValue computed.transcript
    computed.digest computed.choice labels tapes old next randomized state
    (literalSourceFrame largeEnough descriptor relation values binding commit coins old)
    frameEq recoveredEq
   have responseEq := certified_opening_scalar_is_response largeEnough descriptor relation values
    statement salt binding commit labels next randomized old state coins tapes
   exact leftEq.symm.trans (transportEq.trans responseEq)

private theorem selected_frame_value_is_cleared_source {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work)
  (coins : OriginalCoins) (tapes : FullTapes) :
  selected_frame_left_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes =
  selected_frame_right_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes := by
 with_reducible
  have rightAtOriginal :
    selected_frame_right_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes =
    selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
     (originalResponse largeEnough old relation values binding commit coins) :=
   selected_frame_right_value_as_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
  have responseTransport :
    selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
     (originalResponse largeEnough old relation values binding commit coins) =
    selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
     (actualDecsReply values coins commit,
     actualTranscript relation values coins
      (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
       (piopPrefix bound (by omega) commit.hashMt binding (actualDecsReply values coins commit)
        commit.pendingFailure))) :=
   congrArg
    (selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes)
    (original_response_is_actual_tuple largeEnough old relation values binding commit coins)
  have actualValue :
    selected_frame_left_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes =
    selected_frame_response_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
     (actualDecsReply values coins commit,
     actualTranscript relation values coins
      (V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
       (piopPrefix bound (by omega) commit.hashMt binding (actualDecsReply values coins commit)
        commit.pendingFailure))) :=
   selected_frame_actual_value_is_source largeEnough descriptor relation values statement salt binding commit labels next randomized old state coins tapes
  exact actualValue.trans (responseTransport.symm.trans rightAtOriginal.symm)

private abbrev selected_frame_average_proof {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) :=
 double_average_congr (A := OriginalCoins) (B := FullTapes)
  (selected_frame_left_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state)
  (selected_frame_right_value largeEnough descriptor relation values statement salt binding commit labels next randomized old state)
  (selected_frame_value_is_cleared_source largeEnough descriptor relation values statement salt binding commit labels next randomized old state)
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: selected_frame_average_is_cleared_source"
theorem selected_frame_average_is_cleared_source {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool) (old : Raw bound → DigestRegister)
  (state : GS bound Work) :
  uniformAverage (fun coins : OriginalCoins => uniformAverage (fun tapes : FullTapes =>
   let frame := literalSourceFrame largeEnough descriptor relation values binding commit coins old
   run randomized (next (frame.outcome tapes))
    (currentSourceOverlay old labels statement salt (originalPayload descriptor values coins) frame.opened tapes) state)) =
  clearedSourceValue largeEnough descriptor relation values statement salt binding commit labels next randomized old state := by
 let average : (OriginalCoins → FullTapes → ℝ) → ℝ :=
  fun value => uniformAverage (fun coins : OriginalCoins =>
   uniformAverage (fun tapes : FullTapes => value coins tapes))
 have leftEq := congrArg average (selected_frame_left_value_function largeEnough descriptor relation values statement salt binding commit labels next randomized old state)
 exact leftEq.trans ((selected_frame_average_proof largeEnough descriptor relation values statement salt binding commit labels next randomized old state))
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: publicLabelSource"
def publicLabelSource : V8Smz9HonestWholeViewGames.RandomSource :=
 functionRandomSource Index DigestRegister
private theorem public_label_random_execution {bound : Nat}
  (source : V8Smz9HonestWholeViewGames.RandomSource)
  (randomized : Bool) (next : source.Coins → MixedProgram (Raw bound) Work)
  (old : Raw bound → DigestRegister) (state : GS bound Work) :
  run randomized (.random source next) old state =
   @uniformAverage source.Coins source.finite source.inhabited
    (fun coins : source.Coins => run randomized (next coins) old state) := by
 rfl
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: completePublicSimulator"
def completePublicSimulator {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (relation : PublicRelation) (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (binding : Fin 77 → Goldilocks)
  (next : Option ((Index → DigestRegister) × CommitPrefix) → Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 match currentDescriptor with
 | none => next none (.error "smallwood strict-ZK DECS coset search exhausted")
 | some descriptor => .random publicLabelSource fun labels =>
   compileNonleaf (currentCommitPrefix bound largeEnough salt binding labels) fun commit =>
    clearedPublicRequest largeEnough descriptor relation statement salt binding commit labels
     (next (some (labels, commit)))
private abbrev actual_selected_average_public {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (valid : O.Satisfies relation values) (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (old : Raw bound → DigestRegister) (state : GS bound Work) :=
  (selected_frame_average_is_cleared_source largeEnough descriptor relation values
    statement salt binding commit labels next true old state).trans
    (cleared_source_game_is_public largeEnough descriptor relation values valid
      statement salt binding commit labels next true old state)

private theorem triple_average_difference_le
  {Coins Tapes Labels : Type*} [Fintype Coins] [Nonempty Coins]
  [Fintype Tapes] [Nonempty Tapes] [Fintype Labels] [Nonempty Labels]
  (left : Coins → Tapes → Labels → ℝ) (right : Labels → ℝ) (loss : ℝ)
  (pointwise : ∀ labels, |uniformAverage (fun coins : Coins =>
    uniformAverage (fun tapes : Tapes => left coins tapes labels)) - right labels| ≤ loss) :
  |uniformAverage (fun coins : Coins => uniformAverage (fun tapes : Tapes =>
    uniformAverage (fun labels : Labels => left coins tapes labels))) - uniformAverage right| ≤ loss := by
 simp_rw [uniform_average_comm (A := Tapes) (B := Labels)]
 rw [uniform_average_comm (A := Coins) (B := Labels)]
 exact uniform_average_difference_le
  (fun labels => uniformAverage (fun coins => uniformAverage (fun tapes => left coins tapes labels)))
  right loss pointwise
private theorem scalar_difference_bound_transport
  (left source target loss : ℝ) (same : source = target)
  (bounded : |left - source| ≤ loss) : |left - target| ≤ loss := by
 exact (congrArg (fun rhs : ℝ => |left - rhs| ≤ loss) same).mp bounded
private theorem pointwise_source_public_bound {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (valid : O.Satisfies relation values) (statement : Fin 616 → CByte) (salt : Fin 32 → CByte)
  (binding : Fin 77 → Goldilocks) (commit : CommitPrefix) (labels : Index → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (old : Raw bound → DigestRegister) (state : GS bound Work) (normalized : ‖state‖ = 1)
  (queries : Nat) (queryBound : ∀ result,
   V8Smz9HonestWholeViewGames.queryCount (compile (next result) []) ≤ queries) :
  |uniformAverage (fun coins : OriginalCoins => uniformAverage (fun tapes : FullTapes => run true
    (originalAfterCommit largeEnough descriptor relation values coins statement salt binding
     tapes labels commit next)
    (currentUpdates 8388608 (fun index => .inl
     (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
      (originalPayload descriptor values coins index) index (tapes index))) labels old) state)) -
   run true (clearedPublicRequest largeEnough descriptor relation statement salt binding commit labels next)
    old state| ≤ 4 * (queries : ℝ) / (2 ^ 256 : ℝ) := by
 with_reducible
  exact scalar_difference_bound_transport
   (uniformAverage (fun coins : OriginalCoins => uniformAverage (fun tapes : FullTapes => run true
    (originalAfterCommit largeEnough descriptor relation values coins statement salt binding
     tapes labels commit next)
    (currentUpdates 8388608 (fun index => .inl
     (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
      (originalPayload descriptor values coins index) index (tapes index))) labels old) state))) _ _ (4 * (queries : ℝ) / (2 ^ 256 : ℝ))
   (actual_selected_average_public largeEnough descriptor relation values valid
    statement salt binding commit labels next old state)
   (actual_erasure_average_bound largeEnough descriptor relation values statement salt binding
    commit labels next old state normalized queries queryBound)
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_START: protected_source_complete_public_bound"
theorem protected_source_complete_public_bound {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (relation : PublicRelation) (values : B.CurrentValues) (valid : O.Satisfies relation values)
  (statement : Fin 616 → CByte) (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (next : Option ((Index → DigestRegister) × CommitPrefix) → Except String PublicResult → MixedProgram (Raw bound) Work)
  (old : Raw bound → DigestRegister) (state : GS bound Work) (normalized : ‖state‖ = 1)
  (queries : Nat) (callerQueries : ∀ context result,
   V8Smz9HonestWholeViewGames.queryCount (compile (next context result) []) ≤ queries) :
  |run true (originalRequest largeEnough relation values statement salt binding next) old state -
   run true (completePublicSimulator largeEnough relation statement salt binding next) old state| ≤
    4 * (queries : ℝ) / (2 ^ 256 : ℝ) := by
 have comparison (descriptorChoice : Option Descriptor)
   (constructed : currentDescriptor = descriptorChoice) :
   |run true (originalRequest largeEnough relation values statement salt binding next) old state -
    run true (completePublicSimulator largeEnough relation statement salt binding next) old state| ≤
     4 * (queries : ℝ) / (2 ^ 256 : ℝ) := by
  cases descriptorChoice with
  | none => simp only [originalRequest, completePublicSimulator, constructed, sub_self, abs_zero]; positivity
  | some descriptor =>
    with_reducible
     rw [protected_original_source_expansion largeEnough descriptor constructed]
     simp only [completePublicSimulator, constructed]
     rw [public_label_random_execution publicLabelSource]
     dsimp (config := { instances := true }) only [publicLabelSource, functionRandomSource]
     refine triple_average_difference_le
      (fun coins : OriginalCoins => fun tapes : FullTapes => fun labels : Index → DigestRegister =>
       let commit := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
        (currentCommitPrefix bound largeEnough salt binding labels)
       run true (originalAfterCommit largeEnough descriptor relation values coins statement salt binding
        tapes labels commit (next (some (labels, commit))))
        (currentUpdates 8388608 (fun index => .inl
         (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
          (originalPayload descriptor values coins index) index (tapes index))) labels old) state)
      (fun labels : Index → DigestRegister => run true
       (compileNonleaf (currentCommitPrefix bound largeEnough salt binding labels)
        (fun commit => clearedPublicRequest largeEnough descriptor relation statement salt binding commit labels
         (next (some (labels, commit))))) old state)
      (4 * (queries : ℝ) / (2 ^ 256 : ℝ)) ?_
     intro labels
     rw [compile_nonleaf_executes true (currentCommitPrefix bound largeEnough salt binding labels)
      (fun commit => clearedPublicRequest largeEnough descriptor relation statement salt binding commit labels
       (next (some (labels, commit)))) old state]
     let commit := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => old (.inr input))
      (currentCommitPrefix bound largeEnough salt binding labels)
     let continuation := next (some (labels, commit))
     exact pointwise_source_public_bound largeEnough descriptor relation values valid
      statement salt binding commit labels continuation old state normalized queries
      (fun result => callerQueries (some (labels, commit)) result)
 exact comparison currentDescriptor rfl
#eval IO.eprintln "COMPLETE_PUBLIC_JOIN_DECL_EOF"
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCompletePublicJoin
