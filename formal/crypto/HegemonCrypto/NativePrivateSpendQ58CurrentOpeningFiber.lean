import HegemonCrypto.NativePrivateSpendQ58CurrentOriginalRequest
/-! The actual successful-nonce continuation has one response-indexed affine
transport. The fixed-pool failure is retained in the total fiber rather than
conditioning on success. The same raw table, state, selected original tapes
and externally supplied continuation are used on both sides. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOpeningFiber
open V8Smz9CurrentPrivacyGame
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9HiddenLeafQrom
open V8Smz9HonestOpeningSchedule V8Smz9MixedMaskCompiler
open NativePrivateSpendQ58CurrentLeafInput NativePrivateSpendQ58CurrentSelectedLeaf
open NativePrivateSpendQ58CurrentChronologicalRequest NativePrivateSpendQ58CurrentCosetSelector
open NativePrivateSpendQ58CurrentCoinObservation NativePrivateSpendQ58CurrentInitializedPublic
open NativePrivateSpendQ58CurrentOriginalRequest
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option stderrAsMessages false
abbrev CByte := HegemonCrypto.CanonicalBytes.Byte
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: CByte"
abbrev Raw (bound : Nat) := CurrentFullRawInput bound
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: Raw"
abbrev GS (bound : Nat) (Work : Type) [Fintype Work] :=
 V8Smz9HonestWholeViewGames.GameState (Input := Raw bound) (Work := Work)
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: GS"
namespace B
export NativePrivateSpendQ58CurrentRowBoundary
 (CurrentModel CurrentValues Response maskInverse maskStage conditionedEquiv remainingEquiv)
end B
namespace C
export NativePrivateSpendQ58Compff01OpeningContinuation
 (Tails Targets earlier fullSubset combinationHeads feedback_exact)
end C
namespace O
export NativePrivateSpendQ58CurrentPublicOpening
 (packing_injective PublicFields Satisfies sourceFields sourceDecsResponse publicHeads public_heads_are_current_matrix)
end O
abbrev Original := CurrentPublicScalars
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: Original"
abbrev Tail := C.Tails
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: Tail"
abbrev Response := B.Response
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: Response"
theorem currentWitnessAdmissible (points : Fin 6 → Goldilocks)
  (accepted : currentOpeningAdmissible points) : Smz9WitnessInterpolationAdmissible points :=
 ⟨NativePrivateSpendQ58CurrentPublicOpening.packing_injective, accepted.1, accepted.2.2.1⟩
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: currentWitnessAdmissible"
variable {Work : Type} [Fintype Work]
def actualPublicSelection {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (oracle : Raw bound → DigestRegister) (relation : PublicRelation)
  («prefix» : PiopPrefix) (response : Response) (digest : DigestRegister)
  (points : Fin 6 → Goldilocks) (pending : Bool)
  (observed : Original) (earlier : CurrentEarlier) : DecsSelection :=
 V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
  (currentDecsSelection bound largeEnough digest
   (O.publicHeads relation (observedPublicFields (prefixGamma «prefix») response.2 observed) points)
   earlier pending)
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: actualPublicSelection"
def actualPublicTargets {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (oracle : Raw bound → DigestRegister)
  (relation : PublicRelation) («prefix» : PiopPrefix) (response : Response)
  (digest : DigestRegister) (points : Fin 6 → Goldilocks) (pending : Bool)
  (observed : Original) (earlier : CurrentEarlier) : C.Targets :=
 match selectedCertificate (sourceReturnedWords 80
   (actualPublicSelection largeEnough oracle relation «prefix» response digest points pending observed earlier).sampledCandidates) with
 | none => fallbackTargets descriptor
 | some selected => selectedTargets descriptor selected
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: actualPublicTargets"
def recoveredCoins (model : B.CurrentModel) (response : Response)
  (original : Original) (tails : Tail) : OriginalCoins :=
 let masks := B.maskInverse model (original.1, original.2, tails) response
 (original.1, masks.1, original.2, tails, masks.2)
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: recoveredCoins"
theorem recovered_coins_are_mask_inverse (model : B.CurrentModel) (response : Response)
  (original : Original) (tails : Tail) :
  recoveredCoins model response original tails = (B.maskStage model).symm (response, (original, tails)) := rfl
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: recovered_coins_are_mask_inverse"
def sourceOpeningFiber {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (response : Response) («prefix» : PiopPrefix)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks) (pending : Bool)
  (labels : Index → DigestRegister) (tapes : Index → LeafTape)
  (original : Original) (tails : Tail)
  (oracle : Raw bound → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 let model := currentSourceModel bound (by omega) oracle relation values
  commit.hashMt binding commit.gamma commit.pendingFailure
 let coins := recoveredCoins model response original tails
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
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: sourceOpeningFiber"
def publicOpeningFiber {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (commit : CommitPrefix)
  (response : Response) («prefix» : PiopPrefix) (digest : DigestRegister)
  (nonce : Fin 16) (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
  (pending : Bool) (labels : Index → DigestRegister) (tapes : Index → LeafTape)
  (observed : Original) (earlier : CurrentEarlier) (later : CurrentLater)
  (oracle : Raw bound → DigestRegister)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  MixedProgram (Raw bound) Work :=
 let fields := observedPublicFields (prefixGamma «prefix») response.2 observed
 let heads := O.publicHeads relation fields points
 let selection := actualPublicSelection largeEnough oracle relation «prefix» response digest points pending observed earlier
 match selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates) with
 | none => next (.error "fixed DECS sampler exhausted its candidate pool")
 | some selected =>
   let targets := selectedTargets descriptor selected
   let visible := fun opening => tapes (selected.val opening)
   selectedWrites
    (publicSelectedLeaves statement salt response.1 commit.gamma points distinct heads earlier later
     targets.val selected.val visible)
    (fun opening => labels (selected.val opening))
    (next (scopeReturn selection.pendingFailure (.ok ⟨response.1, «prefix», response.2, digest,
     nonce, points, fields, earlier, later, selected.val, visible⟩)))
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: publicOpeningFiber"
theorem source_opening_fiber_is_public {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (valid : O.Satisfies relation values)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (response : Response)
  (oracle : Raw bound → DigestRegister)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks)
  (accepted : currentOpeningAdmissible points) (pending : Bool)
  (labels : Index → DigestRegister) (tapes : Index → LeafTape)
  (original : Original) (tails : Tail)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work) :
  let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
   (piopPrefix bound (by omega) commit.hashMt binding response.1 commit.pendingFailure)
  let model := currentSourceModel bound (by omega) oracle relation values
   commit.hashMt binding commit.gamma commit.pendingFailure
  let e := B.remainingEquiv values points
   (currentWitnessAdmissible points accepted) accepted.2.1 model response
   (fun witness pcs => actualPublicTargets largeEnough descriptor oracle relation «prefix» response digest points pending (witness, pcs))
  sourceOpeningFiber largeEnough descriptor relation values statement salt binding commit response «prefix»
   digest nonce points pending labels tapes original tails oracle next =
  publicOpeningFiber largeEnough descriptor relation statement salt commit response «prefix» digest nonce
   points accepted.1 pending labels tapes (e (original, tails)).1
   (e (original, tails)).2.1 (e (original, tails)).2.2 oracle next := by
 fail_if_success
  run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: SOURCE_PROOF_START") : Lean.Elab.Tactic.TacticM Unit)
  fail
 have acceptedOriginal : currentOpeningAdmissible points := accepted
 have distinct : Function.Injective points := accepted.1
 have nonzero : ∀ opening, points opening ≠ 0 := accepted.2.1
 dsimp only
 let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
  (piopPrefix bound (by omega) commit.hashMt binding response.1 commit.pendingFailure)
 let model := currentSourceModel bound (by omega) oracle relation values
  commit.hashMt binding commit.gamma commit.pendingFailure
 let masks := B.maskInverse model (original.1, original.2, tails) response
 let coins := recoveredCoins model response original tails
 let data := originalData values coins
 let heads := originalHeads values coins
 let observed := B.conditionedEquiv values points
  (currentWitnessAdmissible points acceptedOriginal) nonzero model response original
 fail_if_success
  run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: FIELDS_START") : Lean.Elab.Tactic.TacticM Unit)
  fail
 have fields : O.sourceFields relation (prefixGamma «prefix») data points =
   observedPublicFields (prefixGamma «prefix») response.2 observed := by
  exact source_fields_are_conditioned_public bound (by omega) oracle relation values commit.hashMt
   binding commit.gamma commit.pendingFailure response points
   (currentWitnessAdmissible points acceptedOriginal) nonzero original
 fail_if_success
  run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: FIELDS_RETURNED") : Lean.Elab.Tactic.TacticM Unit)
  fail
 have headsPublic : O.publicHeads relation
   (observedPublicFields (prefixGamma «prefix») response.2 observed) points =
   C.combinationHeads points heads := by
  rw [← fields]
  exact O.public_heads_are_current_matrix relation (prefixGamma «prefix») data valid points accepted.2.2.1
 fail_if_success
  run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: REPLY_START") : Lean.Elab.Tactic.TacticM Unit)
  fail
 have reply : O.sourceDecsResponse heads tails commit.gamma masks.2 = response.1 := by
  with_reducible
   rw [decs_source_response_is_offset commit.gamma heads tails masks.2]
   dsimp only [masks, B.maskInverse, heads, originalHeads, originalData,
    coins, recoveredCoins, model, currentSourceModel]
   exact add_sub_cancel _ _
 fail_if_success
  run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: REPLY_RETURNED") : Lean.Elab.Tactic.TacticM Unit)
  fail
 let choose := actualPublicTargets largeEnough descriptor oracle relation «prefix» response digest points pending
 let early := C.earlier points tails
 have actualSelection : actualPublicSelection largeEnough oracle relation «prefix» response digest points
   pending observed early = V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
   (currentDecsSelection bound largeEnough digest (C.combinationHeads points heads) early pending) := by
  unfold actualPublicSelection
  rw [headsPublic]
 fail_if_success
  run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: TRANSPORT_START") : Lean.Elab.Tactic.TacticM Unit)
  fail
 have transported : B.remainingEquiv values points (currentWitnessAdmissible points acceptedOriginal) nonzero
   model response (fun witness pcs => choose (witness, pcs)) (original, tails) =
   (observed, (early, C.fullSubset heads (choose observed early).val tails)) := by
  let ce := B.conditionedEquiv values points (currentWitnessAdmissible points acceptedOriginal)
   nonzero model response
  unfold B.remainingEquiv NativePrivateSpendQ58ChronologicalMasks.fiberEquiv
  change (observed, NativePrivateSpendQ58Compff01OpeningContinuation.feedbackEquiv
    points distinct
    (model.heads (ce.symm observed).1 (ce.symm observed).2
      (response.2 - model.piopUnmasked (ce.symm observed).1 response.1))
    (choose observed) tails) =
   (observed, (early, C.fullSubset heads (choose observed early).val tails))
  with_reducible
   rw [ce.symm_apply_apply original]
   rw [C.feedback_exact]
   dsimp only [heads, originalHeads, originalData, coins, recoveredCoins,
    model, currentSourceModel, B.maskInverse]
 fail_if_success
  run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: TRANSPORT_RETURNED") : Lean.Elab.Tactic.TacticM Unit)
  fail
 with_reducible
  rw [transported]
  fail_if_success
   run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: BODY_UNFOLD_START") : Lean.Elab.Tactic.TacticM Unit)
   fail
  simp only [sourceOpeningFiber, publicOpeningFiber]
  fail_if_success
   run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: PUBLIC_REWRITE_START") : Lean.Elab.Tactic.TacticM Unit)
   fail
  rw [fields, headsPublic, ← actualSelection]
  fail_if_success
   run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: SELECTED_CASES_START") : Lean.Elab.Tactic.TacticM Unit)
   fail
  cases selected : selectedCertificate (sourceReturnedWords 80
    (actualPublicSelection largeEnough oracle relation «prefix» response digest points pending observed early).sampledCandidates) with
  | none => rfl
  | some indices =>
    have chosen : choose observed early = selectedTargets descriptor indices := by
     simp only [choose, actualPublicTargets, selected]
    simp only [chosen]
    fail_if_success
     run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: REPLY_REWRITE_START") : Lean.Elab.Tactic.TacticM Unit)
     fail
    have leafEquality :
        publicSelectedLeaves statement salt response.1 commit.gamma points distinct
          (C.combinationHeads points heads) early
          (C.fullSubset heads (selectedTargets descriptor indices).val tails)
          (selectedTargets descriptor indices).val indices.val
          (fun opening => tapes (indices.val opening)) =
        sourceSelectedLeaves statement salt heads tails masks.2
          (selectedTargets descriptor indices).val indices.val
          (fun opening => tapes (indices.val opening)) := by
      rw [← reply]
      exact public_selected_leaf_addresses_are_source statement salt points distinct
        heads tails commit.gamma masks.2 (selectedTargets descriptor indices).val
        indices.val (fun opening => tapes (indices.val opening))
    fail_if_success
     run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: LEAF_REWRITE_START") : Lean.Elab.Tactic.TacticM Unit)
     fail
    rw [leafEquality]
    dsimp only [heads, masks, early, «prefix», coins, recoveredCoins, model]
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: source_opening_fiber_is_public"
theorem opening_fiber_game_equality {bound : Nat} (largeEnough : 1264811 ≤ bound)
  (descriptor : Descriptor) (relation : PublicRelation) (values : B.CurrentValues)
  (valid : O.Satisfies relation values)
  (statement : Fin 616 → CByte)
  (salt : Fin 32 → CByte) (binding : Fin 77 → Goldilocks)
  (commit : CommitPrefix) (response : Response)
  (oracle : Raw bound → DigestRegister)
  (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks)
  (accepted : currentOpeningAdmissible points) (pending : Bool)
  (labels : Index → DigestRegister) (tapes : Index → LeafTape)
  (next : Except String PublicResult → MixedProgram (Raw bound) Work)
  (randomized : Bool)
  (state : GS bound Work) :
  let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
   (piopPrefix bound (by omega) commit.hashMt binding response.1 commit.pendingFailure)
  uniformAverage (fun source : Original × Tail =>
   run randomized (sourceOpeningFiber largeEnough descriptor relation values statement salt binding
    commit response «prefix» digest nonce points pending labels tapes source.1 source.2 oracle next) oracle state) =
  uniformAverage (fun observed : Original => uniformAverage (fun earlier : CurrentEarlier =>
   uniformAverage (fun later : CurrentLater => run randomized
    (publicOpeningFiber largeEnough descriptor relation statement salt commit response «prefix» digest nonce
     points accepted.1 pending labels tapes observed earlier later oracle next) oracle state))) := by
 have acceptedOriginal : currentOpeningAdmissible points := accepted
 have distinct : Function.Injective points := accepted.1
 have nonzero : ∀ opening, points opening ≠ 0 := accepted.2.1
 with_reducible
  fail_if_success
   run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: GAME_PROOF_START") : Lean.Elab.Tactic.TacticM Unit)
   fail
  dsimp only
  let «prefix» := V8Smz9HonestRequestSchedule.NonleafProgram.interpret (fun input => oracle (.inr input))
   (piopPrefix bound (by omega) commit.hashMt binding response.1 commit.pendingFailure)
  let model := currentSourceModel bound (by omega) oracle relation values
   commit.hashMt binding commit.gamma commit.pendingFailure
  let e := B.remainingEquiv values points (currentWitnessAdmissible points acceptedOriginal) nonzero model response
   (fun witness pcs => actualPublicTargets largeEnough descriptor oracle relation «prefix» response digest points pending (witness, pcs))
  let publicView : Original × (CurrentEarlier × CurrentLater) → ℝ := fun view =>
   run randomized
    (publicOpeningFiber largeEnough descriptor relation statement salt commit response «prefix» digest nonce
     points distinct pending labels tapes view.1 view.2.1 view.2.2 oracle next) oracle state
  calc
   _ = uniformAverage (fun source : Original × Tail => publicView (e source)) := by
    fail_if_success
     run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: GAME_TRANSPORT_START") : Lean.Elab.Tactic.TacticM Unit)
     fail
    apply congrArg uniformAverage
    funext source
    exact congrArg (fun program : MixedProgram (Raw bound) Work => run randomized program oracle state)
      (source_opening_fiber_is_public largeEnough descriptor relation values valid statement salt
        binding commit response oracle digest nonce points acceptedOriginal pending labels tapes source.1 source.2 next)
   _ = uniformAverage publicView :=
    uniform_average_equiv e publicView
   _ = uniformAverage (fun observed : Original =>
        uniformAverage (fun view : CurrentEarlier × CurrentLater => publicView (observed, view))) := by
    fail_if_success
     run_tac (liftM (IO.eprintln "OPENING_FIBER_PHASE: GAME_PRODUCT_START") : Lean.Elab.Tactic.TacticM Unit)
     fail
    exact V8Smz9HonestLeafBatch.uniform_average_product
      (fun (observed : Original) (view : CurrentEarlier × CurrentLater) => publicView (observed, view))
   _ = _ := by
    apply congrArg uniformAverage
    funext observed
    exact V8Smz9HonestLeafBatch.uniform_average_product
      (fun (earlier : CurrentEarlier) (later : CurrentLater) => publicView (observed, (earlier, later)))
#eval IO.eprintln "OPENING_FIBER_DECL_DONE: opening_fiber_game_equality"
#eval IO.eprintln "OPENING_FIBER_DECL_EOF"
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOpeningFiber
