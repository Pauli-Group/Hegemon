import HegemonCrypto.NativePrivateSpendQ58CurrentHistoryMass

/-! The literal current public simulator is a mass-preserving continuation
context. This proof follows its actual random draws, reads and fixed writes;
no response equality, successful-branch coverage or normalized history is
supplied. All abort outputs are passed to the same continuation. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentHistoryContinuation
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9MixedMaskCompiler V8Smz9MeasuredRunContinuity V8Smz9CurrentPrivacyComposition
open V8Smz9HonestRequestSchedule
open NativePrivateSpendQ58CurrentLeafInput NativePrivateSpendQ58CurrentSelectedLeaf
open NativePrivateSpendQ58CurrentChronologicalRequest NativePrivateSpendQ58CurrentCosetSelector
open NativePrivateSpendQ58CurrentCoinObservation NativePrivateSpendQ58CurrentInitializedPublic
open NativePrivateSpendQ58CurrentOriginalRequest NativePrivateSpendQ58CurrentCompletePublicJoin
open NativePrivateSpendQ58CurrentHistoryMass
open scoped Classical BigOperators
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

section Generic
variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

def BoundedDifference (left right : MixedProgram Input Work) (loss : ℝ) : Prop :=
  ∀ (old : Input → DigestRegister)
    (state : V8Smz9HonestWholeViewGames.GameState (Input := Input) (Work := Work)),
    |V8Smz9MixedMaskCompiler.run true left old state -
      V8Smz9MixedMaskCompiler.run true right old state| ≤ loss * ‖state‖ ^ 2

theorem random_difference_bound (source : V8Smz9HonestWholeViewGames.RandomSource)
    (left right : source.Coins → MixedProgram Input Work) (loss : ℝ)
    (bounded : ∀ coins, BoundedDifference (left coins) (right coins) loss) :
    BoundedDifference (.random source left) (.random source right) loss := by
  intro old state
  apply (average_difference_abs_le _ _).trans
  exact (average_mono _ _ (fun coins => bounded coins old state)).trans_eq
    (uniform_average_const (loss * ‖state‖ ^ 2))

theorem read_difference_bound (input : Input)
    (left right : DigestRegister → MixedProgram Input Work) (loss : ℝ)
    (bounded : ∀ answer, BoundedDifference (left answer) (right answer) loss) :
    BoundedDifference (.honestRead input left) (.honestRead input right) loss := by
  intro old state
  exact bounded (old input) old state

theorem gate_difference_bound (operation : V8Smz9HonestWholeViewGames.GameGate
      (Input := Input) (Work := Work))
    (left right : MixedProgram Input Work) (loss : ℝ)
    (bounded : BoundedDifference left right loss) :
    BoundedDifference (.gate operation left) (.gate operation right) loss := by
  intro old state
  simpa only [V8Smz9MixedMaskCompiler.run, operation.norm_map] using bounded old (operation state)

theorem query_difference_bound (left right : MixedProgram Input Work) (loss : ℝ)
    (bounded : BoundedDifference left right loss) :
    BoundedDifference (.quantumQuery left) (.quantumQuery right) loss := by
  intro old state
  simpa only [V8Smz9MixedMaskCompiler.run, (query old).norm_map] using bounded old (query old state)

theorem instrument_difference_bound {count : Nat}
    (operation : V8Smz9HonestWholeViewGames.Instrument Input Work count)
    (left right : Fin count → MixedProgram Input Work) (loss : ℝ)
    (bounded : ∀ outcome, BoundedDifference (left outcome) (right outcome) loss) :
    BoundedDifference (.instrument operation left) (.instrument operation right) loss := by
  intro old state
  change |(∑ outcome, V8Smz9MixedMaskCompiler.run true (left outcome) old (operation.branch outcome state)) -
    (∑ outcome, V8Smz9MixedMaskCompiler.run true (right outcome) old (operation.branch outcome state))| ≤ _
  rw [← Finset.sum_sub_distrib]
  apply (Finset.abs_sum_le_sum_abs _ _).trans
  calc
    _ ≤ ∑ outcome, loss * ‖operation.branch outcome state‖ ^ 2 :=
      Finset.sum_le_sum (fun outcome _ => bounded outcome old (operation.branch outcome state))
    _ = _ := by rw [← Finset.mul_sum, operation.complete]

theorem write_difference_bound (input : Input) (answer : DigestRegister)
    (left right : MixedProgram Input Work) (loss : ℝ)
    (bounded : BoundedDifference left right loss) :
    BoundedDifference (.write input answer left) (.write input answer right) loss := by
  intro old state
  exact bounded (Function.update old input answer) state

end Generic

variable {bound : Nat} {Work : Type} [Fintype Work]

theorem nonleaf_difference_bound {Result : Type}
    (program : NonleafProgram (CurrentOtherRawInput bound) Result)
    (left right : Result → MixedProgram (CurrentFullRawInput bound) Work) (loss : ℝ)
    (bounded : ∀ result, BoundedDifference (left result) (right result) loss) :
    BoundedDifference (compileNonleaf program left) (compileNonleaf program right) loss := by
  intro old state
  rw [compile_nonleaf_executes, compile_nonleaf_executes]
  exact bounded _ old state

theorem selected_writes_difference_bound
    (leaves : Fin 58 → CurrentLeafInput) (answers : Fin 58 → DigestRegister)
    (left right : MixedProgram (CurrentFullRawInput bound) Work) (loss : ℝ)
    (bounded : BoundedDifference left right loss) :
    BoundedDifference (selectedWrites leaves answers left) (selectedWrites leaves answers right) loss := by
  have foldBound (entries : List (CurrentLeafInput × DigestRegister)) :
      BoundedDifference
        (entries.foldr (fun entry rest => .write (.inl entry.1) entry.2 rest) left)
        (entries.foldr (fun entry rest => .write (.inl entry.1) entry.2 rest) right) loss := by
    induction entries with
    | nil => exact bounded
    | cons entry rest ih => exact write_difference_bound (.inl entry.1) entry.2 _ _ loss ih
  exact foldBound (List.ofFn (fun opening : Fin 58 => (leaves opening, answers opening)))

theorem after_decs_difference_bound
    (descriptor : Descriptor) (relation : PublicRelation)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) (commit : CommitPrefix)
    (labels : Index → DigestRegister)
    (response : NativePrivateSpendQ58CurrentRowBoundary.Response) («prefix» : PiopPrefix)
    (digest : DigestRegister) (nonce : Fin 16) (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (fields : NativePrivateSpendQ58CurrentPublicOpening.PublicFields)
    (earlier : CurrentEarlier) (selection : DecsSelection)
    (left right : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work)
    (loss : ℝ) (bounded : ∀ outcome, BoundedDifference (left outcome) (right outcome) loss) :
    BoundedDifference
      (clearedPublicAfterDecs descriptor relation statement salt commit labels response «prefix»
        digest nonce points distinct fields earlier selection left)
      (clearedPublicAfterDecs descriptor relation statement salt commit labels response «prefix»
        digest nonce points distinct fields earlier selection right) loss := by
  unfold clearedPublicAfterDecs
  split
  · exact bounded _
  · apply random_difference_bound
    intro later
    apply random_difference_bound
    intro tapes
    apply selected_writes_difference_bound
    exact bounded _

theorem after_opening_difference_bound (largeEnough : 1264811 ≤ bound)
    (descriptor : Descriptor) (relation : PublicRelation)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) (commit : CommitPrefix)
    (labels : Index → DigestRegister)
    (response : NativePrivateSpendQ58CurrentRowBoundary.Response) («prefix» : PiopPrefix)
    (digest : DigestRegister) (choice : OpeningChoice)
    (left right : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work)
    (loss : ℝ) (bounded : ∀ outcome, BoundedDifference (left outcome) (right outcome) loss) :
    BoundedDifference
      (clearedPublicAfterOpening largeEnough descriptor relation statement salt commit labels
        response «prefix» digest choice left)
      (clearedPublicAfterOpening largeEnough descriptor relation statement salt commit labels
        response «prefix» digest choice right) loss := by
  unfold clearedPublicAfterOpening
  split
  · exact bounded _
  · split
    · apply random_difference_bound
      intro observed
      apply random_difference_bound
      intro earlier
      apply nonleaf_difference_bound
      intro selection
      apply after_decs_difference_bound
      exact bounded
    · exact bounded _

theorem cleared_request_difference_bound (largeEnough : 1264811 ≤ bound)
    (descriptor : Descriptor) (relation : PublicRelation)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) (binding : Fin 77 → Goldilocks)
    (commit : CommitPrefix) (labels : Index → DigestRegister)
    (left right : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work)
    (loss : ℝ) (bounded : ∀ outcome, BoundedDifference (left outcome) (right outcome) loss) :
    BoundedDifference
      (clearedPublicRequest largeEnough descriptor relation statement salt binding commit labels left)
      (clearedPublicRequest largeEnough descriptor relation statement salt binding commit labels right) loss := by
  unfold clearedPublicRequest
  apply random_difference_bound
  intro reply
  apply nonleaf_difference_bound
  intro «prefix»
  apply random_difference_bound
  intro transcript
  apply read_difference_bound
  intro digest
  apply nonleaf_difference_bound
  intro choice
  apply after_opening_difference_bound
  exact bounded

/-- This is the literal complete simulator context, including root/tree labels,
nonceNone, DECSNone and poisoned-field outputs. All fixed updates are retained. -/
theorem complete_public_continuation_bound (data : RequestData bound)
    (left right : Context → Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work)
    (loss : ℝ) (bounded : ∀ context outcome,
      BoundedDifference (left context outcome) (right context outcome) loss) :
    BoundedDifference
      (NativePrivateSpendQ58CurrentHistoryMass.publicRequest data left)
      (NativePrivateSpendQ58CurrentHistoryMass.publicRequest data right) loss := by
  unfold NativePrivateSpendQ58CurrentHistoryMass.publicRequest completePublicSimulator
  split
  · exact bounded _ _
  · apply random_difference_bound
    intro labels
    apply nonleaf_difference_bound
    intro commit
    exact cleared_request_difference_bound data.largeEnough _ _ _ _ _ commit labels _ _ loss
      (bounded (some (labels, commit)))

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentHistoryContinuation
