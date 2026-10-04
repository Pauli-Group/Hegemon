import HegemonCrypto.SmallWoodV8Smz9BytePrefix
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAdapters

/-! Pre-oracle witness-free code for the public byte pivot. All source
opening/index reads are honest-read instructions. Only public opened leaf
entries are written, and the future retains its explicitly fixed mode. -/

namespace HegemonCrypto.SmallWood.V8Smz9PublicByteProgram

open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9SingleProofPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPublicContext V8Smz9CurrentProgramPiop
open V8Smz9CurrentProgramOpeningBinding V8Smz9ZeroKnowledge V8Smz9HonestHybrid
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler V8Smz9AdjacentComposition
open V8Smz9PrivacyGameComposition V8Smz9RuntimeDistribution V8Smz9WholeViewObservation
open V8Smz9PostFinalSerializer V8Smz9PostFinalProgram V8Smz9MeasuredSameOracleAdjacent
open V8Smz9BytePrefix
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
set_option Elab.async false

section GenericCode

variable {Input Other Result Work : Type}
variable [Fintype Input] [DecidableEq Input] [Fintype Other] [DecidableEq Other] [Fintype Work]

def compileNonleaf : NonleafProgram Other Result →
    (Result → MixedProgram (LeafInput ⊕ Other) Work) → MixedProgram (LeafInput ⊕ Other) Work
  | .done result, next => next result
  | .read input rest, next => .honestRead (Sum.inr input) (fun output => compileNonleaf (rest output) next)

theorem compile_nonleaf_executes (mode : Bool) (program : NonleafProgram Other Result)
    (next : Result → MixedProgram (LeafInput ⊕ Other) Work)
    (oracle : (LeafInput ⊕ Other) → DigestRegister)
    (state : GameState (Input := LeafInput ⊕ Other) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode (compileNonleaf program next) oracle state =
      V8Smz9MixedMaskCompiler.run mode
        (next (NonleafProgram.interpret (fun input => oracle (Sum.inr input)) program)) oracle state := by
  induction program with
  | done result => rfl
  | read input rest ih => exact ih _

def writeInputs (inputs : List Input) (answers : Input → DigestRegister)
    (next : MixedProgram Input Work) : MixedProgram Input Work :=
  match inputs with
  | [] => next
  | input :: rest => .write input (answers input) (writeInputs rest answers next)

def inputOverride (inputs : List Input) (answers : Input → DigestRegister)
    (oracle : Input → DigestRegister) : Input → DigestRegister :=
  fun input => if input ∈ inputs then answers input else oracle input

omit [Fintype Input] in
theorem input_override_cons (input : Input) (rest : List Input) (answers : Input → DigestRegister)
    (oracle : Input → DigestRegister) :
    inputOverride rest answers (Function.update oracle input (answers input)) =
      inputOverride (input :: rest) answers oracle := by
  funext point
  by_cases inRest : point ∈ rest
  · simp only [inputOverride, inRest, List.mem_cons, or_true, if_true]
  · by_cases same : point = input
    · subst point
      simp only [inputOverride, inRest, if_false, Function.update_self, List.mem_cons,
        true_or, if_true]
    · simp only [inputOverride, inRest, if_false, Function.update_of_ne same, List.mem_cons,
        same, false_or]

/-- Repeated keys are harmless because each occurrence writes the same
public answer. The table is not reset, and all nonlisted keys are retained. -/
theorem write_inputs_execute (mode : Bool) (inputs : List Input) (answers : Input → DigestRegister)
    (next : MixedProgram Input Work) (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode (writeInputs inputs answers next) oracle state =
      V8Smz9MixedMaskCompiler.run mode next (inputOverride inputs answers oracle) state := by
  induction inputs generalizing oracle with
  | nil => rfl
  | cons input rest ih =>
      simp only [writeInputs, V8Smz9MixedMaskCompiler.run]
      rw [ih, input_override_cons]

end GenericCode

variable {Work : Type} [Fintype Work]

def finiteCoins (Coins : Type) [Fintype Coins] [Nonempty Coins] : RandomSource where
  Coins := Coins
  finite := inferInstance
  inhabited := inferInstance

def openedRawInputs (bound : Nat) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable) :
    Finset (LeafInput ⊕ OtherRawInput bound) :=
  (publicOpenedInputs points selected salt context tapes).image Sum.inl

def publicOpenedReplay (bound : Nat) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister) (next : MixedProgram (LeafInput ⊕ OtherRawInput bound) Work) :
    MixedProgram (LeafInput ⊕ OtherRawInput bound) Work :=
  writeInputs (openedRawInputs bound points selected salt context tapes).toList
    (Sum.elim (fun input => labels (rawInputIndex input)) (fun _ => 0)) next

theorem public_opened_replay_executes (mode : Bool) (bound : Nat) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister) (next : MixedProgram (LeafInput ⊕ OtherRawInput bound) Work)
    (oracle : FullOracle bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode
      (publicOpenedReplay bound points selected salt context tapes labels next) oracle state =
    V8Smz9MixedMaskCompiler.run mode next
      (Sum.elim (publicOpenedOracle (fun input => oracle (Sum.inl input)) labels points selected salt context tapes)
        (fun input => oracle (Sum.inr input))) state := by
  rw [publicOpenedReplay, write_inputs_execute]
  congr 1
  funext input
  cases input with
  | inl input => simp [inputOverride, openedRawInputs, publicOpenedOracle]
  | inr input => simp [inputOverride, openedRawInputs]

theorem public_opened_oracle_ignores_padding (bound : Nat) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister) (oracle : FullOracle bound) :
    publicOpenedOracle (fun input => oracle (Sum.inl input)) labels points selected salt context tapes =
    publicOpenedOracle (fun input => oracle (Sum.inl input)) labels points selected salt context
      (mergeTapes (openedOrEmpty (contextSelection context))
        (splitTapes (openedOrEmpty (contextSelection context)) tapes).1 (fun _ => 0)) := by
  have supports := public_opened_inputs_only_revealed_tapes points selected salt context tapes
    (mergeTapes (openedOrEmpty (contextSelection context))
      (splitTapes (openedOrEmpty (contextSelection context)) tapes).1 (fun _ => 0)) (by
        intro index member
        rw [merge_tapes_opened _ _ _ index member]
        rfl)
  funext input
  simp only [publicOpenedOracle, supports]

def publicIndexProgram (bound : Nat) (job : PublicBytePivot (Work := Work) bound)
    (opening : ComputedOpening) (view : SourceRemainingView Goldilocks) :
    NonleafProgram (OtherRawInput bound) (DecsSelectionResult opening.points) :=
  sourceCurrentDecsSelection bound job.largeEnough (statementParameters job.statement job.batching)
    opening.points (computed_opening_points_distinct opening) job.transcript job.digest
    view.1 view.2.1 view.2.2.1 opening.pendingFailure

def publicIndexContext (bound : Nat) (job : PublicBytePivot (Work := Work) bound)
    (opening : ComputedOpening) (view : SourceRemainingView Goldilocks)
    (result : DecsSelectionResult opening.points) : EagerContext opening.points :=
  result.targets.map fun targets =>
    (targets, currentEagerAlgebraicFields (statementParameters job.statement job.batching)
      opening.points (computed_opening_selected_rank opening) job.gamma job.response job.transcript
      (indexedPoints targets.val) view)

theorem public_index_context_is_kernel_context (bound : Nat) (job : PublicBytePivot (Work := Work) bound)
    (opening : ComputedOpening) (view : SourceRemainingView Goldilocks)
    (oracle : OtherRawInput bound → DigestRegister) :
    publicIndexContext bound job opening view (NonleafProgram.interpret oracle (publicIndexProgram bound job opening view)) =
    currentIndexedContext (statementParameters job.statement job.batching) opening.points
      (computed_opening_selected_rank opening) job.gamma job.response job.transcript
      (computedIndexChooser bound job.largeEnough (statementParameters job.statement job.batching)
        opening job.transcript job.digest oracle) view := by
  unfold publicIndexContext currentIndexedContext computedIndexChooser sourceCurrentIndexChooser
    publicIndexProgram sourceCurrentDecsSelection
  rw [source_decs_targets_ignore_pending (left := opening.pendingFailure) (right := false)]

theorem public_fields_reproduce_index_program (bound : Nat) (job : PublicBytePivot (Work := Work) bound)
    (opening : ComputedOpening) (view : SourceRemainingView Goldilocks) (targets : IndexedTargets opening.points) :
    sourceFieldsDecsSelection bound job.largeEnough opening.points (computed_opening_points_distinct opening)
      job.digest (currentEagerAlgebraicFields (statementParameters job.statement job.batching)
        opening.points (computed_opening_selected_rank opening) job.gamma job.response job.transcript
        (indexedPoints targets.val) view) opening.pendingFailure = publicIndexProgram bound job opening view := by
  exact current_fields_reproduce_source_decs_selection bound job.largeEnough
    (statementParameters job.statement job.batching) opening.points (computed_opening_points_distinct opening)
    (computed_opening_selected_rank opening) job.gamma job.response job.transcript (indexedPoints targets.val)
    view job.digest opening.pendingFailure

def publicSelectedBytes (bound : Nat) (job : PublicBytePivot (Work := Work) bound)
    (opening : ComputedOpening) (view : SourceRemainingView Goldilocks) (tapes : TapeTable)
    (result : DecsSelectionResult opening.points) : Except String (List CanonicalBytes.Byte) :=
  match result.targets with
  | none => .error "fixed DECS sampler exhausted its candidate pool"
  | some targets => finishBytes result.pendingFailure
      (sourceProofBytes job.salt opening.nonce job.digest job.tree targets.val
        (currentEagerAlgebraicFields (statementParameters job.statement job.batching)
          opening.points (computed_opening_selected_rank opening) job.gamma job.response job.transcript
          (indexedPoints targets.val) view) (fun index => tapes (targets.val index)))

theorem public_selected_bytes_are_context_bytes (bound : Nat) (job : PublicBytePivot (Work := Work) bound)
    (opening : ComputedOpening) (view : SourceRemainingView Goldilocks) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister) :
    let result := NonleafProgram.interpret oracle (publicIndexProgram bound job opening view)
    let context := publicIndexContext bound job opening view result
    publicSelectedBytes bound job opening view tapes result =
      sourceContextBytes bound job.largeEnough job.salt opening job.digest job.tree oracle context
        (splitTapes (openedOrEmpty (contextSelection context)) tapes).1 := by
  dsimp only
  generalize resultEq : NonleafProgram.interpret oracle (publicIndexProgram bound job opening view) = result
  obtain ⟨challenge, sampled, targets, pending⟩ := result
  cases targets with
  | none => rfl
  | some targets =>
      simp only [publicIndexContext, Option.map_some, publicSelectedBytes, sourceContextBytes,
        public_fields_reproduce_index_program, resultEq, finishBytes]
      rfl

def publicByteProgram (futureMode : Bool) (bound : Nat) (job : PublicBytePivot (Work := Work) bound) :
    MixedProgram (LeafInput ⊕ OtherRawInput bound) Work :=
  compileNonleaf (sourceChooseOpening bound (by have := job.largeEnough; omega) job.digest job.pending) fun result =>
    match certifyOpening result with
    | none => V8Smz9MixedMaskCompiler.fixedProgram futureMode
        (job.next (.error "smallwood opening nonce trial limit exhausted"))
    | some opening => .random (finiteCoins (SourceRemainingView Goldilocks)) fun view =>
        .random (finiteCoins TapeTable) fun tapes =>
          compileNonleaf (publicIndexProgram bound job opening view) fun result =>
            publicOpenedReplay bound opening.points (computed_opening_selected_rank opening)
              job.salt (publicIndexContext bound job opening view result) tapes job.labels
              (V8Smz9MixedMaskCompiler.fixedProgram futureMode
                (job.next (publicSelectedBytes bound job opening view tapes result)))

attribute [local irreducible] sourceChooseOpening sourceComputedOpening sourceContextBytes
  publicIndexProgram currentIndexedContext V8Smz9HonestWholeViewGames.run

/-- Any surrounding selected-game mode executes the same witness-free
public kernel. The complete byte continuation has its own fixed mode. -/
theorem public_byte_program_executes_raw_kernel (outerMode futureMode : Bool)
    (bound : Nat) (job : PublicBytePivot (Work := Work) bound) (oracle : FullOracle bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run outerMode (publicByteProgram futureMode bound job) oracle state =
      rawBytePublicKernel futureMode bound job oracle state := by
  rw [publicByteProgram, compile_nonleaf_executes, certify_actual_opening]
  unfold rawBytePublicKernel
  cases chosen : sourceComputedOpening bound (by have := job.largeEnough; omega) job.digest job.pending
      (fun input => oracle (Sum.inr input)) with
  | none => exact V8Smz9MixedMaskCompiler.fixed_program_execution outerMode futureMode _ oracle state
  | some opening =>
      simp only [V8Smz9MixedMaskCompiler.run]
      apply congrArg uniformAverage
      funext view
      apply congrArg uniformAverage
      funext tapes
      rw [compile_nonleaf_executes, public_opened_replay_executes,
        V8Smz9MixedMaskCompiler.fixed_program_execution,
        public_selected_bytes_are_context_bytes, public_index_context_is_kernel_context,
        public_opened_oracle_ignores_padding]

end
end HegemonCrypto.SmallWood.V8Smz9PublicByteProgram
