import HegemonCrypto.SmallWoodV8Smz9PublicByteProgram
import HegemonCrypto.SmallWoodV8Smz9MixedAdapterAccounting
import HegemonCrypto.SmallWoodV8Smz9PostFinalQueryBudget

/-! Query costs of the literal public byte simulator. The nonce and index
reads, all failure branches and each of at most twenty opened fixed writes
are charged. The complete future retains its original query count. -/

namespace HegemonCrypto.SmallWood.V8Smz9PublicByteAccounting

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9HonestRequestSchedule V8Smz9HonestWholeViewGames
open V8Smz9HonestFinalGame V8Smz9SourceIndexSampler V8Smz9BytePrefix
open V8Smz9PublicByteProgram V8Smz9PostFinalQueryBudget V8Smz9PostFinalProgram
open V8Smz9MixedMaskCompiler (MixedProgram fixedProgram)
open V8Smz9ZeroKnowledge V8Smz9PrivacyGameComposition V8Smz9AdjacentComposition
open V8Smz9HonestOpeningSchedule
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

section Generic
variable {Input Other Result Work : Type}
variable [Fintype Input] [DecidableEq Input] [Fintype Other] [DecidableEq Other] [Fintype Work]

omit [DecidableEq Other] in
theorem mixed_nonleaf_query_bound (program : NonleafProgram Other Result)
    (next : Result → MixedProgram (LeafInput ⊕ Other) Work) (queries : Nat)
    (remaining : ∀ result, V8Smz9MixedMaskCompiler.queryCount (next result) ≤ queries) :
    V8Smz9MixedMaskCompiler.queryCount (compileNonleaf program next) ≤
      NonleafProgram.readCount program + queries := by
  induction program with
  | done result => simpa only [compileNonleaf, NonleafProgram.readCount, Nat.zero_add] using remaining result
  | read input rest ih =>
      change (Finset.univ.sup fun output => V8Smz9MixedMaskCompiler.queryCount
        (compileNonleaf (rest output) next)) + 1 ≤
          (Finset.univ.sup fun output => NonleafProgram.readCount (rest output)) + 1 + queries
      have bounded : (Finset.univ.sup fun output => V8Smz9MixedMaskCompiler.queryCount
          (compileNonleaf (rest output) next)) ≤
          (Finset.univ.sup fun output => NonleafProgram.readCount (rest output)) + queries := by
        apply Finset.sup_le
        intro output member
        exact (ih output).trans (Nat.add_le_add_right
          (Finset.le_sup (f := fun output => NonleafProgram.readCount (rest output)) member) queries)
      omega

omit [DecidableEq Other] in
theorem mixed_nonleaf_program_bound (program : NonleafProgram Other Result)
    (next : Result → MixedProgram (LeafInput ⊕ Other) Work) (programs : Nat)
    (remaining : ∀ result, V8Smz9MixedMaskCompiler.programmingCount (next result) ≤ programs) :
    V8Smz9MixedMaskCompiler.programmingCount (compileNonleaf program next) ≤ programs := by
  induction program with
  | done result => exact remaining result
  | read input rest ih => exact Finset.sup_le (fun output _ => ih output)

omit [DecidableEq Input] in
theorem write_inputs_query_count (inputs : List Input) (answers : Input → DigestRegister)
    (next : MixedProgram Input Work) :
    V8Smz9MixedMaskCompiler.queryCount (writeInputs inputs answers next) =
      inputs.length + V8Smz9MixedMaskCompiler.queryCount next := by
  induction inputs with
  | nil => simp only [writeInputs, List.length_nil, Nat.zero_add]
  | cons input rest ih => simp only [writeInputs, V8Smz9MixedMaskCompiler.queryCount, List.length_cons, ih]; omega

omit [DecidableEq Input] in
theorem write_inputs_program_count (inputs : List Input) (answers : Input → DigestRegister)
    (next : MixedProgram Input Work) :
    V8Smz9MixedMaskCompiler.programmingCount (writeInputs inputs answers next) =
      V8Smz9MixedMaskCompiler.programmingCount next := by
  induction inputs with
  | nil => rfl
  | cons input rest ih => exact ih

end Generic

variable {Work : Type} [Fintype Work]

theorem public_opened_inputs_card_le (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable) :
    (publicOpenedInputs points selected salt context tapes).card ≤ 20 := by
  cases context with
  | none => simp only [publicOpenedInputs, Finset.card_empty]; omega
  | some output =>
      exact Finset.card_image_le.trans (by simp)

theorem public_opened_replay_query_bound (bound : Nat) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister) (next : MixedProgram (LeafInput ⊕ OtherRawInput bound) Work) :
    V8Smz9MixedMaskCompiler.queryCount
      (publicOpenedReplay bound points selected salt context tapes labels next) ≤
      20 + V8Smz9MixedMaskCompiler.queryCount next := by
  rw [publicOpenedReplay, write_inputs_query_count, Finset.length_toList]
  exact Nat.add_le_add_right (Finset.card_image_le.trans
    (public_opened_inputs_card_le points selected salt context tapes)) _

theorem public_opened_replay_program_count (bound : Nat) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister) (next : MixedProgram (LeafInput ⊕ OtherRawInput bound) Work) :
    V8Smz9MixedMaskCompiler.programmingCount
      (publicOpenedReplay bound points selected salt context tapes labels next) =
      V8Smz9MixedMaskCompiler.programmingCount next :=
  write_inputs_program_count _ _ _

theorem public_index_read_bound (bound : Nat) (job : PublicBytePivot (Work := Work) bound)
    (opening : ComputedOpening) (view : V8Smz9EagerPrivacy.SourceRemainingView Goldilocks) :
    NonleafProgram.readCount (publicIndexProgram bound job opening view) ≤ 12 := by
  unfold publicIndexProgram sourceCurrentDecsSelection
  exact source_decs_selection_read_bound _ _ _ _ _ _ _ _

attribute [local irreducible] sourceChooseOpening publicIndexProgram publicOpenedReplay

theorem public_byte_program_query_bound (futureMode : Bool) (bound : Nat)
    (job : PublicBytePivot (Work := Work) bound) (queries : Nat)
    (remaining : ∀ bytes, queryCount (job.next bytes) ≤ queries) :
    V8Smz9MixedMaskCompiler.queryCount (publicByteProgram futureMode bound job) ≤ 117 + queries := by
  unfold publicByteProgram
  apply Nat.le_trans (m := NonleafProgram.readCount
    (sourceChooseOpening bound (by have := job.largeEnough; omega) job.digest job.pending) + (32 + queries))
  · apply mixed_nonleaf_query_bound
    intro result
    cases chosen : certifyOpening result with
    | none =>
        rw [V8Smz9MixedMaskCompiler.fixed_program_query_count]
        exact (remaining _).trans (by omega)
    | some opening =>
        apply Finset.sup_le
        intro view _
        apply Finset.sup_le
        intro tapes _
        apply Nat.le_trans (m := NonleafProgram.readCount (publicIndexProgram bound job opening view) + (20 + queries))
        · apply mixed_nonleaf_query_bound
          intro result
          exact (public_opened_replay_query_bound _ _ _ _ _ _ _ _).trans
            (Nat.add_le_add_left (by
              rw [V8Smz9MixedMaskCompiler.fixed_program_query_count]
              exact remaining _) 20)
        · have cap := public_index_read_bound bound job opening view
          omega
  · have cap := source_choose_opening_read_bound bound (by have := job.largeEnough; omega) job.digest job.pending
    omega

theorem public_byte_program_selected_count_zero (futureMode : Bool) (bound : Nat)
    (job : PublicBytePivot (Work := Work) bound) :
    V8Smz9MixedMaskCompiler.programmingCount (publicByteProgram futureMode bound job) = 0 := by
  apply Nat.eq_zero_of_le_zero
  unfold publicByteProgram
  apply mixed_nonleaf_program_bound
  intro result
  cases chosen : certifyOpening result with
  | none => exact Nat.le_of_eq (V8Smz9MixedMaskCompiler.fixed_program_selected_count_zero _ _)
  | some opening =>
      apply Finset.sup_le
      intro view _
      apply Finset.sup_le
      intro tapes _
      apply mixed_nonleaf_program_bound
      intro result
      rw [public_opened_replay_program_count, V8Smz9MixedMaskCompiler.fixed_program_selected_count_zero]

end
end HegemonCrypto.SmallWood.V8Smz9PublicByteAccounting
