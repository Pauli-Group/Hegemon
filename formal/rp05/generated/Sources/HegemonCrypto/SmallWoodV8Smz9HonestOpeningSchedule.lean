import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule

/-! The actual post-h_piop ordinary-read schedule, pending field-error state,
and the exact final-input programming/point-selection interchange. Every
source nonce attempt and the repeated selected-nonce XOF remain in the game.
This is a source-phase bridge, not a claimed Rust refinement or a complete
repeated-request privacy endpoint. -/

namespace HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9HiddenLeafQrom V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9HonestWholeViewGames V8Smz9HonestWholeViewFinalInput V8Smz9HonestFinalGame
open V8Smz9HonestRequestSchedule V8Smz9EagerPrivacy V8Smz9RawCounterCompiler
open V8Smz9RuntimeDistribution V8Smz9WholeViewObservation
open V8Smz9ZeroKnowledge
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

/-- The selected LVCS block requires only the point distinctness already
checked by the source; it is not an additional rank assumption. -/
theorem actual_selected_block_injective {F : Type*} [Field F]
    {points : Fin 6 → F} (distinct : Function.Injective points) :
    Function.Injective (smz9LvcsSelectedBlockMap points) := by
  have block0 (values : Fin 12 → F) (opening : Fin 6) :
      smz9LvcsSelectedBlockMap points values ⟨2 * opening.val, by change _ < 12; omega⟩ =
        sourcePcsCoinEvaluation points (fun i => values ⟨i.val, by omega⟩) opening := by
    unfold smz9LvcsSelectedBlockMap
    change (∑ selected : Fin 12, _) = _
    fin_cases opening <;>
      simp [smz9LvcsCombinationCoefficient,
        smz9LvcsCombinationOpening, smz9LvcsSelectedRow, sourcePcsCoinEvaluation,
        lvcsOpenedCombinationCount, piopOpeningCount, Fin.sum_univ_succ]
  have block1 (values : Fin 12 → F) (opening : Fin 6) :
      smz9LvcsSelectedBlockMap points values ⟨2 * opening.val + 1, by change _ < 12; omega⟩ =
        sourcePcsCoinEvaluation points (fun i => values ⟨i.val + 6, by omega⟩) opening := by
    unfold smz9LvcsSelectedBlockMap
    change (∑ selected : Fin 12, _) = _
    fin_cases opening <;>
      simp [smz9LvcsCombinationCoefficient,
        smz9LvcsCombinationOpening, smz9LvcsSelectedRow, sourcePcsCoinEvaluation,
        lvcsOpenedCombinationCount, piopOpeningCount, Fin.sum_univ_succ]
  change Function.Injective (smz9LvcsSelectedBlockMap points : (Fin 12 → F) → (Fin 12 → F))
  intro left right same
  have first : (fun i : Fin 6 => left (⟨i.val, by omega⟩ : Fin 12)) =
      (fun i : Fin 6 => right (⟨i.val, by omega⟩ : Fin 12)) := by
    apply source_pcs_coin_evaluation_injective distinct
    funext opening
    rw [← block0, ← block0, same]
  have second : (fun i : Fin 6 => left (⟨i.val + 6, by omega⟩ : Fin 12)) =
      (fun i : Fin 6 => right (⟨i.val + 6, by omega⟩ : Fin 12)) := by
    apply source_pcs_coin_evaluation_injective distinct
    funext opening
    rw [← block1, ← block1, same]
  funext index
  have indexBound : index.val < 12 := index.isLt
  by_cases small : index.val < 6
  · exact congrFun first ⟨index.val, small⟩
  · have equal := congrFun second ⟨index.val - 6, by omega⟩
    convert equal using 1 <;> congr 1 <;> apply Fin.ext <;> simp <;> omega

open V8Smz9HonestRequestSchedule.NonleafProgram

variable {Other Result Next : Type}

def nonleafAvoids (forbidden : Other) : NonleafProgram Other Result → Prop
  | .done _ => True
  | .read input next => input ≠ forbidden ∧ ∀ output, nonleafAvoids forbidden (next output)

theorem nonleaf_avoids_bind (forbidden : Other) (program : NonleafProgram Other Result)
    (next : Result → NonleafProgram Other Next) (avoids : nonleafAvoids forbidden program)
    (remaining : ∀ result, nonleafAvoids forbidden (next result)) :
    nonleafAvoids forbidden (NonleafProgram.bind program next) := by
  induction program with
  | done result => exact remaining result
  | read input rest ih => exact ⟨avoids.1, fun output => ih output (avoids.2 output)⟩

theorem nonleaf_interpret_update [DecidableEq Other] (forbidden : Other)
    (program : NonleafProgram Other Result) (avoids : nonleafAvoids forbidden program)
    (oracle : Other → DigestRegister) (value : DigestRegister) :
    interpret (Function.update oracle forbidden value) program = interpret oracle program := by
  induction program with
  | done result => rfl
  | read input rest ih =>
      simp only [interpret, Function.update_of_ne avoids.1]
      exact ih _ (avoids.2 _)

theorem nonleaf_interpret_agrees (program : NonleafProgram Other Result)
    (left right : Other → DigestRegister)
    (agrees : ∀ input, left input = right input) : interpret left program = interpret right program := by
  exact congrArg (fun oracle => interpret oracle program) (funext agrees)


/-- The exact deterministic poison vector returned by the source on field
rejection exhaustion. The pending error is separate from these shaped words. -/
def sourcePoisonWords (requested : Nat) : List FieldWord :=
  List.ofFn fun index : Fin requested =>
    ⟨goldilocksModulus - 1 - index.val, by
      change goldilocksModulus - 1 - index.val < goldilocksModulus
      have positive : 0 < goldilocksModulus := by decide
      omega⟩

def sourceReturnedWords (requested : Nat) (result : Option (List FieldWord)) : List FieldWord :=
  result.getD (sourcePoisonWords requested)

/-- Every in-scope field-XOF failure has the same fixed source diagnostic.
The Boolean therefore exactly records whether the TLS first-error slot is
occupied; later success cannot clear it. -/
def sourcePendingFailure (pending : Bool) (result : Option (List FieldWord)) : Bool :=
  pending || result.isNone

theorem source_poison_word_count (requested : Nat) :
    (sourcePoisonWords requested).length = requested := by simp [sourcePoisonWords]

theorem source_poison_word_exact (requested : Nat) (index : Fin requested) :
    ((sourcePoisonWords requested).get ⟨index.val, by rw [source_poison_word_count]; exact index.isLt⟩).val =
      goldilocksModulus - 1 - index.val := by simp [sourcePoisonWords]

theorem source_first_failure_is_retained (result : Option (List FieldWord)) :
    sourcePendingFailure true result = true := by simp [sourcePendingFailure]

def sourceScopeFinish {Value : Type} (pending : Bool) (value : Value) : Except String Value :=
  if pending then .error "smallwood SHA-512 field-XOF rejection budget exhausted" else .ok value

theorem source_pending_error_cannot_return_success {Value : Type} (value : Value) :
    sourceScopeFinish true value =
      .error "smallwood SHA-512 field-XOF rejection budget exhausted" := rfl

/-- The actual canonical, nonzero, distinct, packing-disjoint, correction and
legacy PCS admissibility predicate on the six returned source words. -/
def sourcePointVector (words : List FieldWord) : Fin 6 → Goldilocks :=
  fun index => (words.getD index.val 0).val

def SourceOpeningAdmissible (points : Fin 6 → Goldilocks) : Prop :=
  Function.Injective points ∧ (∀ i, points i ≠ 0) ∧
    (∀ i (packing : Fin 64), points i ≠ (packing.val : Goldilocks)) ∧
    linearPiopCorrectionFactor points ≠ 0 ∧
    (∀ i, points i ^ 64 ≠ 1 ∧ points i ^ 35 ≠ 1 ∧ points i ^ 63 ≠ 1)

def sourceOpeningValid (words : List FieldWord) : Bool :=
  decide (words.length = 6 ∧ SourceOpeningAdmissible (sourcePointVector words))

theorem source_opening_valid_characterization (words : List FieldWord) :
    sourceOpeningValid words = true ↔
      words.length = 6 ∧ SourceOpeningAdmissible (sourcePointVector words) := by
  simp only [sourceOpeningValid, decide_eq_true_eq]

def sourceOpeningWords (nonce : Fin 16) (digest : DigestRegister) : List Nat :=
  nonce.val :: sourceDigestWords digest

theorem source_opening_word_count (nonce : Fin 16) (digest : DigestRegister) :
    (sourceOpeningWords nonce digest).length = 9 := by
  simp [sourceOpeningWords, source_digest_word_count]

def sourceOpeningKey (bound : Nat) (largeEnough : 25029 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister) (counter : Fin (2 ^ 64)) : OtherRawInput bound :=
  sourceCounterKey bound SmallWoodTranscript.piopOpeningDomain (sourceOpeningWords nonce digest)
    (by rw [source_opening_word_count]; have role : SmallWoodTranscript.piopOpeningDomain.length = 37 := by decide
        rw [role]; omega)
    (by rw [source_opening_word_count]; decide) counter

theorem source_opening_key_length (bound : Nat) (largeEnough : 25029 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister) (counter : Fin (2 ^ 64)) :
    (rawBytes (Sum.inr (sourceOpeningKey bound largeEnough nonce digest counter))).length = 194 := by
  rw [sourceOpeningKey, source_counter_key_is_literal_input, source_counter_raw_length]
  rw [source_opening_word_count]
  decide

def sourceOpeningXof (bound : Nat) (largeEnough : 25029 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister) :
    NonleafProgram (OtherRawInput bound) (Option (List FieldWord)) :=
  sourceFieldReadLoop 6 [] (List.ofFn fun index : Fin 5 =>
    sourceOpeningKey bound largeEnough nonce digest ⟨index.val, by omega⟩)

structure OpeningResult where
  selected : Option (Fin 16 × List FieldWord)
  pendingFailure : Bool

/-- First valid nonce from the literal 0..15 schedule, followed by the source's
second XOF of that same nonce. All failures retain pending state. A missing
selection is the source nonce-exhaustion error, not a sampled-success branch. -/
def sourceChooseOpeningLoop (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (pending : Bool) : List (Fin 16) →
    NonleafProgram (OtherRawInput bound) OpeningResult
  | [] => .done ⟨none, pending⟩
  | nonce :: rest => NonleafProgram.bind (sourceOpeningXof bound largeEnough nonce digest) fun sampled =>
      let words := sourceReturnedWords 6 sampled
      let failed := sourcePendingFailure pending sampled
      if sourceOpeningValid words then
        NonleafProgram.bind (sourceOpeningXof bound largeEnough nonce digest) fun repeated =>
          .done ⟨some (nonce, sourceReturnedWords 6 repeated), sourcePendingFailure failed repeated⟩
      else sourceChooseOpeningLoop bound largeEnough digest failed rest

def sourceChooseOpening (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (pending : Bool) :
    NonleafProgram (OtherRawInput bound) OpeningResult :=
  sourceChooseOpeningLoop bound largeEnough digest pending (List.ofFn id)

theorem source_choose_opening_loop_transition (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (pending : Bool) (nonce : Fin 16) (nonces : List (Fin 16))
    (oracle : OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle (sourceChooseOpeningLoop bound largeEnough digest pending (nonce :: nonces)) =
      let sampled := NonleafProgram.interpret oracle (sourceOpeningXof bound largeEnough nonce digest)
      let words := sourceReturnedWords 6 sampled
      let failed := sourcePendingFailure pending sampled
      if sourceOpeningValid words then
        ⟨some (nonce, words), sourcePendingFailure failed sampled⟩
      else NonleafProgram.interpret oracle (sourceChooseOpeningLoop bound largeEnough digest failed nonces) := by
  simp only [sourceChooseOpeningLoop, NonleafProgram.interpret_bind]
  split
  · rw [NonleafProgram.interpret_bind]
    rfl
  · rfl

theorem source_selected_opening_loop_is_valid (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (pending : Bool) (nonces : List (Fin 16))
    (oracle : OtherRawInput bound → DigestRegister) (nonce : Fin 16) (words : List FieldWord)
    (selected : (NonleafProgram.interpret oracle
      (sourceChooseOpeningLoop bound largeEnough digest pending nonces)).selected = some (nonce, words)) :
    sourceOpeningValid words = true := by
  induction nonces generalizing pending with
  | nil => simp only [sourceChooseOpeningLoop, NonleafProgram.interpret] at selected; cases selected
  | cons attempt rest ih =>
      rw [source_choose_opening_loop_transition] at selected
      dsimp only at selected
      split at selected
      · rename_i valid
        have pair := Option.some.inj selected
        have equal := congrArg Prod.snd pair
        dsimp only at equal
        rw [← equal]
        exact valid
      · exact ih _ selected

theorem source_selected_opening_is_valid (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (pending : Bool)
    (oracle : OtherRawInput bound → DigestRegister) (nonce : Fin 16) (words : List FieldWord)
    (selected : (NonleafProgram.interpret oracle
      (sourceChooseOpening bound largeEnough digest pending)).selected = some (nonce, words)) :
    words.length = 6 ∧ SourceOpeningAdmissible (sourcePointVector words) :=
  (source_opening_valid_characterization words).mp
    (source_selected_opening_loop_is_valid bound largeEnough digest pending _ oracle nonce words selected)

theorem source_field_loop_avoids {Other : Type} (forbidden : Other)
    (requested : Nat) (accepted : List FieldWord) (inputs : List Other)
    (notMember : ∀ input ∈ inputs, input ≠ forbidden) :
    nonleafAvoids forbidden (sourceFieldReadLoop requested accepted inputs) := by
  induction inputs generalizing accepted with
  | nil => simp only [sourceFieldReadLoop]; split <;> trivial
  | cons input rest ih =>
      simp only [sourceFieldReadLoop]
      split
      · trivial
      · exact ⟨notMember input (by simp), fun _ => ih _ (fun key member => notMember key (by simp [member]))⟩

def sourceFinalOtherKey (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks) : OtherRawInput bound :=
  otherRawKey bound (sourceFinalRawInput digestPrefix transcript)
    (by rw [source_final_raw_input_length]; exact largeEnough)
    (by rw [source_final_raw_input_length]; decide)

theorem source_final_other_key_is_final_key (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks) :
    Sum.inr (sourceFinalOtherKey bound largeEnough digestPrefix transcript) =
      sourceFinalKey bound largeEnough digestPrefix transcript := rfl

theorem source_opening_key_avoids_final (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks)
    (nonce : Fin 16) (digest : DigestRegister) (counter : Fin (2 ^ 64)) :
    sourceOpeningKey bound largeEnough nonce digest counter ≠
      sourceFinalOtherKey bound largeEnough digestPrefix transcript := by
  intro equal
  have lengths := congrArg (fun key => (rawBytes (Sum.inr key)).length) equal
  rw [source_opening_key_length, source_final_other_key_is_final_key,
    source_final_key_is_literal_raw_input, source_final_raw_input_length] at lengths
  omega

theorem source_opening_xof_avoids_final (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks)
    (nonce : Fin 16) (digest : DigestRegister) :
    nonleafAvoids (sourceFinalOtherKey bound largeEnough digestPrefix transcript)
      (sourceOpeningXof bound largeEnough nonce digest) := by
  apply source_field_loop_avoids
  intro input member
  obtain ⟨index, rfl⟩ := List.mem_ofFn.mp member
  exact source_opening_key_avoids_final bound largeEnough digestPrefix transcript nonce digest _

theorem source_choose_opening_loop_avoids_final (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (pending : Bool) (nonces : List (Fin 16)) :
    nonleafAvoids (sourceFinalOtherKey bound largeEnough digestPrefix transcript)
      (sourceChooseOpeningLoop bound largeEnough digest pending nonces) := by
  induction nonces generalizing pending with
  | nil => trivial
  | cons nonce rest ih =>
      apply nonleaf_avoids_bind
      · exact source_opening_xof_avoids_final bound largeEnough digestPrefix transcript nonce digest
      · intro sampled
        dsimp only
        split
        · apply nonleaf_avoids_bind
          · exact source_opening_xof_avoids_final bound largeEnough digestPrefix transcript nonce digest
          · intro repeated; trivial
        · exact ih _

theorem source_choose_opening_avoids_final (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (pending : Bool) :
    nonleafAvoids (sourceFinalOtherKey bound largeEnough digestPrefix transcript)
      (sourceChooseOpening bound largeEnough digest pending) :=
  source_choose_opening_loop_avoids_final bound largeEnough digestPrefix transcript digest pending _

attribute [local irreducible] sourceChooseOpening sourceChooseOpeningLoop sourceOpeningXof run uniformAverage

variable {Work : Type} [Fintype Work]

/-- The complete actual point-selector sees exactly the old oracle even when
the final key was programmed. Its complete success/error output is retained. -/
theorem source_opening_after_final_update (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (pending : Bool) (oracle : FullRawInput bound → DigestRegister) :
    NonleafProgram.interpret
      (fun input => Function.update oracle (sourceFinalKey bound largeEnough digestPrefix transcript) digest (Sum.inr input))
      (sourceChooseOpening bound largeEnough digest pending) =
    NonleafProgram.interpret (fun input => oracle (Sum.inr input))
      (sourceChooseOpening bound largeEnough digest pending) := by
  have oracleSame : (fun input => Function.update oracle
      (sourceFinalKey bound largeEnough digestPrefix transcript) digest (Sum.inr input)) =
      Function.update (fun input => oracle (Sum.inr input))
        (sourceFinalOtherKey bound largeEnough digestPrefix transcript) digest := by
    funext input
    by_cases same : input = sourceFinalOtherKey bound largeEnough digestPrefix transcript
    · subst input
      rw [source_final_other_key_is_final_key, Function.update_self, Function.update_self]
    · have notSame : Sum.inr input ≠ sourceFinalKey bound largeEnough digestPrefix transcript := by
        rw [← source_final_other_key_is_final_key]
        exact Sum.inr_injective.ne same
      rw [Function.update_of_ne notSame, Function.update_of_ne same]
  rw [oracleSame]
  exact nonleaf_interpret_update _ _
    (source_choose_opening_avoids_final bound largeEnough digestPrefix transcript digest pending) _ _

/-- Exact input-order bridge into the current algebraic simulator: h_piop and
the entire source opening/error result are sampled/computed BEFORE uniform T.
The final programmed key persists into `next`, including arbitrary subsequent
measurements, quantum queries and later honest requests. No success
conditioning, normalization, or erasure of aborted writes occurs. -/
theorem randomized_final_then_opening_equals_opening_before_transcript
    (bound : Nat) (largeEnough : 25029 ≤ bound) (digestPrefix : Prefix) (pending : Bool)
    (next : PiopCoefficients Goldilocks → DigestRegister → OpeningResult → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    run true (sourceFinal bound largeEnough digestPrefix fun transcript digest =>
      NonleafProgram.compile (sourceChooseOpening bound largeEnough digest pending)
        (next transcript digest)) oracle state =
    uniformAverage (fun digest : DigestRegister =>
      let opening := NonleafProgram.interpret (fun input => oracle (Sum.inr input))
        (sourceChooseOpening bound largeEnough digest pending)
      uniformAverage (fun transcript : PiopCoefficients Goldilocks =>
        run true (next transcript digest opening)
          (Function.update oracle (sourceFinalKey bound largeEnough digestPrefix transcript) digest) state)) := by
  rw [source_final_randomized_execution]
  calc
    _ = uniformAverage (fun transcript : PiopCoefficients Goldilocks =>
        uniformAverage (fun digest : DigestRegister =>
          run true (next transcript digest
            (NonleafProgram.interpret (fun input => oracle (Sum.inr input))
              (sourceChooseOpening bound largeEnough digest pending)))
            (Function.update oracle (sourceFinalKey bound largeEnough digestPrefix transcript) digest) state)) := by
      apply congrArg (fun f : PiopCoefficients Goldilocks → ℝ => uniformAverage f)
      funext transcript
      apply congrArg (fun f : DigestRegister → ℝ => uniformAverage f)
      funext digest
      rw [NonleafProgram.compiled_execution, source_opening_after_final_update]
    _ = _ := uniform_average_comm _

end
end HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
