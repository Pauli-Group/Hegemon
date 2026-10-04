import HegemonCrypto.SmallWoodV8Smz9MixedMaskAccounting
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAdapters
import HegemonCrypto.SmallWoodV8Smz9HonestLeafBatch
import HegemonCrypto.SmallWoodV8Smz9DynamicPhysicalTransport

/-! Literal sequential writes in the mixed physical game. Every write is
performed in both hybrid modes and remains in the oracle passed to the
continuation. The symbolic induction preserves chronological last-write-wins
semantics even when inputs repeat; distinctness is used only by the existing
actual-source overlay theorem. No recursive 2^23-step program is evaluated.
-/

namespace HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestWholeViewGames (GameState)
open V8Smz9HonestFinalGame (FullRawInput OtherRawInput)
open scoped Classical ENNReal

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

variable {Work : Type} [Fintype Work] {bound : Nat}

/-- The head is written first; all later writes see its updated table. -/
def writeBatch : (count : Nat) → (Fin count → FullRawInput bound) →
    (Fin count → DigestRegister) → MixedProgram (FullRawInput bound) Work →
    MixedProgram (FullRawInput bound) Work
  | 0, _, _, next => next
  | count + 1, inputs, outputs, next =>
      .write (inputs 0) (outputs 0)
        (writeBatch count (fun i => inputs i.succ) (fun i => outputs i.succ) next)

theorem write_batch_execution (randomized : Bool) (count : Nat)
    (inputs : Fin count → FullRawInput bound) (outputs : Fin count → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    run randomized (writeBatch count inputs outputs next) oracle state =
      run randomized next (V8Smz9HonestLeafBatch.updateBatch count inputs outputs oracle) state := by
  induction count generalizing oracle with
  | zero => simp only [writeBatch, V8Smz9HonestLeafBatch.updateBatch]
  | succ count ih =>
      simp only [writeBatch, run, V8Smz9HonestLeafBatch.updateBatch]
      exact ih (fun i => inputs i.succ) (fun i => outputs i.succ)
        (Function.update oracle (inputs 0) (outputs 0))

theorem write_batch_input_mass_iff (cap : ℝ≥0∞) (count : Nat)
    (inputs : Fin count → FullRawInput bound) (outputs : Fin count → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work) :
    InputMassAtMost cap (writeBatch count inputs outputs next) ↔ InputMassAtMost cap next := by
  induction count with
  | zero => rfl
  | succ count ih =>
      simpa only [writeBatch, InputMassAtMost] using
        ih (fun i => inputs i.succ) (fun i => outputs i.succ)

theorem write_batch_input_mass (cap : ℝ≥0∞) (count : Nat)
    (inputs : Fin count → FullRawInput bound) (outputs : Fin count → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work) (remaining : InputMassAtMost cap next) :
    InputMassAtMost cap (writeBatch count inputs outputs next) :=
  (write_batch_input_mass_iff cap count inputs outputs next).mpr remaining

/-- Each fixed write costs one raw read in the physical mask compiler. -/
theorem write_batch_query_count (count : Nat)
    (inputs : Fin count → FullRawInput bound) (outputs : Fin count → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work) :
    queryCount (writeBatch count inputs outputs next) = count + queryCount next := by
  induction count with
  | zero => simp only [writeBatch, Nat.zero_add]
  | succ count ih =>
      rw [writeBatch, queryCount, ih]
      omega

theorem write_batch_query_bound (count : Nat)
    (inputs : Fin count → FullRawInput bound) (outputs : Fin count → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work) (queries : Nat)
    (remaining : queryCount next ≤ queries) :
    queryCount (writeBatch count inputs outputs next) ≤ count + queries := by
  rw [write_batch_query_count]
  exact Nat.add_le_add_left remaining count

/-- Fixed writes do not add selected fresh-input reprogramming instructions. -/
theorem write_batch_programming_count (count : Nat)
    (inputs : Fin count → FullRawInput bound) (outputs : Fin count → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work) :
    programmingCount (writeBatch count inputs outputs next) = programmingCount next := by
  induction count with
  | zero => rfl
  | succ count ih =>
      simpa only [writeBatch, programmingCount] using
        ih (fun i => inputs i.succ) (fun i => outputs i.succ)

attribute [irreducible] writeBatch

/-- The literal current source leaf key at every one of the 2^23 indices. -/
def actualLeafWriteInputs (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (tapes : LeafIndex → LeafTape) : LeafIndex → FullRawInput bound :=
  fun index => Sum.inl (sourceLeafInput (canonicalLeafHeader salt)
    (fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2 index)
    index (tapes index))

/-- Retained tapes and labels are written literally; this node samples no new
coins and never discards the table received from earlier requests. -/
def actualLeafWrites (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work) : MixedProgram (FullRawInput bound) Work :=
  writeBatch 8388608 (actualLeafWriteInputs values base masks salt tapes) labels next

theorem actual_leaf_write_batch_is_overlay
    (oracle : FullRawInput bound → DigestRegister)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister) :
    V8Smz9HonestLeafBatch.updateBatch 8388608
        (actualLeafWriteInputs values base masks salt tapes) labels oracle =
      V8Smz9DynamicPhysicalTransport.actualLeafOverlay oracle values base masks salt tapes labels := by
  have inputs : actualLeafWriteInputs (bound := bound) values base masks salt tapes =
      (fun index => Sum.inl (sourceLeafInput (canonicalLeafHeader salt)
        (fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2 index)
        index (tapes index))) := rfl
  rw [inputs]
  exact V8Smz9HonestLeafBatch.all_source_updates_are_full_overlay
      (Other := OtherRawInput bound) (fun _ => canonicalLeafHeader salt)
      (fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2)
      tapes labels oracle

theorem actual_leaf_writes_execution (randomized : Bool)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    run randomized (actualLeafWrites values base masks salt tapes labels next) oracle state =
      run randomized next
        (V8Smz9DynamicPhysicalTransport.actualLeafOverlay oracle values base masks salt tapes labels) state := by
  unfold actualLeafWrites
  rw [write_batch_execution, actual_leaf_write_batch_is_overlay]

theorem actual_leaf_writes_input_mass (cap : ℝ≥0∞)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work) (remaining : InputMassAtMost cap next) :
    InputMassAtMost cap (actualLeafWrites values base masks salt tapes labels next) :=
  write_batch_input_mass cap 8388608 _ labels next remaining

theorem actual_leaf_writes_query_count
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work) :
    queryCount (actualLeafWrites values base masks salt tapes labels next) =
      8388608 + queryCount next :=
  write_batch_query_count 8388608 _ labels next

theorem actual_leaf_writes_programming_count
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister)
    (next : MixedProgram (FullRawInput bound) Work) :
    programmingCount (actualLeafWrites values base masks salt tapes labels next) = programmingCount next :=
  write_batch_programming_count 8388608 _ labels next


end
end HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler
