import HegemonCrypto.SmallWoodV8Smz9HonestHashMaterialization
import Hegemon.Transaction.Poseidon2V8SemanticSpecification
import Mathlib.Data.List.GetD

namespace HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
set_option Elab.async false
set_option maxHeartbeats 600000
set_option maxRecDepth 10000

abbrev Word := Fin Poseidon2Width16Kernel.fieldModulus
abbrev State := Fin 16 → Word

def word (value : Nat) : Word := ⟨value % Poseidon2Width16Kernel.fieldModulus, Nat.mod_lt _ modulus_positive⟩
def zeroState : State := fun _ => word 0
def stateWords (state : State) : List Nat := List.ofFn (fun i => (state i).val)
def wordAtState (state : State) (lane : Nat) : Nat := (stateWords state).getD lane 0
def stateOfWords (values : List Nat) : State := fun i => word (values.getD i.val 0)

theorem word_exact (value : Nat) (canonical : value < Poseidon2Width16Kernel.fieldModulus) :
    (word value).val = value := Nat.mod_eq_of_lt canonical

theorem state_words_length (state : State) : (stateWords state).length = 16 := by
  simp only [stateWords, List.length_ofFn]

theorem state_words_canonical (state : State) : CanonicalWords (stateWords state) := by
  intro value member
  obtain ⟨i, rfl⟩ := List.mem_ofFn.mp member
  exact (state i).isLt

theorem state_of_words_exact (values : List Nat) (shape : values.length = 16)
    (canonical : CanonicalWords values) : stateWords (stateOfWords values) = values := by
  apply List.ext_getElem (by simp only [state_words_length, shape])
  intro i hi hj
  have bound : i < 16 := by simpa only [state_words_length] using hi
  simp only [stateWords, List.getElem_ofFn, stateOfWords, word]
  rw [Nat.mod_eq_of_lt (getD_canonical values canonical i)]
  exact List.getD_eq_getElem values 0 hj

def runState (state : State) : State :=
  stateOfWords (Poseidon2Width16Kernel.permutation (stateWords state))

theorem permutation_words_canonical (values : List Nat) :
    CanonicalWords (Poseidon2Width16Kernel.permutation values) := by
  have result := (compressed_trace_canonical values).2
  change CanonicalWords (Poseidon2Width16Kernel.compressedTrace values).finalState at result
  rwa [Poseidon2Width16Kernel.compressed_trace_final_state] at result

theorem run_state_is_exact_primitive (state : State) : stateWords (runState state) =
    Poseidon2Width16Kernel.permutation (stateWords state) := by
  apply state_of_words_exact
  · have shape := compressed_trace_final_length (stateWords state)
    change (Poseidon2Width16Kernel.compressedTrace (stateWords state)).finalState.length = 16 at shape
    rwa [Poseidon2Width16Kernel.compressed_trace_final_state] at shape
  · exact permutation_words_canonical _

def spongePreparedWords (domain : Nat) (inputs : List Nat) (blocks : Nat)
    (previous : List Nat) (block : Nat) : List Nat :=
  let seeded := if block = 0 then poseidon2V8SeedFirstBlock domain inputs.length previous else previous
  let absorbed := (List.range Poseidon2Width16Kernel.rate).foldl (fun current lane =>
    let inputIndex := block * Poseidon2Width16Kernel.rate + lane
    if inputIndex < inputs.length then
      current.set lane (Poseidon2Width16Kernel.fieldAdd (current.getD lane 0) (inputs.getD inputIndex 0))
    else current) seeded
  if block + 1 = blocks then absorbed.set (Poseidon2Width16Kernel.rate + 3)
    (Poseidon2Width16Kernel.fieldAdd (absorbed.getD (Poseidon2Width16Kernel.rate + 3) 0) 1)
  else absorbed

theorem sponge_absorb_is_source_preparation (domain : Nat) (inputs : List Nat) (blocks : Nat)
    (previous : List Nat) (block : Nat) :
    poseidon2V8AbsorbBlock domain inputs blocks previous block =
      Poseidon2Width16Kernel.permutation (spongePreparedWords domain inputs blocks previous block) := rfl

theorem canonical_set (values : List Nat) (canonical : CanonicalWords values)
    (index value : Nat) (bound : value < Poseidon2Width16Kernel.fieldModulus) :
    CanonicalWords (values.set index value) := by
  intro entry member
  rcases List.mem_or_eq_of_mem_set member with old | rfl
  · exact canonical entry old
  · exact bound

theorem sponge_prepared_shape (domain : Nat) (inputs : List Nat) (blocks : Nat)
    (previous : List Nat) (block : Nat) (shape : previous.length = 16) :
    (spongePreparedWords domain inputs blocks previous block).length = 16 := by
  have foldShape (lanes : List Nat) (values : List Nat) (hv : values.length = 16) :
      (lanes.foldl (fun current lane =>
        if block * Poseidon2Width16Kernel.rate + lane < inputs.length then
          current.set lane (Poseidon2Width16Kernel.fieldAdd (current.getD lane 0)
            (inputs.getD (block * Poseidon2Width16Kernel.rate + lane) 0))
        else current) values).length = 16 := by
    induction lanes generalizing values with
    | nil => exact hv
    | cons lane lanes ih =>
      apply ih
      dsimp only
      split <;> simp only [List.length_set, hv]
  by_cases final : block + 1 = blocks
  all_goals simp only [spongePreparedWords, final, if_true, if_false, List.length_set]
  all_goals apply foldShape
  all_goals split <;> simp only [poseidon2V8SeedFirstBlock, List.length_set, shape]

theorem sponge_prepared_canonical (domain : Nat) (inputs : List Nat) (blocks : Nat)
    (previous : List Nat) (block : Nat) (canonical : CanonicalWords previous)
    (domainBound : domain < Poseidon2Width16Kernel.fieldModulus)
    (lengthBound : inputs.length < Poseidon2Width16Kernel.fieldModulus) :
    CanonicalWords (spongePreparedWords domain inputs blocks previous block) := by
  have seeded : CanonicalWords
      (if block = 0 then poseidon2V8SeedFirstBlock domain inputs.length previous else previous) := by
    split
    · exact canonical_set _ (canonical_set _ (canonical_set _ (canonical_set _ canonical _ _ domainBound)
        _ _ lengthBound) _ _ (by decide)) _ _ (by decide)
    · exact canonical
  have folded (lanes : List Nat) (values : List Nat) (hv : CanonicalWords values) :
      CanonicalWords (lanes.foldl (fun current lane =>
        if block * Poseidon2Width16Kernel.rate + lane < inputs.length then
          current.set lane (Poseidon2Width16Kernel.fieldAdd (current.getD lane 0)
            (inputs.getD (block * Poseidon2Width16Kernel.rate + lane) 0))
        else current) values) := by
    induction lanes generalizing values with
    | nil => exact hv
    | cons lane lanes ih =>
      apply ih
      dsimp only
      split
      · exact canonical_set _ hv _ _ (field_add_canonical _ _)
      · exact hv
  by_cases final : block + 1 = blocks
  all_goals simp only [spongePreparedWords, final, if_true, if_false]
  · exact canonical_set _ (folded _ _ seeded) _ _ (field_add_canonical _ _)
  · exact folded _ _ seeded

def spongeFrame (domain : Nat) (inputs : List Nat) (blocks : Nat) (previous : State) (block : Nat) : State :=
  stateOfWords (spongePreparedWords domain inputs blocks (stateWords previous) block)

theorem sponge_frame_exact (domain : Nat) (inputs : List Nat) (blocks : Nat)
    (previous : State) (block : Nat) (hd : domain < Poseidon2Width16Kernel.fieldModulus)
    (hi : inputs.length < Poseidon2Width16Kernel.fieldModulus) :
    stateWords (spongeFrame domain inputs blocks previous block) =
      spongePreparedWords domain inputs blocks (stateWords previous) block :=
  state_of_words_exact _ (sponge_prepared_shape _ _ _ _ _ (state_words_length previous))
    (sponge_prepared_canonical _ _ _ _ _ (state_words_canonical previous) hd hi)

def compressFrameWords (domain : Nat) (left right : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 7 then left.getD lane 0
    else if lane < 14 then right.getD (lane - 7) 0
    else if lane = 14 then domain else poseidon2V8SuiteMarker

def compressFrame (domain : Nat) (left right : List Nat) : State :=
  stateOfWords (compressFrameWords domain left right)

theorem compress_digest_is_exact_source (domain : Nat) (left right : List Nat) :
    (Poseidon2Width16Kernel.permutation (compressFrameWords domain left right)).take 7 =
      poseidon2V8Compress14 domain left right := rfl

end HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule

