import Hegemon.Transaction.Poseidon2V8ConstraintRefinement
import Hegemon.Transaction.Poseidon2V8DecoderRefinement

/-! Exact constructive hash-row component of the V8 honest lowerer.

This is only the 364 by 64 block at full-relation rows 283 through 646.
The 125 live initial states are explicit canonical component inputs. Their
derivation from typed transaction semantics is not assumed or proved here.
Calls 125, 126 and 127 start at zero and run the actual compressed trace;
their output/wire blocks are not replaced by zeros. No other relation rows
are constructed, and no Rust execution or full packed acceptance is claimed.
-/

namespace HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization

open Hegemon.Transaction

set_option maxRecDepth 10000
set_option maxHeartbeats 600000
set_option Elab.async false

abbrev LiveInitialStates := Fin 125 → Fin 16 → Fin Poseidon2Width16Kernel.fieldModulus

def CanonicalWords (words : List Nat) : Prop :=
  ∀ value, value ∈ words → value < Poseidon2Width16Kernel.fieldModulus

theorem modulus_positive : 0 < Poseidon2Width16Kernel.fieldModulus := by decide

theorem getD_canonical (words : List Nat) (canonical : CanonicalWords words)
    (index : Nat) : words.getD index 0 < Poseidon2Width16Kernel.fieldModulus := by
  cases found : words[index]? with
  | none => simp [List.getD_eq_getElem?_getD, found, modulus_positive]
  | some value =>
      simpa [List.getD_eq_getElem?_getD, found] using
        canonical value (List.mem_of_getElem? found)

theorem field_add_canonical (left right : Nat) : Poseidon2Width16Kernel.fieldAdd left right < Poseidon2Width16Kernel.fieldModulus :=
  Nat.mod_lt _ modulus_positive

theorem mds4_canonical (input : List Nat) : CanonicalWords (Poseidon2Width16Kernel.applyMds4 input) := by
  intro value member
  simp only [Poseidon2Width16Kernel.applyMds4, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl <;> exact field_add_canonical _ _

theorem external_layer_canonical (input : List Nat) :
    CanonicalWords (Poseidon2Width16Kernel.externalLinearLayer input) := by
  intro value member
  obtain ⟨index, _, rfl⟩ := List.mem_map.mp member
  exact getD_canonical _ (mds4_canonical _) _

theorem internal_layer_canonical (input : List Nat) :
    CanonicalWords (Poseidon2Width16Kernel.internalLinearLayer input) := by
  intro value member
  obtain ⟨index, _, rfl⟩ := List.mem_map.mp member
  exact field_add_canonical _ _

theorem external_round_canonical (input constants : List Nat) :
    CanonicalWords (Poseidon2Width16Kernel.externalRound input constants) := external_layer_canonical _

theorem internal_round_canonical (input : List Nat) (constant : Nat) :
    CanonicalWords (Poseidon2Width16Kernel.internalRound input constant) := internal_layer_canonical _

theorem external_wires_canonical (input constants : List Nat) :
    CanonicalWords (Poseidon2Width16Kernel.externalRoundWires input constants) := by
  intro value member
  obtain ⟨index, _, rfl⟩ := List.mem_map.mp member
  exact field_add_canonical _ _

theorem trace_external_canonical (rounds : List (List Nat)) (input : List Nat)
    (canonical : CanonicalWords input) :
    CanonicalWords (Poseidon2Width16Kernel.traceExternalRounds rounds input).wires ∧
      CanonicalWords (Poseidon2Width16Kernel.traceExternalRounds rounds input).finalState := by
  induction rounds generalizing input with
  | nil => exact ⟨by simp [Poseidon2Width16Kernel.traceExternalRounds, CanonicalWords], canonical⟩
  | cons constants rounds ih =>
      have tail := ih (Poseidon2Width16Kernel.externalRound input constants) (external_round_canonical _ _)
      constructor
      · intro value member
        rcases List.mem_append.mp member with left | right
        · exact external_wires_canonical _ _ value left
        · exact tail.1 value right
      · exact tail.2

theorem trace_internal_canonical (rounds input : List Nat)
    (canonical : CanonicalWords input) :
    CanonicalWords (Poseidon2Width16Kernel.traceInternalRounds rounds input).wires ∧
      CanonicalWords (Poseidon2Width16Kernel.traceInternalRounds rounds input).finalState := by
  induction rounds generalizing input with
  | nil => exact ⟨by simp [Poseidon2Width16Kernel.traceInternalRounds, CanonicalWords], canonical⟩
  | cons constant rounds ih =>
      have tail := ih (Poseidon2Width16Kernel.internalRound input constant) (internal_round_canonical _ _)
      constructor
      · intro value member
        rcases List.mem_cons.mp member with rfl | right
        · exact field_add_canonical _ _
        · exact tail.1 value right
      · exact tail.2

theorem trace_chain_canonical (first : List (List Nat)) (middle : List Nat)
    (last : List (List Nat)) (input : List Nat) :
    let initial := Poseidon2Width16Kernel.traceExternalRounds first
      (Poseidon2Width16Kernel.externalLinearLayer input)
    let internal := Poseidon2Width16Kernel.traceInternalRounds middle initial.finalState
    let terminal := Poseidon2Width16Kernel.traceExternalRounds last internal.finalState
    CanonicalWords (initial.wires ++ internal.wires ++ terminal.wires) ∧
      CanonicalWords terminal.finalState := by
  have initial := trace_external_canonical first
    (Poseidon2Width16Kernel.externalLinearLayer input) (external_layer_canonical input)
  have internal := trace_internal_canonical middle
    (Poseidon2Width16Kernel.traceExternalRounds first (Poseidon2Width16Kernel.externalLinearLayer input)).finalState
    initial.2
  have terminal := trace_external_canonical last
    (Poseidon2Width16Kernel.traceInternalRounds middle
      (Poseidon2Width16Kernel.traceExternalRounds first (Poseidon2Width16Kernel.externalLinearLayer input)).finalState).finalState
    internal.2
  constructor
  · intro value member
    rcases List.mem_append.mp member with earlier | last
    · rcases List.mem_append.mp earlier with first | middle
      · exact initial.1 value first
      · exact internal.1 value middle
    · exact terminal.1 value last
  · exact terminal.2

def traceWith (first : List (List Nat)) (middle : List Nat)
    (last : List (List Nat)) (input : List Nat) : Poseidon2Width16Kernel.CompressedTrace :=
  let initial := Poseidon2Width16Kernel.traceExternalRounds first
    (Poseidon2Width16Kernel.externalLinearLayer input)
  let internal := Poseidon2Width16Kernel.traceInternalRounds middle initial.finalState
  let terminal := Poseidon2Width16Kernel.traceExternalRounds last internal.finalState
  ⟨initial.wires ++ internal.wires ++ terminal.wires, terminal.finalState⟩

def TraceCanonical (trace : Poseidon2Width16Kernel.CompressedTrace) : Prop :=
  CanonicalWords trace.wires ∧ CanonicalWords trace.finalState

theorem trace_with_canonical (first : List (List Nat)) (middle : List Nat)
    (last : List (List Nat)) (input : List Nat) :
    TraceCanonical (traceWith first middle last input) :=
  trace_chain_canonical first middle last input

theorem compressed_trace_canonical (input : List Nat) :
    TraceCanonical (Poseidon2Width16Kernel.compressedTrace input) :=
  trace_with_canonical Poseidon2Width16Kernel.externalRoundConstantsInitial
    Poseidon2Width16Kernel.internalRoundConstants
    Poseidon2Width16Kernel.externalRoundConstantsTerminal input

theorem trace_external_length (rounds : List (List Nat)) (input : List Nat)
    (length : input.length = 16) :
    (Poseidon2Width16Kernel.traceExternalRounds rounds input).finalState.length = 16 := by
  induction rounds generalizing input with
  | nil => exact length
  | cons constants rounds ih =>
      exact ih _ (Poseidon2Width16Kernel.external_round_length _ _)

theorem trace_internal_length (rounds input : List Nat) (length : input.length = 16) :
    (Poseidon2Width16Kernel.traceInternalRounds rounds input).finalState.length = 16 := by
  induction rounds generalizing input with
  | nil => exact length
  | cons constant rounds ih =>
      exact ih _ (Poseidon2Width16Kernel.internal_round_length _ _)

theorem trace_chain_final_length (first : List (List Nat)) (middle : List Nat)
    (last : List (List Nat)) (input : List Nat) :
    (Poseidon2Width16Kernel.traceExternalRounds last
      (Poseidon2Width16Kernel.traceInternalRounds middle
        (Poseidon2Width16Kernel.traceExternalRounds first
          (Poseidon2Width16Kernel.externalLinearLayer input)).finalState).finalState).finalState.length = 16 := by
  apply trace_external_length
  apply trace_internal_length
  apply trace_external_length
  exact Poseidon2Width16Kernel.external_linear_layer_length input

def TraceFinalLength (trace : Poseidon2Width16Kernel.CompressedTrace) : Prop :=
  trace.finalState.length = 16

theorem trace_with_final_length (first : List (List Nat)) (middle : List Nat)
    (last : List (List Nat)) (input : List Nat) :
    TraceFinalLength (traceWith first middle last input) :=
  trace_chain_final_length first middle last input

theorem compressed_trace_final_length (input : List Nat) :
    TraceFinalLength (Poseidon2Width16Kernel.compressedTrace input) :=
  trace_with_final_length Poseidon2Width16Kernel.externalRoundConstantsInitial
    Poseidon2Width16Kernel.internalRoundConstants
    Poseidon2Width16Kernel.externalRoundConstantsTerminal input

/-- Actual padded call inputs: live inputs are retained; dummy starts are zero. -/
def callInitial (live : LiveInitialStates) (call : Nat) : List Nat :=
  List.ofFn fun lane : Fin 16 => if bound : call < 125 then (live ⟨call, bound⟩ lane).val else 0

theorem call_initial_length (live : LiveInitialStates) (call : Nat) :
    (callInitial live call).length = 16 := by simp [callInitial]

theorem call_initial_canonical (live : LiveInitialStates) (call : Nat) :
    CanonicalWords (callInitial live call) := by
  intro value member
  obtain ⟨lane, rfl⟩ := List.mem_ofFn.mp member
  split
  · exact (live _ lane).isLt
  · exact modulus_positive

/-- The 16 initial words, 150 exact compressed wires, then 16 exact final words. -/
def callColumn (live : LiveInitialStates) (call : Nat) : List Nat :=
  let initial := callInitial live call
  let trace := Poseidon2Width16Kernel.compressedTrace initial
  initial ++ trace.wires ++ trace.finalState

theorem call_column_length (live : LiveInitialStates) (call : Nat) :
    (callColumn live call).length = 182 := by
  simp only [callColumn, List.length_append, call_initial_length,
    Poseidon2Width16Kernel.compressed_trace_has_exact_wire_count]
  have length := compressed_trace_final_length (callInitial live call)
  change (Poseidon2Width16Kernel.compressedTrace (callInitial live call)).finalState.length = 16 at length
  omega

theorem call_column_canonical (live : LiveInitialStates) (call : Nat) :
    CanonicalWords (callColumn live call) := by
  intro value member
  rcases List.mem_append.mp member with prior | final
  · rcases List.mem_append.mp prior with initial | wires
    · exact call_initial_canonical live call value initial
    · exact (compressed_trace_canonical _).1 value wires
  · exact (compressed_trace_canonical _).2 value final

/-- Complete 364-row hash block, transposing 128 concrete call columns into two groups. -/
def hashRows (live : LiveInitialStates) : List (List Nat) :=
  List.ofFn fun row : Fin 364 =>
    List.ofFn fun lane : Fin 64 =>
      (callColumn live ((row.val / 182) * 64 + lane.val)).getD (row.val % 182) 0

theorem hash_rows_shape (live : LiveInitialStates) :
    (hashRows live).length = 364 ∧
      ∀ row, row ∈ hashRows live → row.length = 64 := by
  constructor
  · simp only [hashRows, List.length_ofFn]
  · intro row member
    obtain ⟨index, rfl⟩ := List.mem_ofFn.mp member
    exact List.length_ofFn

theorem hash_rows_canonical (live : LiveInitialStates) : Poseidon2V8ConstraintRefinement.PackedHashRowsCanonical (hashRows live) := by
  refine ⟨(hash_rows_shape live).1, ?_⟩
  intro row member
  obtain ⟨index, rfl⟩ := List.mem_ofFn.mp member
  refine ⟨by simp only [List.length_ofFn]; rfl, ?_⟩
  intro value member
  obtain ⟨lane, rfl⟩ := List.mem_ofFn.mp member
  exact getD_canonical _ (call_column_canonical live _) _

theorem ofFn_getD {α : Type} {count : Nat} (f : Fin count → α)
    (fallback : α) (index : Nat) (bound : index < count) :
    (List.ofFn f).getD index fallback = f ⟨index, bound⟩ := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn, dif_pos bound, Option.getD_some]

theorem hash_word_at (live : LiveInitialStates) (row lane : Nat)
    (rowBound : row < 364) (laneBound : lane < 64) :
    Poseidon2V8ConstraintRefinement.packedHashValue (hashRows live) row lane =
      (callColumn live ((row / 182) * 64 + lane)).getD (row % 182) 0 := by
  unfold Poseidon2V8ConstraintRefinement.packedHashValue hashRows
  rw [ofFn_getD _ [] row rowBound, ofFn_getD _ 0 lane laneBound]

theorem getD_append_left (left right : List Nat) (index : Nat) (bound : index < left.length) :
    (left ++ right).getD index 0 = left.getD index 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_append_left bound]

theorem getD_append_offset (left right : List Nat) (index : Nat) :
    (left ++ right).getD (left.length + index) 0 = right.getD index 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_append_right (by omega :
    left.length ≤ left.length + index), Nat.add_sub_cancel_left]

theorem three_piece_initial (initial wires final : List Nat) (index : Nat)
    (bound : index < initial.length) :
    (initial ++ wires ++ final).getD index 0 = initial.getD index 0 := by
  rw [getD_append_left _ final index (by simp only [List.length_append]; omega),
    getD_append_left initial wires index bound]

theorem three_piece_wire (initial wires final : List Nat) (index : Nat)
    (bound : index < wires.length) :
    (initial ++ wires ++ final).getD (initial.length + index) 0 = wires.getD index 0 := by
  rw [getD_append_left _ final _ (by simp only [List.length_append]; omega), getD_append_offset]

theorem three_piece_final (initial wires final : List Nat) (index : Nat) :
    (initial ++ wires ++ final).getD (initial.length + wires.length + index) 0 = final.getD index 0 := by
  have length : initial.length + wires.length = (initial ++ wires).length := List.length_append.symm
  rw [length, getD_append_offset]

theorem call_column_initial (live : LiveInitialStates) (call word : Nat) (bound : word < 16) :
    (callColumn live call).getD word 0 = (callInitial live call).getD word 0 :=
  three_piece_initial _ _ _ word (by rw [call_initial_length]; exact bound)

theorem call_column_wire (live : LiveInitialStates) (call wire : Nat) (bound : wire < 150) :
    (callColumn live call).getD (16 + wire) 0 =
      (Poseidon2Width16Kernel.compressedTrace (callInitial live call)).wires.getD wire 0 := by
  have result := three_piece_wire (callInitial live call)
    (Poseidon2Width16Kernel.compressedTrace (callInitial live call)).wires
    (Poseidon2Width16Kernel.compressedTrace (callInitial live call)).finalState wire
    (by rw [Poseidon2Width16Kernel.compressed_trace_has_exact_wire_count]; exact bound)
  simpa only [callColumn, call_initial_length] using result

theorem call_column_final (live : LiveInitialStates) (call word : Nat) :
    (callColumn live call).getD (166 + word) 0 =
      (Poseidon2Width16Kernel.compressedTrace (callInitial live call)).finalState.getD word 0 := by
  have result := three_piece_final (callInitial live call)
    (Poseidon2Width16Kernel.compressedTrace (callInitial live call)).wires
    (Poseidon2Width16Kernel.compressedTrace (callInitial live call)).finalState word
  simpa only [callColumn, call_initial_length, Poseidon2Width16Kernel.compressed_trace_has_exact_wire_count,
    Nat.reduceAdd] using result

open Poseidon2V8ConstraintRefinement

theorem hash_initial_word (live : LiveInitialStates) (group lane word : Nat)
    (groupBound : group < 2) (laneBound : lane < 64) (wordBound : word < 16) :
    packedHashValue (hashRows live) (hashInitialLocalRow group word) lane =
      (callInitial live (group * 64 + lane)).getD word 0 := by
  have row : hashInitialLocalRow group word = group * 182 + word := rfl
  rw [row, hash_word_at live _ lane (by omega) laneBound]
  have quotient : (group * 182 + word) / 182 = group := by omega
  have remainder : (group * 182 + word) % 182 = word := by omega
  rw [quotient, remainder, call_column_initial live _ _ wordBound]

theorem hash_wire_word (live : LiveInitialStates) (group lane wire : Nat)
    (groupBound : group < 2) (laneBound : lane < 64) (wireBound : wire < 150) :
    packedHashValue (hashRows live) (hashSboxWireLocalRow group wire) lane =
      (Poseidon2Width16Kernel.compressedTrace (callInitial live (group * 64 + lane))).wires.getD wire 0 := by
  have row : hashSboxWireLocalRow group wire = group * 182 + (16 + wire) := by
    simp only [hashSboxWireLocalRow, hashGroupLocalRowStart, hashRowsPerGroup,
      Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.sboxWiresPerCall,
      Poseidon2Width16Kernel.externalRoundsPerHalf, Poseidon2Width16Kernel.internalRounds]
    omega
  rw [row, hash_word_at live _ lane (by omega) laneBound]
  have quotient : (group * 182 + (16 + wire)) / 182 = group := by omega
  have remainder : (group * 182 + (16 + wire)) % 182 = 16 + wire := by omega
  rw [quotient, remainder, call_column_wire live _ _ wireBound]

theorem hash_final_word (live : LiveInitialStates) (group lane word : Nat)
    (groupBound : group < 2) (laneBound : lane < 64) (wordBound : word < 16) :
    packedHashValue (hashRows live) (hashFinalLocalRow group word) lane =
      (Poseidon2Width16Kernel.compressedTrace (callInitial live (group * 64 + lane))).finalState.getD word 0 := by
  have row : hashFinalLocalRow group word = group * 182 + (166 + word) := by
    simp only [hashFinalLocalRow, hashGroupLocalRowStart, hashRowsPerGroup,
      Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.sboxWiresPerCall,
      Poseidon2Width16Kernel.externalRoundsPerHalf, Poseidon2Width16Kernel.internalRounds]
    omega
  rw [row, hash_word_at live _ lane (by omega) laneBound]
  have quotient : (group * 182 + (166 + word)) / 182 = group := by omega
  have remainder : (group * 182 + (166 + word)) % 182 = 166 + word := by omega
  rw [quotient, remainder, call_column_final]

theorem range_getD (words : List Nat) (count : Nat) (length : words.length = count) :
    (List.range count).map (fun index => words.getD index 0) = words := by
  apply List.ext_getElem (by simp only [List.length_map, List.length_range, length])
  intro index _ bound
  simp only [List.getElem_map, List.getElem_range, List.getD_eq_getElem?_getD,
    List.getElem?_eq_getElem bound, Option.getD_some]

theorem group_initial_is_actual (live : LiveInitialStates) (group lane : Nat)
    (groupBound : group < 2) (laneBound : lane < 64) :
    groupInitialState (hashRows live) group lane = callInitial live (group * 64 + lane) := by
  unfold groupInitialState
  calc
    _ = (List.range 16).map (fun word => (callInitial live (group * 64 + lane)).getD word 0) := by
      apply List.map_congr_left
      intro word member
      exact hash_initial_word live group lane word groupBound laneBound (List.mem_range.mp member)
    _ = _ := range_getD _ 16 (call_initial_length live _)

theorem group_wires_are_actual (live : LiveInitialStates) (group lane : Nat)
    (groupBound : group < 2) (laneBound : lane < 64) :
    groupSboxWires (hashRows live) group lane =
      (Poseidon2Width16Kernel.compressedTrace (callInitial live (group * 64 + lane))).wires := by
  unfold groupSboxWires
  calc
    _ = (List.range 150).map (fun wire =>
        (Poseidon2Width16Kernel.compressedTrace (callInitial live (group * 64 + lane))).wires.getD wire 0) := by
      apply List.map_congr_left
      intro wire member
      exact hash_wire_word live group lane wire groupBound laneBound (List.mem_range.mp member)
    _ = _ := range_getD _ 150 (Poseidon2Width16Kernel.compressed_trace_has_exact_wire_count _)

theorem group_final_is_actual (live : LiveInitialStates) (group lane : Nat)
    (groupBound : group < 2) (laneBound : lane < 64) :
    groupFinalState (hashRows live) group lane =
      (Poseidon2Width16Kernel.compressedTrace (callInitial live (group * 64 + lane))).finalState := by
  unfold groupFinalState
  calc
    _ = (List.range 16).map (fun word =>
        (Poseidon2Width16Kernel.compressedTrace (callInitial live (group * 64 + lane))).finalState.getD word 0) := by
      apply List.map_congr_left
      intro word member
      exact hash_final_word live group lane word groupBound laneBound (List.mem_range.mp member)
    _ = _ := range_getD _ 16 (compressed_trace_final_length _)

theorem hash_group_trace_matches (live : LiveInitialStates) (group lane : Nat)
    (groupBound : group < 2) (laneBound : lane < 64) :
    HashGroupTraceMatches (hashRows live) group lane := by
  constructor
  · rw [group_initial_is_actual live group lane groupBound laneBound]
    exact group_wires_are_actual live group lane groupBound laneBound
  · rw [group_initial_is_actual live group lane groupBound laneBound]
    exact group_final_is_actual live group lane groupBound laneBound

theorem call_initial_live (live : LiveInitialStates) (call : Fin 125) (word : Fin 16) :
    (callInitial live call.val).getD word.val 0 = (live call word).val := by
  unfold callInitial
  rw [ofFn_getD _ 0 word.val word.isLt]
  simp only [dif_pos call.isLt]

theorem call_initial_dummy (live : LiveInitialStates) (call : Nat) (dummy : 125 ≤ call) :
    callInitial live call = List.replicate 16 0 := by
  apply List.ext_getElem (by simp only [call_initial_length, List.length_replicate])
  intro index _ bound
  simp only [callInitial, List.getElem_ofFn, dif_neg (by omega : ¬ call < 125),
    List.getElem_replicate bound]

theorem dummy_starts_zero (live : LiveInitialStates) : DummyHashStartsZero (hashRows live) := by
  intro call liveBound callBound word wordBound
  change 125 ≤ call at liveBound
  change call < 128 at callBound
  change word < 16 at wordBound
  change packedHashValue (hashRows live) (hashInitialLocalRow (call / 64) word) (call % 64) = 0
  rw [hash_initial_word live _ _ _ (by omega) (by omega) wordBound]
  have recombined : call / 64 * 64 + call % 64 = call := by omega
  rw [recombined, call_initial_dummy live call liveBound]
  simp only [List.getD_eq_getElem?_getD, List.getElem?_replicate, if_pos wordBound, Option.getD_some]

/-- The computed block inhabits the existing fixed hash-kernel shape/trace predicate.
This is not an equivalence to Rust execution or to all generated relation roots. -/
theorem computed_hash_kernel_accepted (live : LiveInitialStates) : LeanHashKernelAccepted (hashRows live) := by
  refine ⟨hash_rows_canonical live, ?_, dummy_starts_zero live⟩
  intro group groupBound lane laneBound
  exact hash_group_trace_matches live group lane groupBound laneBound


end HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
