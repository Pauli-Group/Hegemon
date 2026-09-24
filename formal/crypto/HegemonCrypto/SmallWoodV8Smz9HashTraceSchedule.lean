import HegemonCrypto.SmallWoodV8Smz9HashReplayExistence
import HegemonCrypto.SmallWoodV8Smz9HonestHashMaterialization

namespace HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
open Hegemon.Transaction
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
set_option Elab.async false
set_option maxHeartbeats 600000
set_option maxRecDepth 10000

theorem trace_external_wire (rounds : List (List Nat)) (input : List Nat)
    (round lane : Nat) (hr : round < rounds.length) (hl : lane < 16) :
    (Poseidon2Width16Kernel.traceExternalRounds rounds input).wires.getD (16 * round + lane) 0 =
      Poseidon2Width16Kernel.fieldAdd
        ((rounds.take round).foldl Poseidon2Width16Kernel.externalRound input |>.getD lane 0)
        ((rounds.getD round []).getD lane 0) := by
  induction rounds generalizing input round with
  | nil => simp at hr
  | cons constants rounds ih =>
    cases round with
    | zero =>
      simp only [Nat.mul_zero, Nat.zero_add, Poseidon2Width16Kernel.traceExternalRounds,
        List.take_zero, List.foldl_nil, List.getD_cons_zero]
      rw [getD_append_left _ _ lane (by simpa only
        [Poseidon2Width16Kernel.external_round_wires_length, Poseidon2Width16Kernel.width] using hl)]
      simp only [Poseidon2Width16Kernel.externalRoundWires, Poseidon2Width16Kernel.width,
        List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hl,
        Option.map_some, Option.getD_some]
    | succ round =>
      have offset : 16 * (round + 1) + lane =
          (Poseidon2Width16Kernel.externalRoundWires input constants).length + (16 * round + lane) := by
        rw [Poseidon2Width16Kernel.external_round_wires_length]
        simp only [Poseidon2Width16Kernel.width]
        omega
      simp only [Poseidon2Width16Kernel.traceExternalRounds, offset, getD_append_offset,
        List.take_succ_cons, List.foldl_cons, List.getD_cons_succ]
      exact ih _ round (by simpa using hr)

theorem trace_internal_wire (rounds input : List Nat) (round : Nat) (hr : round < rounds.length) :
    (Poseidon2Width16Kernel.traceInternalRounds rounds input).wires.getD round 0 =
      Poseidon2Width16Kernel.fieldAdd
        ((rounds.take round).foldl Poseidon2Width16Kernel.internalRound input |>.getD 0 0)
        (rounds.getD round 0) := by
  induction rounds generalizing input round with
  | nil => simp at hr
  | cons constant rounds ih =>
    cases round with
    | zero => rfl
    | succ round =>
      simp only [Poseidon2Width16Kernel.traceInternalRounds, List.getD_cons_succ,
        List.take_succ_cons, List.foldl_cons]
      exact ih _ round (by simpa using hr)

noncomputable section

def firstValues (input : List Nat) (n : Nat) : List Nat :=
  (Poseidon2Width16Kernel.externalRoundConstantsInitial.take n).foldl
    Poseidon2Width16Kernel.externalRound (Poseidon2Width16Kernel.externalLinearLayer input)

def middleValues (input : List Nat) (n : Nat) : List Nat :=
  (Poseidon2Width16Kernel.internalRoundConstants.take n).foldl
    Poseidon2Width16Kernel.internalRound (firstValues input 4)

def lastValues (input : List Nat) (n : Nat) : List Nat :=
  (Poseidon2Width16Kernel.externalRoundConstantsTerminal.take n).foldl
    Poseidon2Width16Kernel.externalRound (middleValues input 22)

theorem first_length : Poseidon2Width16Kernel.externalRoundConstantsInitial.length = 4 := by decide
theorem middle_length : Poseidon2Width16Kernel.internalRoundConstants.length = 22 := by decide
theorem last_length : Poseidon2Width16Kernel.externalRoundConstantsTerminal.length = 4 := by decide

theorem first_full (input : List Nat) : firstValues input 4 =
    Poseidon2Width16Kernel.externalRoundConstantsInitial.foldl Poseidon2Width16Kernel.externalRound
      (Poseidon2Width16Kernel.externalLinearLayer input) := by
  unfold firstValues
  rw [List.take_of_length_le (by rw [first_length])]

theorem middle_full (input : List Nat) : middleValues input 22 =
    Poseidon2Width16Kernel.internalRoundConstants.foldl Poseidon2Width16Kernel.internalRound
      (firstValues input 4) := by
  unfold middleValues
  rw [List.take_of_length_le (by rw [middle_length])]

theorem compressed_initial_wire (input : List Nat) (round lane : Nat)
    (hr : round < 4) (hl : lane < 16) :
    (Poseidon2Width16Kernel.compressedTrace input).wires.getD (16 * round + lane) 0 =
      Poseidon2Width16Kernel.fieldAdd ((firstValues input round).getD lane 0)
        ((Poseidon2Width16Kernel.externalRoundConstantsInitial.getD round []).getD lane 0) := by
  unfold Poseidon2Width16Kernel.compressedTrace
  rw [getD_append_left _ _ _ (by
    simp only [List.length_append, Poseidon2Width16Kernel.trace_external_rounds_wire_count,
      Poseidon2Width16Kernel.trace_internal_rounds_wire_count, first_length, middle_length,
      Poseidon2Width16Kernel.width]
    omega)]
  rw [getD_append_left _ _ _ (by
    simp only [Poseidon2Width16Kernel.trace_external_rounds_wire_count, first_length,
      Poseidon2Width16Kernel.width]
    omega)]
  exact trace_external_wire _ _ round lane (by rw [first_length]; exact hr) hl

theorem compressed_internal_wire (input : List Nat) (round : Nat) (hr : round < 22) :
    (Poseidon2Width16Kernel.compressedTrace input).wires.getD (64 + round) 0 =
      Poseidon2Width16Kernel.fieldAdd ((middleValues input round).getD 0 0)
        (Poseidon2Width16Kernel.internalRoundConstants.getD round 0) := by
  unfold Poseidon2Width16Kernel.compressedTrace
  rw [getD_append_left _ _ _ (by
    simp only [List.length_append, Poseidon2Width16Kernel.trace_external_rounds_wire_count,
      Poseidon2Width16Kernel.trace_internal_rounds_wire_count, first_length, middle_length,
      Poseidon2Width16Kernel.width]
    omega)]
  have firstSize : (Poseidon2Width16Kernel.traceExternalRounds
      Poseidon2Width16Kernel.externalRoundConstantsInitial
      (Poseidon2Width16Kernel.externalLinearLayer input)).wires.length = 64 := by
    rw [Poseidon2Width16Kernel.trace_external_rounds_wire_count, first_length]
    rfl
  rw [← firstSize, getD_append_offset, trace_internal_wire _ _ round (by rw [middle_length]; exact hr),
    Poseidon2Width16Kernel.trace_external_rounds_final_state, ← first_full]
  rfl

theorem compressed_terminal_wire (input : List Nat) (round lane : Nat)
    (hr : round < 4) (hl : lane < 16) :
    (Poseidon2Width16Kernel.compressedTrace input).wires.getD (86 + (16 * round + lane)) 0 =
      Poseidon2Width16Kernel.fieldAdd ((lastValues input round).getD lane 0)
        ((Poseidon2Width16Kernel.externalRoundConstantsTerminal.getD round []).getD lane 0) := by
  unfold Poseidon2Width16Kernel.compressedTrace
  have earlierSize : ((Poseidon2Width16Kernel.traceExternalRounds
      Poseidon2Width16Kernel.externalRoundConstantsInitial
      (Poseidon2Width16Kernel.externalLinearLayer input)).wires ++
    (Poseidon2Width16Kernel.traceInternalRounds Poseidon2Width16Kernel.internalRoundConstants
      (Poseidon2Width16Kernel.traceExternalRounds Poseidon2Width16Kernel.externalRoundConstantsInitial
        (Poseidon2Width16Kernel.externalLinearLayer input)).finalState).wires).length = 86 := by
    simp only [List.length_append, Poseidon2Width16Kernel.trace_external_rounds_wire_count,
      Poseidon2Width16Kernel.trace_internal_rounds_wire_count, first_length, middle_length,
      Poseidon2Width16Kernel.width]
  rw [← earlierSize, getD_append_offset,
    trace_external_wire _ _ round lane (by rw [last_length]; exact hr) hl,
    Poseidon2Width16Kernel.trace_internal_rounds_final_state,
    Poseidon2Width16Kernel.trace_external_rounds_final_state, ← first_full, ← middle_full]
  rfl

theorem scheduled_external_prefix (rounds : List (List Nat))
    (states : Nat → Nat → F) (values : List Nat)
    (initial : StateMatches (states 0) values)
    (step : ∀ n, n < rounds.length → ∀ lane : Fin 16,
      states (n+1) lane.val = externalStep (states n) (rounds.getD n []) lane.val)
    (n : Nat) (hn : n ≤ rounds.length) :
    StateMatches (states n) ((rounds.take n).foldl Poseidon2Width16Kernel.externalRound values) := by
  have length : (rounds.take n).length = n := List.length_take_of_le hn
  have result := scheduled_external_rounds (rounds.take n) states values initial (by
    intro i hi lane
    have small : i < n := by simpa only [length] using hi
    have equation := step i (by omega) lane
    simpa only [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos small] using equation)
  simpa only [length] using result

theorem scheduled_internal_prefix (rounds : List Nat)
    (states : Nat → Nat → F) (values : List Nat) (shape : values.length = 16)
    (initial : StateMatches (states 0) values)
    (step : ∀ n, n < rounds.length → ∀ lane : Fin 16,
      states (n+1) lane.val = internalStep (states n) (rounds.getD n 0) lane.val)
    (n : Nat) (hn : n ≤ rounds.length) :
    StateMatches (states n) ((rounds.take n).foldl Poseidon2Width16Kernel.internalRound values) := by
  have length : (rounds.take n).length = n := List.length_take_of_le hn
  have result := scheduled_internal_rounds (rounds.take n) states values shape initial (by
    intro i hi lane
    have small : i < n := by simpa only [length] using hi
    have equation := step i (by omega) lane
    simpa only [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos small] using equation)
  simpa only [length] using result

end
end HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
