import HegemonCrypto.SmallWoodV8Smz9HashTraceSchedule

namespace HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
open Hegemon.Transaction
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
set_option Elab.async false
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
noncomputable section

theorem source_linear_matches (pub rows : Nat → F) (group : Nat) (hg : group < 2)
    (input : List Nat) (initial : StateMatches (fun i => rows (283+182*group+i)) input) :
    StateMatches (externalState pub rows group 0)
      (Poseidon2Width16Kernel.externalLinearLayer input) := by
  constructor
  intro i hi
  change externalState pub rows group 0 i =
    (Poseidon2Width16Kernel.externalLinearLayer input |>.getD i 0 : F)
  rw [source_initial_layer pub rows hg ⟨i,hi⟩, externalField_cast_kernel input ⟨i,hi⟩]
  exact externalField_congr _ _ initial.lane ⟨i,hi⟩

theorem source_first_matches (pub rows : Nat → F) (group : Nat) (hg : group < 2)
    (recurrence : HashRecurrence group pub rows) (input : List Nat)
    (initial : StateMatches (fun i => rows (283+182*group+i)) input)
    (n : Nat) (hn : n ≤ 4) :
    StateMatches (externalState pub rows group n) (firstValues input n) := by
  exact scheduled_external_prefix Poseidon2Width16Kernel.externalRoundConstantsInitial
    (externalState pub rows group) (Poseidon2Width16Kernel.externalLinearLayer input)
    (source_linear_matches pub rows group hg input initial)
    (fun r hr lane => source_initial_round pub rows hg (by rwa [first_length] at hr)
      recurrence lane) n (by rwa [first_length])

theorem source_middle_matches (pub rows : Nat → F) (group : Nat) (hg : group < 2)
    (recurrence : HashRecurrence group pub rows) (input : List Nat)
    (initial : StateMatches (fun i => rows (283+182*group+i)) input)
    (n : Nat) (hn : n ≤ 22) :
    StateMatches (internalState pub rows group n) (middleValues input n) := by
  have first : StateMatches (internalState pub rows group 0) (firstValues input 4) :=
    source_first_matches pub rows group hg recurrence input initial 4 (by omega)
  have shape : (firstValues input 4).length = 16 :=
    external_rounds_length _ _ (Poseidon2Width16Kernel.external_linear_layer_length input)
  exact scheduled_internal_prefix Poseidon2Width16Kernel.internalRoundConstants
    (internalState pub rows group) (firstValues input 4) shape first
    (fun r hr lane => source_internal_round pub rows hg (by rwa [middle_length] at hr)
      recurrence lane) n (by rwa [middle_length])

theorem source_last_matches (pub rows : Nat → F) (group : Nat) (hg : group < 2)
    (recurrence : HashRecurrence group pub rows) (input : List Nat)
    (initial : StateMatches (fun i => rows (283+182*group+i)) input)
    (n : Nat) (hn : n ≤ 4) :
    StateMatches (terminalState pub rows group n) (lastValues input n) := by
  have middle : StateMatches (terminalState pub rows group 0) (middleValues input 22) :=
    source_middle_matches pub rows group hg recurrence input initial 22 (by omega)
  exact scheduled_external_prefix Poseidon2Width16Kernel.externalRoundConstantsTerminal
    (terminalState pub rows group) (middleValues input 22) middle
    (fun r hr lane => source_terminal_round pub rows hg (by rwa [last_length] at hr)
      recurrence lane) n (by rwa [last_length])

/-- The named root fixes the pre-S-box wire, including the actual round constant. -/
theorem recurrence_pre_wire (pub rows : Nat → F) (group : Nat) (hg : group < 2)
    (recurrence : HashRecurrence group pub rows) (wire : Nat) (hw : wire < 150) :
    rows (hashRow group wire) = nodeField pub rows (sboxInputNode group wire) +
      (roundConstant wire : F) := by
  have preceding := ordered_add_field pub rows (sbox_query_source hg hw
    (show ((hashRootPair group wire).1-1,
      orderedAdd (sboxInputNode group wire) (roundConstantNode wire)) ∈ sboxQueries group wire by
      simp [sboxQueries]))
  have row := recurrence wire (by omega)
  change rows (hashRow group wire) = nodeField pub rows (hashRootPair group wire).2 at row
  rw [sbox_expected_node hg hw, preceding, round_constant_field pub rows hw] at row
  exact row

theorem recurrence_initial_wires (pub rows : Nat → F) (group : Nat) (hg : group < 2)
    (recurrence : HashRecurrence group pub rows) (input : List Nat)
    (initial : StateMatches (fun i => rows (283+182*group+i)) input)
    (round lane : Nat) (hr : round < 4) (hl : lane < 16) :
    rows (hashRow group (16*round+lane)) =
      ((Poseidon2Width16Kernel.compressedTrace input).wires.getD (16*round+lane) 0 : F) := by
  rw [recurrence_pre_wire pub rows group hg recurrence _ (by omega),
    compressed_initial_wire input round lane hr hl, cast_fieldAdd]
  obtain ⟨previous, _, constant⟩ := initial_round_schedule hg hr ⟨lane,hl⟩
  rw [previous, constant]
  change externalState pub rows group round lane + _ = _
  rw [(source_first_matches pub rows group hg recurrence input initial round (by omega)).lane lane hl]
  rfl

theorem recurrence_internal_wires (pub rows : Nat → F) (group : Nat) (hg : group < 2)
    (recurrence : HashRecurrence group pub rows) (input : List Nat)
    (initial : StateMatches (fun i => rows (283+182*group+i)) input)
    (round : Nat) (hr : round < 22) :
    rows (hashRow group (64+round)) =
      ((Poseidon2Width16Kernel.compressedTrace input).wires.getD (64+round) 0 : F) := by
  rw [recurrence_pre_wire pub rows group hg recurrence _ (by omega),
    compressed_internal_wire input round hr, cast_fieldAdd]
  obtain ⟨previous, constant⟩ := internal_round_schedule hg hr
  rw [previous, constant]
  have index : nodeField pub rows
      (if round = 0 then externalOutputNode group 4 0 else internalOutputNode group (round-1) 0) =
      internalState pub rows group round 0 := by
    by_cases first : round = 0 <;> simp only [internalState, externalState, first, if_true, if_false]
  rw [index, (source_middle_matches pub rows group hg recurrence input initial round (by omega)).lane 0 (by omega)]
  rfl

theorem recurrence_terminal_wires (pub rows : Nat → F) (group : Nat) (hg : group < 2)
    (recurrence : HashRecurrence group pub rows) (input : List Nat)
    (initial : StateMatches (fun i => rows (283+182*group+i)) input)
    (round lane : Nat) (hr : round < 4) (hl : lane < 16) :
    rows (hashRow group (86+(16*round+lane))) =
      ((Poseidon2Width16Kernel.compressedTrace input).wires.getD (86+(16*round+lane)) 0 : F) := by
  have assoc : 86+(16*round+lane) = 86+16*round+lane := by omega
  rw [recurrence_pre_wire pub rows group hg recurrence _ (by omega),
    compressed_terminal_wire input round lane hr hl, cast_fieldAdd, assoc]
  obtain ⟨previous, _, constant⟩ := terminal_round_schedule hg hr ⟨lane,hl⟩
  rw [previous, constant]
  have index : nodeField pub rows
      (if round = 0 then internalOutputNode group 21 lane else externalOutputNode group (4+round) lane) =
      terminalState pub rows group round lane := by
    by_cases first : round = 0 <;> simp only [terminalState, externalState, first, if_true, if_false]
  rw [index, (source_last_matches pub rows group hg recurrence input initial round (by omega)).lane lane hl]
  rfl

/-- Every intermediate source wire is the corresponding actual compressed-trace wire. -/
theorem recurrence_all_wires (pub rows : Nat → F) (group : Nat) (hg : group < 2)
    (recurrence : HashRecurrence group pub rows) (input : List Nat)
    (initial : StateMatches (fun i => rows (283+182*group+i)) input)
    (wire : Nat) (hw : wire < 150) :
    rows (hashRow group wire) =
      ((Poseidon2Width16Kernel.compressedTrace input).wires.getD wire 0 : F) := by
  by_cases first : wire < 64
  · have split : 16 * (wire / 16) + wire % 16 = wire := by omega
    simpa only [split] using recurrence_initial_wires pub rows group hg recurrence input initial
      (wire/16) (wire%16) (by omega) (by omega)
  · by_cases middle : wire < 86
    · have split : 64 + (wire - 64) = wire := by omega
      simpa only [split] using recurrence_internal_wires pub rows group hg recurrence input initial
        (wire-64) (by omega)
    · have split : 86 + (16 * ((wire-86)/16) + (wire-86)%16) = wire := by omega
      simpa only [split] using recurrence_terminal_wires pub rows group hg recurrence input initial
        ((wire-86)/16) ((wire-86)%16) (by omega) (by omega)

end
end HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
