import NullifierHighLunaImportLightAcceptedAll64
import SmzaRp05NullifierSourceDirection

/-! Initial-state bridge using the import-light checked all-64 accepted
readback. Canonical Nat extraction is separated from the CSR field theorem. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open _root_.Hegemon.Transaction.Poseidon2Width16Kernel
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

private theorem first_frame_word_canonical_of_input
    (inputs : List Nat)
    (positionCanonical : inputs.getD 7 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus)
    (lane : Fin 16) :
    (firstFrame inputs).getD lane.val 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  by_cases isPosition : lane.val = 7
  · have laneEq : lane = (7 : Fin 16) := Fin.ext isPosition
    subst lane
    have modulusEq : Poseidon2Width16Kernel.fieldModulus =
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
      norm_num [Poseidon2Width16Kernel.fieldModulus,
        Hegemon.Transaction.NoteCommitmentInputs.fieldModulus,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus]
    have positionKernel : inputs.getD 7 0 < Poseidon2Width16Kernel.fieldModulus := by
      rw [modulusEq]
      exact positionCanonical
    have frameWord : (firstFrame inputs).getD 7 0 = inputs.getD 7 0 := by
      unfold firstFrame
      rw [List.getD_eq_getElem?_getD, List.getElem?_map,
        List.getElem?_range (by decide), Option.map_some, Option.getD_some]
      simp only [if_pos (by decide : (7 : Nat) < 8)]
      rw [Poseidon2Width16Kernel.fieldAdd, Nat.zero_add,
        Nat.mod_eq_of_lt positionKernel]
    rw [show ((7 : Fin 16).val) = 7 by decide]
    exact frameWord.trans_lt positionCanonical
  · fin_cases lane <;>
    simp [firstFrame, Poseidon2Width16Kernel.fieldAdd,
      List.getD_eq_getElem?_getD, currentNullifierDomain,
      poseidon2V8SpongeModeMarker, poseidon2V8SuiteMarker] <;>
    first
    | exact Nat.mod_lt _ (by decide)
    | norm_num [Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus]

private theorem packed_final_state_word_canonical
    {components : RelationProgramComponents}
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (lane : Fin 16) :
    (packedFinalState packed (nullifierFirstCall input)).getD lane.val 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  have laneBound := lane.isLt
  simp only [packedFinalState, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range laneBound,
    Option.map_some, Option.getD_some, packedWord]
  exact packed_word_canonical accepted.2.1 _

private theorem last_frame_word_canonical
    {components : RelationProgramComponents}
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (lane : Fin 16) :
    (lastFrame (nullifierPreimage packed input)
      (packedFinalState packed (nullifierFirstCall input))).getD lane.val 0 <
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  have stateCanonical := packed_final_state_word_canonical accepted input
  have laneBound := lane.isLt
  simp only [lastFrame, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range laneBound,
    Option.map_some, Option.getD_some]
  by_cases low : lane.val < 4
  · simp [low, Poseidon2Width16Kernel.fieldAdd]
    exact Nat.mod_lt _ (by decide)
  · by_cases eleven : lane.val = 11
    · simp [eleven, Poseidon2Width16Kernel.fieldAdd]
      exact Nat.mod_lt _ (by decide)
    · simp [low, eleven]
      exact stateCanonical lane

/-- Field-to-Nat readback obtained from the checked import-light 64-cell
source theorem, with canonicality handled by one frame-word lemma per block. -/
theorem accepted_initial_frame_word_import_light
    {components : RelationProgramComponents}
    (initial : InitialCertificate components)
    (kernel : KernelCertificate components)
    (direction : DirectionCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (cell : InitialCell) :
    packed.getD (hashInitialIndex (callOf cell) cell.2.2.val) 0 =
      (if cell.2.1.val = 0 then
        firstFrame (nullifierPreimage packed cell.1)
      else lastFrame (nullifierPreimage packed cell.1)
        (packedFinalState packed (nullifierFirstCall cell.1))).getD
      cell.2.2.val 0 := by
  have targetBound :
      (if cell.2.1.val = 0 then
        firstFrame (nullifierPreimage packed cell.1)
      else lastFrame (nullifierPreimage packed cell.1)
        (packedFinalState packed (nullifierFirstCall cell.1))).getD
      cell.2.2.val 0 < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
    rcases cell with ⟨input, block, lane⟩
    fin_cases block
    · have positionBound := accepted_position_lt_32 direction accepted input
      have positionCanonical : projectPosition packed input.val <
          Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus :=
        positionBound.trans (by
          norm_num [Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus])
      have framePositionCanonical :
          (nullifierPreimage packed input).getD 7 0 <
            Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
        simpa [nullifierPreimage] using positionCanonical
      exact first_frame_word_canonical_of_input
        (nullifierPreimage packed input) framePositionCanonical lane
    · exact last_frame_word_canonical accepted input lane
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1
      (hashInitialIndex (callOf cell) cell.2.2.val))
    targetBound
    (accepted_initial_cell_field_luna_import_light_all64
      initial kernel accepted cell)

/-- Both accepted initial states follow from the import-light all-64 CSR
readback and the accepted Boolean direction-root certificate. -/
theorem accepted_nullifier_initial_states_import_light
    {components : RelationProgramComponents}
    (initial : InitialCertificate components)
    (kernel : KernelCertificate components)
    (direction : DirectionCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) :
    packedInitialState packed (nullifierFirstCall input) =
        firstFrame (nullifierPreimage packed input) ∧
      packedInitialState packed (nullifierLastCall input) =
        lastFrame (nullifierPreimage packed input)
          (packedFinalState packed (nullifierFirstCall input)) := by
  constructor
  · apply List.map_congr_left
    intro lane member
    have word := accepted_initial_frame_word_import_light
      initial kernel direction accepted
      (input, ⟨0, by decide⟩, ⟨lane, List.mem_range.mp member⟩)
    have laneBound : lane < 16 := List.mem_range.mp member
    simpa only [packedWord, callOf, Nat.add_zero, ↓reduceIte,
      firstFrame, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range laneBound, Option.map_some, Option.getD_some] using word
  · apply List.map_congr_left
    intro lane member
    have word := accepted_initial_frame_word_import_light
      initial kernel direction accepted
      (input, ⟨1, by decide⟩, ⟨lane, List.mem_range.mp member⟩)
    have laneBound : lane < 16 := List.mem_range.mp member
    simpa only [packedWord, callOf, nullifierLastCall, Nat.one_ne_zero, if_false,
      lastFrame, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range laneBound, Option.map_some, Option.getD_some] using word

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
