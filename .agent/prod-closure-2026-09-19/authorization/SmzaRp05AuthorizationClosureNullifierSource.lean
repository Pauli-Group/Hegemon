import SmzaRp05NullifierSourceInitialStatesImportLight
import SmzaRp05NullifierActiveOutputImportLightLuna

/-! Kernel-free source-state composition for the current nullifier certificate.
The existing block-one readback paired its CSR equality with a permutation
fact. This module derives the needed CSR equality directly from the checked
source-balance lemmas, so no unused KernelCertificate enters initial-state
readback. The actual permutation is proved separately from current roots. -/
namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open Hegemon.Transaction.Poseidon2Width16Kernel
open Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

private theorem packedFinalState_getD_local (packed : List Nat)
    (call lane : Nat) (bound : lane < 16) :
    (packedFinalState packed call).getD lane 0 =
      packed.getD (hashFinalIndex call lane) 0 := by
  simp only [packedFinalState, packedWord, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range bound,
    Option.map_some, Option.getD_some]

private theorem lastFrame_getD_block1_balance_local
    (inputs state : List Nat) (lane : Nat) (bound : lane < 16) :
    ((lastFrame inputs state).getD lane 0 : Goldilocks) =
      (state.getD lane 0 : Goldilocks) +
        ((if lane < 4 then inputs.getD (8 + lane) 0 else 0 : Nat) : Goldilocks) +
        ((if lane = 11 then 1 else 0 : Nat) : Goldilocks) := by
  unfold lastFrame
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range bound, Option.map_some, Option.getD_some]
  by_cases hLow : lane < 4
  · have hNotEleven : lane ≠ 11 := by omega
    simp only [if_pos hLow, if_neg hNotEleven,
      V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd,
      Nat.cast_zero]
    ring
  · by_cases hEleven : lane = 11
    · simp only [if_neg hLow, if_pos hEleven,
        V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd,
        Nat.cast_zero, Nat.cast_one]
      ring
    · simp only [if_neg hLow, if_neg hEleven,
        Nat.cast_zero]
      ring

/-- Replace the two last-frame premises by their exact list definitions.
This CSR readback uses the packed final list and does not need to identify
that list with the previous call's permutation. -/
theorem closure_block1_lane_last_frame_readback_from_definitions
    {packed : List Nat}
    (input : Fin 2) (lane : Fin 16)
    (values : List Nat)
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (constantNode : InitialCell → Nat)
    (sourceBalance :
      csrFieldSum values packed
        (block1SourceTerms negativeNode positiveNode input lane.val) =
        -((if lane.val < 4 then
            (nullifierPreimage packed input).getD (8 + lane.val) 0
          else 0 : Nat) : Goldilocks))
    (equation : csrFieldSum values packed
      (initialTerms oneNode negativeNode positiveNode powerNode
        (input, (1 : Fin 2), lane)) =
        (values.getD (constantNode (input, (1 : Fin 2), lane)) 0 : Goldilocks))
    (one : (values.getD oneNode 0 : Goldilocks) = 1)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1)
    (constant :
      (values.getD (constantNode (input, (1 : Fin 2), lane)) 0 : Goldilocks) =
        (initialConstant (input, (1 : Fin 2), lane) : Goldilocks)) :
    (packed.getD
        (hashInitialIndex (callOf (input, (1 : Fin 2), lane)) lane.val) 0 : Goldilocks) =
      ((lastFrame (nullifierPreimage packed input)
          (packedFinalState packed (nullifierFirstCall input))).getD lane.val 0 : Goldilocks) := by
  have previousFinal :
      (packed.getD (hashFinalIndex (nullifierFirstCall input) lane.val) 0 : Goldilocks) =
        ((packedFinalState packed (nullifierFirstCall input)).getD lane.val 0 : Goldilocks) := by
    exact congrArg (fun word : Nat => (word : Goldilocks))
      (packedFinalState_getD_local packed (nullifierFirstCall input) lane.val lane.isLt).symm
  have constantCell :
      initialConstant (input, (1 : Fin 2), lane) =
        (if lane.val = 11 then 1 else 0 : Nat) := rfl
  have frameBalance :
      ((lastFrame (nullifierPreimage packed input)
          (packedFinalState packed (nullifierFirstCall input))).getD lane.val 0 : Goldilocks) =
        ((packedFinalState packed (nullifierFirstCall input)).getD lane.val 0 : Goldilocks) +
          ((if lane.val < 4 then
              (nullifierPreimage packed input).getD (8 + lane.val) 0
            else 0 : Nat) : Goldilocks) +
          (initialConstant (input, (1 : Fin 2), lane) : Goldilocks) := by
    rw [lastFrame_getD_block1_balance_local _ _ _ lane.isLt, constantCell]
  exact accepted_block1_lane_last_frame_readback
      values packed input lane oneNode negativeNode positiveNode powerNode
      constantNode sourceBalance equation one negative constant previousFinal frameBalance

/-- Accepted block-one lane readback for either input and every lane. Source
balance is derived from the checked 0--1, 2--3, and 4--15 branches; the
middle lanes additionally require positive-node value one and canonical
packed words for the field-subtraction embedding. -/
theorem closure_block1_all_lanes_last_frame_readback
    {packed : List Nat}
    (input : Fin 2) (lane : Fin 16)
    (values : List Nat)
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (constantNode : InitialCell → Nat)
    (equation : csrFieldSum values packed
      (initialTerms oneNode negativeNode positiveNode powerNode
        (input, (1 : Fin 2), lane)) =
        (values.getD (constantNode (input, (1 : Fin 2), lane)) 0 : Goldilocks))
    (one : (values.getD oneNode 0 : Goldilocks) = 1)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1)
    (positive : (values.getD positiveNode 0 : Goldilocks) = 1)
    (packedCanonical : ∀ index, packed.getD index 0 <
      _root_.Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus)
    (constant :
      (values.getD (constantNode (input, (1 : Fin 2), lane)) 0 : Goldilocks) =
        (initialConstant (input, (1 : Fin 2), lane) : Goldilocks)) :
    (packed.getD
        (hashInitialIndex (callOf (input, (1 : Fin 2), lane)) lane.val) 0 : Goldilocks) =
      ((lastFrame (nullifierPreimage packed input)
          (packedFinalState packed (nullifierFirstCall input))).getD lane.val 0 : Goldilocks) := by
  have sourceBalance :
      csrFieldSum values packed
        (block1SourceTerms negativeNode positiveNode input lane.val) =
        -((if lane.val < 4 then
            (nullifierPreimage packed input).getD (8 + lane.val) 0
          else 0 : Nat) : Goldilocks) := by
    by_cases low : lane.val < 2
    · exact block1_source_balance_lanes01 values packed input lane
        negativeNode positiveNode negative low
    · by_cases laneTwo : lane.val = 2
      · have laneEq : lane = (2 : Fin 16) := Fin.ext laneTwo
        subst lane
        have lane2Source := block1_source_balance_lane2_both_inputs values packed input
          negativeNode positiveNode negative positive packedCanonical
        change csrFieldSum values packed
            (block1SourceTerms negativeNode positiveNode input 2) =
          -((nullifierPreimage packed input).getD 10 0 : Goldilocks)
        exact lane2Source
      · by_cases laneThree : lane.val = 3
        · have laneEq : lane = (3 : Fin 16) := Fin.ext laneThree
          subst lane
          have lane3Source := block1_source_balance_lane3_both_inputs values packed input
            negativeNode positiveNode negative positive packedCanonical
          change csrFieldSum values packed
              (block1SourceTerms negativeNode positiveNode input 3) =
            -((nullifierPreimage packed input).getD 11 0 : Goldilocks)
          exact lane3Source
        · have high : 4 ≤ lane.val := by omega
          exact block1_source_balance_lanes4to15 values packed input lane
            negativeNode positiveNode high
  exact closure_block1_lane_last_frame_readback_from_definitions
    input lane values oneNode negativeNode
    positiveNode powerNode constantNode sourceBalance equation one negative constant

/-- Accepted initial-cell readback for all inputs, blocks, and lanes using
only the import-light checked block-zero and block-one lane results. -/
theorem closure_initial_cell_field_all64
    {components : RelationProgramComponents}
    (initial : InitialCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (cell : InitialCell) :
    (packed.getD (hashInitialIndex (callOf cell) cell.2.2.val) 0 : Goldilocks) =
      ((if cell.2.1.val = 0 then
          firstFrame (nullifierPreimage packed cell.1)
        else lastFrame (nullifierPreimage packed cell.1)
          (packedFinalState packed (nullifierFirstCall cell.1))).getD
        cell.2.2.val 0 : Goldilocks) := by
  obtain ⟨values, evaluated, equation⟩ :=
    accepted_initial_cell_equation initial accepted cell
  have one : (values.getD initial.oneNode 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using
      csr_node_value initial.canonical evaluated initial.oneRealizes
  have negative : (values.getD initial.negativeNode 0 : Goldilocks) = -1 := by
    simpa [SourceTerm.eval] using
      csr_node_value initial.canonical evaluated initial.negativeRealizes
  have positive : (values.getD initial.positiveNode 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using
      csr_node_value initial.canonical evaluated initial.positiveRealizes
  have powers : ∀ bit, bit < 32 →
      (values.getD (initial.powerNode bit) 0 : Goldilocks) =
        -(2 ^ bit : Goldilocks) := by
    intro bit bound
    have source := csr_node_value initial.canonical evaluated
      (initial.powerRealizes bit bound)
    simpa [SourceTerm.eval] using source
  have constant :
      (values.getD (initial.constantNode cell) 0 : Goldilocks) =
        (initialConstant cell : Goldilocks) := by
    simpa [SourceTerm.eval] using
      csr_node_value initial.canonical evaluated (initial.constantRealizes cell)
  have position := position_terms_field values packed cell.1
    initial.powerNode powers
  have packedCanonical : ∀ index, packed.getD index 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
    intro index
    exact packed_word_canonical accepted.2.1 index
  rcases cell with ⟨input, block, lane⟩
  fin_cases block
  · by_cases low : lane.val < 7
    · exact accepted_block0_lanes0to6_readback_both_inputs
        values packed input lane initial.oneNode initial.negativeNode
        initial.positiveNode initial.powerNode initial.constantNode
        equation one negative constant low
    · by_cases seven : lane.val = 7
      · have laneEq : lane = (7 : Fin 16) := Fin.ext seven
        subst lane
        have constantZero :
            (values.getD
              (initial.constantNode (input, (0 : Fin 2), (7 : Fin 16))) 0 : Goldilocks) = 0 := by
          simpa [initialConstant] using constant
        exact accepted_block0_lane7_readback_any_input values packed input
          initial.oneNode initial.negativeNode initial.positiveNode
          initial.powerNode initial.constantNode equation one constantZero position
      · have high : 8 ≤ lane.val := by omega
        exact accepted_block0_high_lane_frame_readback values packed input lane
          initial.oneNode initial.negativeNode initial.positiveNode
          initial.powerNode initial.constantNode high equation one constant
  · exact closure_block1_all_lanes_last_frame_readback
        input lane
        values initial.oneNode initial.negativeNode initial.positiveNode
        initial.powerNode initial.constantNode equation one negative positive
        packedCanonical constant

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
theorem closure_initial_frame_word
    {components : RelationProgramComponents}
    (initial : InitialCertificate components)
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
    (closure_initial_cell_field_all64
      initial accepted cell)

/-- Both accepted initial states follow from the import-light all-64 CSR
readback and the accepted Boolean direction-root certificate. -/
theorem closure_nullifier_initial_states
    {components : RelationProgramComponents}
    (initial : InitialCertificate components)
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
    have word := closure_initial_frame_word
      initial direction accepted
      (input, ⟨0, by decide⟩, ⟨lane, List.mem_range.mp member⟩)
    have laneBound : lane < 16 := List.mem_range.mp member
    simpa only [packedWord, callOf, Nat.add_zero, ↓reduceIte,
      firstFrame, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range laneBound, Option.map_some, Option.getD_some] using word
  · apply List.map_congr_left
    intro lane member
    have word := closure_initial_frame_word
      initial direction accepted
      (input, ⟨1, by decide⟩, ⟨lane, List.mem_range.mp member⟩)
    have laneBound : lane < 16 := List.mem_range.mp member
    simpa only [packedWord, callOf, nullifierLastCall, Nat.one_ne_zero, if_false,
      lastFrame, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range laneBound, Option.map_some, Option.getD_some] using word

private theorem list_sixteen_eq_local (state : List Nat)
    (shape : state.length = 16) :
    state = (List.range 16).map (fun lane => state.getD lane 0) := by
  apply List.ext_getElem (by simp [shape])
  intro lane leftBound rightBound
  simp only [List.getElem_map, List.getElem_range]
  exact (List.getD_eq_getElem state 0 leftBound).symm

theorem closure_first_absorb (inputs : List Nat)
    (shape : inputs.length = 12) :
    poseidon2V8AbsorbBlock currentNullifierDomain inputs 2
      poseidon2V8InitialState 0 =
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.permutation
      (firstFrame inputs) := by
  simp [poseidon2V8AbsorbBlock, poseidon2V8InitialState,
    poseidon2V8SeedFirstBlock, currentNullifierDomain,
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.width,
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.rate,
    shape, firstFrame, List.range_succ, List.replicate_succ, List.getD]

theorem closure_last_absorb (inputs state : List Nat)
    (shape : inputs.length = 12) (stateShape : state.length = 16) :
    poseidon2V8AbsorbBlock currentNullifierDomain inputs 2 state 1 =
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.permutation
        (lastFrame inputs state) := by
  conv => lhs; rw [list_sixteen_eq_local state stateShape]
  simp [poseidon2V8AbsorbBlock,
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.rate,
    shape, lastFrame, List.range_succ, List.getD]

/-- The public-certificate source equality is stated only for active slots. -/
theorem closure_active_public_nullifier_word
    {components : RelationProgramComponents}
    (certificate : PublicCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 7)
    (active : publicWords.getD input.val 0 = 1) :
    publicWords.getD (4 + input.val * 7 + limb.val) 0 =
      packed.getD (hashFinalIndex (nullifierLastCall input) limb.val) 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have gate : (values.getD (certificate.activeNode input) 0 : Goldilocks) = 1 := by
    have gateSource := csr_node_value certificate.canonical evaluated
      (certificate.activeRealizes input)
    change (values.getD (certificate.activeNode input) 0 : Goldilocks) =
      (publicWords.getD input.val 0 : Goldilocks) at gateSource
    rw [active] at gateSource
    exact gateSource
  have target :
      (values.getD (certificate.targetNode (input, limb)) 0 : Goldilocks) =
        (publicWords.getD (4 + input.val * 7 + limb.val) 0 : Goldilocks) := by
    have targetSource := csr_node_value certificate.canonical evaluated
      (certificate.targetRealizes (input, limb))
    change (values.getD (certificate.targetNode (input, limb)) 0 : Goldilocks) =
      (publicWords.getD input.val 0 : Goldilocks) *
        (publicWords.getD (4 + input.val * 7 + limb.val) 0 : Goldilocks) at targetSource
    rw [active] at targetSource
    simpa only [Nat.cast_one, one_mul] using targetSource
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (certificate.member (input, limb)))
  rw [certificate.attemptTerms (input, limb),
    certificate.attemptTarget (input, limb)] at equation
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, gate, target, one_mul, add_zero] at equation
  exact canonical_nat_cast_injective
    ((canonical_public_coordinate accepted.1
      (by
        have hi := input.isLt
        have hl := limb.isLt
        norm_num [publicStatementWordCount]
        omega)).2)
    (packed_word_canonical accepted.2.1
      (hashFinalIndex (nullifierLastCall input) limb.val))
    equation.symm

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
