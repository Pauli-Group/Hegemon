import Hegemon.Transaction.SmallWoodProductionConstraintRefinement

namespace Hegemon
namespace Transaction
namespace SmallWoodProductionConstraintRefinement

/-!
Small, structural refinement lemmas for the compressed production Poseidon2 trace.

The deployed relation stores twelve initial state lanes, 118 pre-S-box wires, and twelve final
state lanes for each physical Poseidon group.  This file reconstructs that exact 118-wire
schedule without unfolding the generated 8,841-node expression DAG.  The only remaining
nonlinear refinement boundary is therefore local: 130 accepted equations for one lane/group
must imply equality with this independently executable compressed trace.
-/

structure Poseidon2CompressedTrace where
  wires : List Nat
  finalState : List Nat
deriving DecidableEq, Repr

def poseidon2ExternalRoundWires
    (state roundConstants : List Nat) : List Nat :=
  (List.range Poseidon2NoteCommitment.poseidon2Width).map fun index =>
    Poseidon2NoteCommitment.fieldAdd (state.getD index 0)
      (roundConstants.getD index 0)

def poseidon2InternalRoundWire
    (state : List Nat)
    (roundConstant : Nat) : Nat :=
  Poseidon2NoteCommitment.fieldAdd (state.getD 0 0) roundConstant

def tracePoseidon2ExternalRounds :
    List (List Nat) -> List Nat -> Poseidon2CompressedTrace
  | [], state => { wires := [], finalState := state }
  | roundConstants :: rounds, state =>
      let tail := tracePoseidon2ExternalRounds rounds
        (Poseidon2NoteCommitment.externalRound state roundConstants)
      { wires := poseidon2ExternalRoundWires state roundConstants ++ tail.wires
        finalState := tail.finalState }

def tracePoseidon2InternalRounds :
    List Nat -> List Nat -> Poseidon2CompressedTrace
  | [], state => { wires := [], finalState := state }
  | roundConstant :: rounds, state =>
      let tail := tracePoseidon2InternalRounds rounds
        (Poseidon2NoteCommitment.internalRound state roundConstant)
      { wires := poseidon2InternalRoundWire state roundConstant :: tail.wires
        finalState := tail.finalState }

@[simp] theorem trace_poseidon2_external_rounds_final_state
    (rounds : List (List Nat))
    (state : List Nat) :
    (tracePoseidon2ExternalRounds rounds state).finalState =
      rounds.foldl Poseidon2NoteCommitment.externalRound state := by
  induction rounds generalizing state with
  | nil => rfl
  | cons round rounds inductionHypothesis =>
      simp only [tracePoseidon2ExternalRounds, List.foldl_cons]
      exact inductionHypothesis _

@[simp] theorem trace_poseidon2_internal_rounds_final_state
    (rounds : List Nat)
    (state : List Nat) :
    (tracePoseidon2InternalRounds rounds state).finalState =
      rounds.foldl Poseidon2NoteCommitment.internalRound state := by
  induction rounds generalizing state with
  | nil => rfl
  | cons round rounds inductionHypothesis =>
      simp only [tracePoseidon2InternalRounds, List.foldl_cons]
      exact inductionHypothesis _

@[simp] theorem poseidon2_external_round_wires_length
    (state roundConstants : List Nat) :
    (poseidon2ExternalRoundWires state roundConstants).length =
      Poseidon2NoteCommitment.poseidon2Width := by
  simp [poseidon2ExternalRoundWires]

@[simp] theorem trace_poseidon2_external_rounds_wire_count
    (rounds : List (List Nat))
    (state : List Nat) :
    (tracePoseidon2ExternalRounds rounds state).wires.length =
      rounds.length * Poseidon2NoteCommitment.poseidon2Width := by
  induction rounds generalizing state with
  | nil => rfl
  | cons round rounds inductionHypothesis =>
      simp [tracePoseidon2ExternalRounds, inductionHypothesis, Nat.add_mul]
      omega

@[simp] theorem trace_poseidon2_internal_rounds_wire_count
    (rounds : List Nat)
    (state : List Nat) :
    (tracePoseidon2InternalRounds rounds state).wires.length = rounds.length := by
  induction rounds generalizing state with
  | nil => rfl
  | cons round rounds inductionHypothesis =>
      simp [tracePoseidon2InternalRounds, inductionHypothesis]

def productionPoseidon2CompressedTrace
    (initialState : List Nat) : Poseidon2CompressedTrace :=
  let afterInitialMds := Poseidon2NoteCommitment.mdsLight initialState
  let initialExternal := tracePoseidon2ExternalRounds
    Poseidon2NoteCommitment.externalRoundConstantsInitial afterInitialMds
  let internal := tracePoseidon2InternalRounds
    Poseidon2NoteCommitment.internalRoundConstants initialExternal.finalState
  let terminalExternal := tracePoseidon2ExternalRounds
    Poseidon2NoteCommitment.externalRoundConstantsTerminal internal.finalState
  { wires := initialExternal.wires ++ internal.wires ++ terminalExternal.wires
    finalState := terminalExternal.finalState }

theorem production_poseidon2_compressed_trace_final_state
    (initialState : List Nat) :
    (productionPoseidon2CompressedTrace initialState).finalState =
      Poseidon2NoteCommitment.poseidon2Permutation initialState := by
  simp [productionPoseidon2CompressedTrace, Poseidon2NoteCommitment.poseidon2Permutation]

theorem production_poseidon2_compressed_trace_has_exact_wire_count
    (initialState : List Nat) :
    (productionPoseidon2CompressedTrace initialState).wires.length = 118 := by
  simp [productionPoseidon2CompressedTrace,
    Poseidon2NoteCommitment.poseidon2_constant_tables_have_deployed_shape,
    Poseidon2NoteCommitment.poseidon2Width,
    Poseidon2NoteCommitment.poseidon2ExternalRounds,
    Poseidon2NoteCommitment.poseidon2InternalRounds]

def productionPoseidon2GroupBaseRow (group : Nat) : Nat :=
  273 + group * 142

def productionPoseidon2GroupInitialState
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane group : Nat) : List Nat :=
  (List.range Poseidon2NoteCommitment.poseidon2Width).map fun limb =>
    fieldValue ((witnessLaneRows map witnessValues lane).getD
      (productionPoseidon2GroupBaseRow group + limb) 0)

def productionPoseidon2GroupWires
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane group : Nat) : List Nat :=
  (List.range 118).map fun offset =>
    fieldValue ((witnessLaneRows map witnessValues lane).getD
      (productionPoseidon2GroupBaseRow group + 12 + offset) 0)

def productionPoseidon2GroupFinalState
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane group : Nat) : List Nat :=
  (List.range Poseidon2NoteCommitment.poseidon2Width).map fun limb =>
    fieldValue ((witnessLaneRows map witnessValues lane).getD
      (productionPoseidon2GroupBaseRow group + 130 + limb) 0)

@[simp] theorem production_poseidon2_group_initial_state_length
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane group : Nat) :
    (productionPoseidon2GroupInitialState map witnessValues lane group).length = 12 := by
  simp [productionPoseidon2GroupInitialState,
    Poseidon2NoteCommitment.poseidon2Width]

@[simp] theorem production_poseidon2_group_wires_length
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane group : Nat) :
    (productionPoseidon2GroupWires map witnessValues lane group).length = 118 := by
  simp [productionPoseidon2GroupWires]

@[simp] theorem production_poseidon2_group_final_state_length
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane group : Nat) :
    (productionPoseidon2GroupFinalState map witnessValues lane group).length = 12 := by
  simp [productionPoseidon2GroupFinalState,
    Poseidon2NoteCommitment.poseidon2Width]

structure ProductionPoseidon2GroupTraceMatches
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane group : Nat) : Prop where
  exactCompressedWires :
    productionPoseidon2GroupWires map witnessValues lane group =
      (productionPoseidon2CompressedTrace
        (productionPoseidon2GroupInitialState map witnessValues lane group)).wires
  exactFinalState :
    productionPoseidon2GroupFinalState map witnessValues lane group =
      (productionPoseidon2CompressedTrace
        (productionPoseidon2GroupInitialState map witnessValues lane group)).finalState

theorem production_poseidon2_group_trace_matches_implies_permutation
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {lane group : Nat}
    (traceMatches : ProductionPoseidon2GroupTraceMatches map witnessValues lane group) :
    productionPoseidon2GroupFinalState map witnessValues lane group =
      Poseidon2NoteCommitment.poseidon2Permutation
        (productionPoseidon2GroupInitialState map witnessValues lane group) := by
  rw [traceMatches.exactFinalState,
    production_poseidon2_compressed_trace_final_state]

def ProductionPoseidon2GroupConstraintEquations
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane group : Nat) : Prop :=
  forall relativeConstraint, relativeConstraint < 130 ->
    nonlinearConstraintEquation map witnessValues lane
      (poseidonConstraintSpan.start + group * 130 + relativeConstraint)

theorem production_poseidon2_family_equations_give_group_equations
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {lane group : Nat}
    (family : ProductionNonlinearFamilyEquations
      map witnessValues poseidonConstraintSpan)
    (laneBound : lane < map.lppcPackingFactor)
    (groupBound : group < 3) :
    ProductionPoseidon2GroupConstraintEquations
      map witnessValues lane group := by
  intro relativeConstraint relativeBound
  have equation := family lane laneBound (group * 130 + relativeConstraint) (by
    simp [poseidonConstraintSpan]
    omega)
  simpa [Nat.add_assoc] using equation

/--
The exact remaining nonlinear refinement obligation.  It is local to one 130-equation
lane/group slice and concludes equality with the independently executable 118-wire compressed
trace.  No digest, sparse-linear binding, or collision assumption is hidden in this boundary.
-/
def ProductionPoseidon2NonlinearTraceRefinementAssumption : Prop :=
  forall map witnessValues lane group,
    ProductionConstraintMapBound map ->
    lane < map.lppcPackingFactor ->
    group < 3 ->
    ProductionPoseidon2GroupConstraintEquations map witnessValues lane group ->
      ProductionPoseidon2GroupTraceMatches map witnessValues lane group

theorem production_constraint_map_bound_has_deployed_packing_factor
    {map : ProductionConstraintMap}
    (mapBound : ProductionConstraintMapBound map) :
    map.lppcPackingFactor = 64 := by
  have outputBindings := production_output_hash_linear_bindings_are_map_bound mapBound
  simp only [productionOutputHashLinearBindingsBoundB, Bool.and_eq_true] at outputBindings
  exact (of_decide_eq_true outputBindings.1).2

theorem witness_lane_rows_getD
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane row : Nat)
    (rowBound : row < map.lppcRowCount) :
    (witnessLaneRows map witnessValues lane).getD row 0 =
      witnessValues.getD (row * map.lppcPackingFactor + lane) 0 := by
  simp [witnessLaneRows, List.getD, rowBound]

def productionPoseidon2OutputChunkInitialState
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output chunk : Nat) : List Nat :=
  (List.range Poseidon2NoteCommitment.poseidon2Width).map fun limb =>
    productionOutputHashTraceValue map witnessValues output chunk 0 limb

def productionPoseidon2OutputChunkFinalState
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output chunk : Nat) : List Nat :=
  (List.range Poseidon2NoteCommitment.poseidon2Width).map fun limb =>
    productionOutputHashTraceValue map witnessValues output chunk 30 limb

@[simp] theorem production_poseidon2_output_chunk_initial_state_length
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output chunk : Nat) :
    (productionPoseidon2OutputChunkInitialState
      map witnessValues output chunk).length = 12 := by
  simp [productionPoseidon2OutputChunkInitialState,
    Poseidon2NoteCommitment.poseidon2Width]

@[simp] theorem production_poseidon2_output_chunk_final_state_length
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output chunk : Nat) :
    (productionPoseidon2OutputChunkFinalState
      map witnessValues output chunk).length = 12 := by
  simp [productionPoseidon2OutputChunkFinalState,
    Poseidon2NoteCommitment.poseidon2Width]

theorem production_output_poseidon_permutation_group_is_deployed
    {map : ProductionConstraintMap}
    (mapBound : ProductionConstraintMapBound map)
    (output chunk : Nat)
    (outputBound : output < 2)
    (chunkBound : chunk < 3) :
    productionOutputCommitmentPermutation output chunk /
        map.lppcPackingFactor = 2 := by
  rw [production_constraint_map_bound_has_deployed_packing_factor mapBound]
  simp [productionOutputCommitmentPermutation]
  omega

theorem production_output_poseidon_permutation_lane_is_bounded
    {map : ProductionConstraintMap}
    (mapBound : ProductionConstraintMapBound map)
    (output chunk : Nat) :
    productionOutputCommitmentLane map output chunk < map.lppcPackingFactor := by
  unfold productionOutputCommitmentLane
  rw [production_constraint_map_bound_has_deployed_packing_factor mapBound]
  exact Nat.mod_lt _ (by decide : 0 < 64)

theorem production_output_poseidon_initial_state_is_group_state
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    (mapBound : ProductionConstraintMapBound map)
    (output chunk : Nat)
    (outputBound : output < 2)
    (chunkBound : chunk < 3) :
    productionPoseidon2OutputChunkInitialState map witnessValues output chunk =
      productionPoseidon2GroupInitialState map witnessValues
        (productionOutputCommitmentLane map output chunk)
        (productionOutputCommitmentPermutation output chunk /
          map.lppcPackingFactor) := by
  unfold productionPoseidon2OutputChunkInitialState
  unfold productionPoseidon2GroupInitialState
  apply List.map_congr_left
  intro index indexMembership
  have indexBound : index < 12 := by
    simpa [Poseidon2NoteCommitment.poseidon2Width] using
      (List.mem_range.mp indexMembership)
  ·
    have factor := production_constraint_map_bound_has_deployed_packing_factor mapBound
    have group := production_output_poseidon_permutation_group_is_deployed
      mapBound output chunk outputBound chunkBound
    have rowBound :
        productionPoseidon2GroupBaseRow
            (productionOutputCommitmentPermutation output chunk /
              map.lppcPackingFactor) + index < map.lppcRowCount := by
      have outputBindings := production_output_hash_linear_bindings_are_map_bound mapBound
      simp only [productionOutputHashLinearBindingsBoundB, Bool.and_eq_true] at outputBindings
      have rowCount : map.lppcRowCount = 699 := (of_decide_eq_true outputBindings.1).1
      rw [group, rowCount]
      simp [productionPoseidon2GroupBaseRow]
      omega
    rw [witness_lane_rows_getD map witnessValues _ _ rowBound]
    simp [productionOutputHashTraceValue, productionOutputCommitmentPoseidonIndex,
      productionOutputCommitmentPoseidonRow, productionPoseidon2GroupBaseRow,
      productionPackedWitnessIndex, productionOutputCommitmentLane, Nat.add_assoc]

theorem production_output_poseidon_final_state_is_group_state
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    (mapBound : ProductionConstraintMapBound map)
    (output chunk : Nat)
    (outputBound : output < 2)
    (chunkBound : chunk < 3) :
    productionPoseidon2OutputChunkFinalState map witnessValues output chunk =
      productionPoseidon2GroupFinalState map witnessValues
        (productionOutputCommitmentLane map output chunk)
        (productionOutputCommitmentPermutation output chunk /
          map.lppcPackingFactor) := by
  unfold productionPoseidon2OutputChunkFinalState
  unfold productionPoseidon2GroupFinalState
  apply List.map_congr_left
  intro index indexMembership
  have indexBound : index < 12 := by
    simpa [Poseidon2NoteCommitment.poseidon2Width] using
      (List.mem_range.mp indexMembership)
  ·
    have group := production_output_poseidon_permutation_group_is_deployed
      mapBound output chunk outputBound chunkBound
    have rowBound :
        productionPoseidon2GroupBaseRow
            (productionOutputCommitmentPermutation output chunk /
              map.lppcPackingFactor) + 130 + index < map.lppcRowCount := by
      have outputBindings := production_output_hash_linear_bindings_are_map_bound mapBound
      simp only [productionOutputHashLinearBindingsBoundB, Bool.and_eq_true] at outputBindings
      have rowCount : map.lppcRowCount = 699 := (of_decide_eq_true outputBindings.1).1
      rw [group, rowCount]
      simp [productionPoseidon2GroupBaseRow]
      omega
    rw [witness_lane_rows_getD map witnessValues _ _ rowBound]
    simp [productionOutputHashTraceValue, productionOutputCommitmentPoseidonIndex,
      productionOutputCommitmentPoseidonRow, productionPoseidon2GroupBaseRow,
      productionPackedWitnessIndex, productionOutputCommitmentLane, Nat.add_assoc]

theorem production_poseidon2_nonlinear_trace_refinement_gives_output_permutation
    (refinement : ProductionPoseidon2NonlinearTraceRefinementAssumption)
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {output chunk : Nat}
    (image : ProductionAcceptedOutputHashImage map witnessValues output)
    (chunkBound : chunk < 3) :
    productionPoseidon2OutputChunkFinalState map witnessValues output chunk =
      Poseidon2NoteCommitment.poseidon2Permutation
        (productionPoseidon2OutputChunkInitialState map witnessValues output chunk) := by
  let lane := productionOutputCommitmentLane map output chunk
  let group := productionOutputCommitmentPermutation output chunk /
    map.lppcPackingFactor
  have laneBound : lane < map.lppcPackingFactor :=
    production_output_poseidon_permutation_lane_is_bounded image.mapBound output chunk
  have groupEq : group = 2 :=
    production_output_poseidon_permutation_group_is_deployed image.mapBound
      output chunk image.outputIndexBound chunkBound
  have groupBound : group < 3 := by omega
  have groupEquations := production_poseidon2_family_equations_give_group_equations
    image.exactHashTransitionEquations laneBound groupBound
  have traceMatches := refinement map witnessValues lane group image.mapBound
    laneBound groupBound groupEquations
  have permutation :=
    production_poseidon2_group_trace_matches_implies_permutation traceMatches
  rw [production_output_poseidon_initial_state_is_group_state
      image.mapBound output chunk image.outputIndexBound chunkBound,
    production_output_poseidon_final_state_is_group_state
      image.mapBound output chunk image.outputIndexBound chunkBound]
  exact permutation

def poseidon2AbsorbedState
    (inputs state : List Nat)
    (chunk : Nat) : List Nat :=
  (List.range Poseidon2NoteCommitment.poseidon2Width).map fun index =>
    let inputIndex := chunk * Poseidon2NoteCommitment.poseidon2Rate + index
    if index < Poseidon2NoteCommitment.poseidon2Rate && inputIndex < inputs.length then
      Poseidon2NoteCommitment.fieldAdd (state.getD index 0)
        (inputs.getD inputIndex 0)
    else
      state.getD index 0

theorem poseidon2_field_add_zero_of_canonical
    {value : Nat}
    (canonical : value < goldilocksModulus) :
    Poseidon2NoteCommitment.fieldAdd 0 value = value := by
  have concreteCanonical : value < 18446744069414584321 := by
    simpa [goldilocksModulus] using canonical
  simp [Poseidon2NoteCommitment.fieldAdd,
    Poseidon2NoteCommitment.fieldModulus,
    NoteCommitmentInputs.fieldModulus,
    Nat.mod_eq_of_lt concreteCanonical]

theorem poseidon2_field_add_commutative
    (left right : Nat) :
    Poseidon2NoteCommitment.fieldAdd left right =
      Poseidon2NoteCommitment.fieldAdd right left := by
  simp [Poseidon2NoteCommitment.fieldAdd, Nat.add_comm]

theorem poseidon2_field_add_constraint_sub_cancel_of_canonical
    {left right : Nat}
    (leftCanonical : left < goldilocksModulus)
    (rightCanonical : right < goldilocksModulus) :
    Poseidon2NoteCommitment.fieldAdd left (fieldSub right left) = right := by
  have leftConcrete : left < 18446744069414584321 := by
    simpa [goldilocksModulus] using leftCanonical
  have rightConcrete : right < 18446744069414584321 := by
    simpa [goldilocksModulus] using rightCanonical
  simp only [Poseidon2NoteCommitment.fieldAdd,
    Poseidon2NoteCommitment.fieldModulus,
    NoteCommitmentInputs.fieldModulus, fieldSub, goldilocksModulus]
  rw [Nat.mod_eq_of_lt leftConcrete]
  by_cases ordered : left <= right
  · have differenceBound : right - left < 18446744069414584321 := by omega
    have subtraction :
        right + 18446744069414584321 - left =
          (right - left) + 18446744069414584321 := by omega
    rw [subtraction]
    have reducedDifference :
      ((right - left) + 18446744069414584321) % 18446744069414584321 =
          right - left := by
      simp [Nat.mod_eq_of_lt differenceBound]
    rw [reducedDifference]
    have sumIsRight : left + (right - left) = right := by omega
    rw [sumIsRight, Nat.mod_eq_of_lt rightConcrete]
  · have wrappedBound :
        right + 18446744069414584321 - left < 18446744069414584321 := by omega
    rw [Nat.mod_eq_of_lt wrappedBound]
    have wrappedSum :
        left + (right + 18446744069414584321 - left) =
          right + 18446744069414584321 := by omega
    rw [wrappedSum]
    simp [Nat.mod_eq_of_lt rightConcrete]

theorem eq_of_constraint_field_sub_eq_zero_of_canonical
    {left right : Nat}
    (leftCanonical : left < goldilocksModulus)
    (rightCanonical : right < goldilocksModulus)
    (equation : fieldSub left right = 0) :
    left = right := by
  have leftConcrete : left < 18446744069414584321 := by
    simpa [goldilocksModulus] using leftCanonical
  have rightConcrete : right < 18446744069414584321 := by
    simpa [goldilocksModulus] using rightCanonical
  simp only [fieldSub, goldilocksModulus] at equation
  rw [Nat.mod_eq_of_lt rightConcrete] at equation
  by_cases ordered : right <= left
  · have differenceBound : left - right < 18446744069414584321 := by omega
    have subtraction :
        left + 18446744069414584321 - right =
          (left - right) + 18446744069414584321 := by omega
    rw [subtraction] at equation
    have reducedDifference :
        ((left - right) + 18446744069414584321) % 18446744069414584321 =
          left - right := by
      simp [Nat.mod_eq_of_lt differenceBound]
    rw [reducedDifference] at equation
    omega
  · have wrappedPositive :
        0 < left + 18446744069414584321 - right := by omega
    have wrappedBound :
        left + 18446744069414584321 - right < 18446744069414584321 := by omega
    rw [Nat.mod_eq_of_lt wrappedBound] at equation
    omega

theorem constraint_field_value_is_canonical (value : Nat) :
    fieldValue value < goldilocksModulus := by
  unfold fieldValue
  exact Nat.mod_lt _ (by decide : 0 < goldilocksModulus)

@[simp] theorem poseidon2_field_add_zero_constraint_field_value
    (value : Nat) :
    Poseidon2NoteCommitment.fieldAdd 0 (fieldValue value) = fieldValue value := by
  exact poseidon2_field_add_zero_of_canonical
    (constraint_field_value_is_canonical value)

@[simp] theorem poseidon2_field_add_constraint_sub_cancel_field_values
    (left right : Nat) :
    Poseidon2NoteCommitment.fieldAdd (fieldValue left)
        (fieldSub (fieldValue right) (fieldValue left)) =
      fieldValue right := by
  exact poseidon2_field_add_constraint_sub_cancel_of_canonical
    (constraint_field_value_is_canonical left)
    (constraint_field_value_is_canonical right)

theorem poseidon2_absorb_chunk_is_permutation_of_absorbed_state
    (inputs state : List Nat)
    (chunk : Nat) :
    Poseidon2NoteCommitment.absorbChunk inputs state chunk =
      Poseidon2NoteCommitment.poseidon2Permutation
        (poseidon2AbsorbedState inputs state chunk) := by
  rfl

/--
Semantic interpretation of the 26 sparse-linear bindings needed only for the three-chunk
Poseidon frame: two domain/input bindings, six fresh-capacity bindings, twelve continuation
bindings, and six public-digest bindings.  The four authorization-key bindings are separate
semantic input bindings and are deliberately not smuggled into digest refinement.
-/
structure ProductionPoseidon2OutputFrameBindings
    (spec : ProductionNoteHashSpec)
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) : Prop where
  firstChunkInput :
    productionPoseidon2OutputChunkInitialState map witnessValues output 0 =
      poseidon2AbsorbedState
        (productionOutputHashPreimage map witnessValues output)
        (Poseidon2NoteCommitment.initialSpongeState spec.domainTag) 0
  secondChunkContinuation :
    productionPoseidon2OutputChunkInitialState map witnessValues output 1 =
      poseidon2AbsorbedState
        (productionOutputHashPreimage map witnessValues output)
        (productionPoseidon2OutputChunkFinalState map witnessValues output 0) 1
  thirdChunkContinuation :
    productionPoseidon2OutputChunkInitialState map witnessValues output 2 =
      poseidon2AbsorbedState
        (productionOutputHashPreimage map witnessValues output)
        (productionPoseidon2OutputChunkFinalState map witnessValues output 1) 2
  publicDigest :
    (productionPoseidon2OutputChunkFinalState map witnessValues output 2).take
        Poseidon2NoteCommitment.poseidon2Rate =
      productionOutputCommitmentFelts map output

structure ProductionPoseidon2SparseFrameEquationSemantics
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) : Prop where
  initialValue :
    productionOutputHashTraceValue map witnessValues output 0 0 0 =
      Poseidon2NoteCommitment.fieldAdd 1
        (productionOutputValue map witnessValues
          (productionOutputCommitmentLane map output 0) output)
  initialAsset :
    productionOutputHashTraceValue map witnessValues output 0 0 1 =
      productionOutputAsset map witnessValues
        (productionOutputCommitmentLane map output 0) output
  freshCapacity :
    forall relativeLimb, relativeLimb < 6 ->
      productionOutputHashTraceValue map witnessValues output 0 0
          (6 + relativeLimb) =
        if relativeLimb = 5 then 1 else 0
  continuationCapacity :
    forall previousChunk, previousChunk < 2 ->
      forall relativeLimb, relativeLimb < 6 ->
        productionOutputHashTraceValue map witnessValues output
            (previousChunk + 1) 0 (6 + relativeLimb) =
          productionOutputHashTraceValue map witnessValues output
            previousChunk 30 (6 + relativeLimb)
  publicDigest :
    forall limb, limb < 6 ->
      productionOutputHashTraceValue map witnessValues output 2 30 limb =
        publicValueAt map.publicValues (16 + output * 6 + limb)

theorem deployed_production_note_hash_spec_has_domain_one
    {spec : ProductionNoteHashSpec}
    (accepted : deployedProductionNoteHashSpecAccepts spec = true) :
    spec.domainTag = 1 := by
  unfold deployedProductionNoteHashSpecAccepts at accepted
  exact (of_decide_eq_true accepted).1

theorem production_poseidon2_sparse_semantics_give_first_frame
    {spec : ProductionNoteHashSpec}
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {output : Nat}
    (specAccepted : deployedProductionNoteHashSpecAccepts spec = true)
    (semantics : ProductionPoseidon2SparseFrameEquationSemantics
      map witnessValues output) :
    productionPoseidon2OutputChunkInitialState map witnessValues output 0 =
      poseidon2AbsorbedState
        (productionOutputHashPreimage map witnessValues output)
        (Poseidon2NoteCommitment.initialSpongeState spec.domainTag) 0 := by
  unfold productionPoseidon2OutputChunkInitialState poseidon2AbsorbedState
  apply List.map_congr_left
  intro index indexMembership
  have indexBound : index < 12 := by
    simpa [Poseidon2NoteCommitment.poseidon2Width] using
      (List.mem_range.mp indexMembership)
  have domain := deployed_production_note_hash_spec_has_domain_one specAccepted
  have indexCases :
      index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨ index = 4 ∨
      index = 5 ∨ index = 6 ∨ index = 7 ∨ index = 8 ∨ index = 9 ∨
      index = 10 ∨ index = 11 := by omega
  rcases indexCases with rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl
  · simpa [productionOutputHashPreimage,
      Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.fieldValue,
      Poseidon2NoteCommitment.fieldModulus,
      NoteCommitmentInputs.fieldModulus,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width] using semantics.initialValue
  · simpa [productionOutputHashPreimage, productionOutputAsset,
      Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width] using semantics.initialAsset
  · simp [productionOutputHashPreimage,
      Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width,
      productionOutputHashTraceValue]
  · simp [productionOutputHashPreimage,
      Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width,
      productionOutputHashTraceValue]
  · simp [productionOutputHashPreimage,
      Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width,
      productionOutputHashTraceValue]
  · simp [productionOutputHashPreimage,
      Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width,
      productionOutputHashTraceValue]
  · simpa [Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width] using semantics.freshCapacity 0 (by decide)
  · simpa [Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width] using semantics.freshCapacity 1 (by decide)
  · simpa [Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width] using semantics.freshCapacity 2 (by decide)
  · simpa [Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width] using semantics.freshCapacity 3 (by decide)
  · simpa [Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width] using semantics.freshCapacity 4 (by decide)
  · simpa [Poseidon2NoteCommitment.initialSpongeState, domain,
      Poseidon2NoteCommitment.poseidon2Rate,
      Poseidon2NoteCommitment.poseidon2Width] using semantics.freshCapacity 5 (by decide)

theorem production_poseidon2_sparse_semantics_bind_public_digest
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {output : Nat}
    (semantics : ProductionPoseidon2SparseFrameEquationSemantics
      map witnessValues output) :
    (productionPoseidon2OutputChunkFinalState map witnessValues output 2).take
        Poseidon2NoteCommitment.poseidon2Rate =
      productionOutputCommitmentFelts map output := by
  have takenState :
      (productionPoseidon2OutputChunkFinalState map witnessValues output 2).take 6 =
        (List.range 6).map fun limb =>
          productionOutputHashTraceValue map witnessValues output 2 30 limb := by
    simp [productionPoseidon2OutputChunkFinalState,
      Poseidon2NoteCommitment.poseidon2Width]
    rw [← List.map_take]
    congr
  rw [show Poseidon2NoteCommitment.poseidon2Rate = 6 by rfl, takenState]
  unfold productionOutputCommitmentFelts
  apply List.map_congr_left
  intro limb limbMembership
  exact semantics.publicDigest limb (List.mem_range.mp limbMembership)

theorem production_poseidon2_output_chunk_final_state_getD
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output chunk index : Nat)
    (indexBound : index < 12) :
    (productionPoseidon2OutputChunkFinalState
      map witnessValues output chunk).getD index 0 =
      productionOutputHashTraceValue map witnessValues output chunk 30 index := by
  simp [productionPoseidon2OutputChunkFinalState, List.getD,
    Poseidon2NoteCommitment.poseidon2Width, indexBound]

def productionOutputHashFirstChunk
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) : List Nat :=
  [ productionOutputValue map witnessValues
      (productionOutputCommitmentLane map output 0) output,
    productionOutputAsset map witnessValues
      (productionOutputCommitmentLane map output 0) output ]
    ++ (List.range 4).map (fun limb =>
      productionOutputHashTraceValue map witnessValues output 0 0 (2 + limb))

def productionOutputHashSecondChunk
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) : List Nat :=
  (List.range 6).map (fun limb =>
    fieldSub
      (productionOutputHashTraceValue map witnessValues output 1 0 limb)
      (productionOutputHashTraceValue map witnessValues output 0 30 limb))

def productionOutputHashThirdChunk
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) : List Nat :=
  (List.range 6).map (fun limb =>
    fieldSub
      (productionOutputHashTraceValue map witnessValues output 2 0 limb)
      (productionOutputHashTraceValue map witnessValues output 1 30 limb))

theorem production_output_hash_preimage_is_three_exact_chunks
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) :
    productionOutputHashPreimage map witnessValues output =
      productionOutputHashFirstChunk map witnessValues output
        ++ (productionOutputHashSecondChunk map witnessValues output
          ++ productionOutputHashThirdChunk map witnessValues output) := by
  unfold productionOutputHashPreimage productionOutputHashFirstChunk
    productionOutputHashSecondChunk productionOutputHashThirdChunk
  rw [List.append_assoc]

@[simp] theorem production_output_hash_first_chunk_length
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) :
    (productionOutputHashFirstChunk map witnessValues output).length = 6 := by
  simp [productionOutputHashFirstChunk]

@[simp] theorem production_output_hash_second_chunk_length
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) :
    (productionOutputHashSecondChunk map witnessValues output).length = 6 := by
  simp [productionOutputHashSecondChunk]

@[simp] theorem production_output_hash_third_chunk_length
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) :
    (productionOutputHashThirdChunk map witnessValues output).length = 6 := by
  simp [productionOutputHashThirdChunk]

theorem production_output_hash_preimage_second_chunk_getD
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output index : Nat)
    (indexBound : index < 6) :
    (productionOutputHashPreimage map witnessValues output).getD (6 + index) 0 =
      fieldSub
        (productionOutputHashTraceValue map witnessValues output 1 0 index)
        (productionOutputHashTraceValue map witnessValues output 0 30 index) := by
  have fullBound :
      6 + index < (productionOutputHashPreimage map witnessValues output).length := by
    rw [production_output_hash_preimage_has_exact_deployed_word_count]
    omega
  rw [← List.getElem_eq_getD (h := fullBound) 0]
  rw [List.getElem_of_eq
    (production_output_hash_preimage_is_three_exact_chunks
      map witnessValues output)]
  rw [List.getElem_append_right]
  · rw [List.getElem_append_left (by simp; omega)]
    simp [productionOutputHashSecondChunk]
  · simp

theorem production_output_hash_preimage_third_chunk_getD
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output index : Nat)
    (indexBound : index < 6) :
    (productionOutputHashPreimage map witnessValues output).getD (12 + index) 0 =
      fieldSub
        (productionOutputHashTraceValue map witnessValues output 2 0 index)
        (productionOutputHashTraceValue map witnessValues output 1 30 index) := by
  have fullBound :
      12 + index < (productionOutputHashPreimage map witnessValues output).length := by
    rw [production_output_hash_preimage_has_exact_deployed_word_count]
    omega
  rw [← List.getElem_eq_getD (h := fullBound) 0]
  rw [List.getElem_of_eq
    (production_output_hash_preimage_is_three_exact_chunks
      map witnessValues output)]
  rw [List.getElem_append_right]
  · rw [List.getElem_append_right]
    · simp [productionOutputHashThirdChunk]
      congr <;> omega
    · simp
      omega
  · simp
    omega

theorem production_poseidon2_sparse_semantics_give_second_frame
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {output : Nat}
    (semantics : ProductionPoseidon2SparseFrameEquationSemantics
      map witnessValues output) :
    productionPoseidon2OutputChunkInitialState map witnessValues output 1 =
      poseidon2AbsorbedState
        (productionOutputHashPreimage map witnessValues output)
        (productionPoseidon2OutputChunkFinalState map witnessValues output 0) 1 := by
  unfold productionPoseidon2OutputChunkInitialState poseidon2AbsorbedState
  apply List.map_congr_left
  intro index indexMembership
  have indexBound : index < 12 := by
    simpa [Poseidon2NoteCommitment.poseidon2Width] using
      (List.mem_range.mp indexMembership)
  by_cases rateIndex : index < 6
  · have preimageBound : 6 + index <
        (productionOutputHashPreimage map witnessValues output).length := by
      rw [production_output_hash_preimage_has_exact_deployed_word_count]
      omega
    rw [if_pos (by
      simp [Poseidon2NoteCommitment.poseidon2Rate, rateIndex, preimageBound])]
    rw [production_poseidon2_output_chunk_final_state_getD
      map witnessValues output 0 index indexBound]
    simp only [Poseidon2NoteCommitment.poseidon2Rate, Nat.one_mul]
    rw [production_output_hash_preimage_second_chunk_getD
      map witnessValues output index rateIndex]
    unfold productionOutputHashTraceValue
    exact (poseidon2_field_add_constraint_sub_cancel_field_values _ _).symm
  · have capacityIndex : 6 ≤ index := by omega
    have relativeBound : index - 6 < 6 := by omega
    rw [if_neg (by
      simp [Poseidon2NoteCommitment.poseidon2Rate, rateIndex])]
    rw [production_poseidon2_output_chunk_final_state_getD
      map witnessValues output 0 index indexBound]
    have continuation := semantics.continuationCapacity
      0 (by decide) (index - 6) relativeBound
    simpa [Nat.add_sub_of_le capacityIndex] using continuation

theorem production_poseidon2_sparse_semantics_give_third_frame
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {output : Nat}
    (semantics : ProductionPoseidon2SparseFrameEquationSemantics
      map witnessValues output) :
    productionPoseidon2OutputChunkInitialState map witnessValues output 2 =
      poseidon2AbsorbedState
        (productionOutputHashPreimage map witnessValues output)
        (productionPoseidon2OutputChunkFinalState map witnessValues output 1) 2 := by
  unfold productionPoseidon2OutputChunkInitialState poseidon2AbsorbedState
  apply List.map_congr_left
  intro index indexMembership
  have indexBound : index < 12 := by
    simpa [Poseidon2NoteCommitment.poseidon2Width] using
      (List.mem_range.mp indexMembership)
  by_cases rateIndex : index < 6
  · have preimageBound : 12 + index <
        (productionOutputHashPreimage map witnessValues output).length := by
      rw [production_output_hash_preimage_has_exact_deployed_word_count]
      omega
    rw [if_pos (by
      simp [Poseidon2NoteCommitment.poseidon2Rate, rateIndex, preimageBound])]
    rw [production_poseidon2_output_chunk_final_state_getD
      map witnessValues output 1 index indexBound]
    simp only [Poseidon2NoteCommitment.poseidon2Rate]
    rw [production_output_hash_preimage_third_chunk_getD
      map witnessValues output index rateIndex]
    unfold productionOutputHashTraceValue
    exact (poseidon2_field_add_constraint_sub_cancel_field_values _ _).symm
  · have capacityIndex : 6 ≤ index := by omega
    have relativeBound : index - 6 < 6 := by omega
    rw [if_neg (by
      simp [Poseidon2NoteCommitment.poseidon2Rate, rateIndex])]
    rw [production_poseidon2_output_chunk_final_state_getD
      map witnessValues output 1 index indexBound]
    have continuation := semantics.continuationCapacity
      1 (by decide) (index - 6) relativeBound
    simpa [Nat.add_sub_of_le capacityIndex] using continuation

theorem production_poseidon2_sparse_semantics_give_frame_bindings
    {spec : ProductionNoteHashSpec}
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {output : Nat}
    (specAccepted : deployedProductionNoteHashSpecAccepts spec = true)
    (semantics : ProductionPoseidon2SparseFrameEquationSemantics
      map witnessValues output) :
    ProductionPoseidon2OutputFrameBindings spec map witnessValues output :=
  { firstChunkInput :=
      production_poseidon2_sparse_semantics_give_first_frame
        specAccepted semantics
    secondChunkContinuation :=
      production_poseidon2_sparse_semantics_give_second_frame semantics
    thirdChunkContinuation :=
      production_poseidon2_sparse_semantics_give_third_frame semantics
    publicDigest :=
      production_poseidon2_sparse_semantics_bind_public_digest semantics }

def productionPoseidon2FrameBindingIndices : List Nat :=
  List.range 20 ++ (List.range 6).map (24 + ·)

theorem production_poseidon2_frame_binding_index_count_is_exact :
    productionPoseidon2FrameBindingIndices.length = 26 := by
  decide

theorem production_poseidon2_frame_binding_index_is_required
    {binding : Nat}
    (membership : binding ∈ productionPoseidon2FrameBindingIndices) :
    binding < 30 := by
  simp [productionPoseidon2FrameBindingIndices] at membership
  omega

/--
The remaining sparse interpreter is stated over exactly the 26 relevant entries of
`productionOutputHashRequiredLinearSpecs`: bindings 0--19 and 24--29.  Bindings 20--23 bind
the authorization-key words and are intentionally outside the digest-frame theorem.
-/
def ProductionPoseidon2SparseEquationInterpreterAssumption : Prop :=
  forall map witnessValues output,
    ProductionConstraintMapBound map ->
    output < 2 ->
    publicValueAt map.publicValues (2 + output) = 1 ->
    (forall binding,
      binding ∈ productionPoseidon2FrameBindingIndices ->
        ProductionLinearConstraintSpecExecuted map witnessValues
          ((productionOutputHashRequiredLinearSpecs map output).getD binding
            zeroProductionLinearConstraintSpec)) ->
      ProductionPoseidon2SparseFrameEquationSemantics map witnessValues output

theorem production_poseidon2_sparse_interpreter_gives_frame_bindings
    (interpreter : ProductionPoseidon2SparseEquationInterpreterAssumption)
    {spec : ProductionNoteHashSpec}
    (specAccepted : deployedProductionNoteHashSpecAccepts spec = true)
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {output : Nat}
    (image : ProductionAcceptedOutputHashImage map witnessValues output) :
    ProductionPoseidon2OutputFrameBindings spec map witnessValues output := by
  apply production_poseidon2_sparse_semantics_give_frame_bindings specAccepted
  apply interpreter map witnessValues output image.mapBound
    image.outputIndexBound image.outputActive
  intro binding membership
  exact image.exactRequiredLinearBindings binding
    (by
      rw [production_output_hash_required_linear_spec_count_is_exact]
      exact production_poseidon2_frame_binding_index_is_required membership)

theorem three_chunk_trace_and_frame_refine_deployed_poseidon2_sponge
    {domainTag : Nat}
    {inputs : List Nat}
    (inputWidth : inputs.length = 18)
    {initial0 final0 initial1 final1 initial2 final2 : List Nat}
    (firstFrame : initial0 =
      poseidon2AbsorbedState inputs
        (Poseidon2NoteCommitment.initialSpongeState domainTag) 0)
    (firstPermutation : final0 =
      Poseidon2NoteCommitment.poseidon2Permutation initial0)
    (secondFrame : initial1 =
      poseidon2AbsorbedState inputs final0 1)
    (secondPermutation : final1 =
      Poseidon2NoteCommitment.poseidon2Permutation initial1)
    (thirdFrame : initial2 =
      poseidon2AbsorbedState inputs final1 2)
    (thirdPermutation : final2 =
      Poseidon2NoteCommitment.poseidon2Permutation initial2) :
    Poseidon2NoteCommitment.deployedPoseidon2Sponge domainTag inputs =
      final2.take Poseidon2NoteCommitment.poseidon2Rate := by
  have firstAbsorb :
      Poseidon2NoteCommitment.absorbChunk inputs
          (Poseidon2NoteCommitment.initialSpongeState domainTag) 0 = final0 := by
    rw [poseidon2_absorb_chunk_is_permutation_of_absorbed_state,
      <- firstFrame]
    exact firstPermutation.symm
  have secondAbsorb :
      Poseidon2NoteCommitment.absorbChunk inputs final0 1 = final1 := by
    rw [poseidon2_absorb_chunk_is_permutation_of_absorbed_state,
      <- secondFrame]
    exact secondPermutation.symm
  have thirdAbsorb :
      Poseidon2NoteCommitment.absorbChunk inputs final1 2 = final2 := by
    rw [poseidon2_absorb_chunk_is_permutation_of_absorbed_state,
      <- thirdFrame]
    exact thirdPermutation.symm
  unfold Poseidon2NoteCommitment.deployedPoseidon2Sponge
  rw [Poseidon2NoteCommitment.eighteen_word_preimage_uses_three_poseidon2_permutations
    inputs inputWidth]
  simp only [List.range_succ, List.range_zero, List.foldl_append,
    List.foldl_cons, List.foldl_nil]
  rw [firstAbsorb, secondAbsorb, thirdAbsorb]

theorem production_poseidon2_trace_and_frame_bind_accepted_output_digest
    (refinement : ProductionPoseidon2NonlinearTraceRefinementAssumption)
    {spec : ProductionNoteHashSpec}
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {output : Nat}
    (image : ProductionAcceptedOutputHashImage map witnessValues output)
    (frame : ProductionPoseidon2OutputFrameBindings
      spec map witnessValues output) :
    ProductionAcceptedOutputHashDigestBinding spec map witnessValues output := by
  have firstPermutation :=
    production_poseidon2_nonlinear_trace_refinement_gives_output_permutation
      refinement image (chunk := 0) (by decide)
  have secondPermutation :=
    production_poseidon2_nonlinear_trace_refinement_gives_output_permutation
      refinement image (chunk := 1) (by decide)
  have thirdPermutation :=
    production_poseidon2_nonlinear_trace_refinement_gives_output_permutation
      refinement image (chunk := 2) (by decide)
  unfold ProductionAcceptedOutputHashDigestBinding
  unfold productionDeployedPoseidon2Digest productionPoseidon2Sponge
  rw [three_chunk_trace_and_frame_refine_deployed_poseidon2_sponge
    (production_output_hash_preimage_has_exact_deployed_word_count
      map witnessValues output)
    frame.firstChunkInput firstPermutation
    frame.secondChunkContinuation secondPermutation
    frame.thirdChunkContinuation thirdPermutation]
  exact frame.publicDigest

/--
The exact remaining sparse-linear interpreter obligation.  It mentions only the accepted
26 frame/continuation/digest specs through their semantic consequence and contains no
nonlinear or collision-resistance assumption.
-/
def ProductionPoseidon2SparseFrameRefinementAssumption
    (spec : ProductionNoteHashSpec) : Prop :=
  forall map witnessValues output,
    ProductionAcceptedOutputHashImage map witnessValues output ->
      ProductionPoseidon2OutputFrameBindings spec map witnessValues output

theorem production_poseidon2_local_refinements_imply_constraint_digest_refinement
    {spec : ProductionNoteHashSpec}
    (nonlinearRefinement : ProductionPoseidon2NonlinearTraceRefinementAssumption)
    (sparseFrameRefinement : ProductionPoseidon2SparseFrameRefinementAssumption spec) :
    ProductionPoseidon2ConstraintDigestRefinementAssumption spec := by
  intro map witnessValues output image
  exact production_poseidon2_trace_and_frame_bind_accepted_output_digest
    nonlinearRefinement image
    (sparseFrameRefinement map witnessValues output image)

theorem production_poseidon2_equation_interpreters_imply_constraint_digest_refinement
    {spec : ProductionNoteHashSpec}
    (specAccepted : deployedProductionNoteHashSpecAccepts spec = true)
    (nonlinearInterpreter : ProductionPoseidon2NonlinearTraceRefinementAssumption)
    (sparseInterpreter : ProductionPoseidon2SparseEquationInterpreterAssumption) :
    ProductionPoseidon2ConstraintDigestRefinementAssumption spec := by
  intro map witnessValues output image
  exact production_poseidon2_trace_and_frame_bind_accepted_output_digest
    nonlinearInterpreter image
    (production_poseidon2_sparse_interpreter_gives_frame_bindings
      sparseInterpreter specAccepted image)

end SmallWoodProductionConstraintRefinement
end Transaction
end Hegemon
