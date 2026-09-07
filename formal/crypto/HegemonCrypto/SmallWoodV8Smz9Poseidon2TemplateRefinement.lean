import HegemonCrypto.SmallWoodV8Smz9Poseidon2LocalTemplateRefinement

/-! Composition of the checked local templates into the pinned full round schedule. -/

namespace HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement

open Hegemon.Transaction
set_option Elab.async false
set_option maxHeartbeats 10000
set_option maxRecDepth 1000000

theorem range_getD (input : List Nat) :
    (List.range input.length).map (fun i => input.getD i 0) = input := by
  induction input with
  | nil => rfl
  | cons value values ih =>
    simp only [List.length_cons, List.range_succ_eq_map, List.map_cons, List.map_map,
      Function.comp_def, List.getD_cons_zero, List.getD_cons_succ, ih]

theorem state16_getD (input : List Nat) (shape : input.length = 16) :
    state16 (fun i => input.getD i 0) = input := by
  simpa only [shape, state16] using range_getD input

/-- Equality of all sixteen lanes; no condition is imposed on out-of-range function values. -/
structure StateMatches (state : Nat → F) (values : List Nat) : Prop where
  lane : ∀ i < 16, state i = toGoldilocks (values.getD i 0)

def externalStep (state : Nat → F) (constants : List Nat) : Nat → F :=
  externalRoundField state (fun i => (constants.getD i 0 : F))

def internalStep (state : Nat → F) (constant : Nat) : Nat → F :=
  internalRoundField state (constant : F)

theorem external_step_refines (state : Nat → F) (values constants : List Nat)
    (matched : StateMatches state values) :
    StateMatches (externalStep state constants)
      (Poseidon2Width16Kernel.externalRound values constants) := by
  constructor
  intro i hi
  have compatible :
      externalField (fun j => (state j + (constants.getD j 0 : F))^7) i =
      externalField (fun j => ((values.getD j 0 : F) + (constants.getD j 0 : F))^7) i :=
    externalField_congr _ _ (by
      intro j hj
      rw [matched.lane j hj]
      rfl) ⟨i, hi⟩
  exact compatible.trans (externalRoundField_cast_kernel values constants ⟨i, hi⟩).symm

theorem internal_step_refines (state : Nat → F) (values : List Nat) (constant : Nat)
    (shape : values.length = 16) (matched : StateMatches state values) :
    StateMatches (internalStep state constant)
      (Poseidon2Width16Kernel.internalRound values constant) := by
  constructor
  intro i hi
  have kernel := internalRoundField_cast_kernel (fun j => values.getD j 0) constant ⟨i, hi⟩
  rw [state16_getD values shape] at kernel
  have compatible :
      internalField (replaceZero state (constant : F)) i =
      internalField (replaceZero (fun j => (values.getD j 0 : F)) (constant : F)) i :=
    internalField_congr _ _ (by
      intro j hj
      by_cases zero : j = 0
      · simp [replaceZero, zero, matched.lane 0 (by decide), toGoldilocks]
      · simp [replaceZero, zero, matched.lane j hj, toGoldilocks]) ⟨i, hi⟩
  exact compatible.trans kernel.symm

theorem external_rounds_refine (rounds : List (List Nat))
    (state : Nat → F) (values : List Nat) (matched : StateMatches state values) :
    StateMatches (rounds.foldl externalStep state)
      (rounds.foldl Poseidon2Width16Kernel.externalRound values) := by
  induction rounds generalizing state values with
  | nil => exact matched
  | cons constants rounds ih =>
    exact ih (externalStep state constants) (Poseidon2Width16Kernel.externalRound values constants)
      (external_step_refines state values constants matched)

theorem external_rounds_length (rounds : List (List Nat)) (values : List Nat)
    (shape : values.length = 16) :
    (rounds.foldl Poseidon2Width16Kernel.externalRound values).length = 16 := by
  induction rounds generalizing values with
  | nil => exact shape
  | cons constants rounds ih =>
    exact ih (Poseidon2Width16Kernel.externalRound values constants)
      (Poseidon2Width16Kernel.external_round_length values constants)

theorem internal_rounds_refine (rounds : List Nat)
    (state : Nat → F) (values : List Nat) (shape : values.length = 16)
    (matched : StateMatches state values) :
    StateMatches (rounds.foldl internalStep state)
      (rounds.foldl Poseidon2Width16Kernel.internalRound values) := by
  induction rounds generalizing state values with
  | nil => exact matched
  | cons constant rounds ih =>
    simp only [List.foldl_cons]
    exact ih (internalStep state constant) (Poseidon2Width16Kernel.internalRound values constant)
      (Poseidon2Width16Kernel.internal_round_length values constant)
      (internal_step_refines state values constant shape matched)

def permutationField (state : Nat → F) : Nat → F :=
  let initialLinear := externalField state
  let initialExternal :=
    Poseidon2Width16Kernel.externalRoundConstantsInitial.foldl externalStep initialLinear
  let internal :=
    Poseidon2Width16Kernel.internalRoundConstants.foldl internalStep initialExternal
  Poseidon2Width16Kernel.externalRoundConstantsTerminal.foldl externalStep internal

/-- All 31 scheduled steps refine the pinned permutation, after local template refinement. -/
theorem permutationField_refines_kernel (state : Nat → F) (values : List Nat)
    (matched : StateMatches state values) :
    StateMatches (permutationField state) (Poseidon2Width16Kernel.permutation values) := by
  let fieldLinear := externalField state
  let natLinear := Poseidon2Width16Kernel.externalLinearLayer values
  let fieldInitial := Poseidon2Width16Kernel.externalRoundConstantsInitial.foldl externalStep fieldLinear
  let natInitial := Poseidon2Width16Kernel.externalRoundConstantsInitial.foldl
    Poseidon2Width16Kernel.externalRound natLinear
  let fieldInternal := Poseidon2Width16Kernel.internalRoundConstants.foldl internalStep fieldInitial
  let natInternal := Poseidon2Width16Kernel.internalRoundConstants.foldl
    Poseidon2Width16Kernel.internalRound natInitial
  have aligned : ∀ i < 16, state i = (values.getD i 0 : F) := by
    intro i hi
    exact matched.lane i hi
  have linear : StateMatches fieldLinear natLinear := by
    constructor
    intro i hi
    exact (externalField_congr _ _ aligned ⟨i, hi⟩).trans
      (externalField_cast_kernel values ⟨i, hi⟩).symm
  have initial : StateMatches fieldInitial natInitial := external_rounds_refine
    Poseidon2Width16Kernel.externalRoundConstantsInitial fieldLinear natLinear linear
  have initialShape : natInitial.length = 16 := external_rounds_length
    Poseidon2Width16Kernel.externalRoundConstantsInitial
    natLinear
    (Poseidon2Width16Kernel.external_linear_layer_length values)
  have internal : StateMatches fieldInternal natInternal := internal_rounds_refine
    Poseidon2Width16Kernel.internalRoundConstants fieldInitial natInitial initialShape initial
  have terminal := external_rounds_refine
    Poseidon2Width16Kernel.externalRoundConstantsTerminal fieldInternal natInternal internal
  simpa only [permutationField, Poseidon2Width16Kernel.permutation,
    fieldInternal, natInternal, fieldInitial, natInitial, fieldLinear, natLinear] using terminal

end HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
