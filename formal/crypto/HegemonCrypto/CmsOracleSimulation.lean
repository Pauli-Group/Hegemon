import HegemonCrypto.CmsCompressedOracleUnitary
import HegemonCrypto.CmsQuerySequence
import Mathlib.Data.Finset.Dedup

/-!
# Finite standard-oracle simulation of the CMS compressed oracle

This module starts the exact finite proof of CMS Lemma 3.3.  It defines the decompression
reflection at an arbitrary oracle input over the full compressed-oracle state, proves exact norm
preservation, and proves that one implemented compressed query is the conjugation of the ordinary
diagonal phase query by the controlled decompression reflection.

No query log, measurement, asymptotic notation, or cryptographic assumption appears here.
-/

namespace HegemonCrypto.CmsOracleSimulation

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.DatabaseFiber
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsKernelBounds

noncomputable section

set_option linter.unusedSectionVars false

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- One database fiber at an arbitrary selected oracle input, with adversary registers fixed. -/
def databaseFiberState
    (state : State Input Output Phase Workspace)
    (registerInput : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (selectedInput : Input)
    (base : AbsentDatabase (Output := Output) selectedInput) :
    FiberState Output :=
  WithLp.toLp 2 fun coordinate =>
    state
      { input := registerInput
        phase := phaseValue
        workspace := workspace
        database :=
          (databaseEquiv (Output := Output) selectedInput).symm (base, coordinate) }

@[simp]
theorem database_fiber_state_apply
    (state : State Input Output Phase Workspace)
    (registerInput : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (selectedInput : Input)
    (base : AbsentDatabase (Output := Output) selectedInput)
    (coordinate : Option Output) :
    databaseFiberState state registerInput phaseValue workspace selectedInput base coordinate =
      state
        { input := registerInput
          phase := phaseValue
          workspace := workspace
          database :=
            (databaseEquiv (Output := Output) selectedInput).symm (base, coordinate) } := by
  rfl

/-- Apply the CMS decompression reflection at one fixed oracle input. -/
def decompressAt
    (selectedInput : Input)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun target =>
    let coordinate :=
      databaseEquiv (Output := Output) selectedInput target.database
    decompressFiber
      (databaseFiberState state target.input target.phase target.workspace
        selectedInput coordinate.1)
      coordinate.2

@[simp]
theorem decompress_at_apply_coordinate
    (selectedInput : Input)
    (state : State Input Output Phase Workspace)
    (registerInput : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (base : AbsentDatabase (Output := Output) selectedInput)
    (coordinate : Option Output) :
    decompressAt selectedInput state
        { input := registerInput
          phase := phaseValue
          workspace := workspace
          database :=
            (databaseEquiv (Output := Output) selectedInput).symm (base, coordinate) } =
      decompressFiber
        (databaseFiberState state registerInput phaseValue workspace selectedInput base)
        coordinate := by
  simp [decompressAt]

/-- Decompressing a full-state fiber applies exactly the one-fiber reflection. -/
theorem database_fiber_state_decompress_at
    (selectedInput : Input)
    (state : State Input Output Phase Workspace)
    (registerInput : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (base : AbsentDatabase (Output := Output) selectedInput) :
    databaseFiberState (decompressAt selectedInput state)
        registerInput phaseValue workspace selectedInput base =
      decompressFiber
        (databaseFiberState state registerInput phaseValue workspace selectedInput base) := by
  ext coordinate
  exact decompress_at_apply_coordinate
    selectedInput state registerInput phaseValue workspace base coordinate

/-- Full-state squared norm is the exact sum of arbitrary-input database-fiber norms. -/
theorem norm_squared_eq_sum_database_fiber_norm
    (selectedInput : Input)
    (state : State Input Output Phase Workspace) :
    normSquared state =
      ∑ registerInput : Input,
        ∑ phaseValue : Phase,
          ∑ workspace : Workspace,
            ∑ base : AbsentDatabase (Output := Output) selectedInput,
              ‖databaseFiberState state registerInput phaseValue workspace
                selectedInput base‖ ^ 2 := by
  unfold normSquared
  rw [← (basisEquiv (Input := Input) (Output := Output) (Phase := Phase)
    (Workspace := Workspace)).sum_comp
      (fun basis => Complex.normSq (state basis))]
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro registerInput _
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro phaseValue _
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro workspace _
  rw [sum_database_eq_sum_fibers]
  apply Finset.sum_congr rfl
  intro base _
  rw [EuclideanSpace.norm_sq_eq, Fintype.sum_option]
  simp [database_fiber_state_apply, Complex.sq_norm, basisEquiv,
    databaseEquiv_symm_none, databaseEquiv_symm_some]

/-- Decompression at one oracle input preserves the exact full-state squared norm. -/
theorem decompress_at_preserves_norm_squared
    (selectedInput : Input)
    (state : State Input Output Phase Workspace) :
    normSquared (decompressAt selectedInput state) = normSquared state := by
  rw [norm_squared_eq_sum_database_fiber_norm,
    norm_squared_eq_sum_database_fiber_norm]
  apply Finset.sum_congr rfl
  intro registerInput _
  apply Finset.sum_congr rfl
  intro phaseValue _
  apply Finset.sum_congr rfl
  intro workspace _
  apply Finset.sum_congr rfl
  intro base _
  rw [database_fiber_state_decompress_at,
    decompress_fiber_preserves_norm]

/-- Decompression at one input is an involution on the full state. -/
theorem decompress_at_involutive
    (selectedInput : Input)
    (state : State Input Output Phase Workspace) :
    decompressAt selectedInput (decompressAt selectedInput state) = state := by
  funext target
  let coordinate :=
    databaseEquiv (Output := Output) selectedInput target.database
  have databaseEq :
      (databaseEquiv (Output := Output) selectedInput).symm coordinate =
        target.database :=
    Equiv.symm_apply_apply
      (databaseEquiv (Output := Output) selectedInput) target.database
  rcases coordinate with ⟨base, targetCoordinate⟩
  have targetEq :
      ({ input := target.input
         phase := target.phase
         workspace := target.workspace
         database :=
           (databaseEquiv (Output := Output) selectedInput).symm
             (base, targetCoordinate) } :
        Basis Input Output Phase Workspace) =
        target := by
    cases target
    simp_all
  rw [← targetEq, decompress_at_apply_coordinate,
    database_fiber_state_decompress_at, decompress_fiber_involutive]
  rfl

/-- Replace exactly one recorded-database coordinate, including replacing it by `none`. -/
def setDatabaseCoordinate
    (database : Database Input Output)
    (input : Input)
    (coordinate : Option Output) :
    Database Input Output :=
  fun selected => if selected = input then coordinate else database selected

@[simp]
theorem set_database_coordinate_same
    (database : Database Input Output)
    (input : Input)
    (coordinate : Option Output) :
    setDatabaseCoordinate database input coordinate input = coordinate := by
  simp [setDatabaseCoordinate]

@[simp]
theorem set_database_coordinate_other
    (database : Database Input Output)
    {input selected : Input}
    (different : selected ≠ input)
    (coordinate : Option Output) :
    setDatabaseCoordinate database input coordinate selected =
      database selected := by
  simp [setDatabaseCoordinate, different]

/-- The canonical fiber equivalence replaces exactly the selected database coordinate. -/
theorem database_equiv_symm_fiber_eq_set_coordinate
    (database : Database Input Output)
    (input : Input)
    (coordinate : Option Output) :
    (databaseEquiv (Output := Output) input).symm
        ((databaseEquiv (Output := Output) input database).1, coordinate) =
      setDatabaseCoordinate database input coordinate := by
  funext selected
  by_cases same : selected = input
  · subst selected
    cases coordinate <;>
      simp [databaseEquiv, setDatabaseCoordinate, erase,
        HegemonCrypto.FiniteOracleDatabase.insert]
  · cases coordinate <;>
      simp [databaseEquiv, setDatabaseCoordinate, erase,
        HegemonCrypto.FiniteOracleDatabase.insert, same]

/-- Replacing two distinct coordinates is order-independent. -/
theorem set_database_coordinate_commutes
    (database : Database Input Output)
    (left right : Input)
    (different : left ≠ right)
    (leftCoordinate rightCoordinate : Option Output) :
    setDatabaseCoordinate
        (setDatabaseCoordinate database left leftCoordinate)
        right rightCoordinate =
      setDatabaseCoordinate
        (setDatabaseCoordinate database right rightCoordinate)
        left leftCoordinate := by
  funext selected
  by_cases selectedLeft : selected = left
  · subst selected
    simp [setDatabaseCoordinate, different]
  · by_cases selectedRight : selected = right
    · subst selected
      simp [setDatabaseCoordinate, selectedLeft]
    · simp [setDatabaseCoordinate, selectedLeft, selectedRight]

/-- Matrix coefficient of the one-coordinate decompression reflection. -/
def decompressKernel
    (source target : Option Output) : ℂ :=
  decompressFiber
    (fiberBasisKet (Output := Output) source) target

/-- Exact computational-basis expansion of the one-coordinate decompression reflection. -/
theorem decompress_fiber_eq_sum_basis
    (state : FiberState Output)
    (target : Option Output) :
    decompressFiber state target =
      ∑ source : Option Output,
        state source *
          decompressKernel (Output := Output) source target := by
  have expansion :
      decompressFiber state =
        ∑ source : Option Output,
          decompressFiber
            (state source • fiberBasisKet (Output := Output) source) := by
    rw [← map_sum]
    exact congrArg
      (decompressFiber (Output := Output))
      (fiber_state_eq_sum_basis state)
  simp_rw [map_smul] at expansion
  have atTarget :=
    congrArg (fun value : FiberState Output => value target) expansion
  simpa [decompressKernel, Finset.sum_apply, PiLp.smul_apply, smul_eq_mul]
    using atTarget

/-- Full-state decompression is the exact finite matrix action on one database coordinate. -/
theorem decompress_at_eq_sum_kernel
    (selectedInput : Input)
    (state : State Input Output Phase Workspace)
    (target : Basis Input Output Phase Workspace) :
    decompressAt selectedInput state target =
      ∑ source : Option Output,
        state
            { input := target.input
              phase := target.phase
              workspace := target.workspace
              database :=
                setDatabaseCoordinate target.database selectedInput source } *
          decompressKernel (Output := Output) source
            (target.database selectedInput) := by
  unfold decompressAt
  rw [decompress_fiber_eq_sum_basis]
  apply Finset.sum_congr rfl
  intro source _
  rw [database_fiber_state_apply]
  rw [database_equiv_symm_fiber_eq_set_coordinate]
  rfl

/-- Decompression reflections at any two oracle inputs commute on the complete state space. -/
theorem decompress_at_commutes
    (left right : Input)
    (state : State Input Output Phase Workspace) :
    decompressAt left (decompressAt right state) =
      decompressAt right (decompressAt left state) := by
  by_cases same : left = right
  · subst right
    rfl
  funext target
  rw [decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel]
  simp_rw [decompress_at_eq_sum_kernel]
  have leftLeavesRight :
      ∀ coordinate : Option Output,
        setDatabaseCoordinate target.database left coordinate right =
          target.database right := by
    intro coordinate
    exact set_database_coordinate_other
      target.database (Ne.symm same) coordinate
  have rightLeavesLeft :
      ∀ coordinate : Option Output,
        setDatabaseCoordinate target.database right coordinate left =
          target.database left := by
    intro coordinate
    exact set_database_coordinate_other target.database same coordinate
  simp_rw [leftLeavesRight, rightLeavesLeft, Finset.sum_mul]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro rightCoordinate _
  apply Finset.sum_congr rfl
  intro leftCoordinate _
  rw [set_database_coordinate_commutes
    target.database left right same leftCoordinate rightCoordinate]
  ring

/-- Apply one independent decompression reflection for every input in a finite list. -/
def decompressList
    (inputs : List Input)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  inputs.foldr (fun input current => decompressAt input current) state

@[simp]
theorem decompress_list_nil
    (state : State Input Output Phase Workspace) :
    decompressList ([] : List Input) state = state := by
  rfl

@[simp]
theorem decompress_list_cons
    (input : Input)
    (inputs : List Input)
    (state : State Input Output Phase Workspace) :
    decompressList (input :: inputs) state =
      decompressAt input (decompressList inputs state) := by
  rfl

/-- The product of coordinate decompressions depends only on the input set, not list order. -/
theorem decompress_list_perm
    {left right : List Input}
    (permutation : left.Perm right)
    (state : State Input Output Phase Workspace) :
    decompressList left state = decompressList right state := by
  letI : LeftCommutative
      (fun (input : Input)
          (current : State Input Output Phase Workspace) =>
        decompressAt input current) :=
    ⟨fun first second current =>
      decompress_at_commutes first second current⟩
  exact permutation.foldr_eq state

/-- A coordinate decompression commutes through any finite product of decompressions. -/
theorem decompress_at_decompress_list_commutes
    (selectedInput : Input)
    (inputs : List Input)
    (state : State Input Output Phase Workspace) :
    decompressAt selectedInput (decompressList inputs state) =
      decompressList inputs (decompressAt selectedInput state) := by
  induction inputs with
  | nil =>
      rfl
  | cons input remaining inductionHypothesis =>
      rw [decompress_list_cons, decompress_list_cons,
        decompress_at_commutes selectedInput input,
        inductionHypothesis]

/-- Full tensor-product decompression over the complete finite oracle domain. -/
def globalDecompress
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  decompressList (Finset.univ : Finset Input).toList state

/-- Full decompression with one selected input omitted. -/
def decompressExcept
    (selectedInput : Input)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  decompressList ((Finset.univ : Finset Input).erase selectedInput).toList state

/-- The complete input list is a permutation of one selected input followed by all others. -/
theorem selected_cons_erase_perm_univ
    (selectedInput : Input) :
    (selectedInput ::
        ((Finset.univ : Finset Input).erase selectedInput).toList).Perm
      (Finset.univ : Finset Input).toList := by
  apply List.perm_of_nodup_nodup_toFinset_eq
  · exact
      (((Finset.univ : Finset Input).erase selectedInput).nodup_toList).cons
        (by simp)
  · exact (Finset.univ : Finset Input).nodup_toList
  · ext input
    by_cases same : input = selectedInput <;> simp [same]

/-- Full decompression factors through the selected coordinate first. -/
theorem global_decompress_eq_selected_first
    (selectedInput : Input)
    (state : State Input Output Phase Workspace) :
    globalDecompress state =
      decompressAt selectedInput (decompressExcept selectedInput state) := by
  unfold globalDecompress decompressExcept
  exact
    (decompress_list_perm
      (selected_cons_erase_perm_univ selectedInput) state).symm

/-- Full decompression also factors through the selected coordinate last. -/
theorem global_decompress_eq_selected_last
    (selectedInput : Input)
    (state : State Input Output Phase Workspace) :
    globalDecompress state =
      decompressExcept selectedInput (decompressAt selectedInput state) := by
  rw [global_decompress_eq_selected_first]
  unfold decompressExcept
  rw [
    decompress_at_decompress_list_commutes]

/-- Computational basis of the prover/verifier registers, excluding the oracle database. -/
abbrev RegisterBasis :=
  Input × Phase × Workspace

/-- Register tuple carried by a complete compressed-oracle basis state. -/
def basisRegisters
    (basis : Basis Input Output Phase Workspace) :
    RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) :=
  (basis.input, basis.phase, basis.workspace)

/-- A finite database records exactly the inputs in one finite set. -/
def RecordsExactly
    (inputs : Finset Input)
    (database : Database Input Output) : Prop :=
  ∀ input, (∃ output, database input = some output) ↔ input ∈ inputs

noncomputable local instance recordsExactlyDecidable
    (inputs : Finset Input) :
    DecidablePred (RecordsExactly (Output := Output) inputs) :=
  Classical.decPred _

/-- Recording no inputs is equivalent to the canonical empty database. -/
theorem records_exactly_empty_iff
    (database : Database Input Output) :
    RecordsExactly (Output := Output) ∅ database ↔
      database = empty := by
  constructor
  · intro records
    funext input
    cases recorded : database input with
    | none =>
        rfl
    | some output =>
        have atInput := (records input).mp ⟨output, recorded⟩
        simp at atInput
  · intro databaseEmpty
    subst database
    simp [RecordsExactly]

/-- A database with a fixed coordinate reset to `none` records nothing at that coordinate. -/
theorem set_database_coordinate_none_not_recorded
    (database : Database Input Output)
    (input : Input) :
    ¬ ∃ output,
      setDatabaseCoordinate database input none input = some output := by
  simp

/-- A fixed `some` coordinate is recorded. -/
theorem set_database_coordinate_some_recorded
    (database : Database Input Output)
    (input : Input)
    (output : Output) :
    ∃ recorded,
      setDatabaseCoordinate database input (some output) input =
        some recorded := by
  exact ⟨output, by simp⟩

/-- Exact support condition after adding one previously unrecorded input. -/
theorem records_exactly_insert_iff
    (inputs : Finset Input)
    (selectedInput : Input)
    (database : Database Input Output)
    (fresh : selectedInput ∉ inputs) :
    RecordsExactly (Output := Output) (insert selectedInput inputs) database ↔
      (∃ output, database selectedInput = some output) ∧
        RecordsExactly (Output := Output) inputs
          (setDatabaseCoordinate database selectedInput none) := by
  constructor
  · intro records
    constructor
    · exact (records selectedInput).mpr (by simp)
    · intro input
      by_cases same : input = selectedInput
      · subst input
        simp [fresh]
      · rw [set_database_coordinate_other database same none]
        rw [records input]
        simp [same]
  · rintro ⟨selectedRecorded, remainingRecords⟩
    intro input
    by_cases same : input = selectedInput
    · subst input
      simp [selectedRecorded]
    · have unchanged :
          setDatabaseCoordinate database selectedInput none input =
            database input :=
        set_database_coordinate_other database same none
      rw [← unchanged, remainingRecords input]
      simp [same]

/-- A `some` value at an input outside the exact support makes the support predicate false. -/
theorem records_exactly_set_some_false
    (inputs : Finset Input)
    (selectedInput : Input)
    (database : Database Input Output)
    (output : Output)
    (fresh : selectedInput ∉ inputs) :
    ¬ RecordsExactly (Output := Output) inputs
      (setDatabaseCoordinate database selectedInput (some output)) := by
  intro records
  exact fresh ((records selectedInput).mp ⟨output, by simp⟩)

/-- Replacing a coordinate by its current value leaves the database unchanged. -/
theorem set_database_coordinate_current
    (database : Database Input Output)
    (input : Input) :
    setDatabaseCoordinate database input (database input) = database := by
  funext selected
  by_cases same : selected = input
  · subst selected
    simp
  · simp [setDatabaseCoordinate, same]

/-- Register amplitude lifted onto databases whose exact support is one finite input set. -/
def partialRandomOracleState
    (inputs : Finset Input)
    (registerState :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ) :
    State Input Output Phase Workspace :=
  fun basis =>
    if RecordsExactly (Output := Output) inputs basis.database then
      inverseSqrtOutputCard (Output := Output) ^ inputs.card *
        registerState (basisRegisters basis)
    else 0

@[simp]
theorem decompress_kernel_none_none :
    decompressKernel (Output := Output) none none = 0 := by
  unfold decompressKernel
  rw [show fiberBasisKet (Output := Output) none =
      absentKet (Output := Output) by rfl]
  rw [decompress_absent_ket]
  exact uniform_ket_apply_none (Output := Output)

@[simp]
theorem decompress_kernel_none_some
    (output : Output) :
    decompressKernel (Output := Output) none (some output) =
      inverseSqrtOutputCard (Output := Output) := by
  unfold decompressKernel
  rw [show fiberBasisKet (Output := Output) none =
      absentKet (Output := Output) by rfl]
  rw [decompress_absent_ket]
  exact uniform_ket_apply_some output

/--
Decompressing one fresh coordinate extends the exact random-oracle purification support by that
coordinate and contributes exactly one `1 / sqrt |Y|` amplitude factor.
-/
theorem decompress_at_partial_random_oracle_state
    (inputs : Finset Input)
    (selectedInput : Input)
    (registerState :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ)
    (fresh : selectedInput ∉ inputs) :
    decompressAt selectedInput
        (partialRandomOracleState (Output := Output) inputs registerState) =
      partialRandomOracleState (Output := Output)
        (insert selectedInput inputs : Finset Input) registerState := by
  funext target
  rw [decompress_at_eq_sum_kernel, Fintype.sum_option]
  simp_rw [partialRandomOracleState]
  have someUnsupported :
      ∀ output : Output,
        ¬ RecordsExactly (Output := Output) inputs
          (setDatabaseCoordinate target.database selectedInput (some output)) :=
    fun output =>
      records_exactly_set_some_false
        inputs selectedInput target.database output fresh
  simp_rw [if_neg (someUnsupported _), zero_mul, Finset.sum_const_zero, add_zero]
  cases recorded : target.database selectedInput with
  | none =>
      have targetUnsupported :
          ¬ RecordsExactly (Output := Output) (insert selectedInput inputs)
            target.database := by
        intro records
        obtain ⟨output, outputRecorded⟩ :=
          (records selectedInput).mpr (by simp)
        rw [recorded] at outputRecorded
        contradiction
      rw [if_neg targetUnsupported]
      simp
  | some selectedOutput =>
      have supportIff :
          RecordsExactly (Output := Output) (insert selectedInput inputs)
              target.database ↔
            RecordsExactly (Output := Output) inputs
              (setDatabaseCoordinate target.database selectedInput none) := by
        rw [records_exactly_insert_iff
          inputs selectedInput target.database fresh]
        simp [recorded]
      by_cases supported :
          RecordsExactly (Output := Output) inputs
            (setDatabaseCoordinate target.database selectedInput none)
      · rw [if_pos supported, if_pos (supportIff.mpr supported)]
        rw [decompress_kernel_none_some]
        rw [Finset.card_insert_of_notMem fresh, pow_succ]
        simp only [basisRegisters]
        ring
      · rw [if_neg supported, if_neg (fun targetSupported =>
          supported (supportIff.mp targetSupported))]
        simp

/-- Apply decompression over one finite input set in the set's canonical list order. -/
def decompressFinset
    (inputs : Finset Input)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  decompressList inputs.toList state

/-- Inserting one fresh set element factors its decompression from the remaining set. -/
theorem decompress_finset_insert
    (inputs : Finset Input)
    (selectedInput : Input)
    (state : State Input Output Phase Workspace)
    (fresh : selectedInput ∉ inputs) :
    decompressFinset (insert selectedInput inputs : Finset Input) state =
      decompressAt selectedInput (decompressFinset inputs state) := by
  have permutation :
      (selectedInput :: inputs.toList).Perm
        (insert selectedInput inputs : Finset Input).toList := by
    apply List.perm_of_nodup_nodup_toFinset_eq
    · exact inputs.nodup_toList.cons (by simpa)
    · exact (insert selectedInput inputs : Finset Input).nodup_toList
    · ext input
      simp
  unfold decompressFinset
  exact (decompress_list_perm permutation state).symm

/--
Decompressing any finite set of inputs from the empty support produces exactly the uniform
finite-map purification on that set.
-/
theorem decompress_finset_empty_support
    (inputs : Finset Input)
    (registerState :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ) :
    decompressFinset inputs
        (partialRandomOracleState (Output := Output) ∅ registerState) =
      partialRandomOracleState (Output := Output) inputs registerState := by
  induction inputs using Finset.induction_on with
  | empty =>
      simp [decompressFinset]
  | @insert selectedInput inputs fresh inductionHypothesis =>
      rw [decompress_finset_insert inputs selectedInput _ fresh,
        inductionHypothesis,
        decompress_at_partial_random_oracle_state
          inputs selectedInput registerState fresh]

/--
Full decompression of the empty database is exactly the uniform purification over complete finite
random-oracle functions.
-/
theorem global_decompress_empty_support
    (registerState :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ) :
    globalDecompress
        (partialRandomOracleState (Output := Output) ∅ registerState) =
      partialRandomOracleState (Output := Output)
        (Finset.univ : Finset Input) registerState := by
  unfold globalDecompress
  change
    decompressFinset (Finset.univ : Finset Input)
        (partialRandomOracleState (Output := Output) ∅ registerState) =
      partialRandomOracleState (Output := Output)
        (Finset.univ : Finset Input) registerState
  exact decompress_finset_empty_support
    (Output := Output) (Finset.univ : Finset Input) registerState

/-- Embed one total oracle function as a complete compressed-database basis value. -/
def totalDatabase
    (oracle : Input → Output) :
    Database Input Output :=
  fun input => some (oracle input)

@[simp]
theorem records_exactly_univ_total_database
    (oracle : Input → Output) :
    RecordsExactly (Finset.univ : Finset Input) (totalDatabase oracle) := by
  intro input
  simp [totalDatabase]

/-- Every total-oracle basis branch has the same exact purification amplitude. -/
theorem partial_random_oracle_state_univ_total
    (registerState :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ)
    (registerInput : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (oracle : Input → Output) :
    partialRandomOracleState (Output := Output)
        (Finset.univ : Finset Input) registerState
        { input := registerInput
          phase := phaseValue
          workspace := workspace
          database := totalDatabase oracle } =
      inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
        registerState (registerInput, phaseValue, workspace) := by
  simp [partialRandomOracleState, basisRegisters]

/-- Complete databases are in bijection with total finite oracle functions. -/
theorem total_database_injective :
    Function.Injective (totalDatabase :
      (Input → Output) → Database Input Output) := by
  intro left right databasesEqual
  funext input
  have atInput := congrFun databasesEqual input
  simpa [totalDatabase] using atInput

/-- Exact complete-support characterization by a unique total oracle function. -/
theorem records_exactly_univ_iff_exists_total
    (database : Database Input Output) :
    RecordsExactly (Output := Output) (Finset.univ : Finset Input) database ↔
      ∃ oracle : Input → Output, database = totalDatabase oracle := by
  constructor
  · intro records
    let oracle : Input → Output :=
      fun input =>
        Classical.choose ((records input).mpr (by simp))
    have oracleSpec :
        ∀ input, database input = some (oracle input) := by
      intro input
      exact Classical.choose_spec ((records input).mpr (by simp))
    refine ⟨oracle, ?_⟩
    funext input
    exact oracleSpec input
  · rintro ⟨oracle, rfl⟩
    exact records_exactly_univ_total_database oracle

/-- Register-state family indexed by the purified total oracle function. -/
abbrev OracleRegisterFamily :=
  (Input → Output) →
    RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ

/--
Exact purified state for an arbitrary oracle-indexed family of adversary register states.  The sum
has at most one nonzero term because `totalDatabase` is injective.
-/
def totalOracleFamilyState
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)) :
    State Input Output Phase Workspace :=
  fun basis =>
    inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
      ∑ oracle : Input → Output,
        if basis.database = totalDatabase oracle then
          family oracle (basisRegisters basis)
        else 0

/-- Evaluate a purified oracle family on one named total-oracle branch. -/
theorem total_oracle_family_state_apply
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (oracle : Input → Output)
    (registerInput : Input)
    (phaseValue : Phase)
    (workspace : Workspace) :
    totalOracleFamilyState family
        { input := registerInput
          phase := phaseValue
          workspace := workspace
          database := totalDatabase oracle } =
      inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
        family oracle (registerInput, phaseValue, workspace) := by
  unfold totalOracleFamilyState
  rw [Finset.sum_eq_single oracle]
  · simp [basisRegisters]
  · intro candidate _ different
    have databasesDifferent :
        totalDatabase oracle ≠ totalDatabase candidate := by
      intro databasesEqual
      exact different (total_database_injective databasesEqual.symm)
    simp [databasesDifferent]
  · simp

/-- A database outside the complete-oracle image has zero purified-family amplitude. -/
theorem total_oracle_family_state_eq_zero_of_no_match
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (basis : Basis Input Output Phase Workspace)
    (noMatch : ¬ ∃ oracle : Input → Output,
      basis.database = totalDatabase oracle) :
    totalOracleFamilyState family basis = 0 := by
  unfold totalOracleFamilyState
  apply mul_eq_zero_of_right
  apply Finset.sum_eq_zero
  intro oracle _
  rw [if_neg]
  exact fun databaseEqual => noMatch ⟨oracle, databaseEqual⟩

/-- The previous complete-support state is the constant-family special case. -/
theorem partial_random_oracle_state_univ_eq_family
    (registerState :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ) :
    partialRandomOracleState (Output := Output)
        (Finset.univ : Finset Input) registerState =
      totalOracleFamilyState
        (fun _oracle => registerState) := by
  funext basis
  by_cases complete :
      RecordsExactly (Output := Output) (Finset.univ : Finset Input)
        basis.database
  · obtain ⟨oracle, databaseEqual⟩ :=
      (records_exactly_univ_iff_exists_total basis.database).mp complete
    cases basis
    simp_all [partial_random_oracle_state_univ_total,
      total_oracle_family_state_apply]
  · have noMatch :
        ¬ ∃ oracle : Input → Output,
          basis.database = totalDatabase oracle := by
      exact fun existsTotal =>
        complete ((records_exactly_univ_iff_exists_total basis.database).mpr
          existsTotal)
    rw [total_oracle_family_state_eq_zero_of_no_match _ basis noMatch]
    simp [partialRandomOracleState, complete]

/-- Ordinary phase query on one adversary-register branch for a fixed total oracle. -/
def phaseRegisterState
    (system : PhaseSystem Output Phase)
    (oracle : Input → Output)
    (state :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ) :
    RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ :=
  fun basis =>
    system.character basis.2.1 (oracle basis.1) * state basis

/--
Lift an arbitrary finite matrix on adversary registers while acting as the identity on the oracle
database register.
-/
def liftRegisterKernel
    (kernel :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) →
        RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun target =>
    ∑ source :
        RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace),
      state
          { input := source.1
            phase := source.2.1
            workspace := source.2.2
            database := target.database } *
        kernel source (basisRegisters target)

/--
An inter-query computation that acts only on adversary registers.  Contractivity is the only
analytic premise; database independence is enforced by the lifted-kernel definition rather than
asserted as a commuting axiom.
-/
structure DatabaseIndependentContraction where
  kernel :
    RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) →
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ
  contractive :
    ∀ state : State Input Output Phase Workspace,
      stateNorm (liftRegisterKernel kernel state) <= stateNorm state

namespace DatabaseIndependentContraction

/-- Apply the database-independent register matrix. -/
def apply
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  liftRegisterKernel step.kernel state

/-- Apply the same matrix directly to an adversary-register state. -/
def applyRegister
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (state :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ) :
    RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ :=
  fun target =>
    ∑ source :
        RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace),
      state source * step.kernel source target

theorem map_add
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (left right : State Input Output Phase Workspace) :
    step.apply (left + right) = step.apply left + step.apply right := by
  funext target
  unfold apply liftRegisterKernel
  simp_rw [Pi.add_apply, add_mul, Finset.sum_add_distrib]

theorem commutes_project
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    project property queryBound (step.apply state) =
      step.apply (project property queryBound state) := by
  funext target
  by_cases accepted :
      size target.database <= queryBound ∧ property target.database
  · simp [apply, liftRegisterKernel, project, accepted]
  · simp [apply, liftRegisterKernel, project, accepted]

/-- Forget the explicit register matrix after deriving the database-blind interface. -/
def toDatabaseBlindContraction
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)) :
    DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace) where
  apply := step.apply
  mapAdd := step.map_add
  contractive := step.contractive
  commutesProject := step.commutes_project

/-- Register-only computation commutes exactly with decompression at any oracle input. -/
theorem decompress_at_apply_commutes
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (selectedInput : Input)
    (state : State Input Output Phase Workspace) :
    decompressAt selectedInput (step.apply state) =
      step.apply (decompressAt selectedInput state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold apply liftRegisterKernel
  simp_rw [decompress_at_eq_sum_kernel, Finset.sum_mul]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro source _
  apply Finset.sum_congr rfl
  intro coordinate _
  simp [basisRegisters]
  ring

/-- Register-only computation commutes with any finite decompression product. -/
theorem decompress_list_apply_commutes
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (inputs : List Input)
    (state : State Input Output Phase Workspace) :
    decompressList inputs (step.apply state) =
      step.apply (decompressList inputs state) := by
  induction inputs with
  | nil =>
      rfl
  | cons selectedInput remaining inductionHypothesis =>
      rw [decompress_list_cons, decompress_list_cons,
        inductionHypothesis, decompress_at_apply_commutes]

/-- Register-only computation commutes with full finite-domain decompression. -/
theorem global_decompress_apply_commutes
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (state : State Input Output Phase Workspace) :
    globalDecompress (step.apply state) =
      step.apply (globalDecompress state) := by
  unfold globalDecompress
  exact step.decompress_list_apply_commutes _ state

/-- Register-only computation evolves each purified total-oracle branch independently. -/
theorem apply_total_oracle_family_state
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)) :
    step.apply (totalOracleFamilyState family) =
      totalOracleFamilyState
        (fun oracle => step.applyRegister (family oracle)) := by
  funext target
  by_cases matched :
      ∃ oracle : Input → Output, target.database = totalDatabase oracle
  · obtain ⟨oracle, databaseEqual⟩ := matched
    rcases target with ⟨registerInput, phaseValue, workspace, database⟩
    dsimp at databaseEqual ⊢
    subst database
    unfold apply liftRegisterKernel
    rw [total_oracle_family_state_apply]
    simp_rw [total_oracle_family_state_apply]
    unfold applyRegister
    rw [Finset.mul_sum]
    apply Finset.sum_congr rfl
    intro source _
    simp only [basisRegisters]
    ring
  · rw [total_oracle_family_state_eq_zero_of_no_match _ target matched]
    unfold apply liftRegisterKernel
    apply Finset.sum_eq_zero
    intro source _
    rw [total_oracle_family_state_eq_zero_of_no_match]
    · simp
    · exact matched

end DatabaseIndependentContraction

/-- Ordinary diagonal phase-oracle action on the database value at the query input. -/
def phaseQueryState
    (system : PhaseSystem Output Phase)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun basis =>
    recordedPhase system basis.phase basis.database basis.input * state basis

/-- Ordinary phase queries evolve every purified total-oracle branch independently. -/
theorem phase_query_total_oracle_family_state
    (system : PhaseSystem Output Phase)
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)) :
    phaseQueryState system (totalOracleFamilyState family) =
      totalOracleFamilyState
        (fun oracle => phaseRegisterState system oracle (family oracle)) := by
  funext target
  by_cases matched :
      ∃ oracle : Input → Output, target.database = totalDatabase oracle
  · obtain ⟨oracle, databaseEqual⟩ := matched
    rcases target with ⟨registerInput, phaseValue, workspace, database⟩
    dsimp at databaseEqual ⊢
    subst database
    unfold phaseQueryState
    rw [total_oracle_family_state_apply,
      total_oracle_family_state_apply]
    unfold phaseRegisterState recordedPhase totalDatabase
    ring
  · rw [total_oracle_family_state_eq_zero_of_no_match _ target matched]
    unfold phaseQueryState
    rw [total_oracle_family_state_eq_zero_of_no_match _ target matched]
    simp

/-- Two states agree on the complete adversary/database fiber of one query-register input. -/
def AgreeOnInput
    (input : Input)
    (left right : State Input Output Phase Workspace) : Prop :=
  ∀ basis, basis.input = input -> left basis = right basis

namespace AgreeOnInput

theorem refl
    (input : Input)
    (state : State Input Output Phase Workspace) :
    AgreeOnInput input state state := by
  intro basis _
  rfl

theorem symm
    {input : Input}
    {left right : State Input Output Phase Workspace}
    (agreement : AgreeOnInput input left right) :
    AgreeOnInput input right left := by
  intro basis atInput
  exact (agreement basis atInput).symm

theorem trans
    {input : Input}
    {first second third : State Input Output Phase Workspace}
    (firstSecond : AgreeOnInput input first second)
    (secondThird : AgreeOnInput input second third) :
    AgreeOnInput input first third := by
  intro basis atInput
  exact (firstSecond basis atInput).trans (secondThird basis atInput)

end AgreeOnInput

/-- Database-coordinate decompression preserves agreement on an adversary input fiber. -/
theorem decompress_at_preserves_agreement
    (selectedInput queryInput : Input)
    {left right : State Input Output Phase Workspace}
    (agreement : AgreeOnInput queryInput left right) :
    AgreeOnInput queryInput
      (decompressAt selectedInput left)
      (decompressAt selectedInput right) := by
  intro target targetInput
  rw [decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel]
  apply Finset.sum_congr rfl
  intro source _
  rw [agreement
    { input := target.input
      phase := target.phase
      workspace := target.workspace
      database :=
        setDatabaseCoordinate target.database selectedInput source }
    targetInput]

/-- The ordinary phase query preserves agreement on an adversary input fiber. -/
theorem phase_query_preserves_agreement
    (system : PhaseSystem Output Phase)
    (queryInput : Input)
    {left right : State Input Output Phase Workspace}
    (agreement : AgreeOnInput queryInput left right) :
    AgreeOnInput queryInput
      (phaseQueryState system left)
      (phaseQueryState system right) := by
  intro target targetInput
  unfold phaseQueryState
  rw [agreement target targetInput]

/-- A decompression away from the active query input commutes with the phase oracle. -/
theorem decompress_at_phase_query_apply_of_ne
    (system : PhaseSystem Output Phase)
    (selectedInput : Input)
    (state : State Input Output Phase Workspace)
    (target : Basis Input Output Phase Workspace)
    (different : selectedInput ≠ target.input) :
    decompressAt selectedInput (phaseQueryState system state) target =
      phaseQueryState system (decompressAt selectedInput state) target := by
  rw [decompress_at_eq_sum_kernel]
  unfold phaseQueryState
  rw [decompress_at_eq_sum_kernel]
  have leavesQueryInput :
      ∀ coordinate : Option Output,
        setDatabaseCoordinate target.database selectedInput coordinate
            target.input =
          target.database target.input := by
    intro coordinate
    exact set_database_coordinate_other
      target.database (Ne.symm different) coordinate
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro source _
  have phaseEqual :
      recordedPhase system target.phase
          (setDatabaseCoordinate target.database selectedInput source)
          target.input =
        recordedPhase system target.phase target.database target.input := by
    unfold recordedPhase
    rw [leavesQueryInput source]
  rw [phaseEqual]
  ring

/--
A finite product of decompressions omitting one query input commutes with the phase oracle on
that entire input fiber.
-/
theorem decompress_list_phase_agrees
    (system : PhaseSystem Output Phase)
    (inputs : List Input)
    (queryInput : Input)
    (state : State Input Output Phase Workspace)
    (omitted : queryInput ∉ inputs) :
    AgreeOnInput queryInput
      (decompressList inputs (phaseQueryState system state))
      (phaseQueryState system (decompressList inputs state)) := by
  induction inputs with
  | nil =>
      exact AgreeOnInput.refl queryInput (phaseQueryState system state)
  | cons selectedInput remaining inductionHypothesis =>
      have selectedDifferent : selectedInput ≠ queryInput := by
        intro same
        apply omitted
        simp [same]
      have remainingOmitted : queryInput ∉ remaining := by
        intro member
        apply omitted
        simp [member]
      have tailAgreement :
          AgreeOnInput queryInput
            (decompressList remaining (phaseQueryState system state))
            (phaseQueryState system (decompressList remaining state)) :=
        inductionHypothesis remainingOmitted
      apply AgreeOnInput.trans
        (decompress_at_preserves_agreement
          selectedInput queryInput tailAgreement)
      intro target targetInput
      exact decompress_at_phase_query_apply_of_ne
        system selectedInput (decompressList remaining state) target
          (by
            intro same
            exact selectedDifferent (same.trans targetInput))

/-- Decompression over every input except the active one commutes with the phase oracle there. -/
theorem decompress_except_phase_agrees
    (system : PhaseSystem Output Phase)
    (queryInput : Input)
    (state : State Input Output Phase Workspace) :
    AgreeOnInput queryInput
      (decompressExcept queryInput (phaseQueryState system state))
      (phaseQueryState system (decompressExcept queryInput state)) := by
  unfold decompressExcept
  apply decompress_list_phase_agrees
  simp

/-- On a current-query-input fiber, the ordinary phase query is exactly `phaseFiber`. -/
theorem database_fiber_state_phase_query
    (system : PhaseSystem Output Phase)
    (state : State Input Output Phase Workspace)
    (registerInput : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (base : AbsentDatabase (Output := Output) registerInput) :
    databaseFiberState (phaseQueryState system state)
        registerInput phaseValue workspace registerInput base =
      phaseFiber system phaseValue
        (databaseFiberState state registerInput phaseValue workspace
          registerInput base) := by
  ext coordinate
  cases coordinate with
  | none =>
      simp [phaseQueryState, recordedPhase, databaseEquiv_symm_none, base.2]
  | some output =>
      simp [phaseQueryState, recordedPhase, databaseEquiv_symm_some]

/--
Controlled decompression applies the reflection at the input currently held by the adversary query
register.
-/
def controlledDecompress
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun target => decompressAt target.input state target

/-- A controlled-decompression fiber is exactly the active one-fiber decompression. -/
theorem state_fiber_controlled_decompress
    (state : State Input Output Phase Workspace)
    (input : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (base : AbsentDatabase (Output := Output) input) :
    stateFiber (controlledDecompress state) input phaseValue workspace base =
      decompressFiber (stateFiber state input phaseValue workspace base) := by
  ext coordinate
  exact decompress_at_apply_coordinate
    input state input phaseValue workspace base coordinate

/-- The arbitrary-selected-input fiber specializes definitionally to the active state fiber. -/
theorem database_fiber_state_eq_state_fiber
    (state : State Input Output Phase Workspace)
    (input : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (base : AbsentDatabase (Output := Output) input) :
    databaseFiberState state input phaseValue workspace input base =
      stateFiber state input phaseValue workspace base := by
  rfl

/-- Selected-input decompression and controlled decompression agree on that input fiber. -/
theorem decompress_at_agrees_controlled
    (selectedInput : Input)
    (state : State Input Output Phase Workspace) :
    AgreeOnInput selectedInput
      (decompressAt selectedInput state)
      (controlledDecompress state) := by
  intro target targetInput
  unfold controlledDecompress
  rw [targetInput]

/-- Any finite decompression product preserves agreement on an adversary input fiber. -/
theorem decompress_list_preserves_agreement
    (inputs : List Input)
    (queryInput : Input)
    {left right : State Input Output Phase Workspace}
    (agreement : AgreeOnInput queryInput left right) :
    AgreeOnInput queryInput
      (decompressList inputs left)
      (decompressList inputs right) := by
  induction inputs with
  | nil =>
      exact agreement
  | cons selectedInput remaining inductionHypothesis =>
      exact decompress_at_preserves_agreement selectedInput queryInput
        inductionHypothesis

/-- Decompression over all but one input preserves agreement on the omitted input fiber. -/
theorem decompress_except_preserves_agreement
    (selectedInput : Input)
    {left right : State Input Output Phase Workspace}
    (agreement : AgreeOnInput selectedInput left right) :
    AgreeOnInput selectedInput
      (decompressExcept selectedInput left)
      (decompressExcept selectedInput right) := by
  unfold decompressExcept
  exact decompress_list_preserves_agreement _ selectedInput agreement

/-- Controlled decompression is an involution on the complete state space. -/
theorem controlled_decompress_involutive
    (state : State Input Output Phase Workspace) :
    controlledDecompress (controlledDecompress state) = state := by
  funext target
  let coordinate :=
    databaseEquiv (Output := Output) target.input target.database
  have databaseEq :
      (databaseEquiv (Output := Output) target.input).symm coordinate =
        target.database :=
    Equiv.symm_apply_apply
      (databaseEquiv (Output := Output) target.input) target.database
  rcases coordinate with ⟨base, targetCoordinate⟩
  have targetEq :
      ({ input := target.input
         phase := target.phase
         workspace := target.workspace
         database :=
           (databaseEquiv (Output := Output) target.input).symm
             (base, targetCoordinate) } :
        Basis Input Output Phase Workspace) =
        target := by
    cases target
    simp_all
  rw [← targetEq]
  change
    decompressAt target.input (controlledDecompress state)
        { input := target.input
          phase := target.phase
          workspace := target.workspace
          database :=
            (databaseEquiv (Output := Output) target.input).symm
              (base, targetCoordinate) } =
      state
        { input := target.input
          phase := target.phase
          workspace := target.workspace
          database :=
            (databaseEquiv (Output := Output) target.input).symm
              (base, targetCoordinate) }
  rw [decompress_at_apply_coordinate]
  rw [database_fiber_state_eq_state_fiber]
  rw [state_fiber_controlled_decompress]
  rw [decompress_fiber_involutive]
  rfl

/--
One implemented compressed-oracle query is exactly controlled decompression, ordinary phase
query, and controlled decompression again on every strict reachable state.
-/
theorem query_state_eq_controlled_decompression_phase
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (strict : StrictSupport queryBound state) :
    queryState system queryBound state =
      controlledDecompress
        (phaseQueryState system (controlledDecompress state)) := by
  funext target
  let coordinate :=
    databaseEquiv (Output := Output) target.input target.database
  have databaseEq :
      (databaseEquiv (Output := Output) target.input).symm coordinate =
        target.database :=
    Equiv.symm_apply_apply
      (databaseEquiv (Output := Output) target.input) target.database
  rcases coordinate with ⟨base, targetCoordinate⟩
  have targetEq :
      ({ input := target.input
         phase := target.phase
         workspace := target.workspace
         database :=
           (databaseEquiv (Output := Output) target.input).symm
             (base, targetCoordinate) } :
        Basis Input Output Phase Workspace) =
        target := by
    cases target
    simp_all
  rw [← targetEq]
  rw [query_state_apply_eq_active_fiber
    system queryBound state strict]
  change
    activeFiberQuery system target.phase
        (stateFiber state target.input target.phase target.workspace base)
        targetCoordinate =
      decompressAt target.input
        (phaseQueryState system (controlledDecompress state))
        { input := target.input
          phase := target.phase
          workspace := target.workspace
          database :=
            (databaseEquiv (Output := Output) target.input).symm
              (base, targetCoordinate) }
  rw [decompress_at_apply_coordinate]
  rw [database_fiber_state_phase_query]
  rw [database_fiber_state_eq_state_fiber]
  rw [state_fiber_controlled_decompress]
  rfl

/-- Undoing controlled decompression turns one compressed query into one ordinary phase query. -/
theorem controlled_decompress_query_state_eq_phase
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (strict : StrictSupport queryBound state) :
    controlledDecompress (queryState system queryBound state) =
      phaseQueryState system (controlledDecompress state) := by
  calc
    controlledDecompress (queryState system queryBound state) =
        controlledDecompress
          (controlledDecompress
            (phaseQueryState system (controlledDecompress state))) :=
      congrArg controlledDecompress
        (query_state_eq_controlled_decompression_phase
          system queryBound state strict)
    _ = phaseQueryState system (controlledDecompress state) :=
      controlled_decompress_involutive _

/--
CMS Lemma 3.3, one-query algebraic core: after full finite-domain decompression, the implemented
reachable compressed query is exactly the ordinary phase query.  The equality is over the complete
state vector and has no probability loss or cryptographic premise.
-/
theorem global_decompress_query_state_eq_phase
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (strict : StrictSupport queryBound state) :
    globalDecompress (queryState system queryBound state) =
      phaseQueryState system (globalDecompress state) := by
  funext target
  have controlledQuery :
      controlledDecompress (queryState system queryBound state) =
        phaseQueryState system (controlledDecompress state) :=
    controlled_decompress_query_state_eq_phase
      system queryBound state strict
  have queryFiberAgreement :
      AgreeOnInput target.input
        (decompressAt target.input (queryState system queryBound state))
        (phaseQueryState system (controlledDecompress state)) := by
    apply AgreeOnInput.trans
      (decompress_at_agrees_controlled
        target.input (queryState system queryBound state))
    intro basis _
    exact congrFun controlledQuery basis
  have queryRestAgreement :
      AgreeOnInput target.input
        (decompressExcept target.input
          (decompressAt target.input (queryState system queryBound state)))
        (decompressExcept target.input
          (phaseQueryState system (controlledDecompress state))) :=
    decompress_except_preserves_agreement target.input queryFiberAgreement
  have restPhaseAgreement :
      AgreeOnInput target.input
        (decompressExcept target.input
          (phaseQueryState system (controlledDecompress state)))
        (phaseQueryState system
          (decompressExcept target.input (controlledDecompress state))) :=
    decompress_except_phase_agrees
      system target.input (controlledDecompress state)
  have initialFiberAgreement :
      AgreeOnInput target.input
        (decompressAt target.input state)
        (controlledDecompress state) :=
    decompress_at_agrees_controlled target.input state
  have initialRestAgreement :
      AgreeOnInput target.input
        (decompressExcept target.input (decompressAt target.input state))
        (decompressExcept target.input (controlledDecompress state)) :=
    decompress_except_preserves_agreement
      target.input initialFiberAgreement
  have restToGlobal :
      AgreeOnInput target.input
        (decompressExcept target.input (controlledDecompress state))
        (globalDecompress state) := by
    intro basis atInput
    calc
      decompressExcept target.input (controlledDecompress state) basis =
          decompressExcept target.input
            (decompressAt target.input state) basis :=
        (initialRestAgreement basis atInput).symm
      _ = globalDecompress state basis :=
        (congrFun
          (global_decompress_eq_selected_last target.input state)
          basis).symm
  have phaseToGlobal :
      AgreeOnInput target.input
        (phaseQueryState system
          (decompressExcept target.input (controlledDecompress state)))
        (phaseQueryState system (globalDecompress state)) :=
    phase_query_preserves_agreement system target.input restToGlobal
  calc
    globalDecompress (queryState system queryBound state) target =
        decompressExcept target.input
          (decompressAt target.input
            (queryState system queryBound state)) target :=
      congrFun
        (global_decompress_eq_selected_last target.input
          (queryState system queryBound state))
        target
    _ =
        decompressExcept target.input
          (phaseQueryState system (controlledDecompress state)) target :=
      queryRestAgreement target rfl
    _ =
        phaseQueryState system
          (decompressExcept target.input (controlledDecompress state)) target :=
      restPhaseAgreement target rfl
    _ = phaseQueryState system (globalDecompress state) target :=
      phaseToGlobal target rfl

/-- Execute ordinary phase-oracle queries with explicit database-independent inter-query steps. -/
def standardRun
    (system : PhaseSystem Output Phase) :
    List (DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)) →
      State Input Output Phase Workspace →
        State Input Output Phase Workspace
  | [], state => state
  | step :: remaining, state =>
      standardRun system remaining
        (step.apply (phaseQueryState system state))

/-- Pointwise evolution of the adversary-register family for each fixed total oracle. -/
def oracleFamilyRun
    (system : PhaseSystem Output Phase) :
    List (DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)) →
      OracleRegisterFamily
        (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace) →
        OracleRegisterFamily
          (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)
  | [], family => family
  | step :: remaining, family =>
      oracleFamilyRun system remaining
        (fun oracle =>
          step.applyRegister
            (phaseRegisterState system oracle (family oracle)))

/-- Ordinary phase-oracle execution preserves the exact purified total-oracle family form. -/
theorem standard_run_total_oracle_family
    (system : PhaseSystem Output Phase)
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)) :
    standardRun system steps (totalOracleFamilyState family) =
      totalOracleFamilyState (oracleFamilyRun system steps family) := by
  induction steps generalizing family with
  | nil =>
      rfl
  | cons step remaining inductionHypothesis =>
      rw [standardRun, oracleFamilyRun,
        phase_query_total_oracle_family_state,
        step.apply_total_oracle_family_state,
        inductionHypothesis]

/--
Finite CMS Lemma 3.3 for a complete query sequence.  Starting from a database support bound and
staying within the fixed query cap, full decompression maps the exact raw compressed-oracle run to
the ordinary phase-oracle run with the same adversary-register matrices.
-/
theorem global_decompress_raw_run_eq_standard_run
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (state : State Input Output Phase Workspace)
    (initialBound : Nat)
    (capacity : initialBound + steps.length <= queryBound)
    (bounded : BoundedState initialBound state) :
    globalDecompress
        (rawRun system queryBound
          (steps.map
            DatabaseIndependentContraction.toDatabaseBlindContraction)
          state) =
      standardRun system steps (globalDecompress state) := by
  induction steps generalizing state initialBound with
  | nil =>
      rfl
  | cons step remaining inductionHypothesis =>
      have belowCap : initialBound < queryBound := by
        simp only [List.length_cons] at capacity
        omega
      have strict : StrictSupport queryBound state :=
        bounded_state_strict_support bounded belowCap
      have queryBounded :
          BoundedState (initialBound + 1)
            (queryState system queryBound state) :=
        query_state_bounded_succ_of_bounded
          system queryBound initialBound state belowCap bounded
      have nextBounded :
          BoundedState (initialBound + 1)
            (step.apply (queryState system queryBound state)) :=
        step.toDatabaseBlindContraction.preserves_bounded queryBounded
      have remainingCapacity :
          (initialBound + 1) + remaining.length <= queryBound := by
        simp only [List.length_cons] at capacity
        omega
      have tailSimulation :
          globalDecompress
              (rawRun system queryBound
                (remaining.map
                  DatabaseIndependentContraction.toDatabaseBlindContraction)
                (step.apply (queryState system queryBound state))) =
            standardRun system remaining
              (globalDecompress
                (step.apply (queryState system queryBound state))) :=
        inductionHypothesis
          (state := step.apply (queryState system queryBound state))
          (initialBound := initialBound + 1)
          remainingCapacity nextBounded
      change
        globalDecompress
            (rawRun system queryBound
              (remaining.map
                DatabaseIndependentContraction.toDatabaseBlindContraction)
              (step.apply (queryState system queryBound state))) =
          standardRun system remaining
            (step.apply (phaseQueryState system (globalDecompress state)))
      calc
        globalDecompress
            (rawRun system queryBound
              (remaining.map
                DatabaseIndependentContraction.toDatabaseBlindContraction)
              (step.apply (queryState system queryBound state))) =
            standardRun system remaining
              (globalDecompress
                (step.apply (queryState system queryBound state))) :=
          tailSimulation
        _ =
            standardRun system remaining
              (step.apply
                (globalDecompress (queryState system queryBound state))) := by
          rw [step.global_decompress_apply_commutes]
        _ =
            standardRun system remaining
              (step.apply
                (phaseQueryState system (globalDecompress state))) := by
          rw [global_decompress_query_state_eq_phase
            system queryBound state strict]

/-- The constant-family initial state has support only on the empty compressed database. -/
theorem partial_random_oracle_empty_bounded
    (registerState :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ) :
    BoundedState 0
      (partialRandomOracleState (Output := Output) ∅ registerState) := by
  unfold BoundedState
  funext basis
  by_cases records :
      RecordsExactly (Output := Output) ∅ basis.database
  · have databaseEmpty :
        basis.database = (empty : Database Input Output) :=
      (records_exactly_empty_iff basis.database).mp records
    have sizeZero : size basis.database = 0 := by
      rw [databaseEmpty, size_empty]
    simp [project, sizeZero]
  · simp [project, partialRandomOracleState, records]

/--
Exact finite CMS Lemma 3.3 from the empty compressed database: the decompressed simulated run is
the uniform purified family of ordinary random-oracle executions, with no statistical error.
-/
theorem compressed_run_is_uniform_random_oracle_purification
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (initialRegisters :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace) → ℂ)
    (capacity : steps.length <= queryBound) :
    globalDecompress
        (rawRun system queryBound
          (steps.map
            DatabaseIndependentContraction.toDatabaseBlindContraction)
          (partialRandomOracleState (Output := Output) ∅ initialRegisters)) =
      totalOracleFamilyState
        (oracleFamilyRun system steps (fun _oracle => initialRegisters)) := by
  calc
    globalDecompress
        (rawRun system queryBound
          (steps.map
            DatabaseIndependentContraction.toDatabaseBlindContraction)
          (partialRandomOracleState (Output := Output) ∅ initialRegisters)) =
      standardRun system steps
        (globalDecompress
          (partialRandomOracleState (Output := Output) ∅ initialRegisters)) := by
      exact global_decompress_raw_run_eq_standard_run
        system queryBound steps
          (partialRandomOracleState (Output := Output) ∅ initialRegisters)
          0 (by simpa using capacity)
          (partial_random_oracle_empty_bounded initialRegisters)
    _ =
      standardRun system steps
        (partialRandomOracleState (Output := Output)
          (Finset.univ : Finset Input) initialRegisters) := by
      rw [global_decompress_empty_support]
    _ =
      standardRun system steps
        (totalOracleFamilyState (fun _oracle => initialRegisters)) := by
      rw [partial_random_oracle_state_univ_eq_family]
    _ =
      totalOracleFamilyState
        (oracleFamilyRun system steps (fun _oracle => initialRegisters)) :=
      standard_run_total_oracle_family system steps _

/-- The exact squared branch amplitude is the reciprocal number of finite oracle functions. -/
theorem normSq_uniform_oracle_amplitude :
    Complex.normSq
        (inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input) =
      1 / (Fintype.card (Input → Output) : ℝ) := by
  rw [map_pow, normSq_inverseSqrtOutputCard, Fintype.card_fun]
  simp [one_div]

/-- Born probability of an event on adversary registers after tracing out the database. -/
def registerEventProbability
    (state : State Input Output Phase Workspace)
    (event : Finset
      (RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace))) : ℝ :=
  ∑ register ∈ event,
    ∑ database : Database Input Output,
      Complex.normSq
        (state
          { input := register.1
            phase := register.2.1
            workspace := register.2.2
            database := database })

/-- Uniform random-oracle average of the same adversary-register event. -/
def uniformOracleRegisterEventProbability
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (event : Finset
      (RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace))) : ℝ :=
  (∑ oracle : Input → Output,
      ∑ register ∈ event, Complex.normSq (family oracle register)) /
    Fintype.card (Input → Output)

/-- Squared amplitude at one database is a sum over at most one matching total oracle. -/
theorem normSq_total_oracle_family_state_eq_sum
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (basis : Basis Input Output Phase Workspace) :
    Complex.normSq (totalOracleFamilyState family basis) =
      ∑ oracle : Input → Output,
        if basis.database = totalDatabase oracle then
          Complex.normSq
            (inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
              family oracle (basisRegisters basis))
        else 0 := by
  by_cases matched :
      ∃ oracle : Input → Output, basis.database = totalDatabase oracle
  · obtain ⟨oracle, databaseEqual⟩ := matched
    rcases basis with ⟨registerInput, phaseValue, workspace, database⟩
    dsimp at databaseEqual ⊢
    subst database
    rw [total_oracle_family_state_apply]
    rw [Finset.sum_eq_single oracle]
    · simp [basisRegisters]
    · intro candidate _ different
      have databasesDifferent :
          totalDatabase oracle ≠ totalDatabase candidate := by
        intro databasesEqual
        exact different (total_database_injective databasesEqual.symm)
      simp [databasesDifferent]
    · simp
  · rw [total_oracle_family_state_eq_zero_of_no_match _ basis matched]
    simp only [map_zero]
    symm
    apply Finset.sum_eq_zero
    intro oracle _
    rw [if_neg]
    exact fun databaseEqual => matched ⟨oracle, databaseEqual⟩

/-- Tracing out the database gives the exact uniform average for one register basis state. -/
theorem sum_database_normSq_total_oracle_family_state
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (register :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace)) :
    (∑ database : Database Input Output,
      Complex.normSq
        (totalOracleFamilyState family
          { input := register.1
            phase := register.2.1
            workspace := register.2.2
            database := database })) =
      (∑ oracle : Input → Output,
        Complex.normSq (family oracle register)) /
          Fintype.card (Input → Output) := by
  calc
    (∑ database : Database Input Output,
      Complex.normSq
        (totalOracleFamilyState family
          { input := register.1
            phase := register.2.1
            workspace := register.2.2
            database := database })) =
        ∑ database : Database Input Output,
          ∑ oracle : Input → Output,
            if database = totalDatabase oracle then
              Complex.normSq
                (inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
                  family oracle register)
            else 0 := by
      apply Finset.sum_congr rfl
      intro database _
      simpa [basisRegisters] using
        normSq_total_oracle_family_state_eq_sum family
          { input := register.1
            phase := register.2.1
            workspace := register.2.2
            database := database }
    _ =
        ∑ oracle : Input → Output,
          ∑ database : Database Input Output,
            if database = totalDatabase oracle then
              Complex.normSq
                (inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
                  family oracle register)
            else 0 := by
      rw [Finset.sum_comm]
    _ =
        ∑ oracle : Input → Output,
          Complex.normSq
            (inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
              family oracle register) := by
      simp
    _ =
        (1 / (Fintype.card (Input → Output) : ℝ)) *
          ∑ oracle : Input → Output,
            Complex.normSq (family oracle register) := by
      simp_rw [Complex.normSq_mul, normSq_uniform_oracle_amplitude]
      rw [Finset.mul_sum]
    _ =
        (∑ oracle : Input → Output,
          Complex.normSq (family oracle register)) /
            Fintype.card (Input → Output) := by
      simp [div_eq_mul_inv, mul_comm]

/--
CMS Lemma 3.3 in observable form: after tracing out the compressed database, every adversary
register event has exactly the same probability as uniform averaging over all finite random oracles.
-/
theorem register_event_probability_total_oracle_family
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (event : Finset
      (RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Workspace))) :
    registerEventProbability (totalOracleFamilyState family) event =
      uniformOracleRegisterEventProbability family event := by
  unfold registerEventProbability uniformOracleRegisterEventProbability
  simp_rw [sum_database_normSq_total_oracle_family_state]
  simp_rw [Finset.sum_div]
  rw [Finset.sum_comm]

end

end HegemonCrypto.CmsOracleSimulation
