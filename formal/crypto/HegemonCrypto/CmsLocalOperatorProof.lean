import HegemonCrypto.CmsFiberDecomposition
import HegemonCrypto.DatabaseFiber

/-!
# Exact CMS local-operator theorem

This module connects the exact compressed-oracle matrix kernel to the four-component database-fiber
bound.  It does not postulate a local operator norm: source amplitudes are projected onto bounded
complement databases, the finite kernel is applied, and target amplitudes are projected onto the
property.
-/

namespace HegemonCrypto.CmsLocalOperatorProof

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.DatabaseFiber
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsKernelBounds
open HegemonCrypto.CmsFiberDecomposition

noncomputable section

variable {Input Output Phase : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]

noncomputable local instance complementDecidable
    (property : Property Input Output) :
    DecidablePred (complement property) :=
  Classical.decPred _

/-- Recover a database amplitude from its canonical fiber coefficients. -/
def fiberAmplitude
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (database : Database Input Output) : ℂ :=
  match database input with
  | none => coefficient.absent database
  | some output => coefficient.recorded (erase database input) output

/-- Source state projected onto bounded complement databases. -/
def boundedComplementAmplitude
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (database : Database Input Output) : ℂ :=
  if size database <= queryBound ∧ complement property database then
    fiberAmplitude input coefficient database
  else 0

/-- One fixed-register block of `P * O * Pbar_t`. -/
def projectedQueryAmplitude
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (target : Database Input Output) : ℂ :=
  if size target <= queryBound ∧ property target then
    ∑ source : Database Input Output,
      boundedComplementAmplitude property queryBound input coefficient source *
        databaseKernel system queryBound input phaseValue source target
  else 0

/-- Squared norm of one fixed input/phase/workspace block after the projected query. -/
def projectedQueryNorm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ target : Database Input Output,
    Complex.normSq
      (projectedQueryAmplitude system phaseValue property queryBound input coefficient target)

/-- The fiber coefficients induced by an arbitrary database-amplitude function. -/
def coefficientsOfAmplitude
    (input : Input)
    (amplitude : Database Input Output -> ℂ) :
    FiberCoefficients Input Output where
  absent := amplitude
  recorded := fun base output => amplitude (insert base input output)

omit [Fintype Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] in
theorem fiberAmplitude_coefficientsOfAmplitude
    (input : Input)
    (amplitude : Database Input Output -> ℂ)
    (database : Database Input Output) :
    fiberAmplitude input (coefficientsOfAmplitude input amplitude) database =
      amplitude database := by
  unfold fiberAmplitude coefficientsOfAmplitude
  split
  next recorded =>
    rfl
  next output recorded =>
    exact congrArg amplitude
      (erase_then_insert_restores database input output recorded)

omit [Fintype Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] in
theorem fiberAmplitude_of_absent
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (database : Database Input Output)
    (absent : database input = none) :
    fiberAmplitude input coefficient database = coefficient.absent database := by
  simp [fiberAmplitude, absent]

omit [Fintype Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] in
theorem fiberAmplitude_insert_of_absent
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : Database Input Output)
    (output : Output)
    (absent : base input = none) :
    fiberAmplitude input coefficient (insert base input output) =
      coefficient.recorded base output := by
  simp [fiberAmplitude,
    insert_then_erase_restores_of_absent base input output absent]

omit [Fintype Phase] in
/-- Reindex the exact source-database sum into canonical absent-base fibers. -/
theorem projected_query_source_sum_eq_fibers
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (target : Database Input Output) :
    (∑ source : Database Input Output,
      boundedComplementAmplitude property queryBound input coefficient source *
        databaseKernel system queryBound input phaseValue source target) =
      ∑ base : AbsentDatabase (Output := Output) input,
        (boundedComplementAmplitude property queryBound input coefficient base.1 *
            databaseKernel system queryBound input phaseValue base.1 target +
          ∑ output : Output,
            boundedComplementAmplitude property queryBound input coefficient
                (insert base.1 input output) *
              databaseKernel system queryBound input phaseValue
                (insert base.1 input output) target) := by
  exact sum_database_eq_sum_fibers input
    (fun source =>
      boundedComplementAmplitude property queryBound input coefficient source *
        databaseKernel system queryBound input phaseValue source target)

/-- The exact compressed-oracle kernel in canonical database-fiber coordinates. -/
def fiberKernel
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phaseValue : Phase)
    (source target : Coordinate (Output := Output) input) : ℂ :=
  databaseKernel system queryBound input phaseValue
    ((databaseEquiv (Output := Output) input).symm source)
    ((databaseEquiv (Output := Output) input).symm target)

/-- Closed-form three-case kernel after canonical fiber reindexing. -/
def explicitFiberKernel
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phaseValue : Phase)
    (source target : Coordinate (Output := Output) input) : ℂ :=
  if target.1 = source.1 then
    match source.2, target.2 with
    | none, none =>
        if size source.1.1 = queryBound ∨ phaseValue = system.zeroPhase then 1 else 0
    | none, some targetOutput =>
        if size source.1.1 = queryBound ∨ phaseValue = system.zeroPhase then 0
        else inverseSqrtOutputCard (Output := Output) *
          system.character phaseValue targetOutput
    | some sourceOutput, none =>
        if size source.1.1 + 1 = queryBound ∨ phaseValue = system.zeroPhase then 0
        else system.character phaseValue sourceOutput *
          inverseSqrtOutputCard (Output := Output)
    | some sourceOutput, some targetOutput =>
        if size source.1.1 + 1 = queryBound ∨ phaseValue = system.zeroPhase then
          if targetOutput = sourceOutput then
            system.character phaseValue sourceOutput
          else 0
        else
          (if targetOutput = sourceOutput then
            system.character phaseValue sourceOutput
          else 0) +
          inverseOutputCard (Output := Output) *
            (1 - system.character phaseValue targetOutput -
              system.character phaseValue sourceOutput)
  else 0

set_option linter.unusedSimpArgs false
omit [Fintype Phase] in
/-- The basis kernel is exactly the closed fiber formula; no transition crosses absent bases. -/
theorem fiberKernel_eq_explicit
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phaseValue : Phase)
    (source target : Coordinate (Output := Output) input) :
    fiberKernel system queryBound input phaseValue source target =
      explicitFiberKernel system queryBound input phaseValue source target := by
  rcases source with ⟨⟨sourceBase, sourceAbsent⟩, sourceOutput⟩
  rcases target with ⟨⟨targetBase, targetAbsent⟩, targetOutput⟩
  cases sourceOutput with
  | none =>
      cases targetOutput with
      | none =>
          by_cases sameBase : targetBase = sourceBase
          · subst targetBase
            have sourceNotInserted (output : Output) :
                sourceBase ≠ insert sourceBase input output :=
              absent_ne_insert_at sourceBase sourceBase input output sourceAbsent
            simp [fiberKernel, explicitFiberKernel, databaseEquiv, databaseKernel, recordedPhase,
              sourceAbsent, sourceNotInserted]
          · have targetNotInserted (output : Output) :
                targetBase ≠ insert sourceBase input output :=
              absent_ne_insert_at targetBase sourceBase input output targetAbsent
            simp [fiberKernel, explicitFiberKernel, databaseEquiv, databaseKernel, recordedPhase,
              sourceAbsent, sameBase, targetNotInserted]
      | some targetValue =>
          by_cases sameBase : targetBase = sourceBase
          · subst targetBase
            have insertedNotSource :
                insert sourceBase input targetValue ≠ sourceBase :=
              insert_at_ne_absent sourceBase sourceBase input targetValue sourceAbsent
            simp [fiberKernel, explicitFiberKernel, databaseEquiv, databaseKernel, recordedPhase,
              sourceAbsent, insertedNotSource]
          · have insertedNotSource :
                insert targetBase input targetValue ≠ sourceBase :=
              insert_at_ne_absent targetBase sourceBase input targetValue sourceAbsent
            simp [fiberKernel, explicitFiberKernel, databaseEquiv, databaseKernel, recordedPhase,
              sourceAbsent, targetAbsent, sameBase, insertedNotSource]
  | some sourceValue =>
      cases targetOutput with
      | none =>
          by_cases sameBase : targetBase = sourceBase
          · subst targetBase
            have sourceNotInserted :
                sourceBase ≠ insert sourceBase input sourceValue :=
              absent_ne_insert_at sourceBase sourceBase input sourceValue sourceAbsent
            have sourceNotReplacement (output : Output) :
                sourceBase ≠ insert sourceBase input output :=
              absent_ne_insert_at sourceBase sourceBase input output sourceAbsent
            simp [fiberKernel, explicitFiberKernel, databaseEquiv, databaseKernel, recordedPhase,
              sourceAbsent, sourceNotInserted, sourceNotReplacement,
              size_insert_of_absent sourceBase input sourceValue sourceAbsent,
              insert_then_erase_restores_of_absent sourceBase input sourceValue sourceAbsent]
          · have targetNotInserted :
                targetBase ≠ insert sourceBase input sourceValue :=
              absent_ne_insert_at targetBase sourceBase input sourceValue targetAbsent
            have targetNotReplacement (output : Output) :
                targetBase ≠ insert sourceBase input output :=
              absent_ne_insert_at targetBase sourceBase input output targetAbsent
            simp [fiberKernel, explicitFiberKernel, databaseEquiv, databaseKernel, recordedPhase,
              sourceAbsent, sameBase, targetNotInserted, targetNotReplacement,
              size_insert_of_absent sourceBase input sourceValue sourceAbsent,
              insert_then_erase_restores_of_absent sourceBase input sourceValue sourceAbsent]
      | some targetValue =>
          by_cases sameBase : targetBase = sourceBase
          · subst targetBase
            have targetNotErased :
                insert sourceBase input targetValue ≠ sourceBase :=
              insert_at_ne_absent sourceBase sourceBase input targetValue sourceAbsent
            simp [fiberKernel, explicitFiberKernel, databaseEquiv, databaseKernel, recordedPhase,
              sourceAbsent, targetNotErased,
              size_insert_of_absent sourceBase input sourceValue sourceAbsent,
              insert_then_erase_restores_of_absent sourceBase input sourceValue sourceAbsent,
              insert_eq_insert_iff_of_absent sourceBase sourceBase input
                targetValue sourceValue sourceAbsent sourceAbsent]
          · have differentDatabases :
                insert targetBase input targetValue ≠
                  insert sourceBase input sourceValue := by
              intro equalDatabases
              exact sameBase
                (insert_eq_insert_iff_of_absent targetBase sourceBase input
                  targetValue sourceValue targetAbsent sourceAbsent |>.mp equalDatabases).1
            have targetNotErased :
                insert targetBase input targetValue ≠ sourceBase :=
              insert_at_ne_absent targetBase sourceBase input targetValue sourceAbsent
            have targetNotReplacement (output : Output) :
                insert targetBase input targetValue ≠
                  insert sourceBase input output := by
              intro equalDatabases
              exact sameBase
                (insert_eq_insert_iff_of_absent targetBase sourceBase input
                  targetValue output targetAbsent sourceAbsent |>.mp equalDatabases).1
            simp [fiberKernel, explicitFiberKernel, databaseEquiv, databaseKernel, recordedPhase,
              sourceAbsent, sameBase, differentDatabases, targetNotErased,
              targetNotReplacement,
              size_insert_of_absent sourceBase input sourceValue sourceAbsent,
              insert_then_erase_restores_of_absent sourceBase input sourceValue sourceAbsent]

set_option linter.unusedSimpArgs true

omit [Fintype Phase] in
/--
For one target coordinate, the explicit kernel has support only on source coordinates with the
same absent base.
-/
theorem sum_explicit_fiber_kernel_same_base
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phaseValue : Phase)
    (amplitude : Coordinate (Output := Output) input -> ℂ)
    (target : Coordinate (Output := Output) input) :
    (∑ source : Coordinate (Output := Output) input,
      amplitude source *
        explicitFiberKernel system queryBound input phaseValue source target) =
      amplitude (target.1, none) *
          explicitFiberKernel system queryBound input phaseValue (target.1, none) target +
        ∑ output : Output,
          amplitude (target.1, some output) *
            explicitFiberKernel system queryBound input phaseValue
              (target.1, some output) target := by
  rw [Fintype.sum_prod_type]
  rw [Finset.sum_eq_single target.1]
  · rw [Fintype.sum_option]
  · intro sourceBase _ differentBase
    have differentTarget : target.1 ≠ sourceBase := Ne.symm differentBase
    simp [explicitFiberKernel, differentTarget]
  · simp

omit [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] in
/-- Exact bounded-complement amplitude of an absent coordinate. -/
theorem bounded_complement_amplitude_absent
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : Database Input Output)
    (absent : base input = none) :
    boundedComplementAmplitude property queryBound input coefficient base =
      if size base <= queryBound ∧ complement property base then
        coefficient.absent base
      else 0 := by
  simp [boundedComplementAmplitude, fiberAmplitude, absent]

omit [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] in
/-- Exact bounded-complement amplitude of a recorded coordinate. -/
theorem bounded_complement_amplitude_recorded
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : Database Input Output)
    (output : Output)
    (absent : base input = none) :
    boundedComplementAmplitude property queryBound input coefficient
        (insert base input output) =
      if size base + 1 <= queryBound ∧
          complement property (insert base input output) then
        coefficient.recorded base output
      else 0 := by
  simp [boundedComplementAmplitude, fiberAmplitude,
    size_insert_of_absent base input output absent,
    insert_then_erase_restores_of_absent base input output absent]

omit [Fintype Input] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] in
/-- A finite insertion-answer sum is exactly the corresponding all-output indicator sum. -/
theorem sum_insertion_answers_eq_indicator
    (property : Property Input Output)
    [DecidablePred property]
    (base : Database Input Output)
    (input : Input)
    (value : Output -> ℂ) :
    (∑ output ∈ insertionAnswers property base input, value output) =
      ∑ output : Output,
        if property (insert base input output) then value output else 0 := by
  rw [insertionAnswers, Finset.sum_filter]
  apply Finset.sum_congr rfl
  intro output _
  by_cases accepted : property (insert base input output) <;> simp [accepted]

omit [Fintype Input] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] in
/-- Membership in an insertion-answer set is exactly property membership after insertion. -/
theorem mem_insertion_answers_iff
    (property : Property Input Output)
    [DecidablePred property]
    (base : Database Input Output)
    (input : Input)
    (output : Output) :
    output ∈ insertionAnswers property base input ↔
      property (insert base input output) := by
  simp [insertionAnswers]

omit [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] in
/--
Sum an indicator over canonical absent-base coordinates by summing directly over any finite set
whose members are all absent at the selected input.
-/
theorem sum_absent_coordinates_filter
    {Value : Type*}
    [AddCommMonoid Value]
    (input : Input)
    (indices : Finset (Database Input Output))
    (indicesAbsent : ∀ database ∈ indices, database input = none)
    (value : Database Input Output -> Value) :
    (∑ base : AbsentDatabase (Output := Output) input,
      if base.1 ∈ indices then value base.1 else 0) =
      ∑ database ∈ indices, value database := by
  let absentDatabases : Finset (Database Input Output) :=
    Finset.univ.filter fun database => database input = none
  calc
    (∑ base : AbsentDatabase (Output := Output) input,
      if base.1 ∈ indices then value base.1 else 0) =
        ∑ database ∈ absentDatabases,
          if database ∈ indices then value database else 0 := by
      symm
      apply Finset.sum_subtype
      intro database
      simp [absentDatabases]
    _ = ∑ database ∈ indices, value database := by
      symm
      calc
        (∑ database ∈ indices, value database) =
            ∑ database ∈ indices,
              if database ∈ indices then value database else 0 := by
          apply Finset.sum_congr rfl
          intro database membership
          simp [membership]
        _ = ∑ database ∈ absentDatabases,
              if database ∈ indices then value database else 0 := by
          apply Finset.sum_subset
          · intro database membership
            simp [absentDatabases, indicesAbsent database membership]
          · intro database _ notInIndices
            simp [notInIndices]

omit [Fintype Input] [DecidableEq Input] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] in
/-- Sum an indicator over a finite output set by summing directly over that set. -/
theorem sum_output_indicator_eq_filter
    {Value : Type*}
    [AddCommMonoid Value]
    (indices : Finset Output)
    (value : Output -> Value) :
    (∑ output : Output, if output ∈ indices then value output else 0) =
      ∑ output ∈ indices, value output := by
  calc
    (∑ output : Output, if output ∈ indices then value output else 0) =
        ∑ output ∈ Finset.univ.filter (fun output => output ∈ indices),
          value output := by
      symm
      rw [Finset.sum_filter]
    _ = ∑ output ∈ indices, value output := by
      congr 1
      ext output
      simp

omit [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] in
/-- Collapse nested absent-base and output indicators into nested finite-set sums. -/
theorem sum_absent_output_indicators
    {Value : Type*}
    [AddCommMonoid Value]
    (input : Input)
    (bases : Finset (Database Input Output))
    (basesAbsent : ∀ database ∈ bases, database input = none)
    (outputs : Database Input Output -> Finset Output)
    (value : Database Input Output -> Output -> Value) :
    (∑ base : AbsentDatabase (Output := Output) input,
      ∑ output : Output,
        if base.1 ∈ bases ∧ output ∈ outputs base.1 then
          value base.1 output
        else 0) =
      ∑ database ∈ bases,
        ∑ output ∈ outputs database, value database output := by
  calc
    (∑ base : AbsentDatabase (Output := Output) input,
      ∑ output : Output,
        if base.1 ∈ bases ∧ output ∈ outputs base.1 then
          value base.1 output
        else 0) =
        ∑ base : AbsentDatabase (Output := Output) input,
          if base.1 ∈ bases then
            ∑ output ∈ outputs base.1, value base.1 output
          else 0 := by
      apply Finset.sum_congr rfl
      intro base _
      by_cases baseMembership : base.1 ∈ bases
      · simp [baseMembership]
      · simp [baseMembership]
    _ = ∑ database ∈ bases,
          ∑ output ∈ outputs database, value database output :=
      sum_absent_coordinates_filter input bases basesAbsent
        (fun database => ∑ output ∈ outputs database, value database output)

/-- Exact `Psi_4` target amplitude on one absent base. -/
def psi4Amplitude
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : Database Input Output) : ℂ :=
  inverseSqrtOutputCard (Output := Output) *
    ∑ output ∈ insertionAnswers (complement property) base input,
      coefficient.recorded base output *
        system.character phaseValue output

/-- Exact `Xi_2` target amplitude on one recorded target. -/
def xi2Amplitude
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : Database Input Output)
    (targetOutput : Output) : ℂ :=
  inverseOutputCard (Output := Output) *
    ∑ sourceOutput ∈ insertionAnswers (complement property) base input,
      coefficient.recorded base sourceOutput *
        (1 - system.character phaseValue sourceOutput -
          system.character phaseValue targetOutput)

omit [Fintype Input] [DecidableEq Output] [Fintype Phase] [DecidableEq Phase] in
/-- The recorded-source replacement sum is exactly the `Xi_2` amplitude. -/
theorem replacement_indicator_sum_eq_xi2
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : Database Input Output)
    (targetOutput : Output) :
    (∑ sourceOutput : Output,
      (if complement property (insert base input sourceOutput) then
        coefficient.recorded base sourceOutput
      else 0) *
        (inverseOutputCard (Output := Output) *
          (1 - system.character phaseValue targetOutput -
            system.character phaseValue sourceOutput))) =
      xi2Amplitude system phaseValue property input coefficient base targetOutput := by
  unfold xi2Amplitude
  rw [sum_insertion_answers_eq_indicator]
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro sourceOutput _
  by_cases crossing :
      complement property (insert base input sourceOutput)
  · change ¬property (insert base input sourceOutput) at crossing
    simp [complement, crossing]
    ring
  · change ¬¬property (insert base input sourceOutput) at crossing
    have accepted : property (insert base input sourceOutput) :=
      Classical.not_not.mp crossing
    simp [complement, accepted]

omit [Fintype Input] [Fintype Phase] [DecidableEq Phase] in
/--
On a property target, the retained diagonal term has no complement source contribution; only the
replacement term remains.
-/
theorem crossing_recorded_sum_eq_xi2
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : Database Input Output)
    (targetOutput : Output)
    (targetAccepted : property (insert base input targetOutput)) :
    (∑ sourceOutput : Output,
      if property (insert base input sourceOutput) then 0
      else
        coefficient.recorded base sourceOutput *
          ((if targetOutput = sourceOutput then
              system.character phaseValue sourceOutput
            else 0) +
            inverseOutputCard (Output := Output) *
              (1 - system.character phaseValue targetOutput -
                system.character phaseValue sourceOutput))) =
      xi2Amplitude system phaseValue property input coefficient base targetOutput := by
  calc
    (∑ sourceOutput : Output,
      if property (insert base input sourceOutput) then 0
      else
        coefficient.recorded base sourceOutput *
          ((if targetOutput = sourceOutput then
              system.character phaseValue sourceOutput
            else 0) +
            inverseOutputCard (Output := Output) *
              (1 - system.character phaseValue targetOutput -
                system.character phaseValue sourceOutput))) =
        ∑ sourceOutput : Output,
          (if complement property (insert base input sourceOutput) then
            coefficient.recorded base sourceOutput
          else 0) *
            (inverseOutputCard (Output := Output) *
              (1 - system.character phaseValue targetOutput -
                system.character phaseValue sourceOutput)) := by
      apply Finset.sum_congr rfl
      intro sourceOutput _
      by_cases sourceAccepted : property (insert base input sourceOutput)
      · simp [complement, sourceAccepted]
      · have sourceDifferent : targetOutput ≠ sourceOutput := by
          intro sameOutput
          subst sourceOutput
          exact sourceAccepted targetAccepted
        simp [complement, sourceAccepted, sourceDifferent]
    _ = xi2Amplitude system phaseValue property input coefficient base targetOutput :=
      replacement_indicator_sum_eq_xi2
        system phaseValue property input coefficient base targetOutput

/--
The four mutually orthogonal CMS target components, written as one total amplitude on canonical
fiber coordinates.
-/
def componentFiberAmplitude
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (target : Coordinate (Output := Output) input) : ℂ :=
  match target.2 with
  | none =>
      if target.1.1 ∈ strictBases property queryBound input then
        psi4Amplitude system phaseValue property input coefficient target.1.1
      else 0
  | some targetOutput =>
      if targetOutput ∈ insertionAnswers property target.1.1 input then
        if target.1.1 ∈ edgeBases (complement property) queryBound input then
          xi3Direct system phaseValue coefficient target.1.1 targetOutput
        else if target.1.1 ∈ strictBases property queryBound input then
          xi2Amplitude system phaseValue property input coefficient
            target.1.1 targetOutput
        else if target.1.1 ∈
            strictBases (complement property) queryBound input then
          xi3Direct system phaseValue coefficient target.1.1 targetOutput +
            xi3Replacement system phaseValue property input coefficient
              target.1.1 targetOutput
        else 0
      else 0

/-- One projected-query amplitude expressed entirely in canonical fiber coordinates. -/
def projectedFiberAmplitude
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (target : Coordinate (Output := Output) input) : ℂ :=
  let targetDatabase := (databaseEquiv (Output := Output) input).symm target
  if size targetDatabase <= queryBound ∧ property targetDatabase then
    ∑ source : Coordinate (Output := Output) input,
      boundedComplementAmplitude property queryBound input coefficient
          ((databaseEquiv (Output := Output) input).symm source) *
        explicitFiberKernel system queryBound input phaseValue source target
  else 0

omit [Fintype Phase] in
/-- An absent target fiber is exactly the `Psi_4` component. -/
theorem projected_fiber_amplitude_none_eq_component
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : AbsentDatabase (Output := Output) input) :
    projectedFiberAmplitude system phaseValue property queryBound input coefficient
        (base, none) =
      componentFiberAmplitude system phaseValue property queryBound input coefficient
        (base, none) := by
  unfold projectedFiberAmplitude
  dsimp only
  rw [databaseEquiv_symm_none]
  by_cases targetAllowed : size base.1 <= queryBound ∧ property base.1
  · rw [if_pos targetAllowed]
    rw [sum_explicit_fiber_kernel_same_base]
    simp only [databaseEquiv_symm_none, databaseEquiv_symm_some]
    rw [bounded_complement_amplitude_absent
      property queryBound input coefficient base.1 base.2]
    simp_rw [bounded_complement_amplitude_recorded
      property queryBound input coefficient base.1 _ base.2]
    by_cases strictSize : size base.1 + 1 < queryBound
    · have baseStrict :
          base.1 ∈ strictBases property queryBound input :=
        (mem_strictBases_iff property queryBound input base.1).2
          ⟨base.2, targetAllowed.2, strictSize⟩
      have insertedSizeBound : size base.1 + 1 <= queryBound :=
        Nat.le_of_lt strictSize
      have insertedNotCapped : size base.1 + 1 ≠ queryBound :=
        Nat.ne_of_lt strictSize
      simp [componentFiberAmplitude, explicitFiberKernel, baseStrict,
        targetAllowed, insertedSizeBound, insertedNotCapped, nonzeroPhase,
        complement, psi4Amplitude]
      rw [sum_insertion_answers_eq_indicator]
      rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro output _
      by_cases crossing :
          complement property (insert base.1 input output)
      · change ¬property (insert base.1 input output) at crossing
        simp [complement, crossing]
        ring
      · change ¬¬property (insert base.1 input output) at crossing
        have accepted : property (insert base.1 input output) :=
          Classical.not_not.mp crossing
        simp [complement, accepted]
    · by_cases edgeSize : size base.1 + 1 = queryBound
      · have notStrict :
            base.1 ∉ strictBases property queryBound input := by
          rw [mem_strictBases_iff]
          omega
        simp [componentFiberAmplitude, explicitFiberKernel, notStrict,
          targetAllowed, edgeSize, nonzeroPhase, complement]
      · have insertedTooLarge : ¬size base.1 + 1 <= queryBound := by
          omega
        have notStrict :
            base.1 ∉ strictBases property queryBound input := by
          rw [mem_strictBases_iff]
          omega
        simp [componentFiberAmplitude, explicitFiberKernel, notStrict,
          targetAllowed, insertedTooLarge, edgeSize, nonzeroPhase, complement]
  · have notStrict :
        base.1 ∉ strictBases property queryBound input := by
      intro membership
      rw [mem_strictBases_iff] at membership
      apply targetAllowed
      exact ⟨by omega, membership.2.1⟩
    rw [if_neg targetAllowed]
    simp [componentFiberAmplitude, notStrict]

set_option linter.unusedSimpArgs false
omit [Fintype Phase] in
/-- A recorded target fiber is exactly one of `Xi_1`, `Xi_2`, or `Xi_3`. -/
theorem projected_fiber_amplitude_some_eq_component
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : AbsentDatabase (Output := Output) input)
    (targetOutput : Output) :
    projectedFiberAmplitude system phaseValue property queryBound input coefficient
        (base, some targetOutput) =
      componentFiberAmplitude system phaseValue property queryBound input coefficient
        (base, some targetOutput) := by
  unfold projectedFiberAmplitude
  dsimp only
  rw [databaseEquiv_symm_some]
  have targetSize :
      size (insert base.1 input targetOutput) = size base.1 + 1 :=
    size_insert_of_absent base.1 input targetOutput base.2
  rw [targetSize]
  by_cases targetAllowed :
      size base.1 + 1 <= queryBound ∧
        property (insert base.1 input targetOutput)
  · rw [if_pos targetAllowed]
    rw [sum_explicit_fiber_kernel_same_base]
    simp only [databaseEquiv_symm_none, databaseEquiv_symm_some]
    rw [bounded_complement_amplitude_absent
      property queryBound input coefficient base.1 base.2]
    simp_rw [bounded_complement_amplitude_recorded
      property queryBound input coefficient base.1 _ base.2]
    have targetMembership :
        targetOutput ∈ insertionAnswers property base.1 input :=
      (mem_insertion_answers_iff property base.1 input targetOutput).2
        targetAllowed.2
    by_cases edgeSize : size base.1 + 1 = queryBound
    · have baseSizeBound : size base.1 <= queryBound := by omega
      have baseNotCapped : size base.1 ≠ queryBound := by omega
      have notStrictProperty :
          base.1 ∉ strictBases property queryBound input := by
        rw [mem_strictBases_iff]
        omega
      have notStrictComplement :
          base.1 ∉ strictBases (complement property) queryBound input := by
        rw [mem_strictBases_iff]
        omega
      by_cases baseProperty : property base.1
      · have notEdgeComplement :
            base.1 ∉ edgeBases (complement property) queryBound input := by
          rw [mem_edgeBases_iff]
          simp [complement, baseProperty]
        simp [componentFiberAmplitude, explicitFiberKernel, targetMembership,
          notEdgeComplement, notStrictProperty, notStrictComplement,
          targetAllowed, targetAllowed.2, baseSizeBound, baseNotCapped,
          edgeSize, nonzeroPhase, complement, baseProperty]
      · have baseComplement : complement property base.1 := baseProperty
        have baseEdge :
            base.1 ∈ edgeBases (complement property) queryBound input :=
          (mem_edgeBases_iff (complement property) queryBound input base.1).2
            ⟨base.2, baseComplement, edgeSize⟩
        simp [componentFiberAmplitude, explicitFiberKernel, targetMembership,
          baseEdge, targetAllowed, targetAllowed.2, baseSizeBound,
          baseNotCapped, edgeSize, nonzeroPhase, complement, baseProperty,
          xi3Direct]
        ring
    · have strictSize : size base.1 + 1 < queryBound := by omega
      have baseSizeBound : size base.1 <= queryBound := by omega
      have baseNotCapped : size base.1 ≠ queryBound := by omega
      have insertedNotCapped : size base.1 + 1 ≠ queryBound := edgeSize
      have notEdgeComplement :
          base.1 ∉ edgeBases (complement property) queryBound input := by
        rw [mem_edgeBases_iff]
        omega
      by_cases baseProperty : property base.1
      · have baseStrict :
            base.1 ∈ strictBases property queryBound input :=
          (mem_strictBases_iff property queryBound input base.1).2
            ⟨base.2, baseProperty, strictSize⟩
        have notStrictComplement :
            base.1 ∉ strictBases (complement property) queryBound input := by
          rw [mem_strictBases_iff]
          simp [complement, baseProperty]
        simp [componentFiberAmplitude, explicitFiberKernel, targetMembership,
          notEdgeComplement, baseStrict, notStrictComplement,
          targetAllowed, targetAllowed.2, baseSizeBound, baseNotCapped,
          insertedNotCapped, nonzeroPhase, complement, baseProperty]
        rw [crossing_recorded_sum_eq_xi2
          system phaseValue property input coefficient base.1 targetOutput
          targetAllowed.2]
      · have baseComplement : complement property base.1 := baseProperty
        have notStrictProperty :
            base.1 ∉ strictBases property queryBound input := by
          rw [mem_strictBases_iff]
          simp [baseProperty]
        have baseStrict :
            base.1 ∈ strictBases (complement property) queryBound input :=
          (mem_strictBases_iff (complement property) queryBound input base.1).2
            ⟨base.2, baseComplement, strictSize⟩
        simp [componentFiberAmplitude, explicitFiberKernel, targetMembership,
          notEdgeComplement, notStrictProperty, baseStrict,
          targetAllowed, targetAllowed.2, baseSizeBound, baseNotCapped,
          insertedNotCapped, nonzeroPhase, complement, baseProperty,
          xi3Direct, xi3Replacement]
        rw [crossing_recorded_sum_eq_xi2
          system phaseValue property input coefficient base.1 targetOutput
          targetAllowed.2]
        unfold xi2Amplitude
        ring
  · rw [if_neg targetAllowed]
    by_cases targetProperty : property (insert base.1 input targetOutput)
    · have targetTooLarge : ¬size base.1 + 1 <= queryBound := by
        intro sizeBound
        exact targetAllowed ⟨sizeBound, targetProperty⟩
      have targetMembership :
          targetOutput ∈ insertionAnswers property base.1 input :=
        (mem_insertion_answers_iff property base.1 input targetOutput).2
          targetProperty
      have notEdgeComplement :
          base.1 ∉ edgeBases (complement property) queryBound input := by
        rw [mem_edgeBases_iff]
        omega
      have notStrictProperty :
          base.1 ∉ strictBases property queryBound input := by
        rw [mem_strictBases_iff]
        omega
      have notStrictComplement :
          base.1 ∉ strictBases (complement property) queryBound input := by
        rw [mem_strictBases_iff]
        omega
      simp [componentFiberAmplitude, targetMembership, notEdgeComplement,
        notStrictProperty, notStrictComplement]
    · have notTargetMembership :
          targetOutput ∉ insertionAnswers property base.1 input := by
        rw [mem_insertion_answers_iff]
        exact targetProperty
      simp [componentFiberAmplitude, notTargetMembership]

set_option linter.unusedSimpArgs true

omit [Fintype Phase] in
/-- Every nonzero-phase projected fiber amplitude is exactly its CMS component amplitude. -/
theorem projected_fiber_amplitude_eq_component
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (target : Coordinate (Output := Output) input) :
    projectedFiberAmplitude system phaseValue property queryBound input coefficient target =
      componentFiberAmplitude system phaseValue property queryBound input coefficient target := by
  rcases target with ⟨base, targetOutput⟩
  cases targetOutput with
  | none =>
      exact projected_fiber_amplitude_none_eq_component
        system phaseValue nonzeroPhase property queryBound input coefficient base
  | some output =>
      exact projected_fiber_amplitude_some_eq_component
        system phaseValue nonzeroPhase property queryBound input coefficient base output

/-- Squared norm of the exact four-component target amplitude. -/
def componentFiberNorm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ target : Coordinate (Output := Output) input,
    Complex.normSq
      (componentFiberAmplitude system phaseValue property queryBound input coefficient target)

/-- Squared norm of all source amplitudes in one canonical database fiber block. -/
def fiberCoefficientNorm
    (input : Input)
    (coefficient : FiberCoefficients Input Output) : ℝ :=
  ∑ base : AbsentDatabase (Output := Output) input,
    (Complex.normSq (coefficient.absent base.1) +
      ∑ output : Output, Complex.normSq (coefficient.recorded base.1 output))

omit [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] in
/-- Canonical fiber reindexing preserves the exact source squared norm. -/
theorem fiber_coefficient_norm_eq_database_norm
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    fiberCoefficientNorm input coefficient =
      ∑ database : Database Input Output,
        Complex.normSq (fiberAmplitude input coefficient database) := by
  unfold fiberCoefficientNorm
  rw [sum_database_eq_sum_fibers input
    (fun database => Complex.normSq (fiberAmplitude input coefficient database))]
  apply Finset.sum_congr rfl
  intro base _
  rw [fiberAmplitude_of_absent input coefficient base.1 base.2]
  apply congrArg (fun recordedMass =>
    Complex.normSq (coefficient.absent base.1) + recordedMass)
  apply Finset.sum_congr rfl
  intro output _
  rw [fiberAmplitude_insert_of_absent input coefficient base.1 output base.2]

omit [Fintype Phase] [DecidableEq Phase] in
/--
The recorded-target component norm is the sum of three disjoint indicators for `Xi_1`, `Xi_2`,
and `Xi_3`.
-/
theorem component_recorded_norm_decomposition
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (base : AbsentDatabase (Output := Output) input)
    (targetOutput : Output) :
    Complex.normSq
        (componentFiberAmplitude system phaseValue property queryBound input coefficient
          (base, some targetOutput)) =
      (if base.1 ∈ edgeBases (complement property) queryBound input ∧
          targetOutput ∈ insertionAnswers property base.1 input then
        Complex.normSq
          (xi3Direct system phaseValue coefficient base.1 targetOutput)
      else 0) +
      (if base.1 ∈ strictBases property queryBound input ∧
          targetOutput ∈ insertionAnswers property base.1 input then
        Complex.normSq
          (xi2Amplitude system phaseValue property input coefficient base.1 targetOutput)
      else 0) +
      (if base.1 ∈ strictBases (complement property) queryBound input ∧
          targetOutput ∈ insertionAnswers property base.1 input then
        Complex.normSq
          (xi3Direct system phaseValue coefficient base.1 targetOutput +
            xi3Replacement system phaseValue property input coefficient
              base.1 targetOutput)
      else 0) := by
  by_cases targetMembership :
      targetOutput ∈ insertionAnswers property base.1 input
  · by_cases edgeMembership :
        base.1 ∈ edgeBases (complement property) queryBound input
    · have notStrictProperty :
          base.1 ∉ strictBases property queryBound input := by
        intro strictMembership
        rw [mem_edgeBases_iff] at edgeMembership
        rw [mem_strictBases_iff] at strictMembership
        omega
      have notStrictComplement :
          base.1 ∉ strictBases (complement property) queryBound input := by
        intro strictMembership
        rw [mem_edgeBases_iff] at edgeMembership
        rw [mem_strictBases_iff] at strictMembership
        omega
      simp [componentFiberAmplitude, targetMembership, edgeMembership,
        notStrictProperty, notStrictComplement]
    · by_cases strictProperty :
          base.1 ∈ strictBases property queryBound input
      · have notStrictComplement :
            base.1 ∉ strictBases (complement property) queryBound input := by
          intro strictComplement
          rw [mem_strictBases_iff] at strictProperty strictComplement
          exact strictComplement.2.1 strictProperty.2.1
        simp [componentFiberAmplitude, targetMembership, edgeMembership,
          strictProperty, notStrictComplement]
      · by_cases strictComplement :
            base.1 ∈ strictBases (complement property) queryBound input
        · simp [componentFiberAmplitude, targetMembership, edgeMembership,
            strictProperty, strictComplement]
        · simp [componentFiberAmplitude, targetMembership, edgeMembership,
            strictProperty, strictComplement]
  · simp [componentFiberAmplitude, targetMembership]

omit [Fintype Phase] [DecidableEq Phase] in
/-- The absent-coordinate part of the component norm is exactly `Psi_4`. -/
theorem component_none_norm_eq_psi4
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    (∑ base : AbsentDatabase (Output := Output) input,
      Complex.normSq
        (componentFiberAmplitude system phaseValue property queryBound input coefficient
          (base, none))) =
      psi4Norm system phaseValue property queryBound input coefficient := by
  calc
    (∑ base : AbsentDatabase (Output := Output) input,
      Complex.normSq
        (componentFiberAmplitude system phaseValue property queryBound input coefficient
          (base, none))) =
        ∑ base : AbsentDatabase (Output := Output) input,
          if base.1 ∈ strictBases property queryBound input then
            Complex.normSq
              (psi4Amplitude system phaseValue property input coefficient base.1)
          else 0 := by
      apply Finset.sum_congr rfl
      intro base _
      by_cases membership : base.1 ∈ strictBases property queryBound input <;>
        simp [componentFiberAmplitude, membership]
    _ = ∑ database ∈ strictBases property queryBound input,
          Complex.normSq
            (psi4Amplitude system phaseValue property input coefficient database) := by
      exact sum_absent_coordinates_filter (Output := Output) input
        (strictBases property queryBound input)
        (fun database membership =>
          (mem_strictBases_iff property queryBound input database).1 membership |>.1)
        (fun database =>
          Complex.normSq
            (psi4Amplitude system phaseValue property input coefficient database))
    _ = psi4Norm system phaseValue property queryBound input coefficient := by
      rfl

omit [Fintype Phase] [DecidableEq Phase] in
/-- The cap-edge recorded-coordinate indicator sum is exactly `Xi_1`. -/
theorem component_edge_norm_eq_xi1
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    (∑ base : AbsentDatabase (Output := Output) input,
      ∑ targetOutput : Output,
        if base.1 ∈ edgeBases (complement property) queryBound input ∧
            targetOutput ∈ insertionAnswers property base.1 input then
          Complex.normSq
            (xi3Direct system phaseValue coefficient base.1 targetOutput)
        else 0) =
      xi1Norm system phaseValue property queryBound input coefficient := by
  calc
    (∑ base : AbsentDatabase (Output := Output) input,
      ∑ targetOutput : Output,
        if base.1 ∈ edgeBases (complement property) queryBound input ∧
            targetOutput ∈ insertionAnswers property base.1 input then
          Complex.normSq
            (xi3Direct system phaseValue coefficient base.1 targetOutput)
        else 0) =
        ∑ database ∈ edgeBases (complement property) queryBound input,
          ∑ targetOutput ∈ insertionAnswers property database input,
            Complex.normSq
              (xi3Direct system phaseValue coefficient database targetOutput) := by
      exact sum_absent_output_indicators (Output := Output) input
        (edgeBases (complement property) queryBound input)
        (fun database membership =>
          (mem_edgeBases_iff (complement property) queryBound input database).1
            membership |>.1)
        (fun database => insertionAnswers property database input)
        (fun database targetOutput =>
          Complex.normSq
            (xi3Direct system phaseValue coefficient database targetOutput))
    _ = xi1Norm system phaseValue property queryBound input coefficient := by
      rfl

omit [Fintype Phase] [DecidableEq Phase] in
/-- The property-base recorded-coordinate indicator sum is exactly `Xi_2`. -/
theorem component_property_base_norm_eq_xi2
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    (∑ base : AbsentDatabase (Output := Output) input,
      ∑ targetOutput : Output,
        if base.1 ∈ strictBases property queryBound input ∧
            targetOutput ∈ insertionAnswers property base.1 input then
          Complex.normSq
            (xi2Amplitude system phaseValue property input coefficient
              base.1 targetOutput)
        else 0) =
      xi2Norm system phaseValue property queryBound input coefficient := by
  calc
    (∑ base : AbsentDatabase (Output := Output) input,
      ∑ targetOutput : Output,
        if base.1 ∈ strictBases property queryBound input ∧
            targetOutput ∈ insertionAnswers property base.1 input then
          Complex.normSq
            (xi2Amplitude system phaseValue property input coefficient
              base.1 targetOutput)
        else 0) =
        ∑ database ∈ strictBases property queryBound input,
          ∑ targetOutput ∈ insertionAnswers property database input,
            Complex.normSq
              (xi2Amplitude system phaseValue property input coefficient
                database targetOutput) := by
      exact sum_absent_output_indicators (Output := Output) input
        (strictBases property queryBound input)
        (fun database membership =>
          (mem_strictBases_iff property queryBound input database).1 membership |>.1)
        (fun database => insertionAnswers property database input)
        (fun database targetOutput =>
          Complex.normSq
            (xi2Amplitude system phaseValue property input coefficient
              database targetOutput))
    _ = xi2Norm system phaseValue property queryBound input coefficient := by
      rfl

omit [Fintype Phase] [DecidableEq Phase] in
/-- The complement-base recorded-coordinate indicator sum is exactly `Xi_3`. -/
theorem component_complement_base_norm_eq_xi3
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    (∑ base : AbsentDatabase (Output := Output) input,
      ∑ targetOutput : Output,
        if base.1 ∈ strictBases (complement property) queryBound input ∧
            targetOutput ∈ insertionAnswers property base.1 input then
          Complex.normSq
            (xi3Direct system phaseValue coefficient base.1 targetOutput +
              xi3Replacement system phaseValue property input coefficient
                base.1 targetOutput)
        else 0) =
      xi3Norm system phaseValue property queryBound input coefficient := by
  calc
    (∑ base : AbsentDatabase (Output := Output) input,
      ∑ targetOutput : Output,
        if base.1 ∈ strictBases (complement property) queryBound input ∧
            targetOutput ∈ insertionAnswers property base.1 input then
          Complex.normSq
            (xi3Direct system phaseValue coefficient base.1 targetOutput +
              xi3Replacement system phaseValue property input coefficient
                base.1 targetOutput)
        else 0) =
        ∑ database ∈ strictBases (complement property) queryBound input,
          ∑ targetOutput ∈ insertionAnswers property database input,
            Complex.normSq
              (xi3Direct system phaseValue coefficient database targetOutput +
                xi3Replacement system phaseValue property input coefficient
                  database targetOutput) := by
      exact sum_absent_output_indicators (Output := Output) input
        (strictBases (complement property) queryBound input)
        (fun database membership =>
          (mem_strictBases_iff (complement property) queryBound input database).1
            membership |>.1)
        (fun database => insertionAnswers property database input)
        (fun database targetOutput =>
          Complex.normSq
            (xi3Direct system phaseValue coefficient database targetOutput +
              xi3Replacement system phaseValue property input coefficient
                database targetOutput))
    _ = xi3Norm system phaseValue property queryBound input coefficient := by
      rfl

omit [Fintype Phase] [DecidableEq Phase] in
/-- The exact component fiber norm is the sum of the four CMS orthogonal component norms. -/
theorem component_fiber_norm_eq_four_components
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    componentFiberNorm system phaseValue property queryBound input coefficient =
      psi4Norm system phaseValue property queryBound input coefficient +
        xi1Norm system phaseValue property queryBound input coefficient +
        xi2Norm system phaseValue property queryBound input coefficient +
        xi3Norm system phaseValue property queryBound input coefficient := by
  unfold componentFiberNorm
  rw [Fintype.sum_prod_type]
  simp_rw [Fintype.sum_option]
  simp_rw [component_recorded_norm_decomposition
    system phaseValue property queryBound input coefficient]
  simp_rw [Finset.sum_add_distrib]
  rw [component_none_norm_eq_psi4,
    component_edge_norm_eq_xi1,
    component_property_base_norm_eq_xi2,
    component_complement_base_norm_eq_xi3]
  ring

omit [AddCommGroup Output] [Fintype Phase] [DecidableEq Phase] in
/-- The four CMS crossing classes are disjoint subsets of the actual source-coordinate mass. -/
theorem crossing_source_mass_le_fiber_coefficient_norm
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    crossingSourceMass property queryBound input coefficient <=
      fiberCoefficientNorm input coefficient := by
  have s1Reindex :
      s1 property queryBound input coefficient =
        ∑ base : AbsentDatabase (Output := Output) input,
          ∑ output : Output,
            if base.1 ∈ strictBases property queryBound input ∧
                output ∈ insertionAnswers (complement property) base.1 input then
              Complex.normSq (coefficient.recorded base.1 output)
            else 0 := by
    symm
    simpa [s1] using
      (sum_absent_output_indicators (Output := Output) input
        (strictBases property queryBound input)
        (fun database membership =>
          (mem_strictBases_iff property queryBound input database).1 membership |>.1)
        (fun database => insertionAnswers (complement property) database input)
        (fun database output =>
          Complex.normSq (coefficient.recorded database output)))
  have s2Reindex :
      s2 property queryBound input coefficient =
        ∑ base : AbsentDatabase (Output := Output) input,
          if base.1 ∈ edgeBases (complement property) queryBound input then
            Complex.normSq (coefficient.absent base.1)
          else 0 := by
    symm
    simpa [s2] using
      (sum_absent_coordinates_filter (Output := Output) input
        (edgeBases (complement property) queryBound input)
        (fun database membership =>
          (mem_edgeBases_iff (complement property) queryBound input database).1
            membership |>.1)
        (fun database => Complex.normSq (coefficient.absent database)))
  have s3Reindex :
      s3 property queryBound input coefficient =
        ∑ base : AbsentDatabase (Output := Output) input,
          if base.1 ∈ strictBases (complement property) queryBound input then
            Complex.normSq (coefficient.absent base.1)
          else 0 := by
    symm
    simpa [s3] using
      (sum_absent_coordinates_filter (Output := Output) input
        (strictBases (complement property) queryBound input)
        (fun database membership =>
          (mem_strictBases_iff (complement property) queryBound input database).1
            membership |>.1)
        (fun database => Complex.normSq (coefficient.absent database)))
  have s4Reindex :
      s4 property queryBound input coefficient =
        ∑ base : AbsentDatabase (Output := Output) input,
          ∑ output : Output,
            if base.1 ∈ strictBases (complement property) queryBound input ∧
                output ∈ insertionAnswers (complement property) base.1 input then
              Complex.normSq (coefficient.recorded base.1 output)
            else 0 := by
    symm
    simpa [s4] using
      (sum_absent_output_indicators (Output := Output) input
        (strictBases (complement property) queryBound input)
        (fun database membership =>
          (mem_strictBases_iff (complement property) queryBound input database).1
            membership |>.1)
        (fun database => insertionAnswers (complement property) database input)
        (fun database output =>
          Complex.normSq (coefficient.recorded database output)))
  unfold crossingSourceMass fiberCoefficientNorm
  rw [s1Reindex, s2Reindex, s3Reindex, s4Reindex]
  repeat rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro base _
  have selectedRecordedLe :
      (∑ output ∈ insertionAnswers (complement property) base.1 input,
        Complex.normSq (coefficient.recorded base.1 output)) <=
        ∑ output : Output,
          Complex.normSq (coefficient.recorded base.1 output) := by
    exact Finset.sum_le_sum_of_subset_of_nonneg
      (Finset.subset_univ (insertionAnswers (complement property) base.1 input))
      (fun output _ _ =>
        Complex.normSq_nonneg (coefficient.recorded base.1 output))
  by_cases edgeMembership :
      base.1 ∈ edgeBases (complement property) queryBound input
  · have notStrictProperty :
        base.1 ∉ strictBases property queryBound input := by
      intro strictMembership
      rw [mem_edgeBases_iff] at edgeMembership
      rw [mem_strictBases_iff] at strictMembership
      omega
    have notStrictComplement :
        base.1 ∉ strictBases (complement property) queryBound input := by
      intro strictMembership
      rw [mem_edgeBases_iff] at edgeMembership
      rw [mem_strictBases_iff] at strictMembership
      omega
    simp [edgeMembership, notStrictProperty, notStrictComplement]
    exact Finset.sum_nonneg fun output _ =>
      Complex.normSq_nonneg (coefficient.recorded base.1 output)
  · by_cases strictComplement :
        base.1 ∈ strictBases (complement property) queryBound input
    · have notStrictProperty :
          base.1 ∉ strictBases property queryBound input := by
        intro strictProperty
        rw [mem_strictBases_iff] at strictComplement strictProperty
        exact strictComplement.2.1 strictProperty.2.1
      simp [edgeMembership, strictComplement, notStrictProperty]
      exact selectedRecordedLe
    · by_cases strictProperty :
          base.1 ∈ strictBases property queryBound input
      · simp [edgeMembership, strictComplement, strictProperty]
        exact selectedRecordedLe.trans
          (le_add_of_nonneg_left
            (Complex.normSq_nonneg (coefficient.absent base.1)))
      · simp [edgeMembership, strictComplement, strictProperty]
        exact add_nonneg
          (Complex.normSq_nonneg (coefficient.absent base.1))
          (Finset.sum_nonneg fun output _ =>
            Complex.normSq_nonneg (coefficient.recorded base.1 output))

omit [Fintype Phase] in
/-- Reindexing into fibers preserves each exact projected-query amplitude. -/
theorem projected_query_amplitude_eq_fiber
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (target : Coordinate (Output := Output) input) :
    projectedQueryAmplitude system phaseValue property queryBound input coefficient
        ((databaseEquiv (Output := Output) input).symm target) =
      projectedFiberAmplitude system phaseValue property queryBound input coefficient target := by
  unfold projectedQueryAmplitude projectedFiberAmplitude
  dsimp only
  split_ifs with targetAllowed
  · rw [← (databaseEquiv (Output := Output) input).symm.sum_comp
      (fun source =>
        boundedComplementAmplitude property queryBound input coefficient source *
          databaseKernel system queryBound input phaseValue source
            ((databaseEquiv (Output := Output) input).symm target))]
    apply Finset.sum_congr rfl
    intro source _
    rw [← fiberKernel_eq_explicit system queryBound input phaseValue source target]
    rfl
  · rfl

omit [Fintype Phase] in
/-- The projected squared norm is unchanged by canonical database-fiber reindexing. -/
theorem projected_query_norm_eq_fibers
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    projectedQueryNorm system phaseValue property queryBound input coefficient =
      ∑ target : Coordinate (Output := Output) input,
        Complex.normSq
          (projectedFiberAmplitude system phaseValue property queryBound input coefficient target) := by
  unfold projectedQueryNorm
  rw [← (databaseEquiv (Output := Output) input).symm.sum_comp
    (fun target =>
      Complex.normSq
        (projectedQueryAmplitude system phaseValue property queryBound input coefficient target))]
  apply Finset.sum_congr rfl
  intro target _
  rw [projected_query_amplitude_eq_fiber]

omit [Fintype Phase] in
/-- The exact projected query norm equals the exact four-component fiber norm. -/
theorem projected_query_norm_eq_component_fiber_norm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    projectedQueryNorm system phaseValue property queryBound input coefficient =
      componentFiberNorm system phaseValue property queryBound input coefficient := by
  rw [projected_query_norm_eq_fibers]
  unfold componentFiberNorm
  apply Finset.sum_congr rfl
  intro target _
  rw [projected_fiber_amplitude_eq_component
    system phaseValue nonzeroPhase property queryBound input coefficient target]

omit [Fintype Phase] in
/--
Concrete CMS Lemma 5.10 for one fixed input/phase/workspace block of the exact compressed oracle.
-/
theorem projected_query_norm_le_six_instability
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound)
    (normalized :
      crossingSourceMass property queryBound input coefficient <= 1) :
    projectedQueryNorm system phaseValue property queryBound input coefficient <=
      6 * bound := by
  rw [projected_query_norm_eq_component_fiber_norm
    system phaseValue nonzeroPhase property queryBound input coefficient]
  rw [component_fiber_norm_eq_four_components]
  exact four_component_local_bound
    system phaseValue nonzeroPhase property queryBound input coefficient
      instability normalized

omit [Fintype Phase] in
/-- Homogeneous concrete local-operator bound before source-mass normalization. -/
theorem projected_query_norm_le_scaled_instability
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound) :
    projectedQueryNorm system phaseValue property queryBound input coefficient <=
      6 * bound * crossingSourceMass property queryBound input coefficient := by
  rw [projected_query_norm_eq_component_fiber_norm
    system phaseValue nonzeroPhase property queryBound input coefficient]
  rw [component_fiber_norm_eq_four_components]
  exact four_component_local_bound_scaled
    system phaseValue nonzeroPhase property queryBound input coefficient instability

omit [Fintype Phase] in
/-- Exact local-operator bound in terms of the full source block norm. -/
theorem projected_query_norm_le_source_norm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound) :
    projectedQueryNorm system phaseValue property queryBound input coefficient <=
      6 * bound * fiberCoefficientNorm input coefficient := by
  calc
    projectedQueryNorm system phaseValue property queryBound input coefficient <=
        6 * bound * crossingSourceMass property queryBound input coefficient :=
      projected_query_norm_le_scaled_instability
        system phaseValue nonzeroPhase property queryBound input coefficient instability
    _ <= 6 * bound * fiberCoefficientNorm input coefficient := by
      exact mul_le_mul_of_nonneg_left
        (crossing_source_mass_le_fiber_coefficient_norm
          property queryBound input coefficient)
        (mul_nonneg (by norm_num) instability.1.1)

omit [Fintype Phase] in
/-- The trivial Fourier phase cannot cross from a property complement into the property. -/
theorem projected_query_amplitude_zero_phase
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output)
    (target : Database Input Output) :
    projectedQueryAmplitude system system.zeroPhase property queryBound input coefficient target =
      0 := by
  unfold projectedQueryAmplitude
  by_cases targetAllowed : size target <= queryBound ∧ property target
  · rw [if_pos targetAllowed]
    simp_rw [database_kernel_of_capped_or_zero
      system queryBound input system.zeroPhase _ _ (Or.inr rfl)]
    rw [Finset.sum_eq_single target]
    · simp [boundedComplementAmplitude, targetAllowed, complement]
    · intro source _ different
      have targetDifferent : target ≠ source := Ne.symm different
      simp [targetDifferent]
    · simp
  · rw [if_neg targetAllowed]

omit [Fintype Phase] in
/-- The trivial Fourier phase contributes zero projected squared norm. -/
theorem projected_query_norm_zero_phase
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (input : Input)
    (coefficient : FiberCoefficients Input Output) :
    projectedQueryNorm system system.zeroPhase property queryBound input coefficient = 0 := by
  unfold projectedQueryNorm
  apply Finset.sum_eq_zero
  intro target _
  rw [projected_query_amplitude_zero_phase
    system property queryBound input coefficient target]
  exact Complex.normSq_zero

end

end HegemonCrypto.CmsLocalOperatorProof
