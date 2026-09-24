import HegemonCrypto.SmallWoodV8Smz9CurrentPrivacyGame
import HegemonCrypto.SmallWoodV8Smz9SemanticDenseRange
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityGenerated

/-! Public specialization of the exact HGV8RP03 CSR program. Coefficients,
targets, row retention and gamma positions are derived from the public statement;
none is supplied as a witness-dependent adapter or relation-validity receipt. -/

namespace HegemonCrypto.SmallWood.V8Smz9CurrentPublicContext

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9RelationProgramComponentsGenerated V8Smz9ProgramCanonicalityGenerated
open V8Smz9SemanticBinding V8Smz9SemanticDenseRange
open V8Smz9EagerPrivacy V8Smz9CurrentProgramPiop V8Smz9CurrentProgramOpeningBinding
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9SingleProofPrivacy V8Smz9HonestHybrid
open V8Smz9JointAlgebraicLaw V8Smz9EagerSimulator V8Smz9EagerOracleGame
open V8Smz9PrivacyGameComposition V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option backward.isDefEq.respectTransparency false

abbrev PackedIndex := Fin 43904

def packedFieldValues (witness : List Nat) : PackedIndex → Goldilocks :=
  fun index => (witness.getD index.val 0 : Goldilocks)

def packingValues (witness : List Nat) : WitnessPackingValues Goldilocks :=
  fun row lane => packedFieldValues witness (finProdFinEquiv (row, lane))

/-- Duplicate coordinates add in the field; zero coefficients vanish. -/
def denseCoefficient (values : List Nat) (terms : List (Nat × Nat))
    (index : PackedIndex) : Goldilocks :=
  (terms.map fun term => if term.1 = index.val then
    (values.getD term.2 0 : Goldilocks) else 0).sum

theorem dense_coefficient_dot (values witness : List Nat) (terms : List (Nat × Nat))
    (bounded : ∀ term, term ∈ terms → term.1 < 43904) :
    (∑ index : PackedIndex, denseCoefficient values terms index * packedFieldValues witness index) =
      csrFieldSum values witness terms := by
  induction terms with
  | nil => simp [denseCoefficient, csrFieldSum]
  | cons term tail ih =>
      have bound := bounded term (by simp)
      have tailBound : ∀ next, next ∈ tail → next.1 < 43904 := by
        intro next member
        exact bounded next (by simp [member])
      have selector : ∀ index : PackedIndex, (term.1 = index.val) ↔ index = ⟨term.1, bound⟩ := by
        intro index
        simp [Fin.ext_iff, eq_comm]
      simp only [denseCoefficient, List.map_cons, List.sum_cons, add_mul, Finset.sum_add_distrib]
      change (∑ index : PackedIndex, (if term.1 = index.val then
        (values.getD term.2 0 : Goldilocks) else 0) * packedFieldValues witness index) +
        (∑ index : PackedIndex, denseCoefficient values tail index * packedFieldValues witness index) = _
      rw [ih tailBound]
      simp only [selector, ite_mul, zero_mul]
      simp [csrFieldSum, packedFieldValues]

theorem exact_attempt_coordinates_bounded (attempt : CsrExecutableAttempt)
    (member : attempt ∈ exactCsrAttempts) :
    ∀ term, term ∈ attempt.terms → term.1 < 43904 := by
  obtain ⟨index, found⟩ := List.mem_iff_getElem?.mp member
  have canonical := hgv8rp03_program_is_canonical
  have attempts := canonical.2.2.2.2.2.2.2.2.2.2.2.1
  have this := (attempts index attempt found).1.2.2.2.1
  intro term inTerms
  exact (this term inTerms).1

/-- The entire selector DAG runs on the public statement, with no witness rows. -/
def publicExpressionValues (publicValues : List Nat) : List Nat :=
  (evalExpressionNodes publicValues [] exactCsrExpressions).getD []

theorem public_expression_values_of_success (publicValues values : List Nat)
    (evaluated : evalExpressionNodes publicValues [] exactCsrExpressions = some values) :
    publicExpressionValues publicValues = values := by
  simp only [publicExpressionValues, evaluated, Option.getD_some]

def rawCoefficient (publicValues : List Nat) (attempt : CsrExecutableAttempt) :
    PackedIndex → Goldilocks :=
  denseCoefficient (publicExpressionValues publicValues) attempt.terms

def rowTarget (publicValues : List Nat) (attempt : CsrExecutableAttempt) : Goldilocks :=
  (publicExpressionValues publicValues).getD attempt.targetRoot 0

def rowEmpty (publicValues : List Nat) (attempt : CsrExecutableAttempt) : Prop :=
  ∀ index, rawCoefficient publicValues attempt index = 0

def rowEmitted (publicValues : List Nat) (attempt : CsrExecutableAttempt) : Prop :=
  ¬ (rowEmpty publicValues attempt ∧ rowTarget publicValues attempt = 0)

/-- Source fallback for an impossible public-only row: tail_source_index(120). -/
def normalizedCoefficient (publicValues : List Nat) (attempt : CsrExecutableAttempt)
    (index : PackedIndex) : Goldilocks :=
  if rowEmpty publicValues attempt then
    if index.val = 41528 then 1 else 0
  else rawCoefficient publicValues attempt index

def retainedAttempts (publicValues : List Nat) : List CsrExecutableAttempt :=
  exactCsrAttempts.filter (fun attempt => decide (rowEmitted publicValues attempt))

/-- Rust derive_gamma_prime takes the maximum of nonlinear and retained-linear
constraint counts; 830 alone is not the full current gamma width. -/
def batchingWidth (publicValues : List Nat) : Nat :=
  max 830 (retainedAttempts publicValues).length

def batchingSampleCount (publicValues : List Nat) : Nat := 5 * batchingWidth publicValues

def gammaFromSamples (publicValues : List Nat)
    (samples : Fin (batchingSampleCount publicValues) → Goldilocks) : Fin 5 → Nat → Goldilocks :=
  fun polynomial coordinate => if bound : coordinate < batchingWidth publicValues then
    samples (finProdFinEquiv (polynomial, ⟨coordinate, bound⟩)) else 0

theorem nonlinear_gamma_sample_is_present (publicValues : List Nat)
    (samples : Fin (batchingSampleCount publicValues) → Goldilocks)
    (polynomial : Fin 5) (root : Fin 830) :
    gammaFromSamples publicValues samples polynomial root.val =
      samples (finProdFinEquiv (polynomial,
        ⟨root.val, root.isLt.trans_le (Nat.le_max_left _ _)⟩)) := by
  have bound : root.val < batchingWidth publicValues := root.isLt.trans_le (Nat.le_max_left _ _)
  simp only [gammaFromSamples, dif_pos bound]

theorem linear_gamma_sample_is_present (publicValues : List Nat)
    (samples : Fin (batchingSampleCount publicValues) → Goldilocks)
    (polynomial : Fin 5) (row : Fin (retainedAttempts publicValues).length) :
    gammaFromSamples publicValues samples polynomial row.val =
      samples (finProdFinEquiv (polynomial,
        ⟨row.val, row.isLt.trans_le (Nat.le_max_right _ _)⟩)) := by
  have bound : row.val < batchingWidth publicValues := row.isLt.trans_le (Nat.le_max_right _ _)
  simp only [gammaFromSamples, dif_pos bound]

theorem batching_sample_count_le (publicValues : List Nat) :
    batchingSampleCount publicValues ≤ 103025 := by
  have retainedBound : (retainedAttempts publicValues).length ≤ 20605 := by
    have bound := List.length_filter_le
      (fun attempt => decide (rowEmitted publicValues attempt)) exactCsrAttempts
    have count : exactCsrAttempts.length = 20605 := exact_program_component_inventory.2.2.2.2.2.2.2.2.2
    simpa only [retainedAttempts, count] using bound
  have width : batchingWidth publicValues ≤ 20605 := max_le (by decide) retainedBound
  exact Nat.mul_le_mul_left 5 width

theorem retained_attempt_is_exact (publicValues : List Nat)
    (index : Fin (retainedAttempts publicValues).length) :
    (retainedAttempts publicValues)[index.val] ∈ exactCsrAttempts ∧
      rowEmitted publicValues (retainedAttempts publicValues)[index.val] := by
  have member := List.getElem_mem (l := retainedAttempts publicValues) index.isLt
  simpa only [retainedAttempts, List.mem_filter, decide_eq_true_eq] using member

theorem accepted_raw_row_equality {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness)
    (attempt : CsrExecutableAttempt) (member : attempt ∈ exactCsrAttempts) :
    (∑ index : PackedIndex, rawCoefficient publicValues attempt index *
      packedFieldValues witness index) = rowTarget publicValues attempt := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have publicEq := public_expression_values_of_success publicValues values evaluated
  simpa only [rawCoefficient, rowTarget, publicEq,
    dense_coefficient_dot values witness attempt.terms (exact_attempt_coordinates_bounded attempt member)]
    using accepted_csr_attempt_field_equality (attempts attempt member)

/-- An accepted statement cannot emit the impossible-empty fallback branch. -/
theorem accepted_retained_row_nonempty {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness)
    (index : Fin (retainedAttempts publicValues).length) :
    ¬ rowEmpty publicValues (retainedAttempts publicValues)[index.val] := by
  obtain ⟨member, emitted⟩ := retained_attempt_is_exact publicValues index
  intro empty
  have equation := accepted_raw_row_equality accepted _ member
  have zeroLhs : (∑ coordinate : PackedIndex,
      rawCoefficient publicValues (retainedAttempts publicValues)[index.val] coordinate *
        packedFieldValues witness coordinate) = 0 := by
    apply Finset.sum_eq_zero
    intro coordinate _
    rw [empty coordinate, zero_mul]
  have zeroTarget : rowTarget publicValues (retainedAttempts publicValues)[index.val] = 0 :=
    equation.symm.trans zeroLhs
  exact emitted ⟨empty, zeroTarget⟩

theorem accepted_normalized_row_equality {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness)
    (index : Fin (retainedAttempts publicValues).length) :
    (∑ coordinate : PackedIndex, normalizedCoefficient publicValues
      (retainedAttempts publicValues)[index.val] coordinate * packedFieldValues witness coordinate) =
      rowTarget publicValues (retainedAttempts publicValues)[index.val] := by
  simp only [normalizedCoefficient, if_neg (accepted_retained_row_nonempty accepted index)]
  exact accepted_raw_row_equality accepted _ (retained_attempt_is_exact publicValues index).1

/-- One public gamma stream; CSR uses retained-row positions, not global attempt numbers. -/
def publicParameters (publicValues : List Nat) (gamma : Fin 5 → Nat → Goldilocks) :
    CurrentPublicParameters where
  publicValues := publicValues
  nonlinearGamma := fun polynomial root => gamma polynomial root.val
  linearWeights := fun polynomial row lane =>
    ∑ index : Fin (retainedAttempts publicValues).length,
      gamma polynomial index.val * normalizedCoefficient publicValues
        (retainedAttempts publicValues)[index.val] (finProdFinEquiv (row, lane))
  linearTargets := fun polynomial =>
    ∑ index : Fin (retainedAttempts publicValues).length,
      gamma polynomial index.val * rowTarget publicValues (retainedAttempts publicValues)[index.val]

theorem accepted_public_linear_batch {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness)
    (gamma : Fin 5 → Nat → Goldilocks) (polynomial : Fin 5) :
    (∑ row : Fin 686, ∑ lane : Fin 64,
      (publicParameters publicValues gamma).linearWeights polynomial row lane * packingValues witness row lane) =
      (publicParameters publicValues gamma).linearTargets polynomial := by
  have reindex (f : PackedIndex → Goldilocks) :
      (∑ row : Fin 686, ∑ lane : Fin 64, f (finProdFinEquiv (row, lane))) = ∑ index, f index := by
    calc
      _ = ∑ pair : Fin 686 × Fin 64, f (finProdFinEquiv pair) :=
        (Fintype.sum_prod_type _).symm
      _ = _ := Equiv.sum_comp (finProdFinEquiv : Fin 686 × Fin 64 ≃ PackedIndex) f
  change (∑ row : Fin 686, ∑ lane : Fin 64,
    (∑ index : Fin (retainedAttempts publicValues).length,
      gamma polynomial index.val * normalizedCoefficient publicValues
        (retainedAttempts publicValues)[index.val] (finProdFinEquiv (row, lane))) *
      packedFieldValues witness (finProdFinEquiv (row, lane))) = _
  rw [reindex (fun coordinate =>
    (∑ index : Fin (retainedAttempts publicValues).length,
      gamma polynomial index.val * normalizedCoefficient publicValues
        (retainedAttempts publicValues)[index.val] coordinate) * packedFieldValues witness coordinate)]
  simp only [Finset.sum_mul]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro index _
  simp only [mul_assoc, ← Finset.mul_sum]
  rw [accepted_normalized_row_equality accepted index]

theorem accepted_public_expression_evaluation_succeeds {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness) :
    evalExpressionNodes publicValues [] exactCsrExpressions =
      some (publicExpressionValues publicValues) := by
  obtain ⟨values, evaluated, _⟩ := accepted.2.2.2
  rw [public_expression_values_of_success publicValues values evaluated]
  exact evaluated

theorem accepted_public_trace_length {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness) :
    (publicExpressionValues publicValues).length = exactCsrExpressions.length := by
  obtain ⟨suffix, result, length, _⟩ := eval_go_equations publicValues [] []
    (publicExpressionValues publicValues) exactCsrExpressions
    (by simpa only [List.length_nil, Nat.zero_add] using exact_csr_is_canonical_with_rows.1)
    (accepted_public_expression_evaluation_succeeds accepted)
  simpa only [List.nil_append, result] using length

/-- Every source coefficient and target lookup is genuinely in the evaluated
public trace. The getD notation is not permission to supply missing roots. -/
theorem accepted_public_roots_resolve {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness)
    (attempt : CsrExecutableAttempt) (member : attempt ∈ exactCsrAttempts) :
    (∀ term, term ∈ attempt.terms → term.2 < (publicExpressionValues publicValues).length) ∧
      attempt.targetRoot < (publicExpressionValues publicValues).length := by
  obtain ⟨index, found⟩ := List.mem_iff_getElem?.mp member
  have attempts := hgv8rp03_program_is_canonical.2.2.2.2.2.2.2.2.2.2.2.1
  have canonical := (attempts index attempt found).1
  rw [accepted_public_trace_length accepted]
  exact ⟨fun term inTerms => (canonical.2.2.2.1 term inTerms).2, canonical.2.2.2.2⟩

/-- All 565 public selector nodes, including inverse, equality choice and bit
operations, satisfy their actual interpreter equations. -/
theorem accepted_public_selector_equations {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness)
    (index : Nat) (expression : FieldExpression)
    (found : exactCsrExpressions[index]? = some expression) :
    (publicExpressionValues publicValues)[index]? =
      evalFieldExpression publicValues [] (publicExpressionValues publicValues) expression :=
  evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows
    (accepted_public_expression_evaluation_succeeds accepted) found

/-- Natural zero and field zero coincide for every specialized target. -/
theorem accepted_public_target_zero_iff {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness)
    (attempt : CsrExecutableAttempt) :
    rowTarget publicValues attempt = 0 ↔
      (publicExpressionValues publicValues).getD attempt.targetRoot 0 = 0 := by
  have canonical := V8Smz9ProgramPolynomials.source_go_canonical publicValues [] []
    (publicExpressionValues publicValues) exactCsrExpressions (by simp)
    (accepted_public_expression_evaluation_succeeds accepted)
  have bound := V8Smz9ProgramPolynomials.canonical_getD _ canonical attempt.targetRoot
  have repr : (rowTarget publicValues attempt).val =
      (publicExpressionValues publicValues).getD attempt.targetRoot 0 :=
    ZMod.val_natCast_of_lt bound
  constructor
  · intro zero
    simpa only [zero, ZMod.val_zero] using repr.symm
  · intro zero
    simp only [rowTarget, zero, Nat.cast_zero]

theorem retained_attempts_preserve_source_order (publicValues : List Nat) :
    (retainedAttempts publicValues).Sublist exactCsrAttempts :=
  List.filter_sublist

/-- Exact row-major 686 by 64 conversion, including canonical natural representatives. -/
theorem source_packing_rows_match_packed_lane {witness : List Nat}
    (canonical : CanonicalPackedWitness witness) (lane : Fin 64) :
    sourcePackingRows (packingValues witness) lane = packedWitnessLaneRows witness lane.val := by
  apply List.ext_getElem
  · simp only [sourcePackingRows, List.length_ofFn, packedWitnessLaneRows,
      List.length_map, List.length_range, relationRowCount]
  · intro row leftBound rightBound
    simp only [sourcePackingRows, List.getElem_ofFn, packingValues, packedFieldValues,
      packedWitnessLaneRows, List.getElem_map, List.getElem_range]
    change ((witness.getD (lane.val + 64 * row) 0 : Goldilocks).val) =
      witness.getD (row * 64 + lane.val) 0
    simpa only [Nat.add_comm, Nat.mul_comm] using ZMod.val_natCast_of_lt
      (V8Smz9ProgramPolynomials.canonical_getD witness canonical.2 (lane.val + 64 * row))

theorem accepted_public_nonlinear_lanes {publicValues witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicValues witness)
    (gamma : Fin 5 → Nat → Goldilocks) :
    ∀ lane, hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
      (publicParameters publicValues gamma).publicValues
      (sourcePackingRows (packingValues witness) lane) := by
  intro lane
  rw [source_packing_rows_match_packed_lane accepted.2.1 lane]
  exact accepted.2.2.1 lane.val lane.isLt

/-- Public encoding is the parameter constructor, not an optional external binding premise. -/
def statementParameters (statement : V8PublicStatement) (gamma : Fin 5 → Nat → Goldilocks) :
    CurrentPublicParameters := publicParameters (encodePublicStatement statement) gamma

/-- Serialized emission 0 is Rust's Always family rule. This is a public guard,
not a witness or compiler-success assumption. -/
def alwaysRowsEmitted (publicValues : List Nat) : Prop :=
  ∀ attempt, attempt ∈ exactCsrAttempts → attempt.emission = 0 → rowEmitted publicValues attempt

/-- Public expression failure and the source Always-family guard are retained.
The exact fixed metadata and finite coordinate/root bounds are separately checked. -/
def compilePublicParameters (publicValues : List Nat) (gamma : Fin 5 → Nat → Goldilocks) :
    Option CurrentPublicParameters :=
  match evalExpressionNodes publicValues [] exactCsrExpressions with
  | none => none
  | some _ => if alwaysRowsEmitted publicValues then some (publicParameters publicValues gamma) else none

def compileStatementParameters (statement : V8PublicStatement)
    (gamma : Fin 5 → Nat → Goldilocks) : Option CurrentPublicParameters :=
  compilePublicParameters (encodePublicStatement statement) gamma

theorem compiled_public_parameters_are_generated {publicValues : List Nat}
    {gamma : Fin 5 → Nat → Goldilocks} {parameters : CurrentPublicParameters}
    (compiled : compilePublicParameters publicValues gamma = some parameters) :
    parameters = publicParameters publicValues gamma ∧ alwaysRowsEmitted publicValues := by
  unfold compilePublicParameters at compiled
  cases evaluated : evalExpressionNodes publicValues [] exactCsrExpressions with
  | none => simp only [evaluated] at compiled; contradiction
  | some values =>
      simp only [evaluated] at compiled
      split at compiled
      next guard => exact ⟨Option.some.inj compiled.symm, guard⟩
      next guard => contradiction

theorem public_expression_failure_preserves_abort (publicValues : List Nat)
    (gamma : Fin 5 → Nat → Goldilocks)
    (failed : evalExpressionNodes publicValues [] exactCsrExpressions = none) :
    compilePublicParameters publicValues gamma = none := by
  simp only [compilePublicParameters, failed]

theorem always_family_failure_preserves_abort (publicValues : List Nat)
    (gamma : Fin 5 → Nat → Goldilocks) (failed : ¬ alwaysRowsEmitted publicValues) :
    compilePublicParameters publicValues gamma = none := by
  unfold compilePublicParameters
  cases evalExpressionNodes publicValues [] exactCsrExpressions <;>
    simp only [if_neg failed]

/-- An identical public abort outcome on both sides incurs no loss. There is no
conditioning on compiler success and no resampling after failure. -/
theorem public_compiler_abort_preserves_bound
    (statement : V8PublicStatement) (gamma : Fin 5 → Nat → Goldilocks)
    (source reference : CurrentPublicParameters → ℝ) (failure loss : ℝ)
    (lossNonnegative : 0 ≤ loss)
    (bounded : |source (statementParameters statement gamma) -
      reference (statementParameters statement gamma)| ≤ loss) :
    |(compileStatementParameters statement gamma).elim failure source -
      (compileStatementParameters statement gamma).elim failure reference| ≤ loss := by
  cases compiled : compileStatementParameters statement gamma with
  | none => simpa only [Option.elim_none, sub_self, abs_zero] using lossNonnegative
  | some parameters =>
      have generated := (compiled_public_parameters_are_generated compiled).1
      simpa only [Option.elim_some, generated, statementParameters] using bounded

/-- All algebraic admission premises of CurrentPrivacyGame follow from one exact
packed-program acceptance on an admitted, encoded public statement. -/
theorem canonical_statement_supplies_current_game_algebra
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (gamma : Fin 5 → Nat → Goldilocks) :
    (statementParameters statement gamma).publicValues = publicValues ∧
    (∀ lane, hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
      (statementParameters statement gamma).publicValues
      (sourcePackingRows (packingValues witness) lane)) ∧
    (∀ polynomial, (∑ row : Fin 686, ∑ lane : Fin 64,
      (statementParameters statement gamma).linearWeights polynomial row lane *
        packingValues witness row lane) =
      (statementParameters statement gamma).linearTargets polynomial) := by
  have encoding := domain.1
  change (encodePublicStatement statement = publicValues) ∧ _
  refine ⟨encoding, ?_, ?_⟩
  · simpa only [statementParameters, encoding] using accepted_public_nonlinear_lanes domain.2.2 gamma
  · intro polynomial
    simpa only [statementParameters, encoding] using
      accepted_public_linear_batch domain.2.2 gamma polynomial

section PhysicalGame

variable {Other Output Workspace : Type*} [Fintype Other] [DecidableEq Other]
variable [Fintype Output] [DecidableEq Output] [AddGroup Output]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Exact encoded statement and packed acceptance now replace both independent
algebraic-validity premises. The public reference contains no packed witness. -/
theorem canonical_statement_current_privacy_bound
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : Fin 5 → Nat → Goldilocks) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (fallback : LvcsAdmissibleTargets points)
    (choose : IndexChooser points) (salt : SaltBytes) (labels : LeafIndex → Output)
    (continuation : CurrentContinuationFactory (Other := Other) (Output := Output) (Workspace := Workspace) points)
    (queryBound : ℕ) (queriesBounded : ∀ context visible,
      (continuation context visible).queries ≤ queryBound) :
    |currentFullSourceAcceptance (statementParameters statement batching) points selected gamma response
      transcript choose (packingValues witness) salt labels continuation -
      currentPublicReferenceAcceptance (statementParameters statement batching) points selected gamma response
        transcript choose salt labels continuation| ≤ hiddenPatchLoss queryBound := by
  obtain ⟨_, nonlinear, linear⟩ :=
    canonical_statement_supplies_current_game_algebra statement publicValues witness domain batching
  exact current_averaged_source_to_witness_free_reference_bound
    (statementParameters statement batching) points admissible pointsNonzero selected packingCardNonzero
    nodesInjective (packingValues witness) gamma response transcript fallback choose
    nonlinear linear salt labels continuation queryBound queriesBounded

/-- Two accepted packed witnesses of the same admitted encoded statement share
the identical generated public reference and retained-row gamma assignment. -/
theorem canonical_statement_two_witness_current_privacy_bound
    (statement : V8PublicStatement) (publicValues leftWitness rightWitness : List Nat)
    (leftDomain : CanonicalPublicPackedDomain statement publicValues leftWitness)
    (rightDomain : CanonicalPublicPackedDomain statement publicValues rightWitness)
    (batching : Fin 5 → Nat → Goldilocks) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (fallback : LvcsAdmissibleTargets points)
    (choose : IndexChooser points) (salt : SaltBytes) (labels : LeafIndex → Output)
    (continuation : CurrentContinuationFactory (Other := Other) (Output := Output) (Workspace := Workspace) points)
    (queryBound : ℕ) (queriesBounded : ∀ context visible,
      (continuation context visible).queries ≤ queryBound) :
    |currentFullSourceAcceptance (statementParameters statement batching) points selected gamma response
      transcript choose (packingValues leftWitness) salt labels continuation -
      currentFullSourceAcceptance (statementParameters statement batching) points selected gamma response
        transcript choose (packingValues rightWitness) salt labels continuation| ≤ 2 * hiddenPatchLoss queryBound := by
  obtain ⟨_, leftNonlinear, leftLinear⟩ :=
    canonical_statement_supplies_current_game_algebra statement publicValues leftWitness leftDomain batching
  obtain ⟨_, rightNonlinear, rightLinear⟩ :=
    canonical_statement_supplies_current_game_algebra statement publicValues rightWitness rightDomain batching
  exact current_two_witness_source_game_bound
    (statementParameters statement batching) points admissible pointsNonzero selected packingCardNonzero
    nodesInjective (packingValues leftWitness) (packingValues rightWitness) gamma response transcript fallback choose
    leftNonlinear rightNonlinear leftLinear rightLinear salt labels continuation queryBound queriesBounded

end PhysicalGame

end
end HegemonCrypto.SmallWood.V8Smz9CurrentPublicContext
