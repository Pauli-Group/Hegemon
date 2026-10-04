import HegemonCrypto.KnowledgeSoundnessTarget
import Mathlib.Algebra.BigOperators.Group.Finset.Basic
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Mathlib.Data.Complex.Basic
import Mathlib.Data.Fintype.OfMap

/-!
# Finite-dimensional standard quantum random-oracle semantics

This module supplies the executable mathematical core that the SmallWood QROM target previously
only described in prose.  Query inputs and output registers are finite.  A pure state is an
arbitrary complex amplitude over the finite computational basis, so oracle calls act on genuine
superpositions rather than a classical query log.

For a function `H : X -> Y`, the controlled oracle basis permutation maps
`|c,x,y>` to `|c,x,y + H(x)>` when `c = true` and leaves the output register unchanged otherwise.
Reindexing amplitudes by the inverse permutation is proved to preserve squared norm.  A purified
oracle algorithm is a finite list of norm-preserving inter-query transformations, and its final
Born event probabilities are proved to lie in `[0,1]`.

This is not the measure-and-reprogram theorem.  It gives that theorem a standard finite-dimensional
semantic target without postulating extractable or classically logged quantum queries.
-/

namespace HegemonCrypto.FiniteQrom

open scoped BigOperators

structure QueryBasis (Input Output : Type*) where
  control : Bool
  input : Input
  output : Output
deriving DecidableEq

def productQueryBasisEquiv (Input Output : Type*) :
    (Bool × Input × Output) ≃ QueryBasis Input Output where
  toFun basis :=
    { control := basis.1,
      input := basis.2.1,
      output := basis.2.2 }
  invFun basis := (basis.control, basis.input, basis.output)
  left_inv basis := by cases basis; rfl
  right_inv basis := by cases basis; rfl

instance {Input Output : Type*} [Fintype Input] [Fintype Output] :
    Fintype (QueryBasis Input Output) :=
  Fintype.ofEquiv (Bool × Input × Output) (productQueryBasisEquiv Input Output)

variable {Input Output : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]

/-- Controlled-addition implementation of the standard finite random-oracle query. -/
def queryBasisEquiv (oracle : Input → Output) :
    QueryBasis Input Output ≃ QueryBasis Input Output where
  toFun basis :=
    { basis with
      output := if basis.control then basis.output + oracle basis.input else basis.output }
  invFun basis :=
    { basis with
      output := if basis.control then basis.output - oracle basis.input else basis.output }
  left_inv basis := by
    cases basis
    rename_i control input output
    cases control <;> simp
  right_inv basis := by
    cases basis
    rename_i control input output
    cases control <;> simp

abbrev State (Input Output : Type*) := QueryBasis Input Output → ℂ

/-- Schrödinger-picture action induced by the oracle's computational-basis permutation. -/
def queryState (oracle : Input → Output) (state : State Input Output) :
    State Input Output :=
  fun basis => state ((queryBasisEquiv oracle).symm basis)

/-- Squared Hilbert norm of a finite pure state. -/
def normSquared (state : State Input Output) : ℝ :=
  ∑ basis, Complex.normSq (state basis)

/-- One computational-basis ket. -/
def basisState (basis : QueryBasis Input Output) : State Input Output :=
  fun candidate => if candidate = basis then 1 else 0

omit [Fintype Input] [Fintype Output] in
/-- The oracle query maps a basis ket to the ket named by the controlled-addition permutation. -/
theorem query_basis_state
    (oracle : Input → Output)
    (basis : QueryBasis Input Output) :
    queryState oracle (basisState basis) =
      basisState (queryBasisEquiv oracle basis) := by
  funext candidate
  by_cases same : candidate = queryBasisEquiv oracle basis
  · simp [queryState, basisState, same]
  · have inverseDifferent : (queryBasisEquiv oracle).symm candidate ≠ basis := by
      intro inverseSame
      exact same ((queryBasisEquiv oracle).symm_apply_eq.mp inverseSame)
    simp [queryState, basisState, same, inverseDifferent]

omit [DecidableEq Input] [DecidableEq Output] in
/-- Reindexing amplitudes by the oracle permutation preserves squared norm exactly. -/
theorem query_state_preserves_norm
    (oracle : Input → Output)
    (state : State Input Output) :
    normSquared (queryState oracle state) = normSquared state := by
  unfold normSquared queryState
  exact (queryBasisEquiv oracle).symm.sum_comp
    (fun basis => Complex.normSq (state basis))

def Normalized (state : State Input Output) : Prop :=
  normSquared state = 1

omit [DecidableEq Input] [DecidableEq Output] in
theorem query_state_preserves_normalization
    (oracle : Input → Output)
    {state : State Input Output}
    (normalized : Normalized state) :
    Normalized (queryState oracle state) := by
  rw [Normalized, query_state_preserves_norm]
  exact normalized

/-- An inter-query purified computation, represented only by the property needed here. -/
structure NormPreservingStep where
  apply : State Input Output → State Input Output
  preservesNorm : ∀ state, normSquared (apply state) = normSquared state

def run
    (oracle : Input → Output) :
    List (NormPreservingStep (Input := Input) (Output := Output)) →
      State Input Output → State Input Output
  | [], state => state
  | step :: remaining, state =>
      run oracle remaining (step.apply (queryState oracle state))

omit [DecidableEq Input] [DecidableEq Output] in
theorem run_preserves_norm
    (oracle : Input → Output)
    (steps : List (NormPreservingStep (Input := Input) (Output := Output)))
    (state : State Input Output) :
    normSquared (run oracle steps state) = normSquared state := by
  induction steps generalizing state with
  | nil => rfl
  | cons step remaining inductionHypothesis =>
      rw [run, inductionHypothesis, step.preservesNorm, query_state_preserves_norm]

/-- Purified finite-query adversary.  Its query budget is definitionally `steps.length`. -/
structure OracleAlgorithm where
  initialState : State Input Output
  initialState_normalized : Normalized initialState
  steps : List (NormPreservingStep (Input := Input) (Output := Output))

def OracleAlgorithm.queryCount (algorithm : OracleAlgorithm (Input := Input) (Output := Output)) :
    Nat :=
  algorithm.steps.length

def OracleAlgorithm.outputState
    (algorithm : OracleAlgorithm (Input := Input) (Output := Output))
    (oracle : Input → Output) : State Input Output :=
  run oracle algorithm.steps algorithm.initialState

omit [DecidableEq Input] [DecidableEq Output] in
theorem OracleAlgorithm.outputState_normalized
    (algorithm : OracleAlgorithm (Input := Input) (Output := Output))
    (oracle : Input → Output) :
    Normalized (algorithm.outputState oracle) := by
  unfold Normalized OracleAlgorithm.outputState
  rw [run_preserves_norm]
  exact algorithm.initialState_normalized

/-- Born probability of measuring a computational-basis event. -/
def eventProbability
    (state : State Input Output)
    (event : Finset (QueryBasis Input Output)) : ℝ :=
  ∑ basis ∈ event, Complex.normSq (state basis)

omit [Fintype Input] [DecidableEq Input] [Fintype Output] [DecidableEq Output]
    [AddCommGroup Output] in
theorem event_probability_nonnegative
    (state : State Input Output)
    (event : Finset (QueryBasis Input Output)) :
    0 ≤ eventProbability state event := by
  exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg (state basis)

omit [DecidableEq Input] [DecidableEq Output] [AddCommGroup Output] in
theorem event_probability_at_most_one
    {state : State Input Output}
    (normalized : Normalized state)
    (event : Finset (QueryBasis Input Output)) :
    eventProbability state event ≤ 1 := by
  calc
    eventProbability state event ≤
        ∑ basis : QueryBasis Input Output, Complex.normSq (state basis) := by
      exact Finset.sum_le_sum_of_subset_of_nonneg (Finset.subset_univ event)
        (fun basis _ _ => Complex.normSq_nonneg (state basis))
    _ = normSquared state := by rfl
    _ = 1 := normalized

section RandomOracleExperiment

variable [Nonempty Output]

/-- Computational-basis event selected by an arbitrary measured predicate. -/
noncomputable def eventFinset
    (event : QueryBasis Input Output → Prop) :
    Finset (QueryBasis Input Output) := by
  classical
  exact Finset.univ.filter event

/-- Uniform average over all finite functions `H : Input -> Output`. -/
noncomputable def randomOracleEventProbability
    (algorithm : OracleAlgorithm (Input := Input) (Output := Output))
    (event : (Input → Output) → QueryBasis Input Output → Prop) : ℝ := by
  classical
  exact
    (∑ oracle : Input → Output,
      eventProbability (algorithm.outputState oracle) (eventFinset (event oracle))) /
        Fintype.card (Input → Output)

omit [DecidableEq Output] [Nonempty Output] in
theorem random_oracle_event_probability_nonnegative
    (algorithm : OracleAlgorithm (Input := Input) (Output := Output))
    (event : (Input → Output) → QueryBasis Input Output → Prop) :
    0 ≤ randomOracleEventProbability algorithm event := by
  classical
  unfold randomOracleEventProbability
  exact div_nonneg
    (Finset.sum_nonneg fun oracle _ =>
      event_probability_nonnegative
        (algorithm.outputState oracle) (eventFinset (event oracle)))
    (by exact_mod_cast Nat.zero_le (Fintype.card (Input → Output)))

omit [DecidableEq Output] in
theorem random_oracle_event_probability_at_most_one
    (algorithm : OracleAlgorithm (Input := Input) (Output := Output))
    (event : (Input → Output) → QueryBasis Input Output → Prop) :
    randomOracleEventProbability algorithm event ≤ 1 := by
  classical
  have oracleSpacePositive : (0 : ℝ) < Fintype.card (Input → Output) := by
    exact_mod_cast Fintype.card_pos_iff.mpr inferInstance
  unfold randomOracleEventProbability
  rw [div_le_iff₀ oracleSpacePositive]
  calc
    (∑ oracle : Input → Output,
      eventProbability (algorithm.outputState oracle) (eventFinset (event oracle))) ≤
        ∑ _oracle : Input → Output, (1 : ℝ) := by
      exact Finset.sum_le_sum fun oracle _ =>
        event_probability_at_most_one
          (algorithm.outputState_normalized oracle) (eventFinset (event oracle))
    _ = (1 : ℝ) * Fintype.card (Input → Output) := by simp

/-- Data needed to turn the finite state-vector semantics into the public adaptive-game API. -/
structure Experiment (Adversary Proof : Type*) where
  algorithm : Adversary → OracleAlgorithm (Input := Input) (Output := Output)
  priorProofInteractions : Adversary → Nat
  decodeTrial :
    (Input → Output) → QueryBasis Input Output → HegemonCrypto.SmallWood.ExtractionTrial Proof

noncomputable def Experiment.toAdaptiveOracleGame
    {Adversary Proof : Type*}
    (experiment : Experiment (Input := Input) (Output := Output) Adversary Proof) :
    HegemonCrypto.SmallWood.AdaptiveOracleGame Adversary Proof where
  model := .standardQrom
  quantumHashQueries adversary := (experiment.algorithm adversary).queryCount
  priorProofInteractions := experiment.priorProofInteractions
  eventProbability adversary event :=
    randomOracleEventProbability (experiment.algorithm adversary)
      (fun oracle basis => event (experiment.decodeTrial oracle basis))
  eventProbability_nonnegative adversary event :=
    random_oracle_event_probability_nonnegative (experiment.algorithm adversary)
      (fun oracle basis => event (experiment.decodeTrial oracle basis))
  eventProbability_atMostOne adversary event :=
    random_oracle_event_probability_at_most_one (experiment.algorithm adversary)
      (fun oracle basis => event (experiment.decodeTrial oracle basis))

omit [DecidableEq Output] in
theorem Experiment.toAdaptiveOracleGame_uses_standard_qrom
    {Adversary Proof : Type*}
    (experiment : Experiment (Input := Input) (Output := Output) Adversary Proof) :
    experiment.toAdaptiveOracleGame.model = .standardQrom := by
  rfl

omit [DecidableEq Output] in
theorem Experiment.toAdaptiveOracleGame_counts_exact_queries
    {Adversary Proof : Type*}
    (experiment : Experiment (Input := Input) (Output := Output) Adversary Proof)
    (adversary : Adversary) :
    experiment.toAdaptiveOracleGame.quantumHashQueries adversary =
      (experiment.algorithm adversary).steps.length := by
  rfl

end RandomOracleExperiment

end HegemonCrypto.FiniteQrom
