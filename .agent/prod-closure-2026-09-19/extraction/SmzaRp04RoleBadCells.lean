import SmzaRp04ChronologicalAlgebra
import SmzaChallengeStageTargets
import HegemonCrypto.CmsClassicalDatabase

/-!
# Fixed-prefix RP04 algebra cells

The label of each cell contains exactly the information committed before that
role's output.  In particular, an opening label contains the already selected
PIOP matrix and response, while a DECS-sample label contains 406-term
coefficient vectors interpolated from the twelve claimed evaluation vectors.
Thus the density theorem below is pointwise in an arbitrary malicious prefix;
there is no fixed-honest-transcript restriction.

The ideal finite output laws reuse these checked interfaces:

* `SmallWood.OracleExtraction.decsChallengeEquiv` and
  `piopChallengeEquiv` for field-word matrices;
* `V8Smz9RuntimeDistribution.iid_uniform_rejection_output_vector_uniform`
  for an ideal vector of accepted Goldilocks rejection-sampler outputs; and
* `V8Smz9PiopSoundness.opening_probability_le_of_affine_failure` for the
  six-point fully-admissible opening type.

The actual RP04 capped raw-output adapters are in `SmzaRp04RawRoleSampling`.
In particular,
`PiopOpeningSampling.active_canonical_nonce_selects_stream_sample` and
`active_first_valid_bad_probability_eq_epsilon3` concern the older five-point
active profile, while `V8Smz9LogicalOracle.decsOpeningChallengeEquivPowerset`
concerns the old twenty-subset.  They must not be used as RP04 six/q38
distribution bridges. The adapters preserve failed sampling in the original
denominator instead of assuming an exactly uniform total field-valued parser.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04RoleBadCells

open Polynomial SmzaQ38Recovery SmzaQ38OracleExtraction
open SmzaQ38McaSourceBinding SmzaRp04ActualProgram SmzaRp04PublicContext
open SmzaRp04CalculatedExtraction SmzaRp04ChronologicalAlgebra
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open V8Smz9RobustQueryMismatch
open HegemonCrypto.CmsClassicalDatabase

noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

structure PiopMatrixLabel (publicWords : List Nat) where
  candidate : Candidate (batchingWidth publicWords)
  invalid : ¬ PiopExtraction.FullySatisfied candidate.system

structure PiopOpeningLabel (publicWords : List Nat) where
  candidate : Candidate (batchingWidth publicWords)
  matrix : Matrix (batchingWidth publicWords)
  response : ClaimedTranscript

/-- A fixed q38 prefix. The rows' degree certificate is produced by the MCA
decoder; claimed-polynomial degree follows from the fixed 406-coefficient
representation, obtained by interpolating the physical heads and tails. -/
structure DecsSampleLabel where
  rows : RecoveredRows
  rowsDegree : ∀ row, (rows row).natDegree ≤ 405
  points : Fin 6 → Goldilocks
  claimedCoefficients : Fixed406Coefficients

inductive Label (publicWords : List Nat)
  | piopMatrix : PiopMatrixLabel publicWords → Label publicWords
  | piopOpening : PiopOpeningLabel publicWords → Label publicWords
  | decsSample : DecsSampleLabel → Label publicWords

def Label.role {publicWords : List Nat} : Label publicWords →
    SmzaChallengeStageTargets.Role
  | .piopMatrix _ => .piopMatrix
  | .piopOpening _ => .piopOpening
  | .decsSample _ => .decsSample

/-- The finite output alphabet appropriate to one fixed-prefix label. -/
def Output {publicWords : List Nat} : Label publicWords → Type
  | .piopMatrix _ => Matrix (batchingWidth publicWords)
  | .piopOpening _ => Opening
  | .decsSample _ => Query

noncomputable instance outputFintype {publicWords : List Nat}
    (label : Label publicWords) : Fintype (Output label) := by
  cases label with
  | piopMatrix _ =>
      change Fintype (Matrix (batchingWidth publicWords))
      exact inferInstance
  | piopOpening _ =>
      change Fintype Opening
      exact inferInstance
  | decsSample _ =>
      change Fintype Query
      exact inferInstance

noncomputable instance outputDecidableEq {publicWords : List Nat}
    (label : Label publicWords) : DecidableEq (Output label) := by
  cases label with
  | piopMatrix _ => exact Classical.decEq _
  | piopOpening _ => exact Classical.decEq _
  | decsSample _ => exact Classical.decEq _

/-- Concrete bad outputs for a fixed prefix. -/
def badCells {publicWords : List Nat} :
    (label : Label publicWords) → Finset (Output label)
  | .piopMatrix label => piopMatrixBadEvent label.candidate
  | .piopOpening label =>
      piopOpeningBadEvent label.candidate label.matrix label.response
  | .decsSample label =>
      lvcsBadQueryEvent label.rows label.points
        (claimedPolynomials label.claimedCoefficients)

def IsBad {publicWords : List Nat} (label : Label publicWords)
    (output : Output label) : Prop := output ∈ badCells label

def roleLoss : SmzaChallengeStageTargets.Role → Rat
  | .decsMatrix => 0
  | .piopMatrix => ((1 : Rat) / Fintype.card Goldilocks) ^ 5
  | .piopOpening => epsilon3
  | .decsSample => q38LvcsLoss

/-- Uniform density of bad outputs for every fixed malicious prefix. -/
theorem bad_cells_probability_le {publicWords : List Nat}
    (label : Label publicWords) :
    FiniteEvents.probability (badCells label) ≤ roleLoss label.role := by
  cases label with
  | piopMatrix label =>
      change FiniteEvents.probability (piopMatrixBadEvent label.candidate) ≤
        ((1 : Rat) / Fintype.card Goldilocks) ^ 5
      exact piop_matrix_bad_probability_le label.candidate label.invalid
  | piopOpening label =>
      change FiniteEvents.probability
        (piopOpeningBadEvent label.candidate label.matrix label.response) ≤ epsilon3
      exact piop_opening_bad_probability_le label.candidate label.matrix label.response
  | decsSample label =>
      change FiniteEvents.probability
        (lvcsBadQueryEvent label.rows label.points
          (claimedPolynomials label.claimedCoefficients)) ≤ q38LvcsLoss
      exact lvcs_bad_query_probability_le label.rows label.points
        (claimedPolynomials label.claimedCoefficients) label.rowsDegree
        (claimed_polynomials_degree405 label.claimedCoefficients)

theorem output_event_probability_membership {OutputType : Type*}
    [Fintype OutputType] [DecidableEq OutputType] (event : Finset OutputType) :
    outputEventProbability (fun output => output ∈ event) =
      FiniteEvents.probability event := by
  classical
  unfold outputEventProbability FiniteEvents.probability
  apply congrArg (fun outputs : Finset OutputType =>
    (outputs.card : Rat) / Fintype.card OutputType)
  ext output
  simp

/-- Same density in the exact form consumed by `DynamicBad`: one uniform
output for one database-derived fixed label. -/
theorem bad_output_event_probability_le {publicWords : List Nat}
    (label : Label publicWords) :
    outputEventProbability (IsBad label) ≤ roleLoss label.role := by
  change outputEventProbability (fun output => output ∈ badCells label) ≤ _
  rw [output_event_probability_membership]
  exact bad_cells_probability_le label

def piopMatrixCellBad {publicWords : List Nat}
    (label : PiopMatrixLabel publicWords)
    (output : Matrix (batchingWidth publicWords)) : Prop :=
  output ∈ piopMatrixBadEvent label.candidate

def piopOpeningCellBad {publicWords : List Nat}
    (label : PiopOpeningLabel publicWords) (output : Opening) : Prop :=
  output ∈ piopOpeningBadEvent label.candidate label.matrix label.response

def decsSampleCellBad (label : DecsSampleLabel) (output : Query) : Prop :=
  output ∈ lvcsBadQueryEvent label.rows label.points
    (claimedPolynomials label.claimedCoefficients)

theorem piop_matrix_cell_density {publicWords : List Nat}
    (label : PiopMatrixLabel publicWords) :
    outputEventProbability (piopMatrixCellBad label) ≤
      roleLoss .piopMatrix := by
  change outputEventProbability
    (fun output => output ∈ piopMatrixBadEvent label.candidate) ≤ _
  rw [output_event_probability_membership]
  exact piop_matrix_bad_probability_le label.candidate label.invalid

theorem piop_opening_cell_density {publicWords : List Nat}
    (label : PiopOpeningLabel publicWords) :
    outputEventProbability (piopOpeningCellBad label) ≤
      roleLoss .piopOpening := by
  change outputEventProbability (fun output => output ∈
    piopOpeningBadEvent label.candidate label.matrix label.response) ≤ _
  rw [output_event_probability_membership]
  exact piop_opening_bad_probability_le label.candidate label.matrix label.response

theorem decs_sample_cell_density (label : DecsSampleLabel) :
    outputEventProbability (decsSampleCellBad label) ≤ roleLoss .decsSample := by
  change outputEventProbability (fun output => output ∈
    lvcsBadQueryEvent label.rows label.points
      (claimedPolynomials label.claimedCoefficients)) ≤ _
  rw [output_event_probability_membership]
  exact lvcs_bad_query_probability_le label.rows label.points
    (claimedPolynomials label.claimedCoefficients) label.rowsDegree
    (claimed_polynomials_degree405 label.claimedCoefficients)

/-- Package a recovered source and post-opening prefix into the literal q38
label consumed by `badCells`. -/
def recoveredDecsSampleLabel {publicWords : List Nat}
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy publicWords) (coefficients : Coefficients)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening)
    (source : RecoveredSource)
    (recovered : recoverSource oracle decsResponse coefficients = some source) :
    DecsSampleLabel :=
  { rows := source.data
    rowsDegree :=
      (recovered_source_degree_and_agreement oracle decsResponse coefficients
        source recovered).2.2.2
    points := baseOpeningPoints opening.1
    claimedCoefficients :=
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients }

/-- A dependent pair is the algebraic cell stored in a role bad database. -/
abbrev Cell (publicWords : List Nat) :=
  Sigma fun label : Label publicWords => Output label

def Cell.IsBad {publicWords : List Nat} (cell : Cell publicWords) : Prop :=
  SmzaRp04RoleBadCells.IsBad cell.1 cell.2

/-- The restored accepted-failure classification can be packaged directly as
one fixed-prefix role cell.  The decoder branch remains separate because its
q38 MCA count is charged at the earlier DECS-matrix stage. -/
theorem accepted_failure_implies_decoder_or_bad_role_cell
    (publicWords : List Nat)
    (canonical : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy publicWords) (coefficients : Coefficients)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening) (query : Query)
    (checks : AcceptedChecks publicWords oracle decsResponse strategy
      coefficients matrix opening query)
    (failed : extractionFailure publicWords oracle decsResponse coefficients) :
    DecoderFailure oracle decsResponse coefficients query ∨
      ∃ cell : Cell publicWords, cell.IsBad := by
  rcases accepted_failure_implies_chronological_bad_event publicWords canonical oracle
      decsResponse strategy coefficients matrix opening query checks failed with decoder |
      ⟨source, recovered, invalid, bad⟩
  · exact Or.inl decoder
  · right
    rcases bad with badMatrix | badOpening | badQuery
    · let label : Label publicWords := .piopMatrix
          { candidate := recoveredCandidate publicWords source.data
            invalid := invalid }
      refine ⟨⟨label, matrix⟩, ?_⟩
      change matrix ∈ piopMatrixBadEvent (recoveredCandidate publicWords source.data)
      exact badMatrix
    · let label : Label publicWords := .piopOpening
          { candidate := recoveredCandidate publicWords source.data
            matrix := matrix
            response := strategy.piopResponse coefficients matrix }
      refine ⟨⟨label, opening⟩, ?_⟩
      change opening ∈ piopOpeningBadEvent
        (recoveredCandidate publicWords source.data) matrix
          (strategy.piopResponse coefficients matrix)
      exact badOpening
    · let label : Label publicWords := .decsSample
          (recoveredDecsSampleLabel oracle decsResponse strategy coefficients
            matrix opening source recovered)
      refine ⟨⟨label, query⟩, ?_⟩
      change query ∈ lvcsBadQueryEvent source.data (baseOpeningPoints opening.1)
        (strategy.afterOpening coefficients matrix opening).claimed
      exact badQuery

end
end HegemonCrypto.SmallWood.SmzaRp04RoleBadCells
