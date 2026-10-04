import SmzaRp05Q38CurrentRebinding
import SmzaRp05AcceptedRelationInterface

/-!
# Current-map, query-local accepted witness bridge

The accepted relation path can use its decoded degree-405 source rows directly
as the packed witness. It needs their agreement with committed values only at
the verifier-sampled q38 positions. It does not need equality with every value
in the 2^23-entry committed table or the full-table Lagrange interpolant.

This file states the weaker current-map theorem. Its sampled row agreement,
current-map LVCS discrepancy detection, and current-map opening checks remain
explicit premises: deriving these from one accepted native PCS execution is a
separate source-to-query/readback obligation. No security or production
endpoint is asserted here.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedQ38AgreementBridge

open Polynomial
open SmzaRp05TracePrefixes
open SmzaRp05StatementNamespace
open SmzaRp05AcceptedExtraction
open SmzaQ38Recovery
open SmzaQ38McaSourceBinding
open SmzaQ38LvcsOpening
open SmzaQ38OpeningFieldReadback
open SmzaPiopGoodOutcome
open SmzaRp04ChronologicalAlgebra
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open V8Smz9ZeroKnowledge V8Smz9EagerPrivacy V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.SmzaRp05Q38CurrentRebinding

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false

def CurrentDiscrepanciesDetected (rows : RecoveredRows)
    (points : Fin 6 → Goldilocks) (claimed : ClaimedPolynomials) (query : Query) : Prop :=
  ∀ combination, SmzaQ38LvcsOpening.discrepancy rows points claimed combination ≠ 0 →
    ∃ index ∈ query.val,
      (SmzaQ38LvcsOpening.discrepancy rows points claimed combination).eval
        (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) ≠ 0

def CurrentOracleOpeningChecks (oracle : CommittedOracle)
    (points : Fin 6 → Goldilocks) (claimed : ClaimedPolynomials) (query : Query) : Prop :=
  ∀ combination index, index ∈ query.val →
    (claimed combination).eval (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) =
      ∑ coefficient : Fin 70, points combination.1 ^ coefficient.val *
        committedColumnValue oracle
          (SmzaQ38LvcsOpening.blockRow combination.2 coefficient) index

/-- Current 406-map query checks force all twelve claimed combinations to be
the corresponding combinations of the decoded source rows. The proof uses
only query-local agreement. -/
theorem current_accepted_lvcs_combinations_are_recovered
    (oracle : CommittedOracle) (rows : RecoveredRows)
    (points : Fin 6 → Goldilocks) (claimed : ClaimedPolynomials) (query : Query)
    (rowAgreement : ∀ row index, index ∈ query.val →
      (rows row).eval (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) =
        SmzaRp05Q38CurrentRebinding.committedColumnValue oracle row index)
    (checked : CurrentOracleOpeningChecks oracle points claimed query)
    (detected : CurrentDiscrepanciesDetected rows points claimed query) :
    ∀ combination, claimed combination =
      SmzaQ38LvcsOpening.rowCombination rows points combination := by
  intro combination
  apply sub_eq_zero.mp
  change SmzaQ38LvcsOpening.discrepancy rows points claimed combination = 0
  by_contra nonzero
  obtain ⟨index, member, mismatch⟩ := detected combination nonzero
  apply mismatch
  simp only [SmzaQ38LvcsOpening.discrepancy, eval_sub,
    SmzaQ38LvcsOpening.rowCombination, eval_finsetSum, eval_mul, eval_C]
  rw [checked combination index member]
  apply sub_eq_zero.mpr
  apply Finset.sum_congr rfl
  intro coefficient _
  rw [rowAgreement _ index member]

/-- Recovered-row combination at an individual PCS head equals the
corresponding recovered-column opening. The displayed 38 offset is the current
RP05 inverse rotation; no 388-domain evaluation map is used in this identity. -/
theorem current_combination_head_is_individual_column_opening
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    (SmzaQ38LvcsOpening.rowCombination rows points (opening, block)).eval
        (SmzaRp05Q38CurrentRebinding.lvcsDataPoint column) =
      (SmzaQ38LvcsOpening.recoveredColumn rows
        (SmzaQ38LvcsOpening.columnIndex block column)).eval (points opening) := by
  simpa [SmzaRp05Q38CurrentRebinding.lvcsDataPoint,
    SmzaRp05Q38CurrentRebinding.decsOpenedEvaluations,
    SmzaQ38OracleExtraction.lvcsDataPoint,
    SmzaQ38OracleExtraction.decsOpenedEvaluations] using
    SmzaQ38LvcsOpening.combination_head_is_individual_column_opening
      rows points opening block column

/-- The twelve current-map combination equalities, together with native
head binding, produce exactly the column openings expected by relation
refinement. -/
theorem current_heads_force_reconstructed_columns
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : ClaimedPolynomials)
    (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks)
    (partials : SourcePcsView Goldilocks)
    (headBinding : ClaimedHeadsReconstructed points claimed witness masks partials)
    (combinations : ∀ combination, claimed combination =
      SmzaQ38LvcsOpening.rowCombination rows points combination) :
    reconstructedColumnEvaluations points witness masks partials =
      (fun opening column =>
        (SmzaQ38LvcsOpening.recoveredColumn rows column).eval (points opening)) := by
  funext opening column
  let block : Fin 2 := ⟨column.val / 368, by omega⟩
  let localColumn : Fin 368 := ⟨column.val % 368, Nat.mod_lt _ (by decide)⟩
  have same : SmzaQ38LvcsOpening.columnIndex block localColumn = column := by
    apply Fin.ext
    change (column.val / 368) * 368 + column.val % 368 = column.val
    omega
  rw [← same, ← headBinding opening block localColumn, combinations (opening, block)]
  exact current_combination_head_is_individual_column_opening rows points opening block localColumn

/-- Query-local current-map checks are enough to produce the accepted packed
witness, provided the independently named PIOP algebraic conditions and the
current relation refinement hold. No all-domain codeword equality appears. -/
theorem current_query_checks_yield_packed_witness {model : RelationModel}
    (refinement : RelationRefinement model) (statement : Statement)
    (oracle : CommittedOracle) (rows : RecoveredRows)
    (matrix : V8Smz9PiopSoundness.Matrix (model.width statement))
    (response : ClaimedTranscript)
    (opening : Opening) (message : OpeningMessage) (query : Query)
    (headBinding : ClaimedHeadsReconstructed (baseOpeningPoints opening.1)
      message.claimed message.witness message.masks message.partials)
    (rowAgreement : ∀ row index, index ∈ query.val →
      (rows row).eval (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) =
        SmzaRp05Q38CurrentRebinding.committedColumnValue oracle row index)
    (openingChecks : CurrentOracleOpeningChecks oracle (baseOpeningPoints opening.1)
      message.claimed query)
    (lvcsDetected : CurrentDiscrepanciesDetected rows (baseOpeningPoints opening.1)
      message.claimed query)
    (statementValid : refinement.StatementValid statement)
    (scalarChecks : refinement.ScalarChecks statement rows matrix response opening message)
    (piopDetected : SmzaPiopGoodOutcome.DiscrepanciesDetected
      (model.recoveredCandidate statement rows) matrix response opening)
    (residualsDetected : SmzaPiopGoodOutcome.ResidualsDetected
      (model.recoveredCandidate statement rows) matrix) :
    refinement.AcceptsPacked statement (packedFromRows rows) := by
  have combinations := current_accepted_lvcs_combinations_are_recovered oracle rows
    (baseOpeningPoints opening.1) message.claimed query rowAgreement openingChecks lvcsDetected
  have columns := current_heads_force_reconstructed_columns rows
    (baseOpeningPoints opening.1) message.claimed message.witness message.masks
    message.partials headBinding combinations
  have openingAccepted := refinement.openingAcceptsOfReadback statement rows matrix
    response opening message columns scalarChecks
  apply refinement.fullySatisfiedAccepts statement rows statementValid
  have candidateSatisfied :
      PiopExtraction.FullySatisfied (model.recoveredCandidate statement rows).system :=
    SmzaPiopGoodOutcome.accepted_piop_outside_named_algebraic_events_satisfies_candidate
    (model.recoveredCandidate statement rows) matrix response opening openingAccepted
    piopDetected residualsDetected
  exact candidateSatisfied

end
end HegemonCrypto.SmallWood.SmzaRp05AcceptedQ38AgreementBridge
