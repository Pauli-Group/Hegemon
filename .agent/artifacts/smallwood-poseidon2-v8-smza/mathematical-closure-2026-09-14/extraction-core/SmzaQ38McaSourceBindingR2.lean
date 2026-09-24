import SmzaQ38Recovery
import HegemonCrypto.SmallWoodV8Smz9McaDecoder

/-! Degree405,38-query source binding for the exact145-column table.
The source and response strategy precede the DECS matrix; the calculated
decoder depends on that matrix/response but not the subsequent38-query subset
or PIOP challenges. This is a finite-table model, not Merkle extraction.
-/
namespace HegemonCrypto.SmallWood.SmzaQ38McaSourceBinding

open Polynomial V8Smz9McaDecoder V8Smz9McaRecovery
open SmzaQ38OracleExtraction SmzaQ38Recovery
open scoped BigOperators

noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

abbrev Position := Fin decsDomainSize
abbrev Coefficients := Fin 140 → Fin 5 → Goldilocks
abbrev ResponseStrategy := Coefficients → BoundedResponse Goldilocks (Fin 5) 405
abbrev RecoveredSource := DecodedSource Goldilocks (Fin 5) 140
abbrev Query := { positions : Finset Position // positions.card = 38 }

def oracleData (oracle : CommittedOracle) (column : Nat) : Position → Goldilocks :=
  if bounded : column < 140 then committedColumnValue oracle ⟨column, bounded⟩ else 0

def oracleMasks (oracle : CommittedOracle) (row : Fin 5) (index : Position) : Goldilocks :=
  wordToGoldilocks (oracle index ⟨140 + row.val, by
    have bound := row.isLt
    change 140 + row.val < 140 + 5
    omega⟩)

def agreementSupport (oracle : CommittedOracle) (response : ResponseStrategy)
    (coefficients : Coefficients) : Finset Position :=
  responseSupport smz9EvaluationPoint 405 (oracleData oracle) (oracleMasks oracle)
    response coefficients

def recoverSource (oracle : CommittedOracle) (response : ResponseStrategy)
    (coefficients : Coefficients) : Option RecoveredSource :=
  responseDecoder smz9EvaluationPoint 405 (oracleData oracle) (oracleMasks oracle)
    response coefficients

/-- Literal five DECS mixture equations at each of38 distinct queried positions. -/
def QueryAccepts (oracle : CommittedOracle) (response : ResponseStrategy)
    (coefficients : Coefficients) (query : Query) : Prop :=
  ∀ index ∈ query.val, ∀ row,
    (responsePolynomials (response coefficients) row).eval (smz9EvaluationPoint index) =
      mixedWord (oracleData oracle) (oracleMasks oracle)
        (extendCoefficients coefficients) 140 row index

theorem query_accepts_iff_prequery_agreement (oracle : CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients) (query : Query) :
    QueryAccepts oracle response coefficients query ↔
      query.val ⊆ agreementSupport oracle response coefficients := by
  constructor
  · intro accepts index member
    exact (mem_agreement smz9EvaluationPoint _ _ index).mpr (accepts index member)
  · intro subset index member
    exact (mem_agreement smz9EvaluationPoint _ _ index).mp (subset member)

theorem recovered_source_degree_and_agreement (oracle : CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients)
    (source : RecoveredSource)
    (recovered : recoverSource oracle response coefficients = some source) :
    405 < (agreementSupport oracle response coefficients).card ∧
      CandidateAgrees smz9EvaluationPoint (agreementSupport oracle response coefficients)
        (oracleData oracle) (oracleMasks oracle) source ∧
      (∀ row, (source.masks row).natDegree ≤ 405) ∧
      (∀ column, (source.data column).natDegree ≤ 405) :=
  decoded_source_agrees_and_has_bounded_degree smz9EvaluationPoint
    smz9_evaluation_point_injective 405 _ _ _ source recovered

/-- A successful calculated recovery reproduces the entire degree405
DECS response, not merely the38 accepted query values. -/
theorem recovered_projection_is_entire_response (oracle : CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients)
    (source : RecoveredSource)
    (recovered : recoverSource oracle response coefficients = some source)
    (row : Fin 5) :
    responsePolynomials (response coefficients) row =
      projectedSource source coefficients row :=
  decoded_response_equals_projection smz9EvaluationPoint
    smz9_evaluation_point_injective 405 _ _ response coefficients source recovered row

/-- Exact q38 LVCS head equation at38+j; no q20 point substitution or
probability theorem is used. This is the input to later LVCS row-opening checks. -/
theorem recovered_q38_heads_supply_response_equation (oracle : CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients)
    (source : RecoveredSource)
    (recovered : recoverSource oracle response coefficients = some source)
    (row : Fin 5) (column : Fin 368) :
    (responsePolynomials (response coefficients) row).eval (lvcsDataPoint column) =
      (source.masks row).eval (lvcsDataPoint column) +
        ∑ dataRow : Fin 140, coefficients dataRow row *
          (source.data dataRow).eval (lvcsDataPoint column) := by
  rw [recovered_projection_is_entire_response oracle response coefficients source recovered row]
  simp only [projectedSource, eval_add, eval_finsetSum, eval_mul, eval_C]

theorem recovered_rows_match_every_accepted_query (oracle : CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients)
    (source : RecoveredSource)
    (recovered : recoverSource oracle response coefficients = some source)
    (query : Query) (accepted : QueryAccepts oracle response coefficients query)
    (row : Fin 140) (index : Position) (member : index ∈ query.val) :
    (source.data row).eval (smz9EvaluationPoint index) =
      committedColumnValue oracle row index := by
  have result := recovered_source_degree_and_agreement oracle response coefficients source recovered
  have included := (query_accepts_iff_prequery_agreement oracle response coefficients query).mp accepted
  have agrees := result.2.1.2 row index (included member)
  have dataEqual : oracleData oracle row.val index = committedColumnValue oracle row index := by
    unfold oracleData
    rw [dif_pos row.isLt]
    apply congrArg (fun r : Fin lvcsRowCount => committedColumnValue oracle r index)
    exact Fin.ext rfl
  exact agrees.trans dataEqual

/-- Explicit failure predicate for the computed pre-query decoder, not an
arbitrary invalid-witness event. No probability budget is postulated here. -/
def DecoderFailure (oracle : CommittedOracle) (response : ResponseStrategy)
    (coefficients : Coefficients) (query : Query) : Prop :=
  QueryAccepts oracle response coefficients query ∧
    recoverSource oracle response coefficients = none

end
end HegemonCrypto.SmallWood.SmzaQ38McaSourceBinding
