import HegemonCrypto.SmallWoodAccumulatedMerkleExtraction
import HegemonCrypto.SmallWoodCompactMerkleExtraction
import HegemonCrypto.SmallWoodDecsExtraction
import HegemonCrypto.SmallWoodProductionBcsInstantiation

set_option maxHeartbeats 100000
set_option maxRecDepth 100000

/-!
# Production accepted-opening accumulation

The compiled SmallWood extractor must not interpolate every leaf query in the
measured hash database. An adversary may query unrelated leaves. Instead it
accumulates rows authenticated by accepted verifier executions that share one
commitment root and first-round DECS response.

This module proves the deterministic degree-enforcement bridge for that exact
support. If the accumulated support has at most `d + 1` coordinates, every
interpolated committed column has degree at most `d`. Otherwise the accepted
response equations identify every challenged affine combination with the
transmitted degree-`d` response polynomial. Consequently an extracted oracle
outside the degree bound can occur only in `DecsChallengePasses`, the first
interactive failure event already charged by the concrete soundness theorem.
-/

namespace HegemonCrypto.SmallWood.ProductionAccumulatedExtraction

open Polynomial
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.CompactMerkleExtraction
open HegemonCrypto.SmallWood.DecsExtraction
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionBcsInstantiation
open HegemonCrypto.SmallWood.ProductionMerkleExtraction
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.RecordedMerkleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodPowerBatching
open scoped BigOperators

noncomputable section

/-- Canonical polynomial represented by one transmitted DECS coefficient row. -/
def responsePolynomial
    (message : DecsPolynomialMessage)
    (repetition : Fin decsEta) : Goldilocks[X] :=
  fieldWordPolynomial (message repetition)

theorem response_polynomial_degree_le
    (message : DecsPolynomialMessage)
    (repetition : Fin decsEta) :
    (responsePolynomial message repetition).natDegree ≤
      decsPolynomialDegree := by
  exact field_word_polynomial_degree_le _

/-- Committed-column value carried by one authenticated production row. -/
def rowCommittedValue
    (row : ProductionRow)
    (column : Fin lvcsRowCount) : Goldilocks :=
  wordToGoldilocks
    (row ⟨column.val, column.isLt.trans (by decide)⟩)

/-- Independent DECS masking value carried by one authenticated production row. -/
def rowMaskValue
    (row : ProductionRow)
    (repetition : Fin decsEta) : Goldilocks :=
  wordToGoldilocks
    (row ⟨lvcsRowCount + repetition.val, by
      have repetitionBound := repetition.isLt
      omega⟩)

/--
Exact row equation checked by `decs_commitment_transcript_with_challenge`.
The right side is the authenticated row's challenged committed-column sum plus
its independently committed mask value.
-/
def ResponseEquation
    (challenge : Matrix decsEta lvcsRowCount)
    (message : DecsPolynomialMessage)
    (coordinate : Fin decsEvaluationCount)
    (row : ProductionRow) : Prop :=
  ∀ repetition,
    (responsePolynomial message repetition).eval
        (activeEvaluationPoint coordinate) =
      (∑ column : Fin lvcsRowCount,
          wordToGoldilocks (challenge repetition column) *
            rowCommittedValue row column) +
        rowMaskValue row repetition

/--
One row admitted to the extractor. Both authentication and the DECS response
equation come from an accepted verifier execution.
-/
structure AcceptedResponseRow
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest)
    (challenge : Matrix decsEta lvcsRowCount)
    (message : DecsPolynomialMessage) where
  coordinate : Fin decsEvaluationCount
  row : ProductionRow
  recorded : RecordedProductionRow salt database root coordinate row
  response : ResponseEquation challenge message coordinate row

abbrev AcceptedTrace
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest)
    (challenge : Matrix decsEta lvcsRowCount)
    (message : DecsPolynomialMessage) :=
  List (AcceptedResponseRow salt database root challenge message)

/-- Exact DECS equations checked on every row reconstructed by one native opening. -/
def NativeDecsOpeningChecks
    (challenge : Matrix decsEta lvcsRowCount)
    (message : DecsPolynomialMessage)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows) : Prop :=
  ∀ opening,
    ResponseEquation challenge message (coordinates opening) (rows opening)

/-- A concrete authenticated row occurs in the accepted-rewind trace. -/
def TraceRowAt
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (coordinate : Fin decsEvaluationCount)
    (row : ProductionRow) : Prop :=
  ∃ accepted ∈ trace,
    accepted.coordinate = coordinate ∧ accepted.row = row

/--
Rows from one accepted compact verifier execution form a valid extractor trace.
The compact-recording theorem supplies authentication; the native DECS check
supplies the response equation.
-/
noncomputable def acceptedTraceOfCompact
    (rawOracle : HegemonCrypto.SmallWood.Sha512Xof.RawOracle)
    (salt : ProductionSalt)
    (fallback : ActiveDigest)
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    (challenge : Matrix decsEta lvcsRowCount)
    (message : DecsPolynomialMessage)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (accepted :
      CompactVerifierAccepted
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth root)
    (claims :
      CompactClaimsRecorded
        (productionMerkleDatabase salt database)
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth)
    (checks : NativeDecsOpeningChecks challenge message coordinates rows) :
    AcceptedTrace salt database root challenge message :=
  List.ofFn fun opening =>
    { coordinate := coordinates opening
      row := rows opening
      recorded :=
        accepted_compact_opening_records_every_row
          rawOracle salt fallback coordinates rows paths accepted claims opening
      response := checks opening }

theorem accepted_trace_of_compact_contains_every_row
    (rawOracle : HegemonCrypto.SmallWood.Sha512Xof.RawOracle)
    (salt : ProductionSalt)
    (fallback : ActiveDigest)
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    (challenge : Matrix decsEta lvcsRowCount)
    (message : DecsPolynomialMessage)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (accepted :
      CompactVerifierAccepted
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth root)
    (claims :
      CompactClaimsRecorded
        (productionMerkleDatabase salt database)
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth)
    (checks : NativeDecsOpeningChecks challenge message coordinates rows)
    (opening : OpeningIndex) :
    TraceRowAt
      (acceptedTraceOfCompact rawOracle salt fallback challenge message
        coordinates rows paths accepted claims checks)
      (coordinates opening) (rows opening) := by
  let selected :
      AcceptedResponseRow salt database root challenge message :=
    { coordinate := coordinates opening
      row := rows opening
      recorded :=
        accepted_compact_opening_records_every_row
          rawOracle salt fallback coordinates rows paths accepted claims opening
      response := checks opening }
  refine ⟨selected, ?_, rfl, rfl⟩
  simp [selected, acceptedTraceOfCompact]
  exact ⟨opening, rfl, rfl⟩

/-- Coordinates accumulated from accepted verifier executions only. -/
def acceptedCoordinates
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message) :
    Finset (Fin decsEvaluationCount) := by
  classical
  exact (trace.map AcceptedResponseRow.coordinate).toFinset

theorem mem_accepted_coordinates
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (coordinate : Fin decsEvaluationCount) :
    coordinate ∈ acceptedCoordinates trace ↔
      ∃ row, TraceRowAt trace coordinate row := by
  constructor
  · intro member
    rw [acceptedCoordinates, List.mem_toFinset, List.mem_map] at member
    obtain ⟨accepted, acceptedMember, coordinateEq⟩ := member
    exact ⟨accepted.row, accepted, acceptedMember,
      coordinateEq, rfl⟩
  · rintro ⟨row, accepted, acceptedMember, coordinateEq, _rowEq⟩
    rw [acceptedCoordinates, List.mem_toFinset, List.mem_map]
    exact ⟨accepted, acceptedMember, coordinateEq⟩

theorem trace_rows_unique
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database)
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    {trace : AcceptedTrace salt database root challenge message}
    {coordinate : Fin decsEvaluationCount}
    {leftRow rightRow : ProductionRow}
    (left : TraceRowAt trace coordinate leftRow)
    (right : TraceRowAt trace coordinate rightRow) :
    leftRow = rightRow := by
  obtain ⟨leftAccepted, _leftMember, leftCoordinate, leftRowEq⟩ := left
  obtain ⟨rightAccepted, _rightMember, rightCoordinate, rightRowEq⟩ := right
  subst leftRow
  subst rightRow
  have sameCoordinate :
      leftAccepted.coordinate = rightAccepted.coordinate :=
    leftCoordinate.trans rightCoordinate.symm
  have sameSides :
      productionPathSides leftAccepted.coordinate =
        productionPathSides rightAccepted.coordinate := by
    rw [sameCoordinate]
  exact recorded_opening_payload_unique
    (production_merkle_database_collision_free salt collisionFree)
    leftAccepted.recorded
    (by
      simpa only [RecordedProductionRow, RecordedAt, sameCoordinate] using
        rightAccepted.recorded)

/-- Canonical accumulated row, with zero used only outside accepted support. -/
def accumulatedRow
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (coordinate : Fin decsEvaluationCount) : ProductionRow := by
  classical
  exact
    if present : ∃ row, TraceRowAt trace coordinate row then
      Classical.choose present
    else
      zeroProductionRow

theorem accumulated_row_eq
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database)
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    {trace : AcceptedTrace salt database root challenge message}
    {coordinate : Fin decsEvaluationCount}
    {row : ProductionRow}
    (recorded : TraceRowAt trace coordinate row) :
    accumulatedRow trace coordinate = row := by
  let present : ∃ selected, TraceRowAt trace coordinate selected :=
    ⟨row, recorded⟩
  rw [accumulatedRow, dif_pos present]
  exact trace_rows_unique collisionFree (Classical.choose_spec present) recorded

/-- One accumulated column polynomial, interpolated only over accepted rows. -/
def accumulatedColumnPolynomial
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (column : Fin (lvcsRowCount + decsEta)) : Goldilocks[X] :=
  Lagrange.interpolate
    (acceptedCoordinates trace)
    activeEvaluationPoint
    (fun coordinate =>
      wordToGoldilocks (accumulatedRow trace coordinate column))

/-- Complete extracted interactive oracle obtained from the accepted support. -/
def accumulatedCommittedOracle
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message) :
    CommittedOracle :=
  fun coordinate column =>
    fieldWordGoldilocksEquiv.symm
      ((accumulatedColumnPolynomial trace column).eval
        (activeEvaluationPoint coordinate))

theorem accumulated_column_eval_on_support
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    {coordinate : Fin decsEvaluationCount}
    (coordinateMember : coordinate ∈ acceptedCoordinates trace)
    (column : Fin (lvcsRowCount + decsEta)) :
    (accumulatedColumnPolynomial trace column).eval
        (activeEvaluationPoint coordinate) =
      wordToGoldilocks (accumulatedRow trace coordinate column) := by
  exact Lagrange.eval_interpolate_at_node
    (s := acceptedCoordinates trace)
    (v := activeEvaluationPoint)
    (r := fun selected =>
      wordToGoldilocks (accumulatedRow trace selected column))
    active_evaluation_point_injective.injOn coordinateMember

theorem accumulated_committed_oracle_row_eq
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database)
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    {trace : AcceptedTrace salt database root challenge message}
    {coordinate : Fin decsEvaluationCount}
    {row : ProductionRow}
    (recorded : TraceRowAt trace coordinate row) :
    accumulatedCommittedOracle trace coordinate = row := by
  have coordinateMember :
      coordinate ∈ acceptedCoordinates trace :=
    (mem_accepted_coordinates trace coordinate).2 ⟨row, recorded⟩
  funext column
  apply fieldWordGoldilocksEquiv.injective
  simp only [accumulatedCommittedOracle, Equiv.apply_symm_apply]
  rw [accumulated_column_eval_on_support trace coordinateMember column]
  rw [accumulated_row_eq collisionFree recorded]
  rfl

theorem accumulated_committed_oracle_to_goldilocks
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (coordinate : Fin decsEvaluationCount)
    (column : Fin (lvcsRowCount + decsEta)) :
    wordToGoldilocks
        (accumulatedCommittedOracle trace coordinate column) =
      (accumulatedColumnPolynomial trace column).eval
        (activeEvaluationPoint coordinate) := by
  change toGoldilocks (fromGoldilocks _) = _
  exact toGoldilocks_fromGoldilocks _

theorem accumulated_column_degree_lt_support
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (column : Fin (lvcsRowCount + decsEta)) :
    (accumulatedColumnPolynomial trace column).degree <
      (acceptedCoordinates trace).card := by
  exact Lagrange.degree_interpolate_lt
    (s := acceptedCoordinates trace)
    (v := activeEvaluationPoint)
    (r := fun selected =>
      wordToGoldilocks (accumulatedRow trace selected column))
    active_evaluation_point_injective.injOn

private theorem natDegree_fin_sum_le
    {count bound : Nat}
    (polynomials : Fin count → Goldilocks[X])
    (bounded : ∀ index, (polynomials index).natDegree ≤ bound) :
    (∑ index, polynomials index).natDegree ≤ bound := by
  apply Polynomial.natDegree_sum_le_of_forall_le Finset.univ polynomials
  intro index _membership
  exact bounded index

theorem accumulated_rows_degree_bounded_of_card_le
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (supportBound :
      (acceptedCoordinates trace).card ≤ decsPolynomialDegree + 1) :
    CommittedRowsDegreeBounded (accumulatedCommittedOracle trace) := by
  intro row
  let column : Fin (lvcsRowCount + decsEta) :=
    ⟨row.val, by
      have rowBound := row.isLt
      change row.val < lvcsRowCount + decsEta
      omega⟩
  refine
    ⟨accumulatedColumnPolynomial trace column, ?_, ?_⟩
  · by_cases polynomialZero :
        accumulatedColumnPolynomial trace column = 0
    · rw [polynomialZero]
      simp
    · have degreeLt :=
        accumulated_column_degree_lt_support trace column
      have natDegreeLt :
          (accumulatedColumnPolynomial trace column).natDegree <
            (acceptedCoordinates trace).card :=
        (Polynomial.natDegree_lt_iff_degree_lt polynomialZero).2 degreeLt
      omega
  · intro coordinate _membership
    rw [← accumulated_committed_oracle_to_goldilocks
      trace coordinate column]
    rfl

/-- Polynomial affine combination represented by the accumulated columns. -/
def accumulatedAffinePolynomial
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (repetition : Fin decsEta) : Goldilocks[X] :=
  (∑ column : Fin lvcsRowCount,
      Polynomial.C
          (wordToGoldilocks (challenge repetition column)) *
        accumulatedColumnPolynomial trace
          ⟨column.val, column.isLt.trans (by decide)⟩) +
    accumulatedColumnPolynomial trace
      ⟨lvcsRowCount + repetition.val, by
        have repetitionBound := repetition.isLt
        omega⟩

theorem accumulated_affine_polynomial_degree_lt_support
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (supportPositive : 0 < (acceptedCoordinates trace).card)
    (repetition : Fin decsEta) :
    (accumulatedAffinePolynomial trace repetition).degree <
      (acceptedCoordinates trace).card := by
  have columnNatDegree :
      ∀ column : Fin (lvcsRowCount + decsEta),
        (accumulatedColumnPolynomial trace column).natDegree <
          (acceptedCoordinates trace).card := by
    intro column
    by_cases polynomialZero :
        accumulatedColumnPolynomial trace column = 0
    · rw [polynomialZero]
      simpa using supportPositive
    · exact
        (Polynomial.natDegree_lt_iff_degree_lt polynomialZero).2
          (accumulated_column_degree_lt_support trace column)
  have sumNatDegree :
      (∑ column : Fin lvcsRowCount,
          Polynomial.C
              (wordToGoldilocks (challenge repetition column)) *
            accumulatedColumnPolynomial trace
              ⟨column.val, column.isLt.trans (by decide)⟩).natDegree <
        (acceptedCoordinates trace).card := by
    apply lt_of_le_of_lt
      (natDegree_fin_sum_le
        (fun column : Fin lvcsRowCount =>
          Polynomial.C
              (wordToGoldilocks (challenge repetition column)) *
            accumulatedColumnPolynomial trace
              ⟨column.val, column.isLt.trans (by decide)⟩)
        (bound := (acceptedCoordinates trace).card - 1) ?_)
    · omega
    · intro column
      exact
        (Polynomial.natDegree_C_mul_le _ _).trans
          (by
            have bounded := columnNatDegree
              ⟨column.val, column.isLt.trans (by decide)⟩
            omega)
  have maskNatDegree :
      (accumulatedColumnPolynomial trace
        ⟨lvcsRowCount + repetition.val, by
          have repetitionBound := repetition.isLt
          omega⟩).natDegree <
        (acceptedCoordinates trace).card :=
    columnNatDegree
      ⟨lvcsRowCount + repetition.val, by
        have repetitionBound := repetition.isLt
        omega⟩
  have affineNatDegree :
      (accumulatedAffinePolynomial trace repetition).natDegree <
        (acceptedCoordinates trace).card := by
    unfold accumulatedAffinePolynomial
    refine lt_of_le_of_lt (Polynomial.natDegree_add_le _ _) ?_
    exact max_lt sumNatDegree maskNatDegree
  exact Polynomial.degree_le_natDegree.trans_lt
    (by exact_mod_cast affineNatDegree)

theorem accumulated_affine_eval_eq
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (repetition : Fin decsEta)
    (coordinate : Fin decsEvaluationCount) :
    (accumulatedAffinePolynomial trace repetition).eval
        (activeEvaluationPoint coordinate) =
      affineCombinedWord
        (committedColumnValue (accumulatedCommittedOracle trace))
        (maskingColumnValue (accumulatedCommittedOracle trace))
        (decsChallengeToGoldilocks challenge)
        repetition coordinate := by
  unfold accumulatedAffinePolynomial affineCombinedWord
    committedColumnValue maskingColumnValue decsChallengeToGoldilocks
  rw [eval_add, eval_finsetSum]
  apply congrArg₂ (· + ·)
  · apply Finset.sum_congr rfl
    intro column _membership
    simp only [eval_mul, eval_C]
    rw [accumulated_committed_oracle_to_goldilocks]
  · rw [accumulated_committed_oracle_to_goldilocks]

theorem response_equation_on_accumulated_support
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database)
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    {trace : AcceptedTrace salt database root challenge message}
    {coordinate : Fin decsEvaluationCount}
    (coordinateMember : coordinate ∈ acceptedCoordinates trace)
    (repetition : Fin decsEta) :
    (responsePolynomial message repetition).eval
        (activeEvaluationPoint coordinate) =
      (accumulatedAffinePolynomial trace repetition).eval
        (activeEvaluationPoint coordinate) := by
  obtain ⟨row, rowInTrace⟩ :=
    (mem_accepted_coordinates trace coordinate).1 coordinateMember
  have extractedRow :=
    accumulated_committed_oracle_row_eq collisionFree rowInTrace
  obtain ⟨accepted, _acceptedMember, acceptedCoordinate, acceptedRow⟩ :=
    rowInTrace
  have response := accepted.response repetition
  rw [accumulated_affine_eval_eq]
  unfold affineCombinedWord committedColumnValue maskingColumnValue
    decsChallengeToGoldilocks
  rw [extractedRow]
  simpa [acceptedCoordinate, acceptedRow, decsChallengeToGoldilocks,
    committedColumnValue, maskingColumnValue, rowCommittedValue,
    rowMaskValue] using response

theorem accumulated_affine_eq_response_of_large_support
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database)
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (supportLarge :
      decsPolynomialDegree + 2 ≤ (acceptedCoordinates trace).card)
    (repetition : Fin decsEta) :
    accumulatedAffinePolynomial trace repetition =
      responsePolynomial message repetition := by
  apply Polynomial.eq_of_degrees_lt_of_eval_index_eq
    (acceptedCoordinates trace)
    active_evaluation_point_injective.injOn
  · exact accumulated_affine_polynomial_degree_lt_support trace
      (by omega) repetition
  · refine lt_of_le_of_lt
      (degree_le_of_natDegree_le
        (response_polynomial_degree_le message repetition)) ?_
    exact_mod_cast (by omega :
      decsPolynomialDegree < (acceptedCoordinates trace).card)
  · intro coordinate coordinateMember
    exact
      (response_equation_on_accumulated_support
        collisionFree coordinateMember repetition).symm

/--
Accepted accumulated responses derive the complete first-round semantic fact;
there is no caller-supplied `decsFirstRoundGood` premise.
-/
theorem accumulated_acceptance_implies_first_round_good
    (statement : Statement)
    {salt : ProductionSalt}
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database)
    {root : ActiveDigest}
    {challenge : Matrix decsEta lvcsRowCount}
    {message : DecsPolynomialMessage}
    (trace : AcceptedTrace salt database root challenge message)
    (notDegreeBounded :
      ¬CommittedRowsDegreeBounded (accumulatedCommittedOracle trace)) :
    FirstRoundGood statement (accumulatedCommittedOracle trace) challenge := by
  apply Or.inr
  refine ⟨notDegreeBounded, ?_⟩
  have supportLarge :
      decsPolynomialDegree + 2 ≤ (acceptedCoordinates trace).card := by
    by_contra notLarge
    apply notDegreeBounded
    apply accumulated_rows_degree_bounded_of_card_le trace
    omega
  unfold DecsChallengePasses degreeEnforcementFailureSet
  simp only [Finset.mem_filter, Finset.mem_univ, true_and]
  intro repetition
  refine
    ⟨responsePolynomial message repetition,
      response_polynomial_degree_le message repetition, ?_⟩
  intro coordinate _membership
  rw [← accumulated_affine_eval_eq trace repetition coordinate]
  rw [accumulated_affine_eq_response_of_large_support
    collisionFree trace supportLarge repetition]

end

end HegemonCrypto.SmallWood.ProductionAccumulatedExtraction
