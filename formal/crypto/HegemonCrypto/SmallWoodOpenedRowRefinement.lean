import HegemonCrypto.SmallWoodCompactMerkleExtraction
import HegemonCrypto.SmallWoodCompiledAcceptance

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Opened-row native refinement

The Rust verifier reconstructs 26 full DECS rows, authenticates them with the compact Merkle
opening, and checks every LVCS combination at those coordinates.  This module proves that those
row-level equations are exactly the `ProductionCombinationPassesOn` predicate used by the fourth
interactive soundness round.

No probability or cryptographic assumption appears below.  Collision freedom is only consumed
when the compact recorded-query theorem identifies the authenticated row with the canonical
extracted oracle.
-/

namespace HegemonCrypto.SmallWood.OpenedRowRefinement

open Polynomial
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.CompactMerkleExtraction
open HegemonCrypto.SmallWood.LvcsOpening
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionMerkleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.Sha512Xof
open scoped BigOperators

noncomputable section

/-- The verifier's ordered 26 coordinates cover the exact fixed-cardinality challenge. -/
def CoordinatesCoverChallenge
    (coordinates : ProductionOpeningCoordinates)
    (challenge : DecsOpeningChallenge) : Prop :=
  ∀ coordinate ∈ challenge.val,
    ∃ opening, coordinates opening = coordinate

/-- Exact coordinate condition enforced by fixed sampling and sorted native reconstruction. -/
def CoordinatesExactlyChallenge
    (coordinates : ProductionOpeningCoordinates)
    (challenge : DecsOpeningChallenge) : Prop :=
  Function.Injective coordinates ∧
    CoordinatesCoverChallenge coordinates challenge

/-- Projection of one authenticated production row onto one of its 138 LVCS columns. -/
def productionRowLvcsValue
    (row : ProductionRow)
    (column : Fin lvcsRowCount) : Goldilocks :=
  wordToGoldilocks
    (row ⟨column.val, by
      have columnBound := column.isLt
      omega⟩)

/--
The Rust row-level LVCS check: the transmitted degree-400 combination polynomial evaluates to
the same linear combination of the reconstructed authenticated row.
-/
def NativeLvcsOpeningChecks
    (openingChallenge : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows) : Prop :=
  ∀ opening combination,
    (claimedCombinationPolynomial message combination).eval
        (activeEvaluationPoint (coordinates opening)) =
      ∑ column : Fin lvcsRowCount,
        productionCombinationCoefficient
            openingChallenge combination column *
          productionRowLvcsValue (rows opening) column

/-- Evaluating a committed combination is exactly the row-wise linear form. -/
theorem committed_combination_polynomial_eval
    (oracle : CommittedOracle)
    (coefficient : Fin lvcsRowCount -> Goldilocks)
    (coordinate : Fin decsEvaluationCount) :
    (committedCombinationPolynomial oracle coefficient).eval
        (activeEvaluationPoint coordinate) =
      ∑ column : Fin lvcsRowCount,
        coefficient column *
          committedColumnValue oracle column coordinate := by
  unfold committedCombinationPolynomial
  rw [eval_finsetSum]
  apply Finset.sum_congr rfl
  intro column _membership
  rw [eval_mul, eval_C, interpolated_committed_row_eval]

theorem committed_column_value_eq_authenticated_row
    (oracle : CommittedOracle)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (rowsAgree : ∀ opening, oracle (coordinates opening) = rows opening)
    (opening : OpeningIndex)
    (column : Fin lvcsRowCount) :
    committedColumnValue oracle column (coordinates opening) =
      productionRowLvcsValue (rows opening) column := by
  unfold committedColumnValue productionRowLvcsValue
  rw [rowsAgree opening]

/--
Exact row checks on a covering coordinate enumeration imply every fourth-round polynomial
opening equation.
-/
theorem native_lvcs_checks_imply_production_combinations_pass
    (oracle : CommittedOracle)
    (openingChallenge : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (decsChallenge : DecsOpeningChallenge)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (coverage : CoordinatesCoverChallenge coordinates decsChallenge)
    (rowsAgree : ∀ opening, oracle (coordinates opening) = rows opening)
    (nativeChecks :
      NativeLvcsOpeningChecks openingChallenge message coordinates rows) :
    ∀ combination : Fin openedCombinationCount,
      ProductionCombinationPassesOn
        openingChallenge message combination oracle decsChallenge := by
  intro combination coordinate coordinateMembership
  obtain ⟨opening, rfl⟩ := coverage coordinate coordinateMembership
  unfold ProductionCombinationPassesAt
  rw [committed_combination_polynomial_eval]
  calc
    (claimedCombinationPolynomial message combination).eval
          (activeEvaluationPoint (coordinates opening)) =
        ∑ column : Fin lvcsRowCount,
          productionCombinationCoefficient
              openingChallenge combination column *
            productionRowLvcsValue (rows opening) column :=
      nativeChecks opening combination
    _ =
        ∑ column : Fin lvcsRowCount,
          productionCombinationCoefficient
              openingChallenge combination column *
            committedColumnValue oracle column (coordinates opening) := by
      apply Finset.sum_congr rfl
      intro column _membership
      rw [committed_column_value_eq_authenticated_row
        oracle coordinates rows rowsAgree opening column]

/--
End-to-end fourth-round deterministic bridge from an accepted compact SHA-512 opening and native
row equations to the canonical polynomial oracle.
-/
theorem accepted_compact_rows_imply_production_combinations_pass
    (rawOracle : RawOracle)
    (salt : ProductionSalt)
    (fallback : ActiveDigest)
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database)
    (openingChallenge : PiopOpeningChallenge)
    (decsChallenge : DecsOpeningChallenge)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    {root : ActiveDigest}
    (coverage : CoordinatesCoverChallenge coordinates decsChallenge)
    (accepted :
      CompactVerifierAccepted
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth root)
    (claims :
      CompactClaimsRecorded
        (productionMerkleDatabase salt database)
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth)
    (message : PcsCombinationMessage)
    (nativeChecks :
      NativeLvcsOpeningChecks openingChallenge message coordinates rows) :
    ∀ combination : Fin openedCombinationCount,
      ProductionCombinationPassesOn
        openingChallenge message combination
          (extractedCommittedOracle salt database root) decsChallenge := by
  apply native_lvcs_checks_imply_production_combinations_pass
    (extractedCommittedOracle salt database root)
      openingChallenge message decsChallenge coordinates rows coverage
  · exact accepted_compact_rows_eq_extracted_oracle
      rawOracle salt fallback collisionFree coordinates rows paths accepted claims
  · exact nativeChecks

end

end HegemonCrypto.SmallWood.OpenedRowRefinement
