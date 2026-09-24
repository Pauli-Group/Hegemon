import HegemonCrypto.SmallWoodBcsQrom
import HegemonCrypto.SmallWoodOracleExtraction
import HegemonCrypto.SmallWoodRecordedMerkleExtraction
import HegemonCrypto.SmallWoodRoundByRound
import Mathlib.Data.List.OfFn

/-!
# Production SHA-512 Merkle extraction

This module specializes recorded-query Merkle extraction to the exact active SmallWood leaf
grammar:

* one 32-byte salt, encoded as four little-endian words;
* one 143-field-element DECS row;
* the Level-5 SHA-512 Merkle leaf and node domain tags; and
* a depth-19 binary tree over 524,288 coordinates.

It proves that a collision-free measured SHA-512 database determines one canonical total
interactive oracle.  Every recorded production opening agrees with that oracle.  The total
oracle is the polynomial completion of every leaf query with a fully recorded path to the root;
it does not pretend that unopened leaves were recovered from the Merkle commitment.
-/

namespace HegemonCrypto.SmallWood.ProductionMerkleExtraction

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.RecordedMerkleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.Sha512Xof
open HegemonCrypto.SmallWoodTranscript

abbrev ProductionSalt := Fin 4 -> Word
abbrev ProductionRow := Fin (lvcsRowCount + decsEta) -> FieldWord
abbrev ProductionHashDatabase := Database ActiveHashRequest ActiveDigest

/-- Canonical embedding of a Goldilocks field word into one serialized `u64`. -/
def fieldWordToWord (value : FieldWord) : Word :=
  ⟨value.val, value.isLt.trans (by decide)⟩

theorem field_word_to_word_injective :
    Function.Injective fieldWordToWord := by
  intro left right equal
  apply Fin.ext
  have wordValues :
      (fieldWordToWord left).val = (fieldWordToWord right).val :=
    congrArg (fun value : Word => value.val) equal
  simpa [fieldWordToWord] using wordValues

/-- Exact four-word production salt encoding. -/
def productionSaltWords (salt : ProductionSalt) : List Word :=
  List.ofFn salt

/-- Exact 143-word production leaf-row encoding. -/
def productionRowWords (row : ProductionRow) : List Word :=
  List.ofFn (fun column => fieldWordToWord (row column))

theorem production_row_words_injective :
    Function.Injective productionRowWords := by
  intro left right equal
  have pointwise :
      (fun column => fieldWordToWord (left column)) =
        fun column => fieldWordToWord (right column) :=
    List.ofFn_injective equal
  funext column
  exact field_word_to_word_injective (congrFun pointwise column)

/-- Exact raw SHA-512 request used for one production Merkle operation. -/
def productionMerkleRequest
    (salt : ProductionSalt) :
    HashInput ProductionRow ActiveDigest -> ActiveHashRequest
  | .leaf row =>
      (merkleLeafDomain, productionSaltWords salt ++ productionRowWords row)
  | .node left right =>
      (merkleNodeDomain, left.words ++ right.words)

/-- The production Merkle request grammar is unambiguous. -/
theorem production_merkle_request_injective
    (salt : ProductionSalt) :
    Function.Injective (productionMerkleRequest salt) := by
  intro leftInput rightInput sameRequest
  cases leftInput with
  | leaf leftRow =>
      cases rightInput with
      | leaf rightRow =>
          apply congrArg HashInput.leaf
          apply production_row_words_injective
          have wordsEqual :
              productionSaltWords salt ++ productionRowWords leftRow =
                productionSaltWords salt ++ productionRowWords rightRow :=
            congrArg Prod.snd sameRequest
          exact List.append_cancel_left wordsEqual
      | node rightLeft rightRight =>
          have domainEqual : merkleLeafDomain = merkleNodeDomain :=
            congrArg Prod.fst sameRequest
          exact ((by decide : merkleLeafDomain ≠ merkleNodeDomain) domainEqual).elim
  | node leftLeft leftRight =>
      cases rightInput with
      | leaf rightRow =>
          have domainEqual : merkleNodeDomain = merkleLeafDomain :=
            congrArg Prod.fst sameRequest
          exact ((by decide : merkleNodeDomain ≠ merkleLeafDomain) domainEqual).elim
      | node rightLeft rightRight =>
          have wordsEqual :
              leftLeft.words ++ leftRight.words =
                rightLeft.words ++ rightRight.words :=
            congrArg Prod.snd sameRequest
          have leftLengths :
              leftLeft.words.length = rightLeft.words.length := by
            simp [RawDigest.words_length]
          obtain ⟨leftWordsEqual, rightWordsEqual⟩ :=
            List.append_inj wordsEqual leftLengths
          have leftEqual : leftLeft = rightLeft :=
            RawDigest.words_injective leftWordsEqual
          have rightEqual : leftRight = rightRight :=
            RawDigest.words_injective rightWordsEqual
          subst leftEqual
          subst rightEqual
          rfl

/-- Total production Merkle hash induced by one raw SHA-512 oracle. -/
def productionMerkleHash
    (rawOracle : RawOracle)
    (salt : ProductionSalt)
    (input : HashInput ProductionRow ActiveDigest) : ActiveDigest :=
  activeHash rawOracle (productionMerkleRequest salt input)

/-- Restrict a measured raw SHA-512 database to production Merkle requests. -/
def productionMerkleDatabase
    (salt : ProductionSalt)
    (database : ProductionHashDatabase) :
    Database (HashInput ProductionRow ActiveDigest) ActiveDigest :=
  fun input => database (productionMerkleRequest salt input)

theorem production_merkle_database_collision_free
    (salt : ProductionSalt)
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database) :
    CollisionFree (productionMerkleDatabase salt database) := by
  intro collision
  rcases collision with
    ⟨left, right, output, different, leftRecorded, rightRecorded⟩
  apply collisionFree
  refine
    ⟨productionMerkleRequest salt left,
      productionMerkleRequest salt right,
      output, ?_, leftRecorded, rightRecorded⟩
  intro sameRequest
  exact different (production_merkle_request_injective salt sameRequest)

theorem production_merkle_database_consistent
    (rawOracle : RawOracle)
    (salt : ProductionSalt)
    {database : ProductionHashDatabase}
    (consistent : ConsistentWith (activeHash rawOracle) database) :
    ConsistentWith
      (productionMerkleHash rawOracle salt)
      (productionMerkleDatabase salt database) := by
  intro input output recorded
  exact consistent (productionMerkleRequest salt input) output recorded

/-- Side of the subtree containing `coordinate` after `level` bottom-up reductions. -/
def productionPathSideAtLevel
    (coordinate : Fin decsEvaluationCount)
    (level : Nat) : ChildSide :=
  if (coordinate.val / 2 ^ level) % 2 = 0 then
    .left
  else
    .right

/--
Root-to-leaf side list for the first `depth` bottom-up reductions.  The recursive cons places the
highest tree level first, exactly matching `RecordedOpening` and the Rust verifier's bottom-up
`index /= 2` loop.
-/
def productionPathSidesAtDepth
    (depth : Nat)
    (coordinate : Fin decsEvaluationCount) : List ChildSide :=
  match depth with
  | 0 => []
  | depth + 1 =>
      productionPathSideAtLevel coordinate depth ::
        productionPathSidesAtDepth depth coordinate

/-- Exact root-to-leaf side list for a production DECS coordinate. -/
def productionPathSides
    (coordinate : Fin decsEvaluationCount) : List ChildSide :=
  productionPathSidesAtDepth activeMerkleDepth coordinate

theorem production_path_sides_at_depth_length
    (depth : Nat)
    (coordinate : Fin decsEvaluationCount) :
    (productionPathSidesAtDepth depth coordinate).length = depth := by
  induction depth with
  | zero =>
      rfl
  | succ depth inductionHypothesis =>
      simp [productionPathSidesAtDepth, inductionHypothesis]

theorem production_path_sides_length
    (coordinate : Fin decsEvaluationCount) :
    (productionPathSides coordinate).length = activeMerkleDepth := by
  exact production_path_sides_at_depth_length activeMerkleDepth coordinate

/-- Zero completion used only for coordinates absent from the measured database. -/
def zeroProductionRow : ProductionRow :=
  fun _ => 0

/-- Pointwise row map extracted before polynomial completion. -/
noncomputable def recordedRowOracle
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest) :
    CommittedOracle :=
  extractedOracle zeroProductionRow
    (productionMerkleDatabase salt database)
    root productionPathSides

/-- A production row has a completely recorded path to the selected root. -/
def RecordedProductionRow
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest)
    (coordinate : Fin decsEvaluationCount)
    (row : ProductionRow) : Prop :=
  RecordedAt (productionMerkleDatabase salt database)
    root productionPathSides coordinate row

/-- Coordinates with at least one completely recorded path to the selected root. -/
noncomputable def recordedCoordinates
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest) :
    Finset (Fin decsEvaluationCount) := by
  classical
  exact Finset.univ.filter fun coordinate =>
    ∃ row, RecordedProductionRow salt database root coordinate row

theorem mem_recorded_coordinates
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest)
    (coordinate : Fin decsEvaluationCount) :
    coordinate ∈ recordedCoordinates salt database root ↔
      ∃ row, RecordedProductionRow salt database root coordinate row := by
  simp [recordedCoordinates]

/--
Canonical polynomial for one committed column, interpolated from every recorded leaf incoming to
the selected root.  This is the pointwise DECS extraction used by the SmallWood straight-line
extractor.
-/
noncomputable def extractedColumnPolynomial
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest)
    (column : Fin (lvcsRowCount + decsEta)) : Polynomial Goldilocks :=
  Lagrange.interpolate
    (recordedCoordinates salt database root)
    activeEvaluationPoint
    (fun coordinate =>
      wordToGoldilocks
        (recordedRowOracle salt database root coordinate column))

/--
Canonical complete interactive oracle: evaluate the polynomial extracted from each recorded
column at every production DECS point.
-/
noncomputable def extractedCommittedOracle
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest) :
    CommittedOracle :=
  fun coordinate column =>
    fieldWordGoldilocksEquiv.symm
      ((extractedColumnPolynomial salt database root column).eval
        (activeEvaluationPoint coordinate))

theorem extracted_committed_oracle_to_goldilocks
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest)
    (coordinate : Fin decsEvaluationCount)
    (column : Fin (lvcsRowCount + decsEta)) :
    wordToGoldilocks
        (extractedCommittedOracle salt database root coordinate column) =
      (extractedColumnPolynomial salt database root column).eval
        (activeEvaluationPoint coordinate) := by
  change
    toGoldilocks
        (fromGoldilocks
          ((extractedColumnPolynomial salt database root column).eval
            (activeEvaluationPoint coordinate))) =
      _
  exact toGoldilocks_fromGoldilocks _

theorem extracted_column_polynomial_degree_le
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest)
    (column : Fin (lvcsRowCount + decsEta))
    (supportBound :
      (recordedCoordinates salt database root).card ≤
        decsPolynomialDegree + 1) :
    (extractedColumnPolynomial salt database root column).natDegree ≤
      decsPolynomialDegree := by
  let polynomial :=
    extractedColumnPolynomial salt database root column
  change polynomial.natDegree ≤ decsPolynomialDegree
  by_cases polynomialZero : polynomial = 0
  · rw [polynomialZero]
    simp
  · have degreeLt :
        polynomial.degree <
          ((recordedCoordinates salt database root).card : WithBot Nat) := by
      exact Lagrange.degree_interpolate_lt
        (s := recordedCoordinates salt database root)
        (v := activeEvaluationPoint)
        (r := fun coordinate =>
          wordToGoldilocks
            (recordedRowOracle salt database root coordinate column))
        active_evaluation_point_injective.injOn
    have natDegreeLt :
        polynomial.natDegree <
          (recordedCoordinates salt database root).card :=
      (Polynomial.natDegree_lt_iff_degree_lt polynomialZero).2 degreeLt
    omega

/--
At most 401 recorded coordinates always interpolate to valid degree-400 production rows.  Larger
recorded prefixes are handled by the first interactive degree-enforcement challenge.
-/
theorem extracted_committed_rows_degree_bounded_of_card_le
    (salt : ProductionSalt)
    (database : ProductionHashDatabase)
    (root : ActiveDigest)
    (supportBound :
      (recordedCoordinates salt database root).card ≤
        decsPolynomialDegree + 1) :
    CommittedRowsDegreeBounded
      (extractedCommittedOracle salt database root) := by
  intro row
  let column : Fin (lvcsRowCount + decsEta) :=
    ⟨row.val, by
      have rowBound := row.isLt
      omega⟩
  refine
    ⟨extractedColumnPolynomial salt database root column,
      extracted_column_polynomial_degree_le
        salt database root column supportBound, ?_⟩
  intro coordinate _membership
  rw [← extracted_committed_oracle_to_goldilocks
    salt database root coordinate column]
  rfl

/--
Every fully recorded accepted row is exactly the corresponding row of the canonical extracted
interactive oracle.
-/
theorem recorded_production_row_eq_extracted
    (salt : ProductionSalt)
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database)
    {root : ActiveDigest}
    {coordinate : Fin decsEvaluationCount}
    {row : ProductionRow}
    (recorded : RecordedProductionRow salt database root coordinate row) :
    extractedCommittedOracle salt database root coordinate = row := by
  have collisionFreeMerkle :
      CollisionFree (productionMerkleDatabase salt database) :=
    production_merkle_database_collision_free salt collisionFree
  have rawRow :
      recordedRowOracle salt database root coordinate = row :=
    recorded_at_extracted_oracle zeroProductionRow
      collisionFreeMerkle recorded
  have coordinateRecorded :
      coordinate ∈ recordedCoordinates salt database root :=
    (mem_recorded_coordinates salt database root coordinate).2
      ⟨row, recorded⟩
  funext column
  apply fieldWordGoldilocksEquiv.injective
  simp only [extractedCommittedOracle, Equiv.apply_symm_apply]
  change
    (extractedColumnPolynomial salt database root column).eval
        (activeEvaluationPoint coordinate) =
      wordToGoldilocks (row column)
  have interpolationEval :
      (extractedColumnPolynomial salt database root column).eval
          (activeEvaluationPoint coordinate) =
        wordToGoldilocks
          (recordedRowOracle salt database root coordinate column) := by
    unfold extractedColumnPolynomial
    exact Lagrange.eval_interpolate_at_node
      (s := recordedCoordinates salt database root)
      (v := activeEvaluationPoint)
      (r := fun selected =>
        wordToGoldilocks
          (recordedRowOracle salt database root selected column))
      active_evaluation_point_injective.injOn coordinateRecorded
  rw [interpolationEval]
  exact congrArg (fun selected => wordToGoldilocks (selected column)) rawRow

end HegemonCrypto.SmallWood.ProductionMerkleExtraction
