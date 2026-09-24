import SmzaQ38LvcsOpening
import HegemonCrypto.SmallWoodRecordedMerkleExtraction
import SmzaRp04Payload

/-!
# RP04 recorded Merkle claims

This is the typed recorded-oracle layer for the RP04 bridge.  It deliberately stops at the
information actually supplied by a CMS database: a collision-free recorded Merkle opening fixes
the payload at its root/coordinate.  Query acceptance, LVCS head checks, and the five-MCA/twelve-
LVCS scalar checks are not manufactured here; callers must supply the corresponding typed opening
checks before applying the existing RP04 readback theorems.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04RecordedClaims

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.RecordedMerkleExtraction
open HegemonCrypto.SmallWood.V8Smz9LogicalOracle
open SmzaQ38OracleExtraction
open SmzaQ38McaSourceBinding
open SmzaQ38LvcsOpening
open V8Smz9McaDecoder V8Smz9McaRecovery
open scoped BigOperators

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
attribute [local irreducible] mixedWord

/-- The fixed fallback used when a coordinate has no complete recorded opening. -/
def fallbackPayload : Rp04Payload where
  salt := fun _ => 0
  index := ⟨0, by decide⟩
  tape := fun _ => 0
  words := fun _ => 0

/-- Coordinate-indexed root path sides for the actual RP04 commitment tree. -/
abbrev Rp04Sides := Rp04Coordinate → List ChildSide

/-- Canonical payload reconstructed from the measured database, without claiming a global hash
injectivity theorem.  Collision-freeness is an explicit event premise at every use site. -/
def extractedRp04Payload
    (database : Rp04HashDatabase) (root : Rp04Digest) (sides : Rp04Sides)
    (coordinate : Rp04Coordinate) : Rp04Payload :=
  extractedPayload fallbackPayload database root sides coordinate

/-- The extracted committed-oracle matrix used by the RP04 logical oracle. -/
def extractedCommittedOracle
    (database : Rp04HashDatabase) (root : Rp04Digest) (sides : Rp04Sides) :
    SmzaQ38OracleExtraction.CommittedOracle :=
  fun coordinate row => (extractedRp04Payload database root sides coordinate) row

structure RecordedRp04Opening
    (database : Rp04HashDatabase) (root : Rp04Digest) (sides : Rp04Sides)
    (coordinate : Rp04Coordinate) where
  payload : Rp04Payload
  opening : RecordedOpening database payload (sides coordinate) root

/-- Every collision-free recorded opening agrees with the extracted RP04 oracle. -/
theorem recorded_rp04_payload_eq_extracted
    (database : Rp04HashDatabase) (root : Rp04Digest) (sides : Rp04Sides)
    {coordinate : Rp04Coordinate}
    (collisionFree : CollisionFree database)
    (claim : RecordedRp04Opening database root sides coordinate) :
    extractedRp04Payload database root sides coordinate = claim.payload := by
  exact recorded_at_extracted_payload fallbackPayload collisionFree claim.opening

theorem recorded_rp04_oracle_cell_eq
    (database : Rp04HashDatabase) (root : Rp04Digest) (sides : Rp04Sides)
    {coordinate : Rp04Coordinate}
    (collisionFree : CollisionFree database)
    (claim : RecordedRp04Opening database root sides coordinate)
    (row : Fin 145) :
    extractedCommittedOracle database root sides coordinate row = claim.payload row := by
  exact congrArg (fun payload : Rp04Payload => payload.words row)
    (recorded_rp04_payload_eq_extracted database root sides collisionFree claim)

/-! A query bundle carries payloads selected from actual recorded openings.  The fallback is
deliberately fixed outside the query: no unrecorded coordinate is silently treated as an
authenticated opening. -/
abbrev Rp04Query := SmzaQ38McaSourceBinding.Query

structure RecordedRp04Query
    (database : Rp04HashDatabase) (root : Rp04Digest) (sides : Rp04Sides)
    (query : Rp04Query) where
  payload : Rp04Coordinate → Rp04Payload
  opening : ∀ index, index ∈ query.val → RecordedRp04Opening database root sides index
  payload_eq_opening : ∀ index (member : index ∈ query.val),
    payload index = (opening index member).payload

def openedOracle
    {database : Rp04HashDatabase} {root : Rp04Digest} {sides : Rp04Sides}
    {query : Rp04Query} (claims : RecordedRp04Query database root sides query) :
    SmzaQ38OracleExtraction.CommittedOracle :=
  fun coordinate row =>
    if coordinate ∈ query.val then claims.payload coordinate row else fallbackPayload row

def FiveMcaChecks
    (payload : Rp04Coordinate → Rp04Payload) (response : ResponseStrategy)
    (coefficients : Coefficients) (query : Rp04Query) : Prop :=
  ∀ index ∈ query.val, ∀ row,
    (responsePolynomials (response coefficients) row).eval (smz9EvaluationPoint index) =
      wordToGoldilocks (payload index ⟨140 + row.val, by omega⟩) +
        ∑ column : Fin 140, coefficients column row *
          wordToGoldilocks (payload index ⟨column.val, by omega⟩)

def TwelveLvcsChecks
    (payload : Rp04Coordinate → Rp04Payload) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials) (query : Rp04Query) : Prop :=
  ∀ (combination : SmzaQ38LvcsOpening.Combination) (index : Rp04Coordinate),
    index ∈ query.val →
    (claimed combination).eval (smz9EvaluationPoint index) =
      ∑ coefficient : Fin 70, points combination.1 ^ coefficient.val *
        wordToGoldilocks (payload index
          ⟨(SmzaQ38LvcsOpening.blockRow combination.2 coefficient).val, by omega⟩)

theorem openedOracle_agrees_extracted_on_query
    (database : Rp04HashDatabase) (root : Rp04Digest) (sides : Rp04Sides)
    (query : Rp04Query) (claims : RecordedRp04Query database root sides query)
    (collisionFree : CollisionFree database) {index : Rp04Coordinate}
    (member : index ∈ query.val) (row : Fin 145) :
    extractedCommittedOracle database root sides index row =
      openedOracle claims index row := by
  change extractedCommittedOracle database root sides index row =
    if index ∈ query.val then claims.payload index row else fallbackPayload row
  rw [if_pos member, claims.payload_eq_opening index member]
  exact recorded_rp04_oracle_cell_eq database root sides collisionFree
    (claims.opening index member) row

theorem mixed_committed_word_eq
    (oracle : SmzaQ38OracleExtraction.CommittedOracle)
    (coefficients : Coefficients) (row : Fin 5) (index : Rp04Coordinate) :
    mixedWord (oracleData oracle) (oracleMasks oracle)
      (extendCoefficients coefficients) 140 row index =
      wordToGoldilocks (oracle index ⟨140 + row.val, by
        change 140 + row.val < 145
        omega⟩) +
        ∑ column : Fin 140, coefficients column row *
          wordToGoldilocks (oracle index ⟨column.val, by
            change column.val < 145
            omega⟩) := by
  rw [mixed_word_eq_sum, ← Fin.sum_univ_eq_sum_range]
  apply congrArg₂ (· + ·)
  · rfl
  · apply Finset.sum_congr rfl
    intro column _
    rw [extendCoefficients, dif_pos column.isLt, oracleData, dif_pos column.isLt]
    rfl

theorem five_mca_checks_imply_query_accepts
    (database : Rp04HashDatabase) (root : Rp04Digest) (sides : Rp04Sides)
    (query : Rp04Query) (claims : RecordedRp04Query database root sides query)
    (collisionFree : CollisionFree database) (response : ResponseStrategy)
    (coefficients : Coefficients)
    (checked : FiveMcaChecks claims.payload response coefficients query) :
    SmzaQ38McaSourceBinding.QueryAccepts
      (extractedCommittedOracle database root sides) response coefficients query := by
  intro index member row
  rw [checked index member row, mixed_committed_word_eq]
  have words (position : Fin 145) :
      extractedCommittedOracle database root sides index position = claims.payload index position := by
    rw [claims.payload_eq_opening index member]
    exact recorded_rp04_oracle_cell_eq database root sides collisionFree
      (claims.opening index member) position
  apply congrArg₂ (· + ·)
  · exact congrArg wordToGoldilocks (words ⟨140 + row.val, by omega⟩).symm
  · apply Finset.sum_congr rfl
    intro column _
    exact congrArg (fun word => coefficients column row * wordToGoldilocks word)
      (words ⟨column.val, by omega⟩).symm

theorem twelve_lvcs_checks_imply_oracle_opening_checks
    (database : Rp04HashDatabase) (root : Rp04Digest) (sides : Rp04Sides)
    (query : Rp04Query) (claims : RecordedRp04Query database root sides query)
    (collisionFree : CollisionFree database) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (checked : TwelveLvcsChecks claims.payload points claimed query) :
    SmzaQ38LvcsOpening.OracleOpeningChecks
      (extractedCommittedOracle database root sides) points claimed query := by
  intro combination index member
  rw [checked combination index member]
  rw [claims.payload_eq_opening index member]
  apply Finset.sum_congr rfl
  intro coefficient _
  congr 2
  rw [← recorded_rp04_oracle_cell_eq database root sides collisionFree
    (claims.opening index member)
    ⟨(SmzaQ38LvcsOpening.blockRow combination.2 coefficient).val, by omega⟩]
  rfl

def recordedPayloadCell
    {database : Rp04HashDatabase} {root : Rp04Digest} {sides : Rp04Sides}
    {coordinate : Rp04Coordinate}
    (claim : RecordedRp04Opening database root sides coordinate) (row : Fin 145) : FieldWord :=
  claim.payload row

end
end HegemonCrypto.SmallWood.SmzaRp04RecordedClaims
