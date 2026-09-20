import SmzaRp04RawRootReadback
import SmzaRp04RecordedClaims

/-! The actual parsed leaf words and the verifier's five/twelve scalar
equations imply the logical MCA/LVCS checks on the extracted root oracle.
No successful MCA decoding or equality to an honest witness is assumed. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawAcceptedOpeningChecks

open SmzaRp04TracePrefixes SmzaRp04RawRootReadback
open SmzaRecordedTracePath SmzaRawStageGeometry
open V8Smz9CoherentMerkleGeometry V8SmzaOnlineParser
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction SmzaQ38LvcsOpening
open V8Smz9McaRecovery
open SmzaRp04RecordedClaims
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

structure RawQueryReadback
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (root : V8SmzaOracleParser.RawDigest) (query : Query) where
  input : Position → V8SmzaOracleParser.RawInput
  leaf : Position → V8SmzaOracleParser.Payload
  recorded : ∀ index ∈ query.val, RecordedPath rawOnlineNext records .root root
    (0 :: indexPath index 23) (input index)
  parsed : ∀ index ∈ query.val,
    V8SmzaOracleParser.rawPayload (input index) = some (leaf index)
  kind : ∀ index ∈ query.val, (leaf index).kind = .leaf
  indexWord : ∀ index ∈ query.val,
    V8SmzaOracleParser.wordAt (leaf index).bytes 4 = index.val
  dataCount : ∀ index ∈ query.val,
    V8SmzaOracleParser.wordAt (leaf index).bytes 13 = 140
  maskCount : ∀ index ∈ query.val,
    V8SmzaOracleParser.wordAt (leaf index).bytes 154 = 5

def decodedOracle
    {records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : RawQueryReadback records root query) : CommittedOracle :=
  fun index row => fieldWordAt (claims.leaf index).bytes
    (if row.val < 140 then 14 + row.val else 155 + (row.val - 140))

theorem decoded_oracle_agrees_with_extracted_root
    {records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : RawQueryReadback records root query)
    (collisionFree : RecordsCollisionFree records)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (index : Position) (member : index ∈ query.val) (row : Fin 145) :
    rootOracle (extract rawOnlineNext records fuel .root root) index row =
      decodedOracle claims index row := by
  exact root_oracle_cell_of_recorded_path records collisionFree root index row
    (claims.input index) (claims.leaf index) (claims.recorded index member)
    (claims.parsed index member) (claims.kind index member)
    (claims.indexWord index member) (claims.dataCount index member)
    (claims.maskCount index member) fuel enough

def RawFiveMcaChecks
    {records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : RawQueryReadback records root query)
    (response : ResponseStrategy) (coefficients : Coefficients) : Prop :=
  ∀ index ∈ query.val, ∀ row : Fin 5,
    (responsePolynomials (response coefficients) row).eval (smz9EvaluationPoint index) =
      wordToGoldilocks (decodedOracle claims index
        ⟨140 + row.val, by change 140 + row.val < 145; omega⟩) +
        ∑ column : Fin 140, coefficients column row *
          wordToGoldilocks (decodedOracle claims index
            ⟨column.val, by change column.val < 145; omega⟩)

def RawTwelveLvcsChecks
    {records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : RawQueryReadback records root query) (points : Fin 6 → Goldilocks)
    (claimed : ClaimedPolynomials) : Prop :=
  ∀ (combination : SmzaQ38LvcsOpening.Combination) (index : Position),
    index ∈ query.val →
    (claimed combination).eval (smz9EvaluationPoint index) =
      ∑ coefficient : Fin 70, points combination.1 ^ coefficient.val *
        wordToGoldilocks (decodedOracle claims index
          ⟨(blockRow combination.2 coefficient).val,
            by change (blockRow combination.2 coefficient).val < 145; omega⟩)

theorem raw_five_checks_supply_query_acceptance
    {records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : RawQueryReadback records root query)
    (collisionFree : RecordsCollisionFree records)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (response : ResponseStrategy) (coefficients : Coefficients)
    (checks : RawFiveMcaChecks claims response coefficients) :
    QueryAccepts (rootOracle (extract rawOnlineNext records fuel .root root))
      response coefficients query := by
  intro index member row
  rw [checks index member row, mixed_committed_word_eq]
  have same (position : Fin 145) := decoded_oracle_agrees_with_extracted_root
    claims collisionFree fuel enough index member position
  apply congrArg₂ (· + ·)
  · exact congrArg wordToGoldilocks (same ⟨140 + row.val, by omega⟩).symm
  · apply Finset.sum_congr rfl
    intro column _
    exact congrArg (fun word => coefficients column row * wordToGoldilocks word)
      (same ⟨column.val, by omega⟩).symm

theorem raw_twelve_checks_supply_oracle_opening_checks
    {records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : RawQueryReadback records root query)
    (collisionFree : RecordsCollisionFree records)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (points : Fin 6 → Goldilocks) (claimed : ClaimedPolynomials)
    (checks : RawTwelveLvcsChecks claims points claimed) :
    OracleOpeningChecks (rootOracle (extract rawOnlineNext records fuel .root root))
      points claimed query := by
  intro combination index member
  rw [checks combination index member]
  apply Finset.sum_congr rfl
  intro coefficient _
  have same := decoded_oracle_agrees_with_extracted_root claims collisionFree fuel
    enough index member ⟨(blockRow combination.2 coefficient).val, by omega⟩
  exact congrArg (fun word => points combination.1 ^ coefficient.val * wordToGoldilocks word)
    same.symm

end
end HegemonCrypto.SmallWood.SmzaRp04RawAcceptedOpeningChecks
