import SmzaRp05TracePrefixes
import SmzaRp04RawAcceptedOpeningChecks

/-! Global strict-leaf-v2 recorded-path readback for the actual RP05
accepted-event oracle. No RP04 relation candidate or v1 leaf parser is used.
Recorded paths are concrete hash records and decoded edges; successful
extraction is a conclusion, not an input certificate. -/
namespace HegemonCrypto.SmallWood.SmzaRp05GlobalOpeningReadback

open SmzaRp05TracePrefixes SmzaRp05LeafNamespace
open SmzaRp05FilteredDecoderInstability
open SmzaRecordedTracePath V8Smz9CoherentMerkleGeometry
open SmzaRawRecordedPrefix (subtree subtree_cons)
open SmzaRp04RecordedClaims (mixed_committed_word_eq)
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction SmzaQ38LvcsOpening
open V8Smz9McaRecovery
open scoped Classical BigOperators

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

abbrev indexPath := SmzaRp05FilteredReadback.indexPath

theorem global_normalized_leaf_roundtrip (ns : Namespace)
    (salt : List HegemonCrypto.CanonicalBytes.Byte)
    (leaf : CurrentLeaf ns salt) :
    globalNormalizedPayload ns (encodeLeaf leaf.preamble leaf.legacyPayload) =
      some leaf.normalized := by
  have framed := encode_frame_roundtrip leaf.preamble leaf.legacyPayload
    leaf.preamble_length leaf.legacy_payload_length
  have dropped : (leaf.preamble ++ leaf.legacyPayload).drop preambleBytes =
      leaf.legacyPayload := by
    simp [leaf.preamble_length]
  have saltRead : leaf.legacyPayload.take 32 = salt := leaf.legacyCanonical.2.2.1
  simp [globalNormalizedPayload, framed, dropped, saltRead,
    normalized_roundtrip ns salt leaf]

theorem child_eq_subtree (trace : SmzaRp05TracePrefixes.Trace) (index : Nat) :
    child trace index = subtree [index] trace := by
  exact SmzaRp05FilteredReadback.child_eq_subtree trace index

theorem descend_eq_subtree (index : Position) (depth : Nat)
    (trace : SmzaRp05TracePrefixes.Trace) :
    descend index depth trace = subtree (indexPath index depth) trace := by
  induction depth generalizing trace with
  | zero => rfl
  | succ depth ih =>
      change descend index depth
          (child trace (if index.val.testBit depth then 1 else 0)) =
        subtree ((if index.val.testBit depth then 1 else 0) ::
          indexPath index depth) trace
      rw [subtree_cons, ← child_eq_subtree, ih]

theorem global_payload_of_read_path (ns : Namespace)
    (path : List Nat) (trace : SmzaRp05TracePrefixes.Trace)
    (input : V8SmzaOracleParser.RawInput) (parsed : V8SmzaOracleParser.Payload)
    (readback : readPath path trace = some input)
    (parse : globalNormalizedPayload ns input = some parsed) :
    payload ns parsed.kind (subtree path trace) = some parsed := by
  induction path generalizing trace with
  | nil =>
      cases trace with
      | missing => cases readback
      | budget => cases readback
      | record actual children =>
          have same : actual = input := Option.some.inj readback
          subst actual
          simp [subtree, payload, parse]
  | cons index rest ih =>
      cases trace with
      | missing => cases readback
      | budget => cases readback
      | record actual children =>
          simp only [readPath] at readback
          cases selected : children[index]? with
          | none => simp [selected] at readback
          | some childTrace =>
              have below : readPath rest childTrace = some input := by
                simpa only [selected, Option.bind_some] using readback
              simpa only [subtree, selected, Option.getD_some] using ih childTrace below

/-- Original full v2 addresses are selected; normalization happens only
when the extracted terminal leaf is interpreted as the 145-word oracle. -/
theorem global_root_oracle_cell_of_recorded_path
    (ns : Namespace)
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (collisionFree : RecordsCollisionFree records)
    (root : V8SmzaOracleParser.RawDigest) (index : Position) (row : Fin 145)
    (input : V8SmzaOracleParser.RawInput) (leaf : V8SmzaOracleParser.Payload)
    (recorded : RecordedPath (globalOnlineNext ns) records .root root
      (0 :: indexPath index 23) input)
    (parsed : globalNormalizedPayload ns input = some leaf)
    (kind : leaf.kind = .leaf)
    (indexWord : V8SmzaOracleParser.wordAt leaf.bytes 4 = index.val)
    (dataCount : V8SmzaOracleParser.wordAt leaf.bytes 13 = 140)
    (maskCount : V8SmzaOracleParser.wordAt leaf.bytes 154 = 5)
    (fuel : Nat) (enough : 25 ≤ fuel) :
    rootOracle ns (extract (globalOnlineNext ns) records fuel .root root)
      index row = fieldWordAt leaf.bytes
        (if row.val < 140 then 14 + row.val else 155 + (row.val - 140)) := by
  have pathRead := recorded_path_readback (globalOnlineNext ns) records collisionFree
    .root root (0 :: indexPath index 23) input recorded fuel
    (by simp only [List.length_cons, SmzaRp05FilteredReadback.index_path_length]; omega)
  have payloadRead := global_payload_of_read_path ns (0 :: indexPath index 23)
    (extract (globalOnlineNext ns) records fuel .root root) input leaf pathRead parsed
  rw [kind, subtree_cons, ← child_eq_subtree, ← descend_eq_subtree] at payloadRead
  unfold rootOracle
  rw [payloadRead]
  exact if_pos ⟨indexWord, dataCount, maskCount⟩

structure GlobalQueryReadback (ns : Namespace)
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (root : V8SmzaOracleParser.RawDigest) (query : Query) where
  input : Position → V8SmzaOracleParser.RawInput
  leaf : Position → V8SmzaOracleParser.Payload
  recorded : ∀ index ∈ query.val, RecordedPath (globalOnlineNext ns) records .root root
    (0 :: indexPath index 23) (input index)
  parsed : ∀ index ∈ query.val,
    globalNormalizedPayload ns (input index) = some (leaf index)
  kind : ∀ index ∈ query.val, (leaf index).kind = .leaf
  indexWord : ∀ index ∈ query.val, V8SmzaOracleParser.wordAt (leaf index).bytes 4 = index.val
  dataCount : ∀ index ∈ query.val, V8SmzaOracleParser.wordAt (leaf index).bytes 13 = 140
  maskCount : ∀ index ∈ query.val, V8SmzaOracleParser.wordAt (leaf index).bytes 154 = 5

/-- Actual canonical v2 leaves discharge normalization and both layout
checks. The only index equation left is the verifier's opened-index check. -/
def canonicalQueryReadback (ns : Namespace)
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (root : V8SmzaOracleParser.RawDigest) (query : Query)
    (salt : List HegemonCrypto.CanonicalBytes.Byte)
    (leaves : Position → CurrentLeaf ns salt)
    (recorded : ∀ index ∈ query.val,
      RecordedPath (globalOnlineNext ns) records .root root
        (0 :: indexPath index 23)
        (encodeLeaf (leaves index).preamble (leaves index).legacyPayload))
    (indexWord : ∀ index ∈ query.val,
      V8SmzaOracleParser.wordAt (leaves index).legacyPayload 4 = index.val) :
    GlobalQueryReadback ns records root query where
  input index := encodeLeaf (leaves index).preamble (leaves index).legacyPayload
  leaf index := (leaves index).normalized
  recorded := recorded
  parsed index _ := global_normalized_leaf_roundtrip ns salt (leaves index)
  kind _ _ := rfl
  indexWord := indexWord
  dataCount index _ := (leaves index).legacyCanonical.2.2.2.2.1
  maskCount index _ := (leaves index).legacyCanonical.2.2.2.2.2.1

variable {ns : Namespace}
variable {records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest}
variable {root : V8SmzaOracleParser.RawDigest} {query : Query}

def decodedOracle (claims : GlobalQueryReadback ns records root query) : CommittedOracle :=
  fun index row => fieldWordAt (claims.leaf index).bytes
    (if row.val < 140 then 14 + row.val else 155 + (row.val - 140))

theorem decoded_oracle_agrees_with_global_root
    (claims : GlobalQueryReadback ns records root query)
    (collisionFree : RecordsCollisionFree records) (fuel : Nat) (enough : 25 ≤ fuel)
    (index : Position) (member : index ∈ query.val) (row : Fin 145) :
    rootOracle ns (extract (globalOnlineNext ns) records fuel .root root)
      index row = decodedOracle claims index row := by
  exact global_root_oracle_cell_of_recorded_path ns records collisionFree root index row
    (claims.input index) (claims.leaf index) (claims.recorded index member)
    (claims.parsed index member) (claims.kind index member) (claims.indexWord index member)
    (claims.dataCount index member) (claims.maskCount index member) fuel enough

def FiveMcaChecks (claims : GlobalQueryReadback ns records root query)
    (response : ResponseStrategy) (coefficients : Coefficients) : Prop :=
  ∀ index ∈ query.val, ∀ row : Fin 5,
    (responsePolynomials (response coefficients) row).eval (smz9EvaluationPoint index) =
      wordToGoldilocks (decodedOracle claims index ⟨140 + row.val, by
        change 140 + row.val < 145
        omega⟩) +
        ∑ column : Fin 140, coefficients column row *
          wordToGoldilocks (decodedOracle claims index ⟨column.val, by
            change column.val < 145
            omega⟩)

def TwelveLvcsChecks (claims : GlobalQueryReadback ns records root query)
    (points : Fin 6 → Goldilocks) (claimed : ClaimedPolynomials) : Prop :=
  ∀ (combination : Combination) (index : Position), index ∈ query.val →
    (claimed combination).eval (smz9EvaluationPoint index) =
      ∑ coefficient : Fin 70, points combination.1 ^ coefficient.val *
        wordToGoldilocks (decodedOracle claims index
          ⟨(blockRow combination.2 coefficient).val, by
            change (blockRow combination.2 coefficient).val < 145
            have := (blockRow combination.2 coefficient).isLt
            omega⟩)

theorem five_checks_supply_global_query_acceptance
    (claims : GlobalQueryReadback ns records root query)
    (collisionFree : RecordsCollisionFree records) (fuel : Nat) (enough : 25 ≤ fuel)
    (response : ResponseStrategy) (coefficients : Coefficients)
    (checks : FiveMcaChecks claims response coefficients) :
    QueryAccepts (rootOracle ns
      (extract (globalOnlineNext ns) records fuel .root root)) response coefficients query := by
  intro index member row
  rw [checks index member row, mixed_committed_word_eq]
  have same (position : Fin 145) := decoded_oracle_agrees_with_global_root
    claims collisionFree fuel enough index member position
  apply congrArg₂ (· + ·)
  · exact congrArg wordToGoldilocks (same ⟨140 + row.val, by
      omega⟩).symm
  · apply Finset.sum_congr rfl
    intro column _
    exact congrArg (fun word => coefficients column row * wordToGoldilocks word)
      (same ⟨column.val, by
        omega⟩).symm

theorem twelve_checks_supply_global_opening_checks
    (claims : GlobalQueryReadback ns records root query)
    (collisionFree : RecordsCollisionFree records) (fuel : Nat) (enough : 25 ≤ fuel)
    (points : Fin 6 → Goldilocks) (claimed : ClaimedPolynomials)
    (checks : TwelveLvcsChecks claims points claimed) :
    OracleOpeningChecks (rootOracle ns
      (extract (globalOnlineNext ns) records fuel .root root)) points claimed query := by
  intro combination index member
  rw [checks combination index member]
  apply Finset.sum_congr rfl
  intro coefficient _
  have same := decoded_oracle_agrees_with_global_root claims collisionFree fuel enough
    index member ⟨(blockRow combination.2 coefficient).val, by
      have := (blockRow combination.2 coefficient).isLt
      omega⟩
  exact congrArg (fun word => points combination.1 ^ coefficient.val * wordToGoldilocks word)
    same.symm

end
end HegemonCrypto.SmallWood.SmzaRp05GlobalOpeningReadback
