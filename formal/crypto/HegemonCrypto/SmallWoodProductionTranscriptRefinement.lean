import HegemonCrypto.SmallWoodBcsQrom
import HegemonCrypto.SmallWoodFixedSampling
import HegemonCrypto.SmallWoodPiopOpeningSampling
import HegemonCrypto.SmallWoodRoundByRound

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact deployed SHA-512 transcript refinement

The active verifier uses raw SHA-512 digests for transcript commitments and canonical
Goldilocks rejection sampling only for verifier challenges.  This module keeps those two
surfaces separate and constructs the four interactive challenges from the exact raw production
transcript:

1. the 5-by-138 DECS batching matrix;
2. the statement-sized 5-row PIOP batching matrix;
3. the first valid five-point PIOP opening tuple among sixteen nonce attempts; and
4. the fixed 50-candidate, first-23-distinct DECS opening set.

All functions below are deterministic consequences of one raw SHA-512 oracle.  No random-oracle
or collision-resistance assumption is used here.
-/

namespace HegemonCrypto.SmallWood.ProductionTranscriptRefinement

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.PiopOpeningSampling
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.Sha512Xof
open HegemonCrypto.SmallWoodTranscript

noncomputable section

/-- The exact field-XOF stream induced by one raw production SHA-512 oracle. -/
def productionFieldOracle (rawOracle : RawOracle) : Oracle :=
  logicalFieldOracleOfRaw rawOracle

/-- Exact first verifier challenge, in the row-major shape consumed by the DECS protocol. -/
def productionDecsChallenge
    (rawOracle : RawOracle)
    (transcript : Transcript) :
    Matrix decsEta lvcsRowCount :=
  activeDecsCoefficientMatrix
    (productionFieldOracle rawOracle)
    (rawMerkleRootDigest rawOracle transcript.commitment
      transcript.statementBindingWords).words

/-- Exact second verifier challenge for one concrete production statement. -/
def productionPiopChallenge
    (rawOracle : RawOracle)
    (transcript : Transcript)
    (statement : Statement) :
    PiopBatchingChallenge statement :=
  productionPiopCoefficientMatrix
    (productionFieldOracle rawOracle)
    (rawHashFpp rawOracle transcript.commitment
      transcript.statementBindingWords).words
    statement.nonlinearConstraintCount
    statement.linearConstraintCount

/-- Canonical list representation of the 64 forbidden packing points. -/
def productionPackingFieldWords : List FieldWord :=
  List.ofFn fun index : Fin packingFactor =>
    ⟨index.val, index.isLt.trans (by decide)⟩

theorem production_packing_field_words_toFinset :
    productionPackingFieldWords.toFinset = packingPoints := by
  ext point
  simp only [productionPackingFieldWords, List.mem_toFinset, List.mem_ofFn,
    packingPoints, Finset.mem_filter, Finset.mem_univ, true_and]
  constructor
  · rintro ⟨index, pointEqual⟩
    subst point
    exact index.isLt
  · intro bounded
    let index : Fin packingFactor := ⟨point.val, bounded⟩
    exact ⟨index, Fin.ext rfl⟩

/-- Raw PIOP digest words used by every canonical nonce attempt. -/
def productionPiopHashWords
    (rawOracle : RawOracle)
    (transcript : Transcript) : List Word :=
  (rawPiopDigest rawOracle transcript.commitment
    transcript.statementBindingWords transcript.piop).words

/-- Exact production first-valid-nonce predicate over the raw PIOP digest. -/
def ProductionCanonicalOpeningNonce
    (rawOracle : RawOracle)
    (transcript : Transcript) : Prop :=
  CanonicalOpeningNonce
    (productionFieldOracle rawOracle)
    activeParameters
    (productionPackingFieldWords.map fieldWordAsWord)
    (productionPiopHashWords rawOracle transcript)
    transcript.openingNonce

/-- Convert a canonical transmitted nonce to its bounded production retry index. -/
def productionNonceIndex
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (canonical : ProductionCanonicalOpeningNonce rawOracle transcript) :
    Fin piopNonceTrialBound :=
  ⟨transcript.openingNonce.val, canonical.1.1⟩

theorem active_nonce_word_productionNonceIndex
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (canonical : ProductionCanonicalOpeningNonce rawOracle transcript) :
    activeNonceWord (productionNonceIndex canonical) =
      transcript.openingNonce := by
  apply Fin.ext
  rfl

/-- Exact five-point PIOP opening tuple selected by the transmitted canonical nonce. -/
def productionPiopOpeningTuple
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (canonical : ProductionCanonicalOpeningNonce rawOracle transcript) :
    OpeningTuple (F := FieldWord) activeParameters.openedEvaluations :=
  activeOpeningCandidateStream
    (productionFieldOracle rawOracle)
    (productionPiopHashWords rawOracle transcript)
    (productionNonceIndex canonical)

theorem production_piop_opening_tuple_valid
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (canonical : ProductionCanonicalOpeningNonce rawOracle transcript) :
    TupleValid packingPoints
      (productionPiopOpeningTuple canonical) := by
  have validWithList :
      TupleValid productionPackingFieldWords.toFinset
        (activeOpeningCandidateStream
          (productionFieldOracle rawOracle)
          (productionPiopHashWords rawOracle transcript)
          (productionNonceIndex canonical)) := by
    apply
      (active_tuple_valid_iff_valid_opening_nonce
        (productionFieldOracle rawOracle)
        (productionPiopHashWords rawOracle transcript)
        productionPackingFieldWords
        (productionNonceIndex canonical)).2
    simpa [active_nonce_word_productionNonceIndex canonical] using canonical.1
  simpa only [productionPiopOpeningTuple,
    production_packing_field_words_toFinset] using validWithList

/-- Exact third verifier challenge as the interactive protocol's valid tuple type. -/
def productionPiopOpening
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (canonical : ProductionCanonicalOpeningNonce rawOracle transcript) :
    PiopOpeningChallenge :=
  ⟨productionPiopOpeningTuple canonical,
    production_piop_opening_tuple_valid canonical⟩

theorem production_piop_first_valid
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (canonical : ProductionCanonicalOpeningNonce rawOracle transcript) :
    firstValid packingPoints
        (streamTuples
          (activeOpeningCandidateStream
            (productionFieldOracle rawOracle)
            (productionPiopHashWords rawOracle transcript))) =
      some (productionPiopOpening canonical) := by
  let selectedIndex := productionNonceIndex canonical
  have selectedValid :
      TupleValid packingPoints
        (activeOpeningCandidateStream
          (productionFieldOracle rawOracle)
          (productionPiopHashWords rawOracle transcript)
          selectedIndex) := by
    exact production_piop_opening_tuple_valid canonical
  have earlierInvalid :
      ∀ earlier : Fin piopNonceTrialBound,
        earlier.val < selectedIndex.val ->
          ¬TupleValid packingPoints
            (activeOpeningCandidateStream
              (productionFieldOracle rawOracle)
              (productionPiopHashWords rawOracle transcript)
              earlier) := by
    intro earlier earlierBefore earlierValid
    have earlierValidWithList :
        TupleValid productionPackingFieldWords.toFinset
          (activeOpeningCandidateStream
            (productionFieldOracle rawOracle)
            (productionPiopHashWords rawOracle transcript)
            earlier) := by
      simpa [production_packing_field_words_toFinset] using earlierValid
    apply canonical.2 (activeNonceWord earlier)
    · dsimp [selectedIndex, productionNonceIndex] at earlierBefore
      change earlier.val < transcript.openingNonce.val
      exact earlierBefore
    · exact
        (active_tuple_valid_iff_valid_opening_nonce
          (productionFieldOracle rawOracle)
          (productionPiopHashWords rawOracle transcript)
          productionPackingFieldWords earlier).1 earlierValidWithList
  rw [first_valid_stream_of_canonical_index
    packingPoints
    (activeOpeningCandidateStream
      (productionFieldOracle rawOracle)
      (productionPiopHashWords rawOracle transcript))
    selectedIndex selectedValid earlierInvalid]
  rfl

/-- Exact 50-word candidate pool used by fixed no-grinding DECS sampling. -/
def productionDecsCandidates
    (rawOracle : RawOracle)
    (transcript : Transcript) : List FieldWord :=
  fieldHashWords (productionFieldOracle rawOracle)
    decsFixedSamplingDomain
    (rawDecsOpeningDigest rawOracle
      (rawPiopDigest rawOracle transcript.commitment
        transcript.statementBindingWords transcript.piop)
      transcript.opening).words
    activeDecsFixedCandidateCount

/-- Exact sorted first-23-distinct DECS indices selected by the native verifier. -/
def productionDecsSelectedIndices
    (rawOracle : RawOracle)
    (transcript : Transcript) :
    List HegemonCrypto.SmallWood.FixedSampling.DomainIndex :=
  HegemonCrypto.SmallWood.FixedSampling.selectedIndices
    (productionDecsCandidates rawOracle transcript)

theorem production_decs_selected_indices_nodup
    (rawOracle : RawOracle)
    (transcript : Transcript) :
    (productionDecsSelectedIndices rawOracle transcript).Nodup := by
  unfold productionDecsSelectedIndices
    HegemonCrypto.SmallWood.FixedSampling.selectedIndices
    HegemonCrypto.SmallWood.FixedSampling.firstDistinctIndices
  rw [List.nodup_mergeSort]
  exact
    (List.nodup_dedup
      ((productionDecsCandidates rawOracle transcript).filterMap
        HegemonCrypto.SmallWood.FixedSampling.candidateIndex)).take

theorem production_decs_selected_indices_toFinset
    (rawOracle : RawOracle)
    (transcript : Transcript) :
    (productionDecsSelectedIndices rawOracle transcript).toFinset =
      HegemonCrypto.SmallWood.FixedSampling.selectedIndexSet
        (productionDecsCandidates rawOracle transcript) := by
  ext coordinate
  simp [productionDecsSelectedIndices,
    HegemonCrypto.SmallWood.FixedSampling.selectedIndices,
    HegemonCrypto.SmallWood.FixedSampling.selectedIndexSet]

/-- The fixed candidate pool produced all 23 required distinct indices. -/
def ProductionDecsSamplerSucceeds
    (rawOracle : RawOracle)
    (transcript : Transcript) : Prop :=
  (productionDecsSelectedIndices rawOracle transcript).length =
    decsOpenedEvaluations

theorem production_decs_selected_set_card
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (success : ProductionDecsSamplerSucceeds rawOracle transcript) :
    (HegemonCrypto.SmallWood.FixedSampling.selectedIndexSet
      (productionDecsCandidates rawOracle transcript)).card =
        decsOpenedEvaluations := by
  rw [HegemonCrypto.SmallWood.FixedSampling.selected_index_set_card_eq_selected_indices_length]
  exact success

/-- Explicit identification of the sampler's `2^20` domain with the active DECS codeword. -/
theorem production_domain_size_eq_decs_evaluation_count :
    HegemonCrypto.SmallWood.FixedSampling.domainSize =
      decsEvaluationCount :=
  HegemonCrypto.SmallWood.FixedSampling.active_sampling_geometry.1

def productionDomainCoordinateEmbedding :
    HegemonCrypto.SmallWood.FixedSampling.DomainIndex ↪
      Fin decsEvaluationCount where
  toFun index :=
    Fin.cast production_domain_size_eq_decs_evaluation_count index
  inj' := by
    intro left right equal
    apply Fin.ext
    exact congrArg Fin.val equal

/-- Exact fourth verifier challenge as the interactive protocol's fixed-size subset type. -/
def productionDecsOpening
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (success : ProductionDecsSamplerSucceeds rawOracle transcript) :
    DecsOpeningChallenge :=
  ⟨HegemonCrypto.SmallWood.FixedSampling.selectedIndexSet
      (productionDecsCandidates rawOracle transcript),
    production_decs_selected_set_card success⟩

/-- Exact sorted coordinate array consumed by the native Merkle and polynomial checks. -/
def productionOpeningCoordinates
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (success : ProductionDecsSamplerSucceeds rawOracle transcript) :
    Fin decsOpenedEvaluations -> Fin decsEvaluationCount :=
  fun opening =>
    (productionDecsSelectedIndices rawOracle transcript).get
      ⟨opening.val, by
        rw [success]
        exact opening.isLt⟩

theorem production_opening_coordinates_injective
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (success : ProductionDecsSamplerSucceeds rawOracle transcript) :
    Function.Injective (productionOpeningCoordinates success) := by
  intro left right coordinatesEqual
  let leftIndex : Fin
      (productionDecsSelectedIndices rawOracle transcript).length :=
    ⟨left.val, by
      rw [success]
      exact left.isLt⟩
  let rightIndex : Fin
      (productionDecsSelectedIndices rawOracle transcript).length :=
    ⟨right.val, by
      rw [success]
      exact right.isLt⟩
  have valuesEqual :
      (productionDecsSelectedIndices rawOracle transcript).get leftIndex =
        (productionDecsSelectedIndices rawOracle transcript).get rightIndex := by
    exact Fin.ext (congrArg Fin.val coordinatesEqual)
  have indicesEqual : leftIndex = rightIndex :=
    (production_decs_selected_indices_nodup rawOracle transcript).injective_get
      valuesEqual
  apply Fin.ext
  simpa [leftIndex, rightIndex] using congrArg Fin.val indicesEqual

/-! ## Exact physical request identities -/

theorem production_decs_challenge_cell_eq_raw_request
    (rawOracle : RawOracle)
    (transcript : Transcript)
    (row : Fin decsEta)
    (column : Fin lvcsRowCount) :
    productionDecsChallenge rawOracle transcript row column =
      productionFieldOracle rawOracle
        (rawFirstChallengePreimage rawOracle transcript)
        (row.val * lvcsRowCount + column.val) := by
  rfl

theorem production_piop_challenge_cell_eq_raw_request
    (rawOracle : RawOracle)
    (transcript : Transcript)
    (statement : Statement)
    (row : Fin rho)
    (column :
      Fin (productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount)) :
    productionPiopChallenge rawOracle transcript statement row column =
      productionFieldOracle rawOracle
        (rawSecondChallengePreimage rawOracle transcript)
        (row.val *
          productionPiopRowWidth
            statement.nonlinearConstraintCount statement.linearConstraintCount +
          column.val) := by
  rfl

theorem production_selected_piop_opening_cell_eq_raw_request
    {rawOracle : RawOracle}
    {transcript : Transcript}
    (canonical : ProductionCanonicalOpeningNonce rawOracle transcript)
    (index : Fin openedEvaluations) :
    (productionPiopOpening canonical).val index =
      productionFieldOracle rawOracle
        (rawThirdChallengePreimage rawOracle transcript)
        index.val := by
  simp only [productionPiopOpening, productionPiopOpeningTuple,
    activeOpeningCandidateStream]
  rw [active_nonce_word_productionNonceIndex canonical]
  rfl

theorem production_decs_candidate_eq_raw_request
    (rawOracle : RawOracle)
    (transcript : Transcript)
    (index : Fin activeDecsFixedCandidateCount) :
    (productionDecsCandidates rawOracle transcript).get
        ⟨index.val, by
          rw [show
            (productionDecsCandidates rawOracle transcript).length =
              activeDecsFixedCandidateCount by
                exact fieldHashWords_length _ _ _ _]
          exact index.isLt⟩ =
      productionFieldOracle rawOracle
        (rawFourthChallengePreimage rawOracle transcript)
        index.val := by
  simp [productionDecsCandidates, fieldHashWords,
    rawFourthChallengePreimage]

/--
The four accepted challenge families use four pairwise-distinct raw SHA-512 base requests.
Together with the cell theorems above, this is the exact deterministic transcript boundary used
by the later physical-QROM reduction.
-/
theorem production_challenge_base_requests_nodup
    (rawOracle : RawOracle)
    (transcript : Transcript) :
    [ rawFirstChallengePreimage rawOracle transcript,
      rawSecondChallengePreimage rawOracle transcript,
      rawThirdChallengePreimage rawOracle transcript,
      rawFourthChallengePreimage rawOracle transcript ].Nodup :=
  raw_active_challenge_preimages_are_pairwise_distinct rawOracle transcript

end

end HegemonCrypto.SmallWood.ProductionTranscriptRefinement
