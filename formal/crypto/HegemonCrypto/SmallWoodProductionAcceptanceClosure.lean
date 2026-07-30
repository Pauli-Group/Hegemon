import HegemonCrypto.SmallWoodNativeLvcsReconstruction
import HegemonCrypto.SmallWoodNativeDecsReconstruction
import HegemonCrypto.SmallWoodNativePiopReconstruction
import HegemonCrypto.SmallWoodNativePiopTraceReconstruction
import HegemonCrypto.SmallWoodProductionAccumulatedExtraction
import HegemonCrypto.SmallWoodProductionStatementBinding
import HegemonCrypto.SmallWoodProductionTranscriptRefinement
import HegemonCrypto.SmallWoodProductionWireRefinement
import HegemonCrypto.TransactionProofWire

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Production compiled-acceptance closure

This is the deterministic theorem joining the deployed SmallWood verifier surfaces:

* compact SHA-512 Merkle multi-opening;
* canonical pointwise-oracle extraction;
* DECS degree-check consequence;
* native nonlinear and sparse-linear PIOP equations;
* LVCS equations at all 20 sampled coordinates; and
* the four-round interactive semantic state consumed by the CMS/QROM extractor.

The theorem does not assume a generic native-verifier Boolean. Each field of the execution-evidence
record is an exact field/hash equation, canonical decoder result, measured-database inclusion, or a
previously proved semantic consequence. The separate compiled-Rust refinement boundary is that an
arbitrary successful production verifier execution constructs this record. Probability enters
afterward through extraction failure and hash-database collisions.
-/

namespace HegemonCrypto.SmallWood.ProductionAcceptanceClosure

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.CompiledAcceptance
open HegemonCrypto.SmallWood.CompactMerkleExtraction
open HegemonCrypto.SmallWood.LvcsOpening
open HegemonCrypto.SmallWood.NativeDecsReconstruction
open HegemonCrypto.SmallWood.NativeLvcsReconstruction
open HegemonCrypto.SmallWood.NativePcsMessageReconstruction
open HegemonCrypto.SmallWood.NativePiopRefinement
open HegemonCrypto.SmallWood.NativePiopReconstruction
open HegemonCrypto.SmallWood.NativePiopTraceReconstruction
open HegemonCrypto.SmallWood.OpenedRowRefinement
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionBcsInstantiation
open HegemonCrypto.SmallWood.ProductionMerkleExtraction
open HegemonCrypto.SmallWood.ProductionAccumulatedExtraction
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.ProductionStatementBinding
open HegemonCrypto.SmallWood.ProductionTranscriptRefinement
open HegemonCrypto.SmallWood.ProductionWireRefinement
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.Sha512Xof
open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.TransactionProofWire

noncomputable section

def decsMessageWords (message : DecsPolynomialMessage) : List (List Word) :=
  List.ofFn fun repetition =>
    List.ofFn fun coefficient =>
      fieldWordAsWord (message repetition coefficient)

def piopNonlinearMessageWords
    (message : PiopPolynomialMessage) : List (List Word) :=
  List.ofFn fun repetition =>
    List.ofFn fun coefficient =>
      fieldWordAsWord (message.nonlinear repetition coefficient)

def piopLinearMessageWordsWithoutConstant
    (message : PiopPolynomialMessage) : List (List Word) :=
  List.ofFn fun repetition =>
    List.ofFn fun coefficient : Fin linearMaskPolynomialDegree =>
      fieldWordAsWord
        (message.linear repetition
          ⟨coefficient.val + 1, by
            have coefficientBound := coefficient.isLt
            omega⟩)

def pcsCombinationHeadWords
    (message : PcsCombinationMessage) : List (List Word) :=
  List.ofFn fun combination =>
    List.ofFn fun column : Fin lvcsColumnCount =>
      fieldWordAsWord
        (message combination (Fin.castAdd decsOpenedEvaluations column))

def pcsCombinationTailWords
    (message : PcsCombinationMessage) : List (List Word) :=
  List.ofFn fun combination =>
    List.ofFn fun column : Fin decsOpenedEvaluations =>
      fieldWordAsWord
        (message combination
          ⟨lvcsColumnCount + column.val, by
            have columnBound := column.isLt
            omega⟩)

/-- Exact transcript fields recomputed by the active SHA-512 verifier. -/
structure ProductionTranscriptBinding
    (rawOracle : RawOracle)
    (transcript : HegemonCrypto.SmallWoodTranscript.Transcript)
    (salt : ProductionSalt)
    (root : ActiveDigest)
    (decsMessage : DecsPolynomialMessage)
    (piopMessage : PiopPolynomialMessage)
    (pcsMessage : PcsCombinationMessage) : Prop where
  activeParameters : transcript.parameters = SmallWoodTranscript.activeParameters
  saltWords : transcript.commitment.saltWords = productionSaltWords salt
  rootWords : transcript.commitment.merkleRootWords = root.words
  decsWords : transcript.commitment.decPolynomials = decsMessageWords decsMessage
  nonlinearWords : transcript.piop.polynomialWords =
    piopNonlinearMessageWords piopMessage
  linearWords : transcript.piop.linearWordsWithoutConstant =
    piopLinearMessageWordsWithoutConstant piopMessage
  combinationHeads : transcript.opening.combinationHeads =
    pcsCombinationHeadWords pcsMessage
  combinationTails : transcript.opening.randomCombinationTails =
    pcsCombinationTailWords pcsMessage

/-- The three canonical byte decoders consumed by the Rust production path agree on one artifact. -/
structure ProductionByteAcceptance
    (proofBytes : List HegemonCrypto.CanonicalBytes.Byte)
    (artifact : ActiveAcceptedProofWire)
    (rawOracle : RawOracle)
    (transcript : HegemonCrypto.SmallWoodTranscript.Transcript)
    (salt : ProductionSalt) : Prop where
  decoded : decodeActiveAcceptedProofWireExact proofBytes = some artifact
  saltBytes : artifact.backendProof.proof.saltBytes =
    flattenWordBytes (productionSaltWords salt)
  nonceBytes : artifact.backendProof.proof.nonceBytes =
    HegemonCrypto.CanonicalBytes.encodeLE 4 transcript.openingNonce.val
  piopDigestBytes : artifact.backendProof.proof.piopHashBytes =
    flattenWordBytes (rawPiopDigest rawOracle transcript.commitment
      transcript.statementBindingWords transcript.piop).words

theorem production_opening_coordinates_cover_challenge
    {rawOracle : RawOracle}
    {transcript : HegemonCrypto.SmallWoodTranscript.Transcript}
    (success : ProductionDecsSamplerSucceeds rawOracle transcript) :
    CoordinatesCoverChallenge
      (productionOpeningCoordinates success)
      (productionDecsOpening success) := by
  intro coordinate coordinateMember
  let domainCoordinate :
      HegemonCrypto.SmallWood.FixedSampling.DomainIndex :=
    ⟨coordinate.val, by
      have coordinateBound := coordinate.isLt
      change coordinate.val < 1048576 at coordinateBound
      change coordinate.val < 2 ^ 20
      norm_num at coordinateBound ⊢
      exact coordinateBound⟩
  have domainCoordinateEqual :
      (domainCoordinate : Fin decsEvaluationCount) = coordinate := by
    apply Fin.ext
    rfl
  rw [← domainCoordinateEqual] at coordinateMember
  change
    domainCoordinate ∈
      HegemonCrypto.SmallWood.FixedSampling.selectedIndexSet
        (productionDecsCandidates rawOracle transcript)
    at coordinateMember
  have selectedMember :
      domainCoordinate ∈
        productionDecsSelectedIndices rawOracle transcript := by
    rw [← List.mem_toFinset]
    rw [production_decs_selected_indices_toFinset]
    exact coordinateMember
  obtain ⟨index, indexValue⟩ := List.mem_iff_get.mp selectedMember
  let opening : OpeningIndex :=
    ⟨index.val, by
      exact index.isLt.trans_eq success⟩
  refine ⟨opening, ?_⟩
  apply Fin.ext
  change
    ((productionDecsSelectedIndices rawOracle transcript).get
      ⟨opening.val, _⟩).val = coordinate.val
  have valueEqual := congrArg Fin.val indexValue
  simpa [opening, domainCoordinate] using valueEqual

theorem production_opening_coordinates_exactly_challenge
    {rawOracle : RawOracle}
    {transcript : HegemonCrypto.SmallWoodTranscript.Transcript}
    (success : ProductionDecsSamplerSucceeds rawOracle transcript) :
    CoordinatesExactlyChallenge
      (productionOpeningCoordinates success)
      (productionDecsOpening success) :=
  ⟨production_opening_coordinates_injective success,
    production_opening_coordinates_cover_challenge success⟩

/--
Evidence for one successful production verifier execution. All challenges, both restored
polynomial messages, the authenticated rows, and the accepted trace are deterministic projections
of this record. `compactClaimsRecorded` records the measured-oracle queries used to extract those
rows; it is not itself a verifier Boolean. Collision freedom and successful extraction are supplied
separately by later probabilistic arguments.
-/
structure ProductionVerifierAccepted
    (proofBytes : List HegemonCrypto.CanonicalBytes.Byte)
    (statement : Statement)
    (rawOracle : RawOracle)
    (fallback : ActiveDigest)
    (database : ProductionHashDatabase) : Type where
  artifact : ActiveAcceptedProofWire
  transcript : HegemonCrypto.SmallWoodTranscript.Transcript
  salt : ProductionSalt
  root : ActiveDigest
  pcsMessage : PcsCombinationMessage
  baseRows : NativeLvcsBaseRows
  maskingRows : NativeMaskingRows
  paths : ProductionCompactPaths
  nativeDecsHigh : NativeDecsHighCoefficients
  nativeNonlinearHigh : NativeNonlinearHighCoefficients
  nativeLinearHigh : NativeLinearHighCoefficients
  piopMessage : PiopPolynomialMessage
  active : ActiveStatement statement
  statementBindingExact :
    StatementBindingExact statement transcript
  bytesAccepted :
    ProductionByteAcceptance proofBytes artifact rawOracle transcript salt
  canonicalOpeningNonce :
    ProductionCanonicalOpeningNonce rawOracle transcript
  decsSamplerSucceeds :
    ProductionDecsSamplerSucceeds rawOracle transcript
  activeWireShape :
    ActiveProofWireShape artifact.backendProof.proof
  pcsMessageFromWire :
    pcsMessage =
      reconstructNativePcsMessage
        (productionPiopOpening canonicalOpeningNonce)
        (productionProofWireData artifact.backendProof.proof).rowScalars
        (productionProofWireData artifact.backendProof.proof).partialEvaluations
        (productionProofWireData artifact.backendProof.proof).combinationTails
  baseRowsFromWire :
    baseRows =
      nativeLvcsBaseRowsFromSubset
        (productionProofWireData artifact.backendProof.proof).subsetEvaluations
  maskingRowsFromWire :
    maskingRows =
      (productionProofWireData artifact.backendProof.proof).maskingEvaluations
  pathsFromWire :
    paths = (productionProofWireData artifact.backendProof.proof).paths
  nativeDecsHighFromWire :
    nativeDecsHigh =
      (productionProofWireData artifact.backendProof.proof).decsHighCoefficients
  nativeNonlinearHighFromWire :
    nativeNonlinearHigh =
      (productionProofWireData artifact.backendProof.proof).nonlinearHighCoefficients
  nativeLinearHighFromWire :
    nativeLinearHigh =
      (productionProofWireData artifact.backendProof.proof).linearHighCoefficients
  transcriptBinding :
    ProductionTranscriptBinding rawOracle transcript salt root
      (reconstructNativeDecsMessage
        (productionDecsChallenge rawOracle transcript)
        (productionOpeningCoordinates decsSamplerSucceeds)
        (reconstructNativeProductionRows
          (productionPiopOpening canonicalOpeningNonce)
          pcsMessage (productionOpeningCoordinates decsSamplerSucceeds)
          baseRows maskingRows)
        nativeDecsHigh)
      piopMessage pcsMessage
  compactAccepted :
    CompactVerifierAccepted
      (productionMerkleHash rawOracle salt)
      fallback (productionOpeningCoordinates decsSamplerSucceeds)
        (reconstructNativeProductionRows
          (productionPiopOpening canonicalOpeningNonce)
          pcsMessage (productionOpeningCoordinates decsSamplerSucceeds)
          baseRows maskingRows)
        paths activeMerkleDepth root
  compactClaimsRecorded :
    CompactClaimsRecorded
      (productionMerkleDatabase salt database)
      (productionMerkleHash rawOracle salt)
      fallback (productionOpeningCoordinates decsSamplerSucceeds)
        (reconstructNativeProductionRows
          (productionPiopOpening canonicalOpeningNonce)
          pcsMessage (productionOpeningCoordinates decsSamplerSucceeds)
          baseRows maskingRows)
        paths activeMerkleDepth
  nativePiopReconstruction :
    reconstructNativePiopMessageFromTrace
      statement
        (productionPiopChallenge rawOracle transcript statement)
        (productionPiopOpening canonicalOpeningNonce)
        nativeNonlinearHigh nativeLinearHigh
          (nativePiopEvaluationTraceFromHeads
            statement
              (productionPiopChallenge rawOracle transcript statement)
              (productionPiopOpening canonicalOpeningNonce)
              pcsMessage) =
      some piopMessage

noncomputable def ProductionVerifierAccepted.coordinates
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database) :
    ProductionOpeningCoordinates :=
  productionOpeningCoordinates accepted.decsSamplerSucceeds

theorem ProductionVerifierAccepted.coordinatesExactlyChallenge
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database) :
    CoordinatesExactlyChallenge accepted.coordinates
      (productionDecsOpening accepted.decsSamplerSucceeds) :=
  production_opening_coordinates_exactly_challenge
    accepted.decsSamplerSucceeds

noncomputable def acceptedTrace
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database) :
    AcceptedTrace accepted.salt database accepted.root
      (productionDecsChallenge rawOracle accepted.transcript)
      (reconstructNativeDecsMessage
        (productionDecsChallenge rawOracle accepted.transcript)
        accepted.coordinates
        (reconstructNativeProductionRows
          (productionPiopOpening accepted.canonicalOpeningNonce)
          accepted.pcsMessage accepted.coordinates
          accepted.baseRows accepted.maskingRows)
        accepted.nativeDecsHigh) :=
  acceptedTraceOfCompact rawOracle accepted.salt fallback
    (productionDecsChallenge rawOracle accepted.transcript)
    (reconstructNativeDecsMessage
      (productionDecsChallenge rawOracle accepted.transcript)
      accepted.coordinates
      (reconstructNativeProductionRows
        (productionPiopOpening accepted.canonicalOpeningNonce)
        accepted.pcsMessage accepted.coordinates
        accepted.baseRows accepted.maskingRows)
      accepted.nativeDecsHigh)
    accepted.coordinates
    (reconstructNativeProductionRows
      (productionPiopOpening accepted.canonicalOpeningNonce)
      accepted.pcsMessage accepted.coordinates
      accepted.baseRows accepted.maskingRows)
    accepted.paths
    accepted.compactAccepted
    accepted.compactClaimsRecorded
    (reconstructed_native_decs_message_checks
      (productionDecsChallenge rawOracle accepted.transcript)
      (productionDecsOpening accepted.decsSamplerSucceeds)
      accepted.coordinates
      (reconstructNativeProductionRows
        (productionPiopOpening accepted.canonicalOpeningNonce)
        accepted.pcsMessage accepted.coordinates
        accepted.baseRows accepted.maskingRows)
      accepted.nativeDecsHigh
      accepted.coordinatesExactlyChallenge)

/--
An accepted production transcript with a collision-free recorded hash database reaches the exact
fourth-round interactive accepting state for the canonical extracted oracle.
-/
theorem production_acceptance_implies_fourth_round_good
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      ProductionVerifierAccepted
        proofBytes statement rawOracle fallback database)
    (hashDatabaseCollisionFree : CollisionFree database) :
    FourthRoundGood statement accepted.active
      (accumulatedCommittedOracle (acceptedTrace accepted))
      (productionDecsChallenge rawOracle accepted.transcript)
      (productionPiopChallenge rawOracle accepted.transcript statement)
      accepted.piopMessage
      (productionPiopOpening accepted.canonicalOpeningNonce)
      accepted.pcsMessage
      (productionDecsOpening accepted.decsSamplerSucceeds) := by
  apply acceptance_predicates_imply_fourth_round_good
    statement accepted.active
      (accumulatedCommittedOracle (acceptedTrace accepted))
      (productionDecsChallenge rawOracle accepted.transcript)
      (productionPiopChallenge rawOracle accepted.transcript statement)
      accepted.piopMessage
      (productionPiopOpening accepted.canonicalOpeningNonce)
      accepted.pcsMessage
      (productionDecsOpening accepted.decsSamplerSucceeds)
  · intro notDegreeBounded
    exact accumulated_acceptance_implies_first_round_good
      statement hashDatabaseCollisionFree (acceptedTrace accepted) notDegreeBounded
  · exact reconstruct_native_piop_message_from_trace_implies_target
      statement
        (productionPiopChallenge rawOracle accepted.transcript statement)
        (productionPiopOpening accepted.canonicalOpeningNonce)
        accepted.nativeNonlinearHigh accepted.nativeLinearHigh
        (nativePiopEvaluationTraceFromHeads
          statement
            (productionPiopChallenge rawOracle accepted.transcript statement)
            (productionPiopOpening accepted.canonicalOpeningNonce)
            accepted.pcsMessage)
        accepted.piopMessage
        accepted.nativePiopReconstruction
  · intro combinationsMatch
    exact native_piop_checks_imply_production_opening_passes
      statement (accumulatedCommittedOracle (acceptedTrace accepted))
      (productionPiopChallenge rawOracle accepted.transcript statement)
      accepted.piopMessage
      (productionPiopOpening accepted.canonicalOpeningNonce)
      (reconstruct_native_piop_message_from_trace_implies_checks
          statement (accumulatedCommittedOracle (acceptedTrace accepted))
          accepted.active
          (productionPiopChallenge rawOracle accepted.transcript statement)
          (productionPiopOpening accepted.canonicalOpeningNonce)
          accepted.nativeNonlinearHigh accepted.nativeLinearHigh
          (nativePiopEvaluationTraceFromHeads
            statement
              (productionPiopChallenge rawOracle accepted.transcript statement)
              (productionPiopOpening accepted.canonicalOpeningNonce)
              accepted.pcsMessage)
          accepted.piopMessage
          (native_piop_evaluation_trace_from_heads_eq_expected
            statement
              (productionPiopChallenge rawOracle accepted.transcript statement)
              (productionPiopOpening accepted.canonicalOpeningNonce)
              accepted.pcsMessage
              (accumulatedCommittedOracle (acceptedTrace accepted))
              combinationsMatch)
          accepted.nativePiopReconstruction)
  · exact native_lvcs_checks_imply_production_combinations_pass
      (accumulatedCommittedOracle (acceptedTrace accepted))
      (productionPiopOpening accepted.canonicalOpeningNonce)
      accepted.pcsMessage
      (productionDecsOpening accepted.decsSamplerSucceeds)
      accepted.coordinates
      (reconstructNativeProductionRows
        (productionPiopOpening accepted.canonicalOpeningNonce)
        accepted.pcsMessage accepted.coordinates
        accepted.baseRows accepted.maskingRows)
      accepted.coordinatesExactlyChallenge.2
      (fun opening =>
        accumulated_committed_oracle_row_eq
          hashDatabaseCollisionFree
          (accepted_trace_of_compact_contains_every_row
            rawOracle accepted.salt fallback
            (productionDecsChallenge rawOracle accepted.transcript)
            (reconstructNativeDecsMessage
              (productionDecsChallenge rawOracle accepted.transcript)
              accepted.coordinates
              (reconstructNativeProductionRows
                (productionPiopOpening accepted.canonicalOpeningNonce)
                accepted.pcsMessage accepted.coordinates
                accepted.baseRows accepted.maskingRows)
              accepted.nativeDecsHigh)
            accepted.coordinates
            (reconstructNativeProductionRows
              (productionPiopOpening accepted.canonicalOpeningNonce)
              accepted.pcsMessage accepted.coordinates
              accepted.baseRows accepted.maskingRows)
            accepted.paths
            accepted.compactAccepted
            accepted.compactClaimsRecorded
            (reconstructed_native_decs_message_checks
              (productionDecsChallenge rawOracle accepted.transcript)
              (productionDecsOpening accepted.decsSamplerSucceeds)
              accepted.coordinates
              (reconstructNativeProductionRows
                (productionPiopOpening accepted.canonicalOpeningNonce)
                accepted.pcsMessage accepted.coordinates
                accepted.baseRows accepted.maskingRows)
              accepted.nativeDecsHigh
              accepted.coordinatesExactlyChallenge)
            opening))
      (reconstructed_native_production_rows_checks
        (productionPiopOpening accepted.canonicalOpeningNonce)
        accepted.pcsMessage accepted.coordinates
        accepted.baseRows accepted.maskingRows)

end

end HegemonCrypto.SmallWood.ProductionAcceptanceClosure
