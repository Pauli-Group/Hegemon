import HegemonCrypto.SmallWoodQrom
import HegemonCrypto.SmallWoodMerkleExtraction
import HegemonCrypto.SmallWoodSha512Xof
import HegemonCrypto.CmsLifting
import HegemonCrypto.CmsOracleDatabaseBridge
import Mathlib.Tactic.FieldSimp

set_option maxRecDepth 100000
set_option exponentiation.threshold 1024

/-!
# SmallWood BCS/QROM instantiation boundary

This module applies the security-accounting method used by mature STARK implementations: every
loss has a stable label, a proof status, and an exact contribution to one sum.  It then maps the
deployed SmallWood PACS-PIOP plus DECS/LVCS transcript to the round-by-round BCS theorem shape of
Chiesa, Manohar, and Spooner (TCC 2019).

The CMS lifting lemmas contribute the exact factor `6 * t^2`; the oracle/database bridge is a
square-root inequality.  The active arithmetic below uses those exact expressions and a proved
one-bit conservative rational envelope.  It does not substitute unit constants for an asymptotic
term.

The active map below uses one raw 512-bit oracle for Merkle and transcript digests.  Challenge
field elements are a deterministic rejection-sampled view of that same oracle, modeled in
`SmallWoodSha512Xof`.  The older ideal field-XOF remains useful for algebraic round proofs but is
not the production hash boundary.

The remaining production obligations are the exact rejection-sampling transfer, the adaptive CMS
game instantiation, and native-verifier refinement.  Those obligations stay visible as typed
hypotheses rather than being replaced by optimistic labels.
-/

namespace HegemonCrypto.SmallWood.BcsQrom

open scoped BigOperators
open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.SmallWood.Qrom
open HegemonCrypto.SmallWood.Extraction
open HegemonCrypto.SmallWood.Interactive
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.Sha512Xof

section DeployedTranscript

/-- The active SHA-512 transcript exposes the complete raw 512-bit digest. -/
abbrev ActiveDigest := RawDigest

/-- One domain-separated raw SHA-512 request before canonical byte encoding. -/
abbrev ActiveHashRequest := List CanonicalBytes.Byte × List Word

/-- Exact active raw digest, using counter zero as production does for commitment hashes. -/
def activeDigest
    (oracle : RawOracle)
    (domain : List CanonicalBytes.Byte)
    (words : List Word) : ActiveDigest :=
  rawDigest oracle domain words 0

def activeHash
    (oracle : RawOracle)
    (request : ActiveHashRequest) : ActiveDigest :=
  activeDigest oracle request.1 request.2

/--
Concrete collision event used by every active transcript reduction.  The inputs include the
domain tag, so cross-role collisions are counted rather than silently excluded.
-/
def ActiveHashCollision (oracle : RawOracle) : Prop :=
  ∃ left right : ActiveHashRequest,
    left ≠ right ∧ activeHash oracle left = activeHash oracle right

/-- Active Merkle leaves and ordered child pairs mapped to exact raw SHA-512 requests. -/
def activeMerkleRequest :
    HashInput (List Word) ActiveDigest -> ActiveHashRequest
  | .leaf payload => (merkleLeafDomain, payload)
  | .node left right => (merkleNodeDomain, left.words ++ right.words)

def activeMerkleHash
    (oracle : RawOracle)
    (input : HashInput (List Word) ActiveDigest) : ActiveDigest :=
  activeHash oracle (activeMerkleRequest input)

/-- Exact digest widths make the active Merkle request encoding unambiguous. -/
theorem active_merkle_request_injective :
    Function.Injective activeMerkleRequest := by
  intro leftInput rightInput sameRequest
  cases leftInput with
  | leaf leftPayload =>
      cases rightInput with
      | leaf rightPayload =>
          have payloadEqual : leftPayload = rightPayload :=
            congrArg Prod.snd sameRequest
          cases payloadEqual
          rfl
      | node rightLeft rightRight =>
          have domainEqual : merkleLeafDomain = merkleNodeDomain :=
            congrArg Prod.fst sameRequest
          have domainDifferent : merkleLeafDomain ≠ merkleNodeDomain := by decide
          exact (domainDifferent domainEqual).elim
  | node leftLeft leftRight =>
      cases rightInput with
      | leaf rightPayload =>
          have domainEqual : merkleNodeDomain = merkleLeafDomain :=
            congrArg Prod.fst sameRequest
          have domainDifferent : merkleNodeDomain ≠ merkleLeafDomain := by decide
          exact (domainDifferent domainEqual).elim
      | node rightLeft rightRight =>
          have wordsEqual :
              leftLeft.words ++ leftRight.words =
                rightLeft.words ++ rightRight.words :=
            congrArg Prod.snd sameRequest
          have leftLengths :
              leftLeft.words.length = rightLeft.words.length := by
            simp [RawDigest.words_length]
          obtain ⟨leftEqual, rightEqual⟩ :=
            List.append_inj wordsEqual leftLengths
          have leftDigestEqual : leftLeft = rightLeft :=
            RawDigest.words_injective leftEqual
          have rightDigestEqual : leftRight = rightRight :=
            RawDigest.words_injective rightEqual
          cases leftDigestEqual
          cases rightDigestEqual
          rfl

/--
Two different leaves accepted at the same active Merkle root and binary index produce a concrete
domain-separated SHA-512 collision request.
-/
theorem different_active_merkle_openings_exhibit_hash_collision
    (oracle : RawOracle)
    {root : ActiveDigest}
    {sides : List ChildSide}
    {leftLeaf rightLeaf : List Word}
    {leftPath rightPath : AuthenticationPath ActiveDigest}
    (differentLeaves : leftLeaf ≠ rightLeaf)
    (leftOpening :
      OpensAt (activeMerkleHash oracle) root sides leftLeaf leftPath)
    (rightOpening :
      OpensAt (activeMerkleHash oracle) root sides rightLeaf rightPath) :
    ActiveHashCollision oracle := by
  rcases different_accepted_leaves_exhibit_hash_collision
      (activeMerkleHash oracle) differentLeaves leftOpening rightOpening with
    ⟨leftInput, rightInput, differentInputs, sameDigest⟩
  refine ⟨activeMerkleRequest leftInput, activeMerkleRequest rightInput, ?_, sameDigest⟩
  exact fun sameRequest =>
    differentInputs (active_merkle_request_injective sameRequest)

/-- Raw statement-bound Merkle-root digest used as the first challenge seed. -/
def rawMerkleRootDigest
    (oracle : RawOracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : ActiveDigest :=
  activeDigest oracle merkleRootDomain
    (merkleRootHashInput commitment statementBindingWords)

/-- Exact PCS commitment transcript with the raw Merkle-root digest in production word order. -/
def rawPcsCommitmentTranscript
    (oracle : RawOracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  (rawMerkleRootDigest oracle commitment statementBindingWords).words
    ++ commitment.decPolynomials.flatten

def rawPiopInputWords
    (oracle : RawOracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  rawPcsCommitmentTranscript oracle commitment statementBindingWords
    ++ statementBindingWords

/-- Raw commitment digest that seeds the uniform PIOP coefficient challenge. -/
def rawHashFpp
    (oracle : RawOracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : ActiveDigest :=
  activeDigest oracle piopInputDomain
    (rawPiopInputWords oracle commitment statementBindingWords)

def rawPiopTranscriptWords
    (oracle : RawOracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word)
    (piop : PiopRound) : List Word :=
  (rawHashFpp oracle commitment statementBindingWords).words ++ piop.messageWords

/-- Raw PIOP transcript digest used after the canonical opening nonce. -/
def rawPiopDigest
    (oracle : RawOracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word)
    (piop : PiopRound) : ActiveDigest :=
  activeDigest oracle piopTranscriptDomain
    (rawPiopTranscriptWords oracle commitment statementBindingWords piop)

/-- Raw DECS-opening transcript digest used by fixed no-grinding sampling. -/
def rawDecsOpeningDigest
    (oracle : RawOracle)
    (piopHash : ActiveDigest)
    (opening : PcsOpeningRound) : ActiveDigest :=
  activeDigest oracle decsOpeningDomain
    (piopHash.words ++ opening.messageWords)

/-- Exact four raw challenge seeds reconstructed from one deployed transcript. -/
def deployedChallengeInputs
    (oracle : RawOracle)
    (transcript : Transcript) : ChallengeInputs :=
  { decsCommitmentDigest :=
      (rawMerkleRootDigest oracle transcript.commitment
        transcript.statementBindingWords).words,
    piopCommitmentDigest :=
      (rawHashFpp oracle transcript.commitment
        transcript.statementBindingWords).words,
    piopOpeningNonce := transcript.openingNonce,
    piopTranscriptDigest :=
      (rawPiopDigest oracle transcript.commitment
        transcript.statementBindingWords transcript.piop).words,
    decsTranscriptDigest :=
      (rawDecsOpeningDigest oracle
        (rawPiopDigest oracle transcript.commitment
          transcript.statementBindingWords transcript.piop)
        transcript.opening).words }

/-- Raw SHA-512 gives the exact deployed digest shape by construction. -/
theorem deployed_challenge_inputs_well_formed
    (oracle : RawOracle)
    (transcript : Transcript) :
    (deployedChallengeInputs oracle transcript).WellFormed := by
  refine ⟨?_, ?_, ?_, ?_⟩
  all_goals exact RawDigest.words_length _

/-- The reconstructed V4 BCS view has challenge-input lengths `8, 8, 9, 8`. -/
theorem deployed_bcs_challenge_input_lengths
    (oracle : RawOracle)
    (transcript : Transcript) :
    ((deployedChallengeInputs oracle transcript).words.map List.length) =
      [8, 8, 9, 8] := by
  exact well_formed_challenge_input_lengths _
    (deployed_challenge_inputs_well_formed oracle transcript)

/-- Exact first physical SHA-512 request for the DECS coefficient challenge. -/
def rawFirstChallengePreimage
    (oracle : RawOracle)
    (transcript : Transcript) : List CanonicalBytes.Byte :=
  sha512BlockPreimage decsCoefficientDomain
    (rawMerkleRootDigest oracle transcript.commitment
      transcript.statementBindingWords).words
    0

/-- Exact first physical SHA-512 request for the PIOP coefficient challenge. -/
def rawSecondChallengePreimage
    (oracle : RawOracle)
    (transcript : Transcript) : List CanonicalBytes.Byte :=
  sha512BlockPreimage piopCoefficientDomain
    (rawHashFpp oracle transcript.commitment
      transcript.statementBindingWords).words
    0

/-- Exact first physical SHA-512 request for the selected PIOP opening challenge. -/
def rawThirdChallengePreimage
    (oracle : RawOracle)
    (transcript : Transcript) : List CanonicalBytes.Byte :=
  sha512BlockPreimage piopOpeningDomain
    (transcript.openingNonce ::
      (rawPiopDigest oracle transcript.commitment
        transcript.statementBindingWords transcript.piop).words)
    0

/-- Exact first physical SHA-512 request for fixed no-grinding DECS sampling. -/
def rawFourthChallengePreimage
    (oracle : RawOracle)
    (transcript : Transcript) : List CanonicalBytes.Byte :=
  sha512BlockPreimage decsFixedSamplingDomain
    (rawDecsOpeningDigest oracle
      (rawPiopDigest oracle transcript.commitment
        transcript.statementBindingWords transcript.piop)
      transcript.opening).words
    0

/--
The four accepted challenge families start from different physical SHA-512 requests.  This is a
byte-grammar fact over the raw production oracle, not a field-XOF idealization.
-/
theorem raw_active_challenge_preimages_are_pairwise_distinct
    (oracle : RawOracle)
    (transcript : Transcript) :
    [ rawFirstChallengePreimage oracle transcript,
      rawSecondChallengePreimage oracle transcript,
      rawThirdChallengePreimage oracle transcript,
      rawFourthChallengePreimage oracle transcript ].Nodup := by
  have first_ne_second :
      rawFirstChallengePreimage oracle transcript ≠
        rawSecondChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 33 0) equal
    have encodedLength :
        CanonicalBytes.encodeLE 8 41 = [41, 0, 0, 0, 0, 0, 0, 0] := by
      decide
    norm_num [rawFirstChallengePreimage, rawSecondChallengePreimage,
      sha512BlockPreimage, decsCoefficientDomain, piopCoefficientDomain,
      level5DomainPrefix, encodedLength] at byteEqual
    exact (by decide : (100 : CanonicalBytes.Byte) ≠ 112) byteEqual
  have first_ne_third :
      rawFirstChallengePreimage oracle transcript ≠
        rawThirdChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [rawFirstChallengePreimage, rawThirdChallengePreimage,
      sha512BlockPreimage, CanonicalBytes.encodeLE, decsCoefficientDomain,
      piopOpeningDomain, level5DomainPrefix] at byteEqual
  have first_ne_fourth :
      rawFirstChallengePreimage oracle transcript ≠
        rawFourthChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [rawFirstChallengePreimage, rawFourthChallengePreimage,
      sha512BlockPreimage, CanonicalBytes.encodeLE, decsCoefficientDomain,
      decsFixedSamplingDomain, level5DomainPrefix] at byteEqual
  have second_ne_third :
      rawSecondChallengePreimage oracle transcript ≠
        rawThirdChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [rawSecondChallengePreimage, rawThirdChallengePreimage,
      sha512BlockPreimage, CanonicalBytes.encodeLE, piopCoefficientDomain,
      piopOpeningDomain, level5DomainPrefix] at byteEqual
  have second_ne_fourth :
      rawSecondChallengePreimage oracle transcript ≠
        rawFourthChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [rawSecondChallengePreimage, rawFourthChallengePreimage,
      sha512BlockPreimage, CanonicalBytes.encodeLE, piopCoefficientDomain,
      decsFixedSamplingDomain, level5DomainPrefix] at byteEqual
  have third_ne_fourth :
      rawThirdChallengePreimage oracle transcript ≠
        rawFourthChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [rawThirdChallengePreimage, rawFourthChallengePreimage,
      sha512BlockPreimage, CanonicalBytes.encodeLE, piopOpeningDomain,
      decsFixedSamplingDomain, level5DomainPrefix] at byteEqual
  simp [first_ne_second, first_ne_third, first_ne_fourth, second_ne_third,
    second_ne_fourth, third_ne_fourth]

/-- Number of rows in the committed DECS evaluation oracle. -/
def activeCommittedOracleLength : Nat := 1048576

/-- Number of DECS leaves opened by the active no-grinding profile. -/
def activeBcsQueryCount : Nat := activeParameters.decsOpenedEvaluations

/-- Binary Merkle depth for the active committed evaluation oracle. -/
def activeMerkleDepth : Nat := 20

theorem active_committed_oracle_length_is_binary_depth :
    activeCommittedOracleLength = 2 ^ activeMerkleDepth := by
  decide

theorem active_bcs_query_count_is_20 : activeBcsQueryCount = 20 := by
  rfl

theorem active_merkle_depth_is_20 : activeMerkleDepth = 20 := by
  rfl

/-- Raw `q * log_2(ell)` unit used by the published asymptotic extractor-query overhead. -/
def activeQueryDepthProduct : Nat := activeBcsQueryCount * activeMerkleDepth

theorem active_query_depth_product_is_400 : activeQueryDepthProduct = 400 := by
  decide

/-- The first DECS verifier challenge hashes the statement-bound Merkle-root digest. -/
def firstDecsChallengeInput
    (oracle : RawOracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  (rawMerkleRootDigest oracle commitment statementBindingWords).words

/-- Exact logical SHA-512 request that binds the statement into the first challenge. -/
def firstDecsChallengeRequest
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : ActiveHashRequest :=
  (merkleRootDomain, merkleRootHashInput commitment statementBindingWords)

/--
Any two distinct statement encodings that produce one first challenge expose a concrete active
hash collision.  This is a reduction theorem, not the false claim that a finite digest is globally
injective.
-/
theorem different_statements_same_first_challenge_exhibit_hash_collision
    (oracle : RawOracle)
    (commitment : CommitmentRound)
    (leftStatement rightStatement : List Word)
    (differentStatements : leftStatement ≠ rightStatement)
    (sameChallenge :
      firstDecsChallengeInput oracle commitment leftStatement =
        firstDecsChallengeInput oracle commitment rightStatement) :
    ActiveHashCollision oracle := by
  have differentRequests :
      firstDecsChallengeRequest commitment leftStatement ≠
        firstDecsChallengeRequest commitment rightStatement := by
    intro sameRequest
    apply differentStatements
    have inputEqual :
        merkleRootHashInput commitment leftStatement =
          merkleRootHashInput commitment rightStatement :=
      congrArg Prod.snd sameRequest
    have normalizedInputEqual :
        commitment.saltWords ++
            (commitment.merkleRootWords ++ leftStatement) =
          commitment.saltWords ++
            (commitment.merkleRootWords ++ rightStatement) := by
      simpa [merkleRootHashInput, List.append_assoc] using inputEqual
    have rootAndStatementEqual :
        commitment.merkleRootWords ++ leftStatement =
          commitment.merkleRootWords ++ rightStatement := by
      exact List.append_cancel_left normalizedInputEqual
    exact List.append_cancel_left rootAndStatementEqual
  refine ⟨firstDecsChallengeRequest commitment leftStatement,
    firstDecsChallengeRequest commitment rightStatement,
    differentRequests, ?_⟩
  exact RawDigest.words_injective sameChallenge

/-- Canonical nonce selection makes the PIOP opening challenge prefix-determined. -/
theorem canonical_opening_nonce_is_determined_by_piop_prefix
    {oracle : Oracle}
    {parameters : Parameters}
    {packingPoints piopHash : List Word}
    {left right : Word}
    (leftCanonical :
      CanonicalOpeningNonce oracle parameters packingPoints piopHash left)
    (rightCanonical :
      CanonicalOpeningNonce oracle parameters packingPoints piopHash right) :
    left = right := by
  exact canonical_opening_nonce_unique leftCanonical rightCanonical

end DeployedTranscript

section RoundByRoundKnowledge

/-!
`RoundByRoundKnowledgeTarget` is the Hegemon specialization of the CMS RBR knowledge condition.
At a verifier-turn prefix whose state is still false, crossing the knowledge-error threshold must
yield an exact witness for the production relation. The active DECS/LVCS instance is constructed
in `SmallWoodProductionBcsInstantiation`.
-/

structure RoundByRoundKnowledgeTarget (Prefix : Type*) where
  Challenge : Prefix -> Type
  challengeFintype : ∀ transcriptPrefix, Fintype (Challenge transcriptPrefix)
  challengeDecidableEq : ∀ transcriptPrefix, DecidableEq (Challenge transcriptPrefix)
  knowledgeError : Rat
  state : Prefix -> Bool
  verifierTurn : Prefix -> Prop
  statement : Prefix -> Statement
  initialPrefix : Statement -> Prefix
  proverExtension : Prefix -> Prefix -> Prop
  verifierExtension : (transcriptPrefix : Prefix) ->
    Challenge transcriptPrefix -> Prefix
  terminal : Prefix -> Prop
  accepts : Prefix -> Bool
  nextGoodProbability : Prefix -> Rat
  extract : Prefix -> Option Witness
  extractorWork : Prefix -> Nat
  extractorWorkBound : Nat
  knowledgeError_nonnegative : 0 ≤ knowledgeError
  initialStateIsDoomed : ∀ selectedStatement,
    state (initialPrefix selectedStatement) = false
  initialStatement : ∀ selectedStatement,
    statement (initialPrefix selectedStatement) = selectedStatement
  proverExtensionPreservesStatement : ∀ before after,
    proverExtension before after ->
      statement after = statement before
  verifierExtensionPreservesStatement : ∀ transcriptPrefix challenge,
    statement (verifierExtension transcriptPrefix challenge) =
      statement transcriptPrefix
  doomedStateSurvivesProverMessage : ∀ before after,
    proverExtension before after ->
    state before = false ->
      state after = false
  doomedTerminalTranscriptRejects : ∀ transcriptPrefix,
    terminal transcriptPrefix ->
    state transcriptPrefix = false ->
      accepts transcriptPrefix = false
  nextGoodProbability_nonnegative : ∀ transcriptPrefix,
    0 ≤ nextGoodProbability transcriptPrefix
  nextGoodProbability_at_most_one : ∀ transcriptPrefix,
    nextGoodProbability transcriptPrefix ≤ 1
  nextGoodProbability_is_uniform : ∀ transcriptPrefix,
    letI := challengeFintype transcriptPrefix
    letI := challengeDecidableEq transcriptPrefix
    nextGoodProbability transcriptPrefix =
      ((Finset.univ.filter fun challenge =>
        state (verifierExtension transcriptPrefix challenge) = true).card : Rat) /
        Fintype.card (Challenge transcriptPrefix)
  extractorWorkWithinBound : ∀ transcriptPrefix,
    extractorWork transcriptPrefix ≤ extractorWorkBound
  extractAboveError : ∀ transcriptPrefix,
    verifierTurn transcriptPrefix →
    state transcriptPrefix = false →
    knowledgeError < nextGoodProbability transcriptPrefix →
      ∃ witness,
        extract transcriptPrefix = some witness ∧
          (statement transcriptPrefix, witness) ∈ Relation

/-- The RBR target extracts the exact production relation, not a surrogate acceptance bit. -/
theorem RoundByRoundKnowledgeTarget.extracts_exact_relation
    {Prefix : Type*}
    (target : RoundByRoundKnowledgeTarget Prefix)
    (transcriptPrefix : Prefix)
    (verifierTurn : target.verifierTurn transcriptPrefix)
    (doomed : target.state transcriptPrefix = false)
    (aboveError : target.knowledgeError < target.nextGoodProbability transcriptPrefix) :
    ∃ witness,
      target.extract transcriptPrefix = some witness ∧
        (target.statement transcriptPrefix, witness) ∈ Relation := by
  exact target.extractAboveError transcriptPrefix verifierTurn doomed aboveError

/-- Hypotheses needed for a direct adaptive BCS/QROM production instantiation. -/
structure DirectAdaptiveInstantiation
    (Prefix : Type*)
    (oracle : RawOracle)
    (CommitmentBinding ConcreteCmsTransfer NativeVerifierRefinement : Prop) : Prop where
  firstChallengeViolationReducesToHashCollision :
    ∀ commitment leftStatement rightStatement,
      leftStatement ≠ rightStatement →
      firstDecsChallengeInput oracle commitment leftStatement =
          firstDecsChallengeInput oracle commitment rightStatement →
        ActiveHashCollision oracle
  roundByRoundKnowledge : Nonempty (RoundByRoundKnowledgeTarget Prefix)
  commitmentBindingReduction : CommitmentBinding
  concreteCmsTransfer : ConcreteCmsTransfer
  nativeVerifierRefinement : NativeVerifierRefinement

/-- Fixed-statement BCS target after removing only the adaptive first-instance requirement. -/
structure FixedStatementInstantiation
    (Prefix : Type*)
    (CommitmentBinding ConcreteCmsTransfer NativeVerifierRefinement : Prop) : Prop where
  roundByRoundKnowledge : Nonempty (RoundByRoundKnowledgeTarget Prefix)
  commitmentBindingReduction : CommitmentBinding
  concreteCmsTransfer : ConcreteCmsTransfer
  nativeVerifierRefinement : NativeVerifierRefinement

/-- V4 discharges the adaptive-instance reduction directly from the transcript encoding. -/
theorem directAdaptiveInstantiation
    (Prefix : Type*)
    (oracle : RawOracle)
    (CommitmentBinding ConcreteCmsTransfer NativeVerifierRefinement : Prop)
    (roundByRoundKnowledge : Nonempty (RoundByRoundKnowledgeTarget Prefix))
    (commitmentBindingReduction : CommitmentBinding)
    (concreteCmsTransfer : ConcreteCmsTransfer)
    (nativeVerifierRefinement : NativeVerifierRefinement) :
    DirectAdaptiveInstantiation Prefix oracle CommitmentBinding ConcreteCmsTransfer
      NativeVerifierRefinement :=
  { firstChallengeViolationReducesToHashCollision :=
      different_statements_same_first_challenge_exhibit_hash_collision oracle,
    roundByRoundKnowledge,
    commitmentBindingReduction,
    concreteCmsTransfer,
    nativeVerifierRefinement }

end RoundByRoundKnowledge

section SecurityLedger

/-- Stable labels prevent a security report from silently dropping a term. -/
inductive LossLabel where
  | rbrKnowledgeAmplification
  | collisionInstability
  | oracleDatabaseBridge
  | commitmentBinding
  | randomOracleInstantiation
  | transcriptCompatibility
  | nativeVerifierRefinement
deriving DecidableEq, Repr

/-- A numeric term receives production credit only after its mathematical dependency is proved. -/
inductive EvidenceStatus where
  | proved
  | hashAssumption
deriving DecidableEq, Repr

structure LossEntry where
  label : LossLabel
  status : EvidenceStatus
  value : Rat
deriving DecidableEq, Repr

/-- Computational loss for replacing the ideal 512-bit oracle by the deployed hash construction. -/
structure HashAssumptionLoss where
  randomOracleInstantiation : Rat
  nonnegative : 0 <= randomOracleInstantiation
deriving DecidableEq, Repr

/-- RBR contribution in the proved `2 * databaseLoss` rational envelope. -/
def cmsRbrEnvelopeLoss
    (queries : Nat)
    (rbrKnowledgeError : Rat) : Rat :=
  (12 * queries ^ 2 : Nat) * rbrKnowledgeError

/--
Collision-instability contribution with one 512-bit random-oracle output
space.  The factor `48` is `2 * 6 * 4`: probability conversion, the exact CMS
lifting constant, and the `4t^3 / 2^lambda` instability term.
-/
def cmsCollisionEnvelopeLoss
    (queries oracleBits : Nat) : Rat :=
  (48 * queries ^ 3 : Nat) / (2 ^ oracleBits : Nat)

/--
Oracle-to-database bridge contribution in the same conservative envelope.

`CmsOracleDatabaseBridge.compressed_oracle_claims_amplitude_bridge` proves the
state-level amplitude loss `k / sqrt(2^oracleBits)` directly for the concrete
decompression implementation.  Squaring with `(a+b)^2 <= 2a^2+2b^2` gives
`2k^2 / 2^oracleBits`.
-/
def cmsOracleBridgeEnvelopeLoss
    (baseGameArity oracleBits : Nat) : Rat :=
  (2 * baseGameArity ^ 2 : Nat) / (2 ^ oracleBits : Nat)

/-- Complete labeled BCS/QROM accounting surface. -/
def securityLedger
    (queries oracleBits baseGameArity : Nat)
    (rbrKnowledgeError : Rat)
    (hashLoss : HashAssumptionLoss) : List LossEntry :=
  [ { label := .rbrKnowledgeAmplification,
      status := .proved,
      value := cmsRbrEnvelopeLoss queries rbrKnowledgeError },
    { label := .collisionInstability,
      status := .proved,
      value := cmsCollisionEnvelopeLoss queries oracleBits },
    { label := .oracleDatabaseBridge,
      status := .proved,
      value := cmsOracleBridgeEnvelopeLoss baseGameArity oracleBits },
    { label := .commitmentBinding,
      status := .proved,
      value := 0 },
    { label := .randomOracleInstantiation,
      status := .hashAssumption,
      value := hashLoss.randomOracleInstantiation },
    { label := .transcriptCompatibility,
      status := .proved,
      value := 0 },
    { label := .nativeVerifierRefinement,
      status := .proved,
      value := 0 } ]

def ledgerTotal (entries : List LossEntry) : Rat :=
  (entries.map LossEntry.value).sum

/-- The report contains each named attack surface exactly once and in a fixed order. -/
theorem security_ledger_labels_are_complete
    (queries oracleBits baseGameArity : Nat)
    (rbrKnowledgeError : Rat)
    (hashLoss : HashAssumptionLoss) :
    (securityLedger queries oracleBits baseGameArity rbrKnowledgeError hashLoss).map
        LossEntry.label =
      [ .rbrKnowledgeAmplification,
        .collisionInstability,
        .oracleDatabaseBridge,
        .commitmentBinding,
        .randomOracleInstantiation,
        .transcriptCompatibility,
        .nativeVerifierRefinement ] := by
  rfl

/-- The ledger total is exactly the proved conservative CMS envelope plus the hash assumption. -/
theorem security_ledger_total_exact
    (queries oracleBits baseGameArity : Nat)
    (rbrKnowledgeError : Rat)
    (hashLoss : HashAssumptionLoss) :
    ledgerTotal
        (securityLedger queries oracleBits baseGameArity rbrKnowledgeError hashLoss) =
      cmsRbrEnvelopeLoss queries rbrKnowledgeError +
        cmsCollisionEnvelopeLoss queries oracleBits +
        cmsOracleBridgeEnvelopeLoss baseGameArity oracleBits +
        hashLoss.randomOracleInstantiation := by
  simp [ledgerTotal, securityLedger]
  ring

end SecurityLedger

section ConcreteBound

/--
Conservative base-game arity cap. The accepted proof cannot authenticate more leaves than the
entire committed oracle. The production refinement proves that the verifier trace fits this cap;
using the cap instead of the exact trace count only weakens the bound.
-/
def activeBaseGameArityUpperBound : Nat := activeCommittedOracleLength

def activeCmsEnvelopeLoss (queries : Nat) : Rat :=
  cmsRbrEnvelopeLoss queries
      ((aggregateErrorNumerator : Rat) / aggregateErrorDenominator) +
    cmsCollisionEnvelopeLoss queries 512 +
    cmsOracleBridgeEnvelopeLoss activeBaseGameArityUpperBound 512

def activeCmsEnvelopeNumerator (queries : Nat) : Nat :=
  12 * queries ^ 2 * aggregateErrorNumerator * 2 ^ 512 +
    (48 * queries ^ 3 + 2 * activeBaseGameArityUpperBound ^ 2) *
      aggregateErrorDenominator

def activeCmsEnvelopeDenominator : Nat :=
  aggregateErrorDenominator * 2 ^ 512

def supportsActiveCmsEnvelopeBits (bits queries : Nat) : Prop :=
  2 ^ bits * activeCmsEnvelopeNumerator queries <= activeCmsEnvelopeDenominator

theorem active_cms_envelope_loss_eq_common_fraction (queries : Nat) :
    activeCmsEnvelopeLoss queries =
      (activeCmsEnvelopeNumerator queries : Rat) /
        activeCmsEnvelopeDenominator := by
  have aggregatePositive : 0 < aggregateErrorDenominator := by decide
  have oraclePositive : 0 < (2 ^ 512 : Nat) := by positivity
  have aggregateNonzero : (aggregateErrorDenominator : Rat) ≠ 0 := by
    exact_mod_cast aggregatePositive.ne'
  have oracleNonzero : ((2 ^ 512 : Nat) : Rat) ≠ 0 := by
    exact_mod_cast oraclePositive.ne'
  unfold activeCmsEnvelopeLoss cmsRbrEnvelopeLoss cmsCollisionEnvelopeLoss
    cmsOracleBridgeEnvelopeLoss activeCmsEnvelopeNumerator
    activeCmsEnvelopeDenominator
  push_cast
  field_simp
  ring

theorem supports_active_cms_envelope_bits_iff (bits queries : Nat) :
    supportsActiveCmsEnvelopeBits bits queries ↔
      activeCmsEnvelopeLoss queries <= (1 : Rat) / 2 ^ bits := by
  rw [active_cms_envelope_loss_eq_common_fraction]
  unfold supportsActiveCmsEnvelopeBits
  have denominatorPositive : 0 < activeCmsEnvelopeDenominator := by
    exact Nat.mul_pos (by decide) (by positivity)
  have scalePositive : 0 < 2 ^ bits := by positivity
  rw [div_le_div_iff₀ (by exact_mod_cast denominatorPositive)
    (by exact_mod_cast scalePositive)]
  norm_cast
  simp [Nat.mul_comm]

/--
The proved CMS constants and conservative state-level bridge retain at least
128 bits at a `2^64` quantum-query budget, before adding the deployed-hash
instantiation loss. The remaining cryptographic boundary is replacing the
ideal logical oracle by the deployed domain-separated SHA-512 construction.
-/
theorem active_cms_2pow64_queries_support_128_bits :
    supportsActiveCmsEnvelopeBits 128 (2 ^ 64) := by
  unfold supportsActiveCmsEnvelopeBits activeCmsEnvelopeNumerator
    activeCmsEnvelopeDenominator activeBaseGameArityUpperBound
    activeCommittedOracleLength
  set_option exponentiation.threshold 1024 in
    set_option maxRecDepth 100000 in
      decide

end ConcreteBound

end HegemonCrypto.SmallWood.BcsQrom
