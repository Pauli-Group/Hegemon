import HegemonCrypto.CanonicalBytes
import HegemonCrypto.Goldilocks
import Mathlib.Tactic.NormNum

/-!
# Active SmallWood V4 transcript

This file models the byte grammar and challenge order selected by circuit V4 / crypto suite Gamma.
Historical V2/V3 used a four-word BLAKE3 transcript and are not represented as the active protocol
here.  Every V4 SHA-512 call prefixes the domain length, the domain bytes, the input-word count,
little-endian words, and an eight-byte counter.  The mathematical oracle abstracts SHA-512 output
and rejection sampling; the preimage grammar and all protocol domains are exact.
-/

namespace HegemonCrypto
namespace SmallWoodTranscript

open CanonicalBytes
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

abbrev Word := Fin (2 ^ 64)
abbrev FieldWord := Fin goldilocksModulus

def digestWordCount : Nat := 8
def piopNonceTrialBound : Nat := 16
def decsNonceTrialBound : Nat := 1
def nonceBound : Nat := piopNonceTrialBound

theorem active_nonce_trial_bounds :
    piopNonceTrialBound = 16 ∧ decsNonceTrialBound = 1 := by
  decide

def level5DomainPrefix : List Byte :=
  [ 104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108,
    119, 111, 111, 100, 46, 108, 101, 118, 101, 108, 53, 46 ]

def piopInputDomain : List Byte :=
  level5DomainPrefix ++ [112, 105, 111, 112, 45, 105, 110, 112, 117, 116]

def piopTranscriptDomain : List Byte :=
  level5DomainPrefix ++
    [112, 105, 111, 112, 45, 116, 114, 97, 110, 115, 99, 114, 105, 112, 116]

def decsOpeningDomain : List Byte :=
  level5DomainPrefix ++
    [100, 101, 99, 115, 45, 111, 112, 101, 110, 105, 110, 103]

def merkleLeafDomain : List Byte :=
  level5DomainPrefix ++ [109, 101, 114, 107, 108, 101, 45, 108, 101, 97, 102]

def merkleNodeDomain : List Byte :=
  level5DomainPrefix ++ [109, 101, 114, 107, 108, 101, 45, 110, 111, 100, 101]

def merkleRootDomain : List Byte :=
  level5DomainPrefix ++ [109, 101, 114, 107, 108, 101, 45, 114, 111, 111, 116]

def decsCoefficientDomain : List Byte :=
  level5DomainPrefix ++
    [100, 101, 99, 115, 45, 99, 111, 101, 102, 102, 105, 99, 105, 101, 110, 116]

def piopCoefficientDomain : List Byte :=
  level5DomainPrefix ++
    [112, 105, 111, 112, 45, 99, 111, 101, 102, 102, 105, 99, 105, 101, 110, 116]

def piopOpeningDomain : List Byte :=
  level5DomainPrefix ++
    [112, 105, 111, 112, 45, 111, 112, 101, 110, 105, 110, 103]

def decsQueryDomain : List Byte :=
  level5DomainPrefix ++
    [100, 101, 99, 115, 45, 113, 117, 101, 114, 121]

def decsFixedSamplingDomain : List Byte :=
  level5DomainPrefix ++
    [100, 101, 99, 115, 45, 102, 105, 120, 101, 100, 45,
      115, 97, 109, 112, 108, 105, 110, 103]

/-- Compatibility name used by the classical-ROM domain-separation lemmas. -/
def xofDomain : List Byte := piopInputDomain

def wordBytes (word : Word) : List Byte :=
  encodeLE 8 word.val

def flattenWordBytes (words : List Word) : List Byte :=
  (words.map wordBytes).flatten

/-- Exact bytes passed to one SHA-512 block invocation in the V4 field-XOF. -/
def sha512BlockPreimage
    (domain : List Byte)
    (words : List Word)
    (counter : Nat) : List Byte :=
  encodeLE 8 domain.length
    ++ domain
    ++ encodeLE 8 words.length
    ++ flattenWordBytes words
    ++ encodeLE 8 counter

/-- Compatibility preimage fixed to the PIOP-input role and counter zero. -/
def xofPreimage (words : List Word) : List Byte :=
  sha512BlockPreimage xofDomain words 0

/--
Ideal variable-output field-XOF view.  The second argument is an output-word index, not a requested
length.  Defining the oracle as one infinite indexed stream makes prefix consistency structural:
asking for five words and later asking for thirty-six words cannot produce unrelated prefixes.

The executable refinement obligation separately proves that repeated SHA-512 counter blocks plus
canonical Goldilocks rejection sampling implement this indexed stream.
-/
abbrev Oracle := List Byte -> Nat -> FieldWord

def fieldWordAsWord (word : FieldWord) : Word :=
  ⟨word.val, word.isLt.trans (by decide)⟩

def fieldHashWords
    (oracle : Oracle)
    (domain : List Byte)
    (words : List Word)
    (outputWords : Nat) : List FieldWord :=
  (List.range outputWords).map
    (oracle (sha512BlockPreimage domain words 0))

def hashWords
    (oracle : Oracle)
    (domain : List Byte)
    (words : List Word)
    (outputWords : Nat) : List Word :=
  (fieldHashWords oracle domain words outputWords).map fieldWordAsWord

theorem fieldHashWords_length
    (oracle : Oracle)
    (domain : List Byte)
    (words : List Word)
    (outputWords : Nat) :
    (fieldHashWords oracle domain words outputWords).length = outputWords := by
  simp [fieldHashWords]

theorem hashWords_length
    (oracle : Oracle)
    (domain : List Byte)
    (words : List Word)
    (outputWords : Nat) :
    (hashWords oracle domain words outputWords).length = outputWords := by
  simp [hashWords, fieldHashWords_length]

theorem hashWords_prefix
    (oracle : Oracle)
    (domain : List Byte)
    (words : List Word)
    {shorter longer : Nat}
    (bounded : shorter ≤ longer) :
    (hashWords oracle domain words longer).take shorter =
      hashWords oracle domain words shorter := by
  simp [hashWords, fieldHashWords, ← List.map_take, bounded]

theorem hashWords_are_canonical_field_elements
    (oracle : Oracle)
    (domain : List Byte)
    (words : List Word)
    (outputWords : Nat)
    (word : Word)
    (membership : word ∈ hashWords oracle domain words outputWords) :
    word.val < goldilocksModulus := by
  simp only [hashWords, fieldHashWords, List.mem_map, List.mem_range] at membership
  rcases membership with ⟨fieldWord, ⟨index, _indexBound, fieldWordEquation⟩,
    wordEquation⟩
  subst fieldWord
  subst word
  exact (oracle (sha512BlockPreimage domain words 0) index).isLt

structure Parameters where
  repetitions : Nat
  openedEvaluations : Nat
  decsOpenedEvaluations : Nat
deriving DecidableEq, Repr

def activeParameters : Parameters :=
  { repetitions := 5,
    openedEvaluations := 5,
    decsOpenedEvaluations := 23 }

/-- Exact dimensions of the active uniform DECS batching challenge. -/
def activeDecsRepetitions : Nat := 5
def activeDecsRowWidth : Nat := 138

/-- Fixed number of candidate field words consumed by the active no-grinding DECS sampler. -/
def activeDecsFixedCandidateCount : Nat := 50

/--
Maximum dimensions of the active uniform PIOP batching challenge.  Individual activity masks use
their exact statement-specific linear count; 18,342 is the fully populated production maximum.
-/
def activePiopRepetitions : Nat := 5
def activePiopNonlinearWidth : Nat := 890
def activePiopLinearWidth : Nat := 18342
def activePiopRowWidth : Nat :=
  max activePiopNonlinearWidth activePiopLinearWidth

theorem active_piop_row_width_is_linear_width :
    activePiopRowWidth = activePiopLinearWidth := by
  decide

/--
One uniformly indexed coefficient matrix drawn from a single domain-separated field-XOF stream.
The row-major index is exactly the index used by Rust after `chunks_exact(rowWidth)`.
-/
def coefficientMatrix
    (oracle : Oracle)
    (domain : List Byte)
    (inputWords : List Word)
    (rows columns : Nat) :
    Fin rows -> Fin columns -> FieldWord :=
  fun row column =>
    oracle
      (sha512BlockPreimage domain inputWords 0)
      (row.val * columns + column.val)

def activeDecsCoefficientMatrix
    (oracle : Oracle)
    (merkleRootHash : List Word) :
    Fin activeDecsRepetitions -> Fin activeDecsRowWidth -> FieldWord :=
  coefficientMatrix oracle decsCoefficientDomain merkleRootHash
    activeDecsRepetitions activeDecsRowWidth

def activePiopCoefficientMatrix
    (oracle : Oracle)
    (fppHash : List Word) :
    Fin activePiopRepetitions -> Fin activePiopRowWidth -> FieldWord :=
  coefficientMatrix oracle piopCoefficientDomain fppHash
    activePiopRepetitions activePiopRowWidth

/-- Exact row width selected by Rust for one concrete production statement. -/
def productionPiopRowWidth
    (nonlinearConstraintCount linearConstraintCount : Nat) : Nat :=
  max nonlinearConstraintCount linearConstraintCount

/-- Exact dynamic PIOP matrix used by a statement with the supplied constraint counts. -/
def productionPiopCoefficientMatrix
    (oracle : Oracle)
    (fppHash : List Word)
    (nonlinearConstraintCount linearConstraintCount : Nat) :
    Fin activePiopRepetitions ->
      Fin (productionPiopRowWidth nonlinearConstraintCount linearConstraintCount) ->
        FieldWord :=
  coefficientMatrix oracle piopCoefficientDomain fppHash
    activePiopRepetitions
    (productionPiopRowWidth nonlinearConstraintCount linearConstraintCount)

/-- Number of canonical field words consumed for one concrete production statement. -/
def productionPiopCoefficientWordCount
    (nonlinearConstraintCount linearConstraintCount : Nat) : Nat :=
  activePiopRepetitions *
    productionPiopRowWidth nonlinearConstraintCount linearConstraintCount

/-- The Rust PIOP generator requests exactly this many canonical Goldilocks words. -/
def activePiopCoefficientWordCount : Nat :=
  activePiopRepetitions * activePiopRowWidth

/-- The Rust DECS generator requests exactly this many canonical Goldilocks words. -/
def activeDecsCoefficientWordCount : Nat :=
  activeDecsRepetitions * activeDecsRowWidth

theorem active_piop_coefficient_word_count_is_91710 :
    activePiopCoefficientWordCount = 91710 := by
  decide

theorem active_decs_coefficient_word_count_is_690 :
    activeDecsCoefficientWordCount = 690 := by
  decide

/-- Nonlinear batching projects the first 890 entries of each full PIOP row. -/
def activePiopNonlinearCoefficient
    (oracle : Oracle)
    (fppHash : List Word)
    (row : Fin activePiopRepetitions)
    (column : Fin activePiopNonlinearWidth) : FieldWord :=
  activePiopCoefficientMatrix oracle fppHash row
    ⟨column.val, column.isLt.trans (by decide)⟩

/--
Nonlinear batching consumes the prefix of the same full PIOP row used for linear batching.  There
is no second challenge and no structured power expansion hidden behind this projection.
-/
theorem active_piop_nonlinear_coefficient_is_full_row_prefix
    (oracle : Oracle)
    (fppHash : List Word)
    (row : Fin activePiopRepetitions)
    (column : Fin activePiopNonlinearWidth) :
    activePiopNonlinearCoefficient oracle fppHash row column =
      activePiopCoefficientMatrix oracle fppHash row
        ⟨column.val, column.isLt.trans (by decide)⟩ := by
  rfl

structure CommitmentRound where
  saltWords : List Word
  merkleRootWords : List Word
  decPolynomials : List (List Word)
deriving DecidableEq, Repr

def merkleRootHashInput
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  commitment.saltWords
    ++ commitment.merkleRootWords
    ++ statementBindingWords

def merkleRootDigest
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  hashWords oracle merkleRootDomain
    (merkleRootHashInput commitment statementBindingWords)
    digestWordCount

def pcsCommitmentTranscript
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  merkleRootDigest oracle commitment statementBindingWords
    ++ commitment.decPolynomials.flatten

def piopInputWords
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  pcsCommitmentTranscript oracle commitment statementBindingWords
    ++ statementBindingWords

def hashFpp
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  hashWords oracle piopInputDomain
    (piopInputWords oracle commitment statementBindingWords)
    digestWordCount

structure PiopRound where
  polynomialWords : List (List Word)
  linearWordsWithoutConstant : List (List Word)
deriving DecidableEq, Repr

def PiopRound.messageWords (piop : PiopRound) : List Word :=
  (List.zipWith (fun polynomial linear => polynomial ++ linear)
    piop.polynomialWords piop.linearWordsWithoutConstant).flatten

def piopTranscriptWords
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word)
    (piop : PiopRound) : List Word :=
  hashFpp oracle commitment statementBindingWords ++ piop.messageWords

def piopDigest
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word)
    (piop : PiopRound) : List Word :=
  hashWords oracle piopTranscriptDomain
    (piopTranscriptWords oracle commitment statementBindingWords piop)
    digestWordCount

def openingChallengeInput (nonce : Word) (piopHash : List Word) : List Word :=
  nonce :: piopHash

def openingPoints
    (oracle : Oracle)
    (parameters : Parameters)
    (nonce : Word)
    (piopHash : List Word) : List Word :=
  hashWords oracle piopOpeningDomain
    (openingChallengeInput nonce piopHash)
    parameters.openedEvaluations

def CollisionFree (packingPoints openingPoints : List Word) : Prop :=
  openingPoints.Nodup
    ∧ ∀ point ∈ openingPoints, point ∉ packingPoints

def ValidOpeningNonce
    (oracle : Oracle)
    (parameters : Parameters)
    (packingPoints : List Word)
    (piopHash : List Word)
    (nonce : Word) : Prop :=
  nonce.val < nonceBound
    ∧ CollisionFree packingPoints
      (openingPoints oracle parameters nonce piopHash)

def CanonicalOpeningNonce
    (oracle : Oracle)
    (parameters : Parameters)
    (packingPoints : List Word)
    (piopHash : List Word)
    (nonce : Word) : Prop :=
  ValidOpeningNonce oracle parameters packingPoints piopHash nonce
    ∧ ∀ earlier : Word,
      earlier.val < nonce.val ->
        ¬ValidOpeningNonce oracle parameters packingPoints piopHash earlier

theorem canonical_opening_nonce_unique
    {oracle : Oracle}
    {parameters : Parameters}
    {packingPoints : List Word}
    {piopHash : List Word}
    {left right : Word}
    (leftCanonical :
      CanonicalOpeningNonce oracle parameters packingPoints piopHash left)
    (rightCanonical :
      CanonicalOpeningNonce oracle parameters packingPoints piopHash right) :
    left = right := by
  apply Fin.ext
  by_contra different
  rcases Nat.lt_or_gt_of_ne different with left_lt_right | right_lt_left
  · exact (rightCanonical.2 left left_lt_right) leftCanonical.1
  · exact (leftCanonical.2 right right_lt_left) rightCanonical.1

theorem alternate_valid_nonce_is_not_canonical
    {oracle : Oracle}
    {parameters : Parameters}
    {packingPoints : List Word}
    {piopHash : List Word}
    {canonical alternate : Word}
    (canonicalProof :
      CanonicalOpeningNonce oracle parameters packingPoints piopHash canonical)
    (different : alternate ≠ canonical) :
    ¬CanonicalOpeningNonce oracle parameters packingPoints piopHash alternate := by
  intro alternateCanonical
  exact different (canonical_opening_nonce_unique alternateCanonical canonicalProof)

structure PcsOpeningRound where
  combinationHeads : List (List Word)
  randomCombinationTails : List (List Word)
deriving DecidableEq, Repr

def PcsOpeningRound.messageWords (opening : PcsOpeningRound) : List Word :=
  (List.zipWith (fun head tail => head ++ tail)
    opening.combinationHeads opening.randomCombinationTails).flatten

def decsOpeningHashInput
    (piopHash : List Word)
    (opening : PcsOpeningRound) : List Word :=
  piopHash ++ opening.messageWords

def decsOpeningHash
    (oracle : Oracle)
    (piopHash : List Word)
    (opening : PcsOpeningRound) : List Word :=
  hashWords oracle decsOpeningDomain
    (decsOpeningHashInput piopHash opening)
    digestWordCount

structure Transcript where
  parameters : Parameters
  commitment : CommitmentRound
  statementBindingWords : List Word
  piop : PiopRound
  openingNonce : Word
  opening : PcsOpeningRound
deriving DecidableEq, Repr

def Transcript.merkleRootHash (oracle : Oracle) (transcript : Transcript) : List Word :=
  merkleRootDigest oracle transcript.commitment transcript.statementBindingWords

def Transcript.piopHash (oracle : Oracle) (transcript : Transcript) : List Word :=
  piopDigest oracle transcript.commitment transcript.statementBindingWords transcript.piop

def Transcript.CanonicalNonce
    (oracle : Oracle)
    (packingPoints : List Word)
    (transcript : Transcript) : Prop :=
  CanonicalOpeningNonce oracle transcript.parameters packingPoints
    (transcript.piopHash oracle) transcript.openingNonce

def Transcript.decsHash (oracle : Oracle) (transcript : Transcript) : List Word :=
  decsOpeningHash oracle (transcript.piopHash oracle) transcript.opening

def firstChallengePreimage
    (oracle : Oracle)
    (transcript : Transcript) : List Byte :=
  sha512BlockPreimage decsCoefficientDomain
    (transcript.merkleRootHash oracle)
    0

def secondChallengePreimage
    (oracle : Oracle)
    (transcript : Transcript) : List Byte :=
  sha512BlockPreimage piopCoefficientDomain
    (hashFpp oracle transcript.commitment transcript.statementBindingWords)
    0

def thirdChallengePreimage
    (oracle : Oracle)
    (transcript : Transcript) : List Byte :=
  sha512BlockPreimage piopOpeningDomain
    (openingChallengeInput transcript.openingNonce (transcript.piopHash oracle))
    0

def fourthChallengePreimage
    (oracle : Oracle)
    (transcript : Transcript) : List Byte :=
  sha512BlockPreimage decsFixedSamplingDomain
    (transcript.decsHash oracle)
    0

theorem active_parameters_are_level5 :
    activeParameters =
      { repetitions := 5, openedEvaluations := 5, decsOpenedEvaluations := 23 } := by
  rfl

theorem first_round_commitment_binds_statement_in_preimage
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) :
    merkleRootHashInput commitment statementBindingWords =
      commitment.saltWords ++ commitment.merkleRootWords ++ statementBindingWords := by
  rfl

theorem statement_binding_is_appended_after_bound_pcs_commitment
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) :
    piopInputWords oracle commitment statementBindingWords =
      pcsCommitmentTranscript oracle commitment statementBindingWords
        ++ statementBindingWords := by
  rfl

theorem piop_transcript_starts_with_hash_fpp
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word)
    (piop : PiopRound) :
    piopTranscriptWords oracle commitment statementBindingWords piop =
      hashFpp oracle commitment statementBindingWords ++ piop.messageWords := by
  rfl

theorem opening_challenge_binds_nonce_before_piop_hash
    (nonce : Word)
    (piopHash : List Word) :
    openingChallengeInput nonce piopHash = nonce :: piopHash := by
  rfl

theorem decs_opening_hash_binds_piop_before_opening_message
    (piopHash : List Word)
    (opening : PcsOpeningRound) :
    decsOpeningHashInput piopHash opening = piopHash ++ opening.messageWords := by
  rfl

theorem active_challenge_domains_are_pairwise_distinct :
    [decsCoefficientDomain, piopCoefficientDomain, piopOpeningDomain,
      decsFixedSamplingDomain].Nodup := by
  decide

theorem active_challenge_preimages_are_pairwise_distinct
    (oracle : Oracle)
    (transcript : Transcript) :
    [ firstChallengePreimage oracle transcript,
      secondChallengePreimage oracle transcript,
      thirdChallengePreimage oracle transcript,
      fourthChallengePreimage oracle transcript ].Nodup := by
  have first_ne_second :
      firstChallengePreimage oracle transcript ≠
        secondChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 33 0) equal
    have encodedLength :
        encodeLE 8 41 = [41, 0, 0, 0, 0, 0, 0, 0] := by
      decide
    norm_num [firstChallengePreimage, secondChallengePreimage, sha512BlockPreimage,
      decsCoefficientDomain, piopCoefficientDomain, level5DomainPrefix, encodedLength]
      at byteEqual
    exact (by decide : (100 : Byte) ≠ 112) byteEqual
  have first_ne_third :
      firstChallengePreimage oracle transcript ≠
        thirdChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [firstChallengePreimage, thirdChallengePreimage, sha512BlockPreimage, encodeLE,
      decsCoefficientDomain, piopOpeningDomain, level5DomainPrefix] at byteEqual
  have first_ne_fourth :
      firstChallengePreimage oracle transcript ≠
        fourthChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [firstChallengePreimage, fourthChallengePreimage, sha512BlockPreimage, encodeLE,
      decsCoefficientDomain, decsFixedSamplingDomain, level5DomainPrefix] at byteEqual
  have second_ne_third :
      secondChallengePreimage oracle transcript ≠
        thirdChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [secondChallengePreimage, thirdChallengePreimage, sha512BlockPreimage, encodeLE,
      piopCoefficientDomain, piopOpeningDomain, level5DomainPrefix] at byteEqual
  have second_ne_fourth :
      secondChallengePreimage oracle transcript ≠
        fourthChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [secondChallengePreimage, fourthChallengePreimage, sha512BlockPreimage, encodeLE,
      piopCoefficientDomain, decsFixedSamplingDomain, level5DomainPrefix] at byteEqual
  have third_ne_fourth :
      thirdChallengePreimage oracle transcript ≠
        fourthChallengePreimage oracle transcript := by
    intro equal
    have byteEqual := congrArg (fun bytes => bytes.getD 0 0) equal
    norm_num [thirdChallengePreimage, fourthChallengePreimage, sha512BlockPreimage, encodeLE,
      piopOpeningDomain, decsFixedSamplingDomain, level5DomainPrefix] at byteEqual
  simp [first_ne_second, first_ne_third, first_ne_fourth, second_ne_third,
    second_ne_fourth, third_ne_fourth]

theorem deployed_hash_preimage_is_exact
    (words : List Word) :
    xofPreimage words =
      encodeLE 8 xofDomain.length
        ++ xofDomain
        ++ encodeLE 8 words.length
        ++ flattenWordBytes words
        ++ encodeLE 8 0 := by
  rfl

end SmallWoodTranscript
end HegemonCrypto
