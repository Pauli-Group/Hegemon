import HegemonCrypto.CanonicalBytes

namespace HegemonCrypto
namespace SmallWoodTranscript

open CanonicalBytes

abbrev Word := Fin (2 ^ 64)

def digestWordCount : Nat := 4
def nonceBound : Nat := 2 ^ 32

def xofDomain : List Byte :=
  [ 104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108,
    119, 111, 111, 100, 46, 102, 54, 52, 45, 120, 111, 102, 46, 118, 49 ]

def wordBytes (word : Word) : List Byte :=
  encodeLE 8 word.val

def flattenWordBytes (words : List Word) : List Byte :=
  (words.map wordBytes).flatten

def xofPreimage (words : List Word) : List Byte :=
  xofDomain ++ encodeLE 8 words.length ++ flattenWordBytes words

abbrev Oracle := List Byte -> Nat -> List Word

def hashWords (oracle : Oracle) (words : List Word) (outputWords : Nat) : List Word :=
  oracle (xofPreimage words) outputWords

structure Parameters where
  repetitions : Nat
  openedEvaluations : Nat
  decsOpenedEvaluations : Nat
deriving DecidableEq, Repr

def activeParameters : Parameters :=
  { repetitions := 3,
    openedEvaluations := 3,
    decsOpenedEvaluations := 24 }

structure CommitmentRound where
  saltWords : List Word
  merkleRootWords : List Word
  decPolynomials : List (List Word)
deriving DecidableEq, Repr

def merkleRootHashInput (commitment : CommitmentRound) : List Word :=
  commitment.saltWords ++ commitment.merkleRootWords

def merkleRootDigest (oracle : Oracle) (commitment : CommitmentRound) : List Word :=
  hashWords oracle (merkleRootHashInput commitment) digestWordCount

def pcsCommitmentTranscript
    (oracle : Oracle)
    (commitment : CommitmentRound) : List Word :=
  merkleRootDigest oracle commitment ++ commitment.decPolynomials.flatten

def piopInputWords
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  pcsCommitmentTranscript oracle commitment ++ statementBindingWords

def hashFpp
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) : List Word :=
  hashWords oracle
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
  hashWords oracle
    (piopTranscriptWords oracle commitment statementBindingWords piop)
    digestWordCount

def openingChallengeInput (nonce : Word) (piopHash : List Word) : List Word :=
  nonce :: piopHash

def openingPoints
    (oracle : Oracle)
    (parameters : Parameters)
    (nonce : Word)
    (piopHash : List Word) : List Word :=
  hashWords oracle
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
  · exact
      (rightCanonical.2 left left_lt_right) leftCanonical.1
  · exact
      (leftCanonical.2 right right_lt_left) rightCanonical.1

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
  hashWords oracle
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

theorem statement_binding_is_appended_after_pcs_commitment
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (statementBindingWords : List Word) :
    piopInputWords oracle commitment statementBindingWords =
      pcsCommitmentTranscript oracle commitment ++ statementBindingWords := by
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

theorem deployed_hash_roles_share_one_domain
    (words : List Word) :
    xofPreimage words = xofDomain ++ encodeLE 8 words.length ++ flattenWordBytes words := by
  rfl

end SmallWoodTranscript
end HegemonCrypto
