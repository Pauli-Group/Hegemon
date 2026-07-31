import HegemonCrypto.SmallWoodExtraction
import HegemonCrypto.SmallWoodFixedSampling
import HegemonCrypto.SmallWoodPiopOpeningSampling
import HegemonCrypto.SmallWoodSha512Xof

/-!
# Exact active SmallWood round syntax

This module keeps two different protocols separate:

* `Interactive` is the public-coin interactive oracle proof to which round-by-round knowledge
  soundness applies. Its first prover message is the complete DECS evaluation oracle, and its
  third and fourth verifier messages are ideal uniform challenges.
* `Compiled` is the logical production transcript after Merkle commitment and Fiat--Shamir.
  Its first prover message is a root, its challenges come from SHA-512 XOF output, and its final
  message carries authentication material.

Conflating these protocols would let a theorem about an oracle be applied directly to a Merkle
root. The BCS proof must instead extract the interactive oracle from the compiled transcript and
then invoke the interactive extractor.
-/

namespace HegemonCrypto.SmallWood.RoundByRound

open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.SmallWood.Extraction
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-! ## Active production geometry -/

def rho : Nat := activeParameters.repetitions
def openedEvaluations : Nat := activeParameters.openedEvaluations
def beta : Nat := 2
def packingFactor : Nat := 64
def rowCount : Nat := 699
def nonlinearConstraintCount : Nat := 890
def effectiveConstraintDegree : Nat := 8
def decsEvaluationCount : Nat := 1048576
def decsOpenedEvaluations : Nat := activeParameters.decsOpenedEvaluations
def decsEta : Nat := activeDecsRepetitions

def witnessPolynomialDegree : Nat :=
  packingFactor + openedEvaluations - 1

def nonlinearMaskPolynomialDegree : Nat :=
  effectiveConstraintDegree * witnessPolynomialDegree - packingFactor

def linearMaskPolynomialDegree : Nat :=
  witnessPolynomialDegree + packingFactor - 1

def polynomialCount : Nat := rowCount + 2 * rho
def unstackedRowCount : Nat := packingFactor + openedEvaluations
def unstackedColumnCount : Nat := 749
def lvcsRowCount : Nat := unstackedRowCount * beta
def lvcsColumnCount : Nat := (unstackedColumnCount + beta - 1) / beta
def openedCombinationCount : Nat := beta * openedEvaluations
def decsPolynomialDegree : Nat :=
  lvcsColumnCount + decsOpenedEvaluations - 1

theorem active_geometry :
    rho = 5 ∧
    openedEvaluations = 5 ∧
    witnessPolynomialDegree = 68 ∧
    nonlinearMaskPolynomialDegree = 480 ∧
    linearMaskPolynomialDegree = 131 ∧
    polynomialCount = 709 ∧
    unstackedRowCount = 69 ∧
    lvcsRowCount = 138 ∧
    lvcsColumnCount = 375 ∧
    openedCombinationCount = 10 ∧
    decsPolynomialDegree = 397 := by
  decide

/-- Exact active statement geometry required before this transcript can authorize production. -/
def ActiveStatement (statement : Statement) : Prop :=
  statement.lppcRowCount = rowCount ∧
    statement.lppcPackingFactor = packingFactor ∧
    statement.effectiveConstraintDegree = effectiveConstraintDegree ∧
    statement.nonlinearConstraintCount = nonlinearConstraintCount ∧
    statement.linearConstraintCount ≤ activePiopLinearWidth ∧
    ProductionConstraintMapBound statement

/-- Fixed-size field matrix. -/
abbrev Matrix (rows columns : Nat) :=
  Fin rows -> Fin columns -> FieldWord

/-- Full DECS evaluation oracle sent by the first prover in the interactive protocol. -/
abbrev CommittedOracle :=
  Matrix decsEvaluationCount (lvcsRowCount + decsEta)

/-- Full DECS polynomials sent after the first verifier challenge. -/
abbrev DecsPolynomialMessage :=
  Matrix decsEta (decsPolynomialDegree + 1)

/-- One exact production-statement PIOP batching challenge. -/
abbrev PiopBatchingChallenge (statement : Statement) :=
  Matrix rho
    (productionPiopRowWidth
      statement.nonlinearConstraintCount statement.linearConstraintCount)

/-- Full PIOP polynomial messages committed before opening points are selected. -/
structure PiopPolynomialMessage where
  nonlinear : Matrix rho (nonlinearMaskPolynomialDegree + 1)
  linear : Matrix rho (linearMaskPolynomialDegree + 1)

noncomputable instance piopPolynomialMessageFintype :
    Fintype PiopPolynomialMessage :=
  Fintype.ofEquiv
    (Matrix rho (nonlinearMaskPolynomialDegree + 1) ×
      Matrix rho (linearMaskPolynomialDegree + 1))
    { toFun := fun components =>
        { nonlinear := components.1, linear := components.2 }
      invFun := fun message => (message.nonlinear, message.linear)
      left_inv := by intro components; cases components; rfl
      right_inv := by intro message; cases message; rfl }

noncomputable instance piopPolynomialMessageDecidableEq :
    DecidableEq PiopPolynomialMessage :=
  Classical.decEq _

/-- The 64 packing points are exactly the field words with canonical value below 64. -/
def packingPoints : Finset FieldWord :=
  Finset.univ.filter fun point => point.val < packingFactor

/-- Ideal third verifier challenge: five distinct points outside the packing domain. -/
abbrev PiopOpeningChallenge :=
  HegemonCrypto.SmallWood.PiopOpeningSampling.ValidTuple
    packingPoints openedEvaluations

noncomputable instance piopOpeningChallengeFintype :
    Fintype PiopOpeningChallenge := by
  unfold PiopOpeningChallenge
  unfold HegemonCrypto.SmallWood.PiopOpeningSampling.ValidTuple
  letI : DecidablePred
      (fun tuple :
          HegemonCrypto.SmallWood.PiopOpeningSampling.OpeningTuple
            (F := FieldWord) openedEvaluations =>
        HegemonCrypto.SmallWood.PiopOpeningSampling.TupleValid
          packingPoints tuple) :=
    fun tuple => Classical.propDecidable
      (HegemonCrypto.SmallWood.PiopOpeningSampling.TupleValid
        packingPoints tuple)
  infer_instance

noncomputable instance piopOpeningChallengeDecidableEq :
    DecidableEq PiopOpeningChallenge :=
  Classical.decEq _

/--
Full LVCS combination values sent before DECS indexes are sampled. Each row is serialized as
375 data values followed by 23 hiding values; it is not a polynomial coefficient vector.
-/
abbrev PcsCombinationMessage :=
  Matrix openedCombinationCount (lvcsColumnCount + decsOpenedEvaluations)

/-- Ideal fourth verifier challenge: a uniform 20-element subset of the DECS domain. -/
abbrev DecsOpeningChallenge :=
  { sample : Finset (Fin decsEvaluationCount) //
      sample.card = decsOpenedEvaluations }

/-- Oracle rows returned exactly at the selected DECS positions. -/
abbrev OpenedOracleRows (challenge : DecsOpeningChallenge) :=
  (position : { index : Fin decsEvaluationCount // index ∈ challenge.val }) ->
    Fin (lvcsRowCount + decsEta) -> FieldWord

theorem active_oracle_row_width :
    lvcsRowCount + decsEta = 143 := by
  decide

/-! ## The underlying public-coin interactive oracle proof -/

namespace Interactive

/--
The final interactive answer contains queried oracle rows and the auxiliary values that tie the
SmallWood PCS combinations back to the original PIOP polynomial evaluations. Merkle paths,
DECS high coefficients, and masking evaluations are absent: the full oracle and full earlier
polynomials are already available in the interactive protocol.
-/
structure FinalOpeningMessage (challenge : DecsOpeningChallenge) where
  oracleRows : OpenedOracleRows challenge
  partialEvaluations :
    Matrix openedEvaluations (unstackedColumnCount - polynomialCount)
  openedPolynomialEvaluations :
    Matrix openedEvaluations polynomialCount

theorem active_final_opening_dimensions :
    unstackedColumnCount - polynomialCount = 40 := by
  decide

/--
Every legal interactive prefix. Each constructor contains exactly the history available at that
point, so future messages cannot influence an earlier verifier challenge.
-/
inductive Prefix where
  | initial (statement : Statement)
  | oracle
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
  | decsChallenge
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (challenge : Matrix decsEta lvcsRowCount)
  | decsPolynomials
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (challenge : Matrix decsEta lvcsRowCount)
      (message : DecsPolynomialMessage)
  | piopChallenge
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (decsChallenge : Matrix decsEta lvcsRowCount)
      (decsMessage : DecsPolynomialMessage)
      (challenge : PiopBatchingChallenge statement)
  | piopPolynomials
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (decsChallenge : Matrix decsEta lvcsRowCount)
      (decsMessage : DecsPolynomialMessage)
      (piopChallenge : PiopBatchingChallenge statement)
      (message : PiopPolynomialMessage)
  | piopOpening
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (decsChallenge : Matrix decsEta lvcsRowCount)
      (decsMessage : DecsPolynomialMessage)
      (piopChallenge : PiopBatchingChallenge statement)
      (piopMessage : PiopPolynomialMessage)
      (challenge : PiopOpeningChallenge)
  | pcsCombination
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (decsChallenge : Matrix decsEta lvcsRowCount)
      (decsMessage : DecsPolynomialMessage)
      (piopChallenge : PiopBatchingChallenge statement)
      (piopMessage : PiopPolynomialMessage)
      (piopOpening : PiopOpeningChallenge)
      (message : PcsCombinationMessage)
  | decsOpening
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (decsChallenge : Matrix decsEta lvcsRowCount)
      (decsMessage : DecsPolynomialMessage)
      (piopChallenge : PiopBatchingChallenge statement)
      (piopMessage : PiopPolynomialMessage)
      (piopOpening : PiopOpeningChallenge)
      (pcsMessage : PcsCombinationMessage)
      (challenge : DecsOpeningChallenge)
  | final
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (decsChallenge : Matrix decsEta lvcsRowCount)
      (decsMessage : DecsPolynomialMessage)
      (piopChallenge : PiopBatchingChallenge statement)
      (piopMessage : PiopPolynomialMessage)
      (piopOpening : PiopOpeningChallenge)
      (pcsMessage : PcsCombinationMessage)
      (decsOpening : DecsOpeningChallenge)
      (message : FinalOpeningMessage decsOpening)

def Prefix.statement : Prefix -> Statement
  | .initial statement
  | .oracle statement _ _
  | .decsChallenge statement _ _ _
  | .decsPolynomials statement _ _ _ _
  | .piopChallenge statement _ _ _ _ _
  | .piopPolynomials statement _ _ _ _ _ _
  | .piopOpening statement _ _ _ _ _ _ _
  | .pcsCombination statement _ _ _ _ _ _ _ _
  | .decsOpening statement _ _ _ _ _ _ _ _ _
  | .final statement _ _ _ _ _ _ _ _ _ _ => statement

/-- Prefixes at which the verifier sends fresh ideal random coins. -/
def Prefix.verifierTurn : Prefix -> Prop
  | .oracle .. | .decsPolynomials .. | .piopPolynomials .. | .pcsCombination .. => True
  | _ => False

/-- Exact finite challenge space available at each verifier turn. -/
def Challenge : Prefix -> Type
  | .oracle .. => Matrix decsEta lvcsRowCount
  | .decsPolynomials statement .. => PiopBatchingChallenge statement
  | .piopPolynomials .. => PiopOpeningChallenge
  | .pcsCombination .. => DecsOpeningChallenge
  | _ => PUnit

noncomputable instance challengeFintype (transcriptPrefix : Prefix) :
    Fintype (Challenge transcriptPrefix) := by
  cases transcriptPrefix <;> simp only [Challenge] <;> infer_instance

noncomputable instance challengeDecidableEq (transcriptPrefix : Prefix) :
    DecidableEq (Challenge transcriptPrefix) := by
  cases transcriptPrefix <;> simp only [Challenge] <;> infer_instance

/-- Verifier transition; non-verifier prefixes are fixed points. -/
def verifierExtension :
    (transcriptPrefix : Prefix) -> Challenge transcriptPrefix -> Prefix
  | .oracle statement active committedOracle, challenge =>
      .decsChallenge statement active committedOracle challenge
  | .decsPolynomials statement active committedOracle decsChallenge decsMessage, challenge =>
      .piopChallenge statement active committedOracle decsChallenge decsMessage challenge
  | .piopPolynomials statement active committedOracle decsChallenge decsMessage
      piopChallenge piopMessage, challenge =>
      .piopOpening statement active committedOracle decsChallenge decsMessage
        piopChallenge piopMessage challenge
  | .pcsCombination statement active committedOracle decsChallenge decsMessage
      piopChallenge piopMessage piopOpening pcsMessage, challenge =>
      .decsOpening statement active committedOracle decsChallenge decsMessage
        piopChallenge piopMessage piopOpening pcsMessage challenge
  | transcriptPrefix, _ => transcriptPrefix

theorem verifier_extension_preserves_statement
    (transcriptPrefix : Prefix)
    (challenge : Challenge transcriptPrefix) :
    (verifierExtension transcriptPrefix challenge).statement =
      transcriptPrefix.statement := by
  cases transcriptPrefix <;> rfl

/-- Legal prover transitions between adjacent verifier turns. -/
inductive ProverExtension : Prefix -> Prefix -> Prop where
  | oracle
      (statement : Statement)
      (active : ActiveStatement statement)
      (message : CommittedOracle) :
      ProverExtension (.initial statement) (.oracle statement active message)
  | decsPolynomials
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (challenge : Matrix decsEta lvcsRowCount)
      (message : DecsPolynomialMessage) :
      ProverExtension
        (.decsChallenge statement active committedOracle challenge)
        (.decsPolynomials statement active committedOracle challenge message)
  | piopPolynomials
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (decsChallenge : Matrix decsEta lvcsRowCount)
      (decsMessage : DecsPolynomialMessage)
      (piopChallenge : PiopBatchingChallenge statement)
      (message : PiopPolynomialMessage) :
      ProverExtension
        (.piopChallenge statement active committedOracle decsChallenge decsMessage piopChallenge)
        (.piopPolynomials statement active committedOracle decsChallenge decsMessage
          piopChallenge message)
  | pcsCombination
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (decsChallenge : Matrix decsEta lvcsRowCount)
      (decsMessage : DecsPolynomialMessage)
      (piopChallenge : PiopBatchingChallenge statement)
      (piopMessage : PiopPolynomialMessage)
      (piopOpening : PiopOpeningChallenge)
      (message : PcsCombinationMessage) :
      ProverExtension
        (.piopOpening statement active committedOracle decsChallenge decsMessage
          piopChallenge piopMessage piopOpening)
        (.pcsCombination statement active committedOracle decsChallenge decsMessage
          piopChallenge piopMessage piopOpening message)
  | final
      (statement : Statement)
      (active : ActiveStatement statement)
      (committedOracle : CommittedOracle)
      (decsChallenge : Matrix decsEta lvcsRowCount)
      (decsMessage : DecsPolynomialMessage)
      (piopChallenge : PiopBatchingChallenge statement)
      (piopMessage : PiopPolynomialMessage)
      (piopOpening : PiopOpeningChallenge)
      (pcsMessage : PcsCombinationMessage)
      (decsOpening : DecsOpeningChallenge)
      (message : FinalOpeningMessage decsOpening) :
      ProverExtension
        (.decsOpening statement active committedOracle decsChallenge decsMessage
          piopChallenge piopMessage piopOpening pcsMessage decsOpening)
        (.final statement active committedOracle decsChallenge decsMessage
          piopChallenge piopMessage piopOpening pcsMessage decsOpening message)

theorem prover_extension_preserves_statement
    {before after : Prefix}
    (extension : ProverExtension before after) :
    after.statement = before.statement := by
  cases extension <;> rfl

def Prefix.terminal : Prefix -> Prop
  | .final .. => True
  | _ => False

theorem verifier_turns_are_exactly_four :
    ∀ transcriptPrefix : Prefix,
      Prefix.verifierTurn transcriptPrefix ↔
        (∃ statement active committedOracle,
          transcriptPrefix = Prefix.oracle statement active committedOracle) ∨
        (∃ statement active committedOracle challenge message,
          transcriptPrefix =
            Prefix.decsPolynomials statement active committedOracle challenge message) ∨
        (∃ statement active committedOracle decsChallenge decsMessage
            piopChallenge piopMessage,
          transcriptPrefix =
            Prefix.piopPolynomials statement active committedOracle decsChallenge decsMessage
              piopChallenge piopMessage) ∨
        (∃ statement active committedOracle decsChallenge decsMessage piopChallenge piopMessage
            piopOpening pcsMessage,
          transcriptPrefix =
            Prefix.pcsCombination statement active committedOracle decsChallenge decsMessage
              piopChallenge piopMessage piopOpening pcsMessage) := by
  intro transcriptPrefix
  cases transcriptPrefix <;> simp [Prefix.verifierTurn] <;> assumption

end Interactive

/-! ## The compiled production transcript -/

namespace Compiled

/-- First compiled prover message: salt and raw SHA-512 Merkle root. -/
structure RootMessage where
  salt : Fin 4 -> Word
  merkleRoot : Sha512Xof.RawDigest

/-- All sixteen five-word nonce candidates consumed by canonical PIOP opening selection. -/
abbrev PiopOpeningCandidateStream :=
  HegemonCrypto.SmallWood.PiopOpeningSampling.CandidateStream
    (F := FieldWord)
    piopNonceTrialBound
    openedEvaluations

/-- Fixed forty-word DECS candidate stream consumed without prover-controlled grinding. -/
abbrev DecsOpeningCandidateStream :=
  Fin activeDecsFixedCandidateCount -> FieldWord

/--
Compact authentication paths have depth 20 but omit siblings shared by the sorted opened set.
The exact path-length vector is checked by native refinement, not approximated by this bound.
-/
structure CompactAuthenticationPaths where
  paths : Fin decsOpenedEvaluations -> List Sha512Xof.RawDigest
  nonempty : ∀ index, (paths index).length > 0
  depthBound : ∀ index, (paths index).length ≤ 20

/-- Final compiled response after all four hash-derived challenges. -/
structure FinalOpeningMessage where
  subsetEvaluations :
    Matrix decsOpenedEvaluations (lvcsRowCount - openedCombinationCount)
  partialEvaluations :
    Matrix openedEvaluations (unstackedColumnCount - polynomialCount)
  authenticationPaths : CompactAuthenticationPaths
  decsMaskingEvaluations : Matrix decsOpenedEvaluations decsEta
  decsHighCoefficients : Matrix decsEta lvcsColumnCount
  openedPolynomialEvaluations : Matrix openedEvaluations polynomialCount

theorem active_final_opening_dimensions :
    lvcsRowCount - openedCombinationCount = 128 ∧
    unstackedColumnCount - polynomialCount = 40 := by
  decide

/--
One complete logical compiled transcript. `pcsMessage` contains the 375 data values followed by
23 hiding values for every combination; the native wire transmits the hiding tails and reconstructs
the data heads from the final response.
-/
structure Transcript (statement : Statement) where
  active : ActiveStatement statement
  rootMessage : RootMessage
  decsChallenge : Matrix decsEta lvcsRowCount
  decsMessage : DecsPolynomialMessage
  piopChallenge : PiopBatchingChallenge statement
  piopMessage : PiopPolynomialMessage
  piopCandidates : PiopOpeningCandidateStream
  piopOpening : PiopOpeningChallenge
  piopFirstValid :
    HegemonCrypto.SmallWood.PiopOpeningSampling.firstValid packingPoints
        (HegemonCrypto.SmallWood.PiopOpeningSampling.streamTuples piopCandidates) =
      some piopOpening
  pcsMessage : PcsCombinationMessage
  decsCandidates : DecsOpeningCandidateStream
  decsOpening : DecsOpeningChallenge
  finalMessage : FinalOpeningMessage

end Compiled

end HegemonCrypto.SmallWood.RoundByRound
