import HegemonCrypto.SmallWoodBcsQrom
import HegemonCrypto.SmallWoodLvcsOpening
import HegemonCrypto.SmallWoodProductionOpeningTransition

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Concrete SmallWood round-by-round knowledge instance

This module replaces the abstract round-by-round field used by the BCS/QROM
ledger with the active four-turn SmallWood interactive protocol.

For an invalid deterministically extracted witness, a verifier challenge can
move the transcript into the semantic accepting state only through one of the
four exact SmallWood failure events:

1. invalid committed rows survive DECS degree enforcement;
2. an invalid production relation survives uniform PIOP batching;
3. a nonzero production discrepancy vanishes at every opening point; or
4. a false LVCS combination survives every sampled DECS position.

The state deliberately over-approximates native acceptance. The exact
accepted-byte and native-transcript bridge is proved separately in
`SmallWoodProductionAcceptanceClosure`.
-/

namespace HegemonCrypto.SmallWood.ProductionBcsInstantiation

open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.Interactive
open HegemonCrypto.SmallWood.LvcsOpening
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.ProductionOpeningTransition
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.RoundByRound.Interactive
open HegemonCrypto.UniformSubsetSampling
open Hegemon.Transaction.SmallWoodNoGrindingSoundness

noncomputable section

def epsilonOne : Rat :=
  (epsilon1Numerator : Rat) / epsilon1Denominator

def epsilonTwo : Rat :=
  (epsilon2Numerator : Rat) / epsilon2Denominator

def epsilonThree : Rat :=
  (epsilon3Numerator : Rat) / epsilon3Denominator

def epsilonFour : Rat :=
  (epsilon4Numerator : Rat) / epsilon4Denominator

/-- Exact union-bound knowledge error of the four interactive verifier turns. -/
def activeInteractiveKnowledgeError : Rat :=
  epsilonOne + epsilonTwo + epsilonThree + epsilonFour

theorem epsilon_one_nonnegative : 0 ≤ epsilonOne := by
  unfold epsilonOne
  positivity

theorem epsilon_two_nonnegative : 0 ≤ epsilonTwo := by
  unfold epsilonTwo
  positivity

theorem epsilon_three_nonnegative : 0 ≤ epsilonThree := by
  unfold epsilonThree
  positivity

theorem epsilon_four_nonnegative : 0 ≤ epsilonFour := by
  unfold epsilonFour
  positivity

theorem active_interactive_knowledge_error_nonnegative :
    0 ≤ activeInteractiveKnowledgeError := by
  unfold activeInteractiveKnowledgeError
  exact add_nonneg
    (add_nonneg
      (add_nonneg epsilon_one_nonnegative epsilon_two_nonnegative)
      epsilon_three_nonnegative)
    epsilon_four_nonnegative

theorem epsilon_one_le_active_interactive_knowledge_error :
    epsilonOne ≤ activeInteractiveKnowledgeError := by
  unfold activeInteractiveKnowledgeError
  linarith [epsilon_two_nonnegative, epsilon_three_nonnegative,
    epsilon_four_nonnegative]

theorem epsilon_two_le_active_interactive_knowledge_error :
    epsilonTwo ≤ activeInteractiveKnowledgeError := by
  unfold activeInteractiveKnowledgeError
  linarith [epsilon_one_nonnegative, epsilon_three_nonnegative,
    epsilon_four_nonnegative]

theorem epsilon_three_le_active_interactive_knowledge_error :
    epsilonThree ≤ activeInteractiveKnowledgeError := by
  unfold activeInteractiveKnowledgeError
  linarith [epsilon_one_nonnegative, epsilon_two_nonnegative,
    epsilon_four_nonnegative]

theorem epsilon_four_le_active_interactive_knowledge_error :
    epsilonFour ≤ activeInteractiveKnowledgeError := by
  unfold activeInteractiveKnowledgeError
  linarith [epsilon_one_nonnegative, epsilon_two_nonnegative,
    epsilon_three_nonnegative]

def ExtractedRelationHolds
    (statement : Statement)
    (oracle : CommittedOracle) : Prop :=
  (statement, extractWitness oracle) ∈ Relation

def FirstRoundGood
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : Matrix decsEta lvcsRowCount) : Prop :=
  ExtractedRelationHolds statement oracle ∨
    (¬CommittedRowsDegreeBounded oracle ∧
      DecsChallengePasses oracle challenge)

def SecondRoundGood
    (statement : Statement)
    (active : ActiveStatement statement)
    (oracle : CommittedOracle)
    (decsChallenge : Matrix decsEta lvcsRowCount)
    (piopChallenge : PiopBatchingChallenge statement) : Prop :=
  FirstRoundGood statement oracle decsChallenge ∨
    (CommittedRowsDegreeBounded oracle ∧
      PiopAffineChallengePasses statement oracle active
        (productionLinearMaskSum oracle) piopChallenge)

def ThirdRoundGood
    (statement : Statement)
    (active : ActiveStatement statement)
    (oracle : CommittedOracle)
    (decsChallenge : Matrix decsEta lvcsRowCount)
    (piopChallenge : PiopBatchingChallenge statement)
    (piopMessage : PiopPolynomialMessage)
    (piopOpening : PiopOpeningChallenge) : Prop :=
  SecondRoundGood statement active oracle decsChallenge piopChallenge ∨
    (CommittedRowsDegreeBounded oracle ∧
      ClaimedLinearTarget statement piopChallenge piopMessage ∧
      ProductionPiopOpeningPasses
        statement oracle piopChallenge piopMessage piopOpening)

/-- Deterministically select one false combination if the transmitted LVCS table is false. -/
def selectedFalseCombination
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle) : Fin openedCombinationCount :=
  if mismatch :
      ∃ combination : Fin openedCombinationCount,
        claimedCombinationPolynomial message combination ≠
          committedCombinationPolynomial oracle
            (productionCombinationCoefficient opening combination) then
    Classical.choose mismatch
  else
    ⟨0, by decide⟩

theorem selected_false_combination_is_false
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (notMatching : ¬ProductionCombinationsMatch opening message oracle) :
    claimedCombinationPolynomial message
        (selectedFalseCombination opening message oracle) ≠
      committedCombinationPolynomial oracle
        (productionCombinationCoefficient opening
          (selectedFalseCombination opening message oracle)) := by
  have mismatch :
      ∃ combination : Fin openedCombinationCount,
        claimedCombinationPolynomial message combination ≠
          committedCombinationPolynomial oracle
            (productionCombinationCoefficient opening combination) := by
    simpa [ProductionCombinationsMatch] using notMatching
  unfold selectedFalseCombination
  simp only [dif_pos mismatch]
  exact Classical.choose_spec mismatch

/-- Fourth-round event for the canonical first false LVCS combination. -/
def LvcsOpeningException
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (challenge : DecsOpeningChallenge) : Prop :=
  ¬ProductionCombinationsMatch opening message oracle ∧
    ProductionCombinationPassesOn opening message
      (selectedFalseCombination opening message oracle) oracle challenge

def FourthRoundGood
    (statement : Statement)
    (active : ActiveStatement statement)
    (oracle : CommittedOracle)
    (decsChallenge : Matrix decsEta lvcsRowCount)
    (piopChallenge : PiopBatchingChallenge statement)
    (piopMessage : PiopPolynomialMessage)
    (piopOpening : PiopOpeningChallenge)
    (pcsMessage : PcsCombinationMessage)
    (decsOpening : DecsOpeningChallenge) : Prop :=
  ThirdRoundGood statement active oracle decsChallenge
      piopChallenge piopMessage piopOpening ∨
    (CommittedRowsDegreeBounded oracle ∧
      LvcsOpeningException piopOpening pcsMessage oracle decsOpening)

/-- Semantic state used by the concrete RBR extractor. -/
def SemanticGood : Prefix -> Prop
  | .initial _ => False
  | .oracle .. => False
  | .decsChallenge statement _ oracle challenge =>
      FirstRoundGood statement oracle challenge
  | .decsPolynomials statement _ oracle challenge _ =>
      FirstRoundGood statement oracle challenge
  | .piopChallenge statement active oracle decsChallenge _ piopChallenge =>
      SecondRoundGood statement active oracle decsChallenge piopChallenge
  | .piopPolynomials statement active oracle decsChallenge _
      piopChallenge _ =>
      SecondRoundGood statement active oracle decsChallenge piopChallenge
  | .piopOpening statement active oracle decsChallenge _
      piopChallenge piopMessage piopOpening =>
      ThirdRoundGood statement active oracle decsChallenge
        piopChallenge piopMessage piopOpening
  | .pcsCombination statement active oracle decsChallenge _
      piopChallenge piopMessage piopOpening _ =>
      ThirdRoundGood statement active oracle decsChallenge
        piopChallenge piopMessage piopOpening
  | .decsOpening statement active oracle decsChallenge _
      piopChallenge piopMessage piopOpening pcsMessage decsOpening =>
      FourthRoundGood statement active oracle decsChallenge
        piopChallenge piopMessage piopOpening pcsMessage decsOpening
  | .final statement active oracle decsChallenge _
      piopChallenge piopMessage piopOpening pcsMessage decsOpening _ =>
      FourthRoundGood statement active oracle decsChallenge
        piopChallenge piopMessage piopOpening pcsMessage decsOpening

noncomputable def semanticState (transcriptPrefix : Prefix) : Bool := by
  classical
  exact if SemanticGood transcriptPrefix then true else false

theorem semantic_state_true_iff (transcriptPrefix : Prefix) :
    semanticState transcriptPrefix = true ↔ SemanticGood transcriptPrefix := by
  simp [semanticState]

theorem semantic_state_false_iff (transcriptPrefix : Prefix) :
    semanticState transcriptPrefix = false ↔ ¬SemanticGood transcriptPrefix := by
  simp [semanticState]

def extractedWitnessAtPrefix : Prefix -> Option Witness
  | .initial _ => none
  | .oracle _ _ oracle
  | .decsChallenge _ _ oracle _
  | .decsPolynomials _ _ oracle _ _
  | .piopChallenge _ _ oracle _ _ _
  | .piopPolynomials _ _ oracle _ _ _ _
  | .piopOpening _ _ oracle _ _ _ _ _
  | .pcsCombination _ _ oracle _ _ _ _ _ _
  | .decsOpening _ _ oracle _ _ _ _ _ _ _
  | .final _ _ oracle _ _ _ _ _ _ _ _ =>
      some (extractWitness oracle)

noncomputable def semanticAccepts (transcriptPrefix : Prefix) : Bool := by
  classical
  exact if Prefix.terminal transcriptPrefix then semanticState transcriptPrefix else false

def nextSemanticGoodProbability (transcriptPrefix : Prefix) : Rat :=
  letI := challengeFintype transcriptPrefix
  letI := challengeDecidableEq transcriptPrefix
  uniformEventProbability fun challenge =>
    semanticState (verifierExtension transcriptPrefix challenge) = true

theorem next_semantic_good_probability_is_uniform (transcriptPrefix : Prefix) :
    letI := challengeFintype transcriptPrefix
    letI := challengeDecidableEq transcriptPrefix
    nextSemanticGoodProbability transcriptPrefix =
      ((Finset.univ.filter fun challenge =>
        semanticState (verifierExtension transcriptPrefix challenge) = true).card : Rat) /
        Fintype.card (Challenge transcriptPrefix) := by
  unfold nextSemanticGoodProbability
  exact uniform_event_probability_eq_filter
    (fun challenge =>
      semanticState (verifierExtension transcriptPrefix challenge) = true)

theorem next_semantic_good_probability_nonnegative (transcriptPrefix : Prefix) :
    0 ≤ nextSemanticGoodProbability transcriptPrefix := by
  unfold nextSemanticGoodProbability
  exact uniform_event_probability_nonnegative _

theorem next_semantic_good_probability_at_most_one (transcriptPrefix : Prefix) :
    nextSemanticGoodProbability transcriptPrefix ≤ 1 := by
  unfold nextSemanticGoodProbability
  exact uniform_event_probability_at_most_one _

theorem semantic_state_survives_prover_message
    {before after : Prefix}
    (extension : ProverExtension before after)
    (beforeFalse : semanticState before = false) :
    semanticState after = false := by
  cases extension <;> simp_all [semanticState, SemanticGood]

theorem semantic_doomed_terminal_rejects
    (transcriptPrefix : Prefix)
    (terminal : Prefix.terminal transcriptPrefix)
    (stateFalse : semanticState transcriptPrefix = false) :
    semanticAccepts transcriptPrefix = false := by
  simp [semanticAccepts, terminal, stateFalse]

theorem lvcs_opening_exception_probability_le
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (degreeBounded : CommittedRowsDegreeBounded oracle) :
    uniformEventProbability (LvcsOpeningException opening message oracle) ≤
      epsilonFour := by
  by_cases matching : ProductionCombinationsMatch opening message oracle
  · have emptyEvent :
        (fun challenge =>
          LvcsOpeningException opening message oracle challenge) =
            fun _ => False := by
      funext challenge
      simp [LvcsOpeningException, matching]
    change uniformEventProbability
      (fun challenge =>
        LvcsOpeningException opening message oracle challenge) ≤ epsilonFour
    rw [emptyEvent]
    rw [uniform_event_probability_false]
    exact epsilon_four_nonnegative
  · have falseClaim :=
      selected_false_combination_is_false opening message oracle matching
    calc
      uniformEventProbability (LvcsOpeningException opening message oracle) =
          uniformEventProbability
            (ProductionCombinationPassesOn opening message
              (selectedFalseCombination opening message oracle) oracle) := by
            congr 1
            funext challenge
            simp [LvcsOpeningException, matching]
      _ = discrepancyOpeningFailureProbability
            (claimedCombinationPolynomial message
                (selectedFalseCombination opening message oracle) -
              committedCombinationPolynomial oracle
                (productionCombinationCoefficient opening
                  (selectedFalseCombination opening message oracle))) :=
          production_combination_opening_uniform_probability_eq
            opening message
              (selectedFalseCombination opening message oracle) oracle
      _ ≤ epsilonFour := by
        calc
          _ ≤
              (Nat.choose decsPolynomialDegree decsOpenedEvaluations : Rat) /
                Nat.choose decsEvaluationCount decsOpenedEvaluations :=
            false_production_combination_opening_probability_le_epsilon4
              opening message
                (selectedFalseCombination opening message oracle)
                oracle degreeBounded falseClaim
          _ = epsilonFour := by
            exact active_epsilon4_is_uniform_bad_leaf_subset_bound.symm

/-- The first verifier turn can enter the good state only through relation validity or DECS error. -/
theorem first_round_next_good_probability_le
    (statement : Statement)
    (active : ActiveStatement statement)
    (oracle : CommittedOracle)
    (notRelation : (statement, extractWitness oracle) ∉ Relation) :
    nextSemanticGoodProbability (.oracle statement active oracle) ≤ epsilonOne := by
  have relationFalse : ¬ExtractedRelationHolds statement oracle := by
    simpa [ExtractedRelationHolds] using notRelation
  unfold nextSemanticGoodProbability
  by_cases degreeBounded : CommittedRowsDegreeBounded oracle
  · have eventEquation :
        (fun challenge =>
          semanticState
            (verifierExtension (.oracle statement active oracle) challenge) = true) =
          fun _ : Matrix decsEta lvcsRowCount => False := by
      funext challenge
      apply propext
      simp [semanticState, SemanticGood, FirstRoundGood, ExtractedRelationHolds,
        notRelation, degreeBounded, verifierExtension]
    rw [eventEquation]
    calc
      uniformEventProbability (fun _ : Matrix decsEta lvcsRowCount => False) = 0 :=
        uniform_event_probability_false
      _ ≤ epsilonOne := epsilon_one_nonnegative
  · have eventEquation :
        (fun challenge =>
          semanticState
            (verifierExtension (.oracle statement active oracle) challenge) = true) =
          DecsChallengePasses oracle := by
      funext challenge
      apply propext
      simp [semanticState, SemanticGood, FirstRoundGood, ExtractedRelationHolds,
        notRelation, degreeBounded, verifierExtension]
    rw [eventEquation]
    exact invalid_committed_rows_decs_challenge_probability_le
      oracle degreeBounded

/-- At the second verifier turn, a doomed state can revive only through affine PIOP batching. -/
theorem second_round_next_good_probability_le
    (statement : Statement)
    (active : ActiveStatement statement)
    (oracle : CommittedOracle)
    (decsChallenge : Matrix decsEta lvcsRowCount)
    (decsMessage : DecsPolynomialMessage)
    (notRelation : (statement, extractWitness oracle) ∉ Relation)
    (beforeFalse :
      semanticState
        (.decsPolynomials statement active oracle decsChallenge decsMessage) = false) :
    nextSemanticGoodProbability
        (.decsPolynomials statement active oracle decsChallenge decsMessage) ≤ epsilonTwo := by
  have firstBad : ¬FirstRoundGood statement oracle decsChallenge := by
    exact (semantic_state_false_iff _).mp (by
      simpa [SemanticGood] using beforeFalse)
  unfold nextSemanticGoodProbability
  by_cases degreeBounded : CommittedRowsDegreeBounded oracle
  · calc
      uniformEventProbability
          (fun challenge =>
            semanticState
              (verifierExtension
                (.decsPolynomials statement active oracle decsChallenge decsMessage)
                challenge) = true) ≤
          uniformEventProbability
            (PiopAffineChallengePasses statement oracle active
              (productionLinearMaskSum oracle)) := by
            apply uniform_event_probability_mono
            intro challenge accepted
            have secondGood :
                SecondRoundGood statement active oracle decsChallenge challenge := by
              exact (semantic_state_true_iff _).mp (by
                simpa [verifierExtension] using accepted)
            exact (secondGood.resolve_left firstBad).2
      _ ≤ epsilonTwo := by
        exact invalid_extracted_witness_piop_affine_challenge_probability_le
          statement oracle active (productionLinearMaskSum oracle) notRelation
  · calc
      uniformEventProbability
          (fun challenge =>
            semanticState
              (verifierExtension
                (.decsPolynomials statement active oracle decsChallenge decsMessage)
                challenge) = true) ≤
          uniformEventProbability
            (fun _ : PiopBatchingChallenge statement => False) := by
              apply uniform_event_probability_mono
              intro challenge accepted
              have secondGood :
                  SecondRoundGood statement active oracle decsChallenge challenge := by
                exact (semantic_state_true_iff _).mp (by
                  simpa [verifierExtension] using accepted)
              exact (degreeBounded (secondGood.resolve_left firstBad).1).elim
      _ = 0 := uniform_event_probability_false
      _ ≤ epsilonTwo := epsilon_two_nonnegative

/-- At the third verifier turn, revival is exactly a false production PIOP opening event. -/
theorem third_round_next_good_probability_le
    (statement : Statement)
    (active : ActiveStatement statement)
    (oracle : CommittedOracle)
    (decsChallenge : Matrix decsEta lvcsRowCount)
    (decsMessage : DecsPolynomialMessage)
    (piopChallenge : PiopBatchingChallenge statement)
    (piopMessage : PiopPolynomialMessage)
    (beforeFalse :
      semanticState
        (.piopPolynomials statement active oracle decsChallenge decsMessage
          piopChallenge piopMessage) = false) :
    nextSemanticGoodProbability
        (.piopPolynomials statement active oracle decsChallenge decsMessage
          piopChallenge piopMessage) ≤ epsilonThree := by
  have secondBad :
      ¬SecondRoundGood statement active oracle decsChallenge piopChallenge := by
    exact (semantic_state_false_iff _).mp (by
      simpa [SemanticGood] using beforeFalse)
  unfold nextSemanticGoodProbability
  by_cases degreeBounded : CommittedRowsDegreeBounded oracle
  · have affineFailure :
        ¬PiopAffineChallengePasses statement oracle active
          (productionLinearMaskSum oracle) piopChallenge := by
      intro affinePasses
      exact secondBad (Or.inr ⟨degreeBounded, affinePasses⟩)
    by_cases claimedTarget :
        ClaimedLinearTarget statement piopChallenge piopMessage
    · calc
        uniformEventProbability
            (fun challenge =>
              semanticState
                (verifierExtension
                  (.piopPolynomials statement active oracle decsChallenge decsMessage
                    piopChallenge piopMessage) challenge) = true) ≤
            uniformEventProbability
              (ProductionPiopOpeningPasses
                statement oracle piopChallenge piopMessage) := by
              apply uniform_event_probability_mono
              intro challenge accepted
              have thirdGood :
                  ThirdRoundGood statement active oracle decsChallenge
                    piopChallenge piopMessage challenge := by
                exact (semantic_state_true_iff _).mp (by
                  simpa [verifierExtension] using accepted)
              exact (thirdGood.resolve_left secondBad).2.2
        _ ≤ epsilonThree := by
          exact production_piop_opening_probability_le_of_affine_challenge_failure
            statement oracle active piopChallenge piopMessage
              claimedTarget affineFailure
    · calc
        uniformEventProbability
            (fun challenge =>
              semanticState
                (verifierExtension
                  (.piopPolynomials statement active oracle decsChallenge decsMessage
                    piopChallenge piopMessage) challenge) = true) ≤
            uniformEventProbability (fun _ : PiopOpeningChallenge => False) := by
              apply uniform_event_probability_mono
              intro challenge accepted
              have thirdGood :
                  ThirdRoundGood statement active oracle decsChallenge
                    piopChallenge piopMessage challenge := by
                exact (semantic_state_true_iff _).mp (by
                  simpa [verifierExtension] using accepted)
              exact (claimedTarget (thirdGood.resolve_left secondBad).2.1).elim
        _ = 0 := uniform_event_probability_false
        _ ≤ epsilonThree := epsilon_three_nonnegative
  · calc
      uniformEventProbability
          (fun challenge =>
            semanticState
              (verifierExtension
                (.piopPolynomials statement active oracle decsChallenge decsMessage
                  piopChallenge piopMessage) challenge) = true) ≤
          uniformEventProbability (fun _ : PiopOpeningChallenge => False) := by
            apply uniform_event_probability_mono
            intro challenge accepted
            have thirdGood :
                ThirdRoundGood statement active oracle decsChallenge
                  piopChallenge piopMessage challenge := by
              exact (semantic_state_true_iff _).mp (by
                simpa [verifierExtension] using accepted)
            exact (degreeBounded (thirdGood.resolve_left secondBad).1).elim
      _ = 0 := uniform_event_probability_false
      _ ≤ epsilonThree := epsilon_three_nonnegative

/-- At the final verifier turn, revival is exactly the canonical false LVCS opening event. -/
theorem fourth_round_next_good_probability_le
    (statement : Statement)
    (active : ActiveStatement statement)
    (oracle : CommittedOracle)
    (decsChallenge : Matrix decsEta lvcsRowCount)
    (decsMessage : DecsPolynomialMessage)
    (piopChallenge : PiopBatchingChallenge statement)
    (piopMessage : PiopPolynomialMessage)
    (piopOpening : PiopOpeningChallenge)
    (pcsMessage : PcsCombinationMessage)
    (beforeFalse :
      semanticState
        (.pcsCombination statement active oracle decsChallenge decsMessage
          piopChallenge piopMessage piopOpening pcsMessage) = false) :
    nextSemanticGoodProbability
        (.pcsCombination statement active oracle decsChallenge decsMessage
          piopChallenge piopMessage piopOpening pcsMessage) ≤ epsilonFour := by
  have thirdBad :
      ¬ThirdRoundGood statement active oracle decsChallenge
        piopChallenge piopMessage piopOpening := by
    exact (semantic_state_false_iff _).mp (by
      simpa [SemanticGood] using beforeFalse)
  unfold nextSemanticGoodProbability
  by_cases degreeBounded : CommittedRowsDegreeBounded oracle
  · calc
      uniformEventProbability
          (fun challenge =>
            semanticState
              (verifierExtension
                (.pcsCombination statement active oracle decsChallenge decsMessage
                  piopChallenge piopMessage piopOpening pcsMessage) challenge) = true) ≤
          uniformEventProbability
            (LvcsOpeningException piopOpening pcsMessage oracle) := by
              apply uniform_event_probability_mono
              intro challenge accepted
              have fourthGood :
                  FourthRoundGood statement active oracle decsChallenge
                    piopChallenge piopMessage piopOpening pcsMessage challenge := by
                exact (semantic_state_true_iff _).mp (by
                  simpa [verifierExtension] using accepted)
              exact (fourthGood.resolve_left thirdBad).2
      _ ≤ epsilonFour :=
        lvcs_opening_exception_probability_le
          piopOpening pcsMessage oracle degreeBounded
  · calc
      uniformEventProbability
          (fun challenge =>
            semanticState
              (verifierExtension
                (.pcsCombination statement active oracle decsChallenge decsMessage
                  piopChallenge piopMessage piopOpening pcsMessage) challenge) = true) ≤
          uniformEventProbability (fun _ : DecsOpeningChallenge => False) := by
            apply uniform_event_probability_mono
            intro challenge accepted
            have fourthGood :
                FourthRoundGood statement active oracle decsChallenge
                  piopChallenge piopMessage piopOpening pcsMessage challenge := by
              exact (semantic_state_true_iff _).mp (by
                simpa [verifierExtension] using accepted)
            exact (degreeBounded (fourthGood.resolve_left thirdBad).1).elim
      _ = 0 := uniform_event_probability_false
      _ ≤ epsilonFour := epsilon_four_nonnegative

/-- Work accounting for deterministic interpolation of the complete committed oracle. -/
def semanticExtractorWork : Prefix -> Nat
  | .initial _ => 0
  | _ => activeCommittedOracleLength

theorem semantic_extractor_work_within_bound (transcriptPrefix : Prefix) :
    semanticExtractorWork transcriptPrefix ≤ activeCommittedOracleLength := by
  cases transcriptPrefix <;> simp [semanticExtractorWork]

/--
Concrete SmallWood round-by-round extraction.  At every verifier turn, probability above the
four-term knowledge error forces the deterministic oracle witness to satisfy the exact Hegemon
production relation.
-/
theorem concrete_extract_above_error
    (transcriptPrefix : Prefix)
    (verifierTurn : Prefix.verifierTurn transcriptPrefix)
    (stateFalse : semanticState transcriptPrefix = false)
    (aboveError :
      activeInteractiveKnowledgeError <
        nextSemanticGoodProbability transcriptPrefix) :
    ∃ witness,
      extractedWitnessAtPrefix transcriptPrefix = some witness ∧
        (transcriptPrefix.statement, witness) ∈ Relation := by
  cases transcriptPrefix with
  | initial statement =>
      simp [Prefix.verifierTurn] at verifierTurn
  | oracle statement active oracle =>
      have relationHolds : (statement, extractWitness oracle) ∈ Relation := by
        by_contra notRelation
        have probabilityLe :=
          (first_round_next_good_probability_le
              statement active oracle notRelation).trans
            epsilon_one_le_active_interactive_knowledge_error
        exact (not_lt_of_ge probabilityLe) aboveError
      exact ⟨extractWitness oracle, rfl, relationHolds⟩
  | decsChallenge statement active oracle challenge =>
      simp [Prefix.verifierTurn] at verifierTurn
  | decsPolynomials statement active oracle decsChallenge decsMessage =>
      have relationHolds : (statement, extractWitness oracle) ∈ Relation := by
        by_contra notRelation
        have probabilityLe :=
          (second_round_next_good_probability_le
              statement active oracle decsChallenge decsMessage
                notRelation stateFalse).trans
            epsilon_two_le_active_interactive_knowledge_error
        exact (not_lt_of_ge probabilityLe) aboveError
      exact ⟨extractWitness oracle, rfl, relationHolds⟩
  | piopChallenge statement active oracle decsChallenge decsMessage challenge =>
      simp [Prefix.verifierTurn] at verifierTurn
  | piopPolynomials statement active oracle decsChallenge decsMessage
      piopChallenge piopMessage =>
      have relationHolds : (statement, extractWitness oracle) ∈ Relation := by
        by_contra notRelation
        have probabilityLe :=
          (third_round_next_good_probability_le
              statement active oracle decsChallenge decsMessage
                piopChallenge piopMessage stateFalse).trans
            epsilon_three_le_active_interactive_knowledge_error
        exact (not_lt_of_ge probabilityLe) aboveError
      exact ⟨extractWitness oracle, rfl, relationHolds⟩
  | piopOpening statement active oracle decsChallenge decsMessage
      piopChallenge piopMessage opening =>
      simp [Prefix.verifierTurn] at verifierTurn
  | pcsCombination statement active oracle decsChallenge decsMessage
      piopChallenge piopMessage piopOpening pcsMessage =>
      have relationHolds : (statement, extractWitness oracle) ∈ Relation := by
        by_contra notRelation
        have probabilityLe :=
          (fourth_round_next_good_probability_le
              statement active oracle decsChallenge decsMessage
                piopChallenge piopMessage piopOpening pcsMessage stateFalse).trans
            epsilon_four_le_active_interactive_knowledge_error
        exact (not_lt_of_ge probabilityLe) aboveError
      exact ⟨extractWitness oracle, rfl, relationHolds⟩
  | decsOpening statement active oracle decsChallenge decsMessage
      piopChallenge piopMessage piopOpening pcsMessage opening =>
      simp [Prefix.verifierTurn] at verifierTurn
  | final statement active oracle decsChallenge decsMessage
      piopChallenge piopMessage piopOpening pcsMessage opening message =>
      simp [Prefix.verifierTurn] at verifierTurn

/-- The active four-turn interactive SmallWood protocol inhabits the CMS RBR knowledge target. -/
noncomputable def activeRoundByRoundKnowledgeTarget :
    RoundByRoundKnowledgeTarget Prefix where
  Challenge := Challenge
  challengeFintype := challengeFintype
  challengeDecidableEq := challengeDecidableEq
  knowledgeError := activeInteractiveKnowledgeError
  state := semanticState
  verifierTurn := Prefix.verifierTurn
  statement := Prefix.statement
  initialPrefix := Prefix.initial
  proverExtension := ProverExtension
  verifierExtension := verifierExtension
  terminal := Prefix.terminal
  accepts := semanticAccepts
  nextGoodProbability := nextSemanticGoodProbability
  extract := extractedWitnessAtPrefix
  extractorWork := semanticExtractorWork
  extractorWorkBound := activeCommittedOracleLength
  knowledgeError_nonnegative := active_interactive_knowledge_error_nonnegative
  initialStateIsDoomed := by
    intro statement
    simp [semanticState, SemanticGood]
  initialStatement := by
    intro statement
    rfl
  proverExtensionPreservesStatement := by
    intro before after extension
    exact prover_extension_preserves_statement extension
  verifierExtensionPreservesStatement := verifier_extension_preserves_statement
  doomedStateSurvivesProverMessage := by
    intro before after extension beforeFalse
    exact semantic_state_survives_prover_message extension beforeFalse
  doomedTerminalTranscriptRejects := semantic_doomed_terminal_rejects
  nextGoodProbability_nonnegative := next_semantic_good_probability_nonnegative
  nextGoodProbability_at_most_one := next_semantic_good_probability_at_most_one
  nextGoodProbability_is_uniform := next_semantic_good_probability_is_uniform
  extractorWorkWithinBound := semantic_extractor_work_within_bound
  extractAboveError := concrete_extract_above_error

theorem active_round_by_round_knowledge :
    Nonempty (RoundByRoundKnowledgeTarget Prefix) :=
  ⟨activeRoundByRoundKnowledgeTarget⟩

end

end HegemonCrypto.SmallWood.ProductionBcsInstantiation
