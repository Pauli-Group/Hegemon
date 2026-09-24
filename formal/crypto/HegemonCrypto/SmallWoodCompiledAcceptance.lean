import HegemonCrypto.SmallWoodProductionBcsInstantiation

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Compiled SmallWood acceptance composition

This module states the exact deterministic facts that the deployed byte verifier must establish
after parsing, transcript derivation, polynomial restoration, LVCS reconstruction, and compact
Merkle verification.  It then proves that those facts imply the four-turn semantic accepting
state used by the interactive extractor.

The case split is exhaustive:

1. the extracted witness already satisfies the production relation;
2. a non-codeword commitment survives DECS degree enforcement;
3. degree-bounded committed combinations match and every PIOP opening equation passes; or
4. a false degree-bounded LVCS combination passes at all 23 sampled coordinates.

No probability or cryptographic assumption appears here.
-/

namespace HegemonCrypto.SmallWood.CompiledAcceptance

open HegemonCrypto.SmallWood.LvcsOpening
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionBcsInstantiation
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.RoundByRound
noncomputable section

/--
Core four-case composition theorem over explicit values.  Keeping the dependent compiled
transcript wrapper outside this proof prevents generated production certificates from being
unfolded during elaboration.
-/
theorem acceptance_predicates_imply_fourth_round_good
    (statement : Statement)
    (active : ActiveStatement statement)
    (oracle : CommittedOracle)
    (decsChallenge : Matrix decsEta lvcsRowCount)
    (piopChallenge : PiopBatchingChallenge statement)
    (piopMessage : PiopPolynomialMessage)
    (piopOpening : PiopOpeningChallenge)
    (pcsMessage : PcsCombinationMessage)
    (decsOpening : DecsOpeningChallenge)
    (decsFirstRoundGood :
      ¬CommittedRowsDegreeBounded oracle ->
        FirstRoundGood statement oracle decsChallenge)
    (claimedLinearTarget :
      ClaimedLinearTarget statement piopChallenge piopMessage)
    (piopOpeningChecks :
      ProductionCombinationsMatch piopOpening pcsMessage oracle ->
        ProductionPiopOpeningPasses
          statement oracle piopChallenge piopMessage piopOpening)
    (lvcsOpeningChecks :
      ∀ combination : Fin openedCombinationCount,
        ProductionCombinationPassesOn
          piopOpening pcsMessage combination oracle decsOpening) :
    FourthRoundGood
      statement active oracle decsChallenge piopChallenge piopMessage
        piopOpening pcsMessage decsOpening := by
  classical
  by_cases relation : ExtractedRelationHolds statement oracle
  · have first :
        FirstRoundGood statement oracle decsChallenge :=
      Or.inl relation
    have second :
        SecondRoundGood statement active oracle decsChallenge piopChallenge :=
      Or.inl first
    have third :
        ThirdRoundGood statement active oracle decsChallenge
          piopChallenge piopMessage piopOpening :=
      Or.inl second
    exact Or.inl third
  · by_cases degreeBounded : CommittedRowsDegreeBounded oracle
    · by_cases combinationsMatch :
        ProductionCombinationsMatch piopOpening pcsMessage oracle
      · have third :
            ThirdRoundGood statement active oracle decsChallenge
              piopChallenge piopMessage piopOpening :=
          Or.inr
          ⟨degreeBounded, claimedLinearTarget,
            piopOpeningChecks combinationsMatch⟩
        exact Or.inl third
      · exact Or.inr
          ⟨degreeBounded, combinationsMatch,
            lvcsOpeningChecks
              (selectedFalseCombination piopOpening pcsMessage oracle)⟩
    · have first :
          FirstRoundGood statement oracle decsChallenge :=
        decsFirstRoundGood degreeBounded
      have second :
          SecondRoundGood statement active oracle decsChallenge piopChallenge :=
        Or.inl first
      have third :
          ThirdRoundGood statement active oracle decsChallenge
            piopChallenge piopMessage piopOpening :=
        Or.inl second
      exact Or.inl third

end

end HegemonCrypto.SmallWood.CompiledAcceptance
