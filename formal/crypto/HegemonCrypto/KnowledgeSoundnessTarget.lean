import HegemonCrypto.SmallWoodRelation

/-!
# SmallWood adaptive QROM knowledge-soundness target

This module states the production research target without importing a proof library. It fixes the
accepted oracle model, relation-bound extraction failure event, query budgets, and concrete loss
interface. A future finite-dimensional quantum experiment must instantiate `AdaptiveOracleGame`
and prove that its `eventProbability` is the probability induced by that experiment. No such
instantiation or soundness theorem is supplied here.
-/

namespace HegemonCrypto.SmallWood

/-- Oracle models that may appear in research reductions. Production credit requires `standardQrom`. -/
inductive OracleModel where
  | classicalRom
  | standardQrom
  | extractableQrom
deriving DecidableEq, Repr

/-- Public resource bounds for one adaptive multi-theorem security experiment. -/
structure QueryBudget where
  quantumHashQueries : Nat
  priorProofInteractions : Nat
deriving DecidableEq, Repr

/-- One measured verifier/extractor outcome. -/
structure ExtractionTrial (Proof : Type*) where
  statement : Statement
  proof : Proof
  extractedWitness : Option Witness

/-- The no-counterfeit bad event: acceptance without an extracted production-relation witness. -/
def ExtractionFailure
    {Proof : Type*}
    (verifier : Statement → Proof → Bool)
    (trial : ExtractionTrial Proof) : Prop :=
  verifier trial.statement trial.proof = true ∧
    ¬∃ witness,
      trial.extractedWitness = some witness ∧
        (trial.statement, witness) ∈ Relation

/--
Interface supplied by a concrete oracle experiment. `eventProbability` is deliberately abstract:
the future QROM development must derive it from finite-dimensional channels, calls to the unitary
`|x,y> -> |x,y xor H(x)>`, and a final measurement rather than postulating a classical query log.
-/
structure AdaptiveOracleGame (Adversary Proof : Type*) where
  model : OracleModel
  quantumHashQueries : Adversary → Nat
  priorProofInteractions : Adversary → Nat
  eventProbability : Adversary → (ExtractionTrial Proof → Prop) → ℚ
  eventProbability_nonnegative :
    ∀ adversary event, 0 ≤ eventProbability adversary event
  eventProbability_atMostOne :
    ∀ adversary event, eventProbability adversary event ≤ 1

/-- Exact rational upper bound, including every query and reduction loss. -/
structure ConcreteLoss where
  bound : QueryBudget → ℚ
  nonnegative : ∀ budget, 0 ≤ bound budget

/--
The release-level target. It is adaptive and multi-theorem, requires the standard QROM, counts all
quantum hash queries and prior proof interactions, and bounds acceptance without an extracted
`Relation` witness by one explicit rational loss. This definition is not a proof that SmallWood
meets the target.
-/
def KnowledgeSoundnessTarget
    {Adversary Proof : Type*}
    (verifier : Statement → Proof → Bool)
    (game : AdaptiveOracleGame Adversary Proof)
    (loss : ConcreteLoss)
    (budget : QueryBudget) : Prop :=
  game.model = .standardQrom ∧
    ∀ adversary,
      game.quantumHashQueries adversary ≤ budget.quantumHashQueries →
      game.priorProofInteractions adversary ≤ budget.priorProofInteractions →
      game.eventProbability adversary (ExtractionFailure verifier) ≤ loss.bound budget

end HegemonCrypto.SmallWood
