import ArkLib.OracleReduction.Security.Basic
import HegemonCrypto.SmallWoodRelation

/-!
# SmallWood knowledge-soundness target

This module only states a necessary relation-bound probabilistic claim using ArkLib's standard
definition. It does not model adaptive multi-theorem Fiat-Shamir knowledge soundness, simulation
extractability, the QROM, canonical proof bytes, or Rust acceptance, and does not assert that any
current SmallWood verifier satisfies the target.
-/

noncomputable section

namespace HegemonCrypto.SmallWood

open OracleComp OracleSpec ProtocolSpec
open scoped NNReal

/-- Successful verifier output relation for a proof whose output witness carries no data. -/
def AcceptRelation : Set (Bool × Unit) :=
  { output | output.1 = true }

/--
The non-vacuous relation-bound knowledge-soundness baseline. ArkLib's definition quantifies over
all malicious provers and requires a straight-line extractor whose bad-event probability is
bounded by `knowledgeError`. Separate theorems must lift this baseline through the exact
Fiat-Shamir ROM and QROM games before it can describe the production verifier.
-/
def KnowledgeSoundnessTarget
    {ι : Type}
    {oSpec : OracleSpec ι}
    {rounds : Nat}
    {pSpec : ProtocolSpec rounds}
    [∀ round, SampleableType (pSpec.Challenge round)]
    {state : Type}
    (init : ProbComp state)
    (impl : QueryImpl oSpec (StateT state ProbComp))
    (verifier : Verifier oSpec Statement Bool pSpec)
    (knowledgeError : ℝ≥0) : Prop :=
  Verifier.knowledgeSoundness init impl Relation AcceptRelation verifier knowledgeError

end HegemonCrypto.SmallWood
