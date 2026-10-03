import Q38ChronologicalStateAlgebra
import SmzaRp05CsrNormalization
import SmzaRp05RelationRefinement

/-!
# Current-relation chronological response algebra

Only the relation-independent q38 coin-transport theorem is reused. Both
polynomial batches below are built from the RP05 DSL: its complete nonlinear
root list and its statement-dependent normalized CSR rows. No RP04 public
parameter or 773-root batch occurs in the construction.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra

open Polynomial
open SmzaRp05StatementNamespace SmzaRp05RelationRefinement
open SmzaRp04DecodedPolynomialSource
open V8Smz9ProgramPolynomials V8Smz9PiopOpeningRecovery
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9EagerPrivacy
open V8Smz9EagerSimulator V8Smz9SingleProofPrivacy V8Smz9HonestHybrid
open V8Smz9CurrentProgramOpeningBinding
open V8SmzaRemainingAlgebra V8SmzaMathPrivacy
open V8SmzaChronologicalStateAlgebra
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

abbrev Q := PiopCoefficients Goldilocks
abbrev D := V8SmzaMathPrivacy.Decs Goldilocks

/-- One current-width batching stream, shared by nonlinear and linear rows. -/
abbrev Parameters (dsl : RelationDsl) (statement : Statement) :=
  Fin 5 → Fin (dsl.width statement) → Goldilocks

def nonlinearGamma (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (polynomial : Fin 5)
    (root : Fin dsl.nonlinearCount) : Goldilocks :=
  parameters polynomial
    ⟨root.val, root.isLt.trans_le (Nat.le_max_left _ _)⟩

def linearGamma (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (polynomial : Fin 5)
    (row : Fin (dsl.linearCount statement)) : Goldilocks :=
  parameters polynomial
    ⟨row.val, row.isLt.trans_le (Nat.le_max_right _ _)⟩

def nonlinearConstraints (dsl : RelationDsl) (statement : Statement)
    (witness : Fin 686 → Goldilocks[X]) : Fin dsl.nonlinearCount → Goldilocks[X] :=
  fun root => polynomialAt dsl.components.nonlinearExecutable.expressions
    (publicFieldAtNat statement)
    (fun row => if bound : row < 686 then witness ⟨row, bound⟩ else 0)
    (dsl.nonlinearRoot root)

def currentNonlinearBatch (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (witness : Fin 686 → Goldilocks[X]) (polynomial : Fin 5) : Goldilocks[X] :=
  nonlinearBatch (nonlinearGamma dsl statement parameters polynomial)
    (nonlinearConstraints dsl statement witness)

def currentLinearWeights (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (polynomial : Fin 5)
    (witnessRow : Fin 686) (lane : Fin 64) : Goldilocks :=
  ∑ row, linearGamma dsl statement parameters polynomial row *
    dsl.linearWeights statement row witnessRow lane

/-- Literal unmasked coefficients: the 489 nonlinear quotient coefficients
and the 132 nonconstant linear coefficients. The omitted linear constant is
publicly reconstructed, not sampled or silently removed from the relation. -/
def unmaskedResponse (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (witness : Fin 686 → Goldilocks[X]) : Q :=
  (fun polynomial coefficient =>
      (sourceNonlinearQuotient canonicalPacking
        (currentNonlinearBatch dsl statement parameters witness polynomial)).coeff
          coefficient.val,
    fun polynomial coefficient =>
      (sourceLinearUnmasked
        (currentLinearWeights dsl statement parameters polynomial)
        (sourcePackingLagrange canonicalPacking) witness).coeff
          (coefficient.val + 1))

def response (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (witness : Fin 686 → Goldilocks[X]) (masks : Q) : Q :=
  unmaskedResponse dsl statement parameters witness + masks

/-- The nonlinear polynomials are the same objects consumed by extraction,
not an independent stronger relation introduced for privacy. -/
theorem nonlinear_constraints_of_source (dsl : RelationDsl) (statement : Statement)
    (source : SourcePolynomials) :
    nonlinearConstraints dsl statement (witnessPolynomials source) =
      nonlinearPolynomial dsl statement source := rfl

def currentHeads (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q) : Heads Goldilocks :=
  physicalHeads (sourceWitnessPolynomials values base.1) masks base.2.1

/-- Source-width chronological transport. The intermediate branch and its
state remain in the kernel, and the parameters may depend on that branch and
the already-published DECS response. No fixed-table or independence premise
is used. -/
theorem response_state_kernel_sum
    {PublicBranch Value : Type*} [Fintype PublicBranch] [AddCommMonoid Value]
    (dsl : RelationDsl) (statement : Statement)
    (gamma : Gamma Goldilocks) (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks)
    (parameters : D → PublicBranch → Parameters dsl statement)
    (kernel : D → PublicBranch → Q → D → Q → Value) :
    (∑ q, ∑ m, ∑ branch,
      let reply := V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m
      kernel reply branch q m
        (response dsl statement (parameters reply branch)
          (sourceWitnessPolynomials values base.1) q)) =
    ∑ reply, ∑ branch, ∑ transcript,
      let q := transcript - unmaskedResponse dsl statement
        (parameters reply branch) (sourceWitnessPolynomials values base.1)
      let m := reply - V8SmzaMathPrivacy.unmasked gamma
        (currentHeads values base q) base.2.2
      kernel reply branch q m transcript := by
  let heads := fun witnessCoins pcsCoins q =>
    physicalHeads (sourceWitnessPolynomials values witnessCoins) q pcsCoins
  let piopUnmasked := fun witnessCoins reply branch =>
    unmaskedResponse dsl statement (parameters reply branch)
      (sourceWitnessPolynomials values witnessCoins)
  simpa only [currentHeads, response, heads, piopUnmasked] using
    (q38_response_state_kernel_sum (Value := Value)
      gamma base heads piopUnmasked kernel)

end
end HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
