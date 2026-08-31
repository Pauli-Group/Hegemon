import HegemonCrypto.SmallWoodCmsQrom
import Hegemon.Transaction.Poseidon2V8ConstraintRefinement

/-!
# V8 SmallWood ideal-QROM accounting

This module instantiates the four interactive SmallWood error terms and the ideal CMS envelope for
the exact V8/SMZ8 geometry.  It does not reuse the historical active V4 constants in
`SmallWoodNoGrindingSoundness` or `SmallWoodBcsQrom`.

The proved inequalities are arithmetic in an ideal logical-oracle model.  They do not establish a
concrete SHA-512 QROM reduction, Poseidon2 hardness, transcript/refinement equivalence, complete
zero knowledge, adaptive whole-view simulation, multi-proof lifecycle composition, independent
review, or production authority.
-/

namespace HegemonCrypto
namespace SmallWood
namespace V8QromAccounting

set_option maxHeartbeats 0
set_option maxRecDepth 100000
set_option exponentiation.threshold 1024

def goldilocksOrder : Nat :=
  Hegemon.Transaction.Poseidon2Width16Kernel.fieldModulus
def packingFactor : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor
def relationRows : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.relationRowCount
def proofGeometryColumns : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.proofGeometryColumnCount
def relationDegree : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.relationConstraintDegree
def rho : Nat := 5
def piopOpenings : Nat := 5
def beta : Nat := 2
def decsEta : Nat := 5
def decsDomainSize : Nat := 2 ^ 23
def decsOpenings : Nat := 19
def transcriptHashBits : Nat := 512
def selectedGlobalQueryExponent : Nat := 64
def selectedGlobalQueryBudget : Nat := 2 ^ selectedGlobalQueryExponent
def workQueryExponent : Nat := 128
def workQueryBudget : Nat := 2 ^ workQueryExponent

def ceilDiv (numerator denominator : Nat) : Nat :=
  (numerator + denominator - 1) / denominator

def fallingProduct (value count : Nat) : Nat :=
  (List.range count).foldl (fun product index => product * (value - index)) 1

def witnessPolynomialDegree : Nat :=
  packingFactor + piopOpenings - 1

def batchedConstraintPolynomialDegree : Nat :=
  relationDegree * witnessPolynomialDegree

def constraintPolynomialDegree : Nat :=
  batchedConstraintPolynomialDegree - packingFactor

def piopConsistencyDiscrepancyDegree : Nat :=
  batchedConstraintPolynomialDegree

def linearPolynomialDegree : Nat :=
  packingFactor + piopOpenings - 1 + packingFactor - 1

def polynomialWidth (degree : Nat) : Nat :=
  ceilDiv (degree + 1 - piopOpenings) packingFactor

def unstackedColumnCount : Nat :=
  relationRows * polynomialWidth witnessPolynomialDegree +
    rho * polynomialWidth constraintPolynomialDegree +
    rho * polynomialWidth linearPolynomialDegree

def lvcsRowCount : Nat :=
  (packingFactor + piopOpenings) * beta

def lvcsColumnCount : Nat :=
  ceilDiv unstackedColumnCount beta

def decsPolynomialDegree : Nat :=
  lvcsColumnCount + decsOpenings - 1

theorem exact_v8_profile_geometry :
    relationRows = 686 ∧ proofGeometryColumns = 368 ∧ relationDegree = 8 ∧
      rho = 5 ∧ piopOpenings = 5 ∧ beta = 2 ∧ decsEta = 5 ∧
      decsDomainSize = 8388608 ∧ decsOpenings = 19 ∧
      witnessPolynomialDegree = 68 ∧ batchedConstraintPolynomialDegree = 544 ∧
      constraintPolynomialDegree = 480 ∧ linearPolynomialDegree = 131 ∧
      unstackedColumnCount = 736 ∧ lvcsRowCount = 138 ∧
      lvcsColumnCount = proofGeometryColumns ∧ decsPolynomialDegree = 386 := by
  decide

def epsilon1Numerator : Nat := 1
def epsilon1Denominator : Nat := goldilocksOrder ^ decsEta
def epsilon2Numerator : Nat := 1
def epsilon2Denominator : Nat := goldilocksOrder ^ rho
def epsilon3Numerator : Nat :=
  fallingProduct piopConsistencyDiscrepancyDegree piopOpenings
def epsilon3Denominator : Nat :=
  fallingProduct (goldilocksOrder - packingFactor) piopOpenings
def epsilon4Numerator : Nat :=
  fallingProduct decsPolynomialDegree decsOpenings
def epsilon4Denominator : Nat :=
  fallingProduct decsDomainSize decsOpenings

def aggregateErrorNumerator : Nat :=
  epsilon1Numerator * epsilon2Denominator * epsilon3Denominator * epsilon4Denominator +
    epsilon2Numerator * epsilon1Denominator * epsilon3Denominator * epsilon4Denominator +
    epsilon3Numerator * epsilon1Denominator * epsilon2Denominator * epsilon4Denominator +
    epsilon4Numerator * epsilon1Denominator * epsilon2Denominator * epsilon3Denominator

def aggregateErrorDenominator : Nat :=
  epsilon1Denominator * epsilon2Denominator * epsilon3Denominator * epsilon4Denominator

def supportsInteractiveBits (bits : Nat) : Prop :=
  2 ^ bits * aggregateErrorNumerator ≤ aggregateErrorDenominator

theorem v8_interactive_aggregate_supports_273_bits :
    supportsInteractiveBits 273 := by
  unfold supportsInteractiveBits aggregateErrorNumerator aggregateErrorDenominator
    epsilon1Numerator epsilon1Denominator epsilon2Numerator epsilon2Denominator
    epsilon3Numerator epsilon3Denominator epsilon4Numerator epsilon4Denominator
    goldilocksOrder decsEta rho piopConsistencyDiscrepancyDegree
    batchedConstraintPolynomialDegree relationDegree witnessPolynomialDegree packingFactor
    piopOpenings decsPolynomialDegree lvcsColumnCount unstackedColumnCount relationRows
    polynomialWidth constraintPolynomialDegree linearPolynomialDegree beta ceilDiv
    decsOpenings decsDomainSize fallingProduct
  decide

theorem v8_interactive_aggregate_does_not_support_274_bits :
    ¬ supportsInteractiveBits 274 := by
  unfold supportsInteractiveBits aggregateErrorNumerator aggregateErrorDenominator
    epsilon1Numerator epsilon1Denominator epsilon2Numerator epsilon2Denominator
    epsilon3Numerator epsilon3Denominator epsilon4Numerator epsilon4Denominator
    goldilocksOrder decsEta rho piopConsistencyDiscrepancyDegree
    batchedConstraintPolynomialDegree relationDegree witnessPolynomialDegree packingFactor
    piopOpenings decsPolynomialDegree lvcsColumnCount unstackedColumnCount relationRows
    polynomialWidth constraintPolynomialDegree linearPolynomialDegree beta ceilDiv
    decsOpenings decsDomainSize fallingProduct
  decide

/-!
CMS ideal-envelope terms:

* `12 * Q^2 * epsilon_interactive`;
* `48 * Q^3 / 2^512` for the ideal transcript collision term;
* `2 * N^2 / 2^512` for the conservative oracle/database bridge.
-/

def idealCmsEnvelopeNumerator (queries : Nat) : Nat :=
  12 * queries ^ 2 * aggregateErrorNumerator * 2 ^ transcriptHashBits +
    (48 * queries ^ 3 + 2 * decsDomainSize ^ 2) * aggregateErrorDenominator

def idealCmsEnvelopeDenominator : Nat :=
  aggregateErrorDenominator * 2 ^ transcriptHashBits

def supportsIdealCmsEnvelopeBits (bits queries : Nat) : Prop :=
  2 ^ bits * idealCmsEnvelopeNumerator queries ≤ idealCmsEnvelopeDenominator

theorem v8_ideal_cms_at_2pow64_supports_141_bits :
    supportsIdealCmsEnvelopeBits 141 selectedGlobalQueryBudget := by
  unfold supportsIdealCmsEnvelopeBits idealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
    selectedGlobalQueryBudget selectedGlobalQueryExponent transcriptHashBits
    aggregateErrorNumerator aggregateErrorDenominator epsilon1Numerator epsilon1Denominator
    epsilon2Numerator epsilon2Denominator epsilon3Numerator epsilon3Denominator
    epsilon4Numerator epsilon4Denominator goldilocksOrder decsEta rho
    piopConsistencyDiscrepancyDegree batchedConstraintPolynomialDegree relationDegree
    witnessPolynomialDegree packingFactor piopOpenings decsPolynomialDegree lvcsColumnCount
    unstackedColumnCount relationRows polynomialWidth constraintPolynomialDegree
    linearPolynomialDegree beta ceilDiv decsOpenings decsDomainSize fallingProduct
  decide

theorem v8_ideal_cms_at_2pow64_does_not_support_142_bits :
    ¬ supportsIdealCmsEnvelopeBits 142 selectedGlobalQueryBudget := by
  unfold supportsIdealCmsEnvelopeBits idealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
    selectedGlobalQueryBudget selectedGlobalQueryExponent transcriptHashBits
    aggregateErrorNumerator aggregateErrorDenominator epsilon1Numerator epsilon1Denominator
    epsilon2Numerator epsilon2Denominator epsilon3Numerator epsilon3Denominator
    epsilon4Numerator epsilon4Denominator goldilocksOrder decsEta rho
    piopConsistencyDiscrepancyDegree batchedConstraintPolynomialDegree relationDegree
    witnessPolynomialDegree packingFactor piopOpenings decsPolynomialDegree lvcsColumnCount
    unstackedColumnCount relationRows polynomialWidth constraintPolynomialDegree
    linearPolynomialDegree beta ceilDiv decsOpenings decsDomainSize fallingProduct
  decide

theorem v8_ideal_cms_at_2pow64_supports_128_bits :
    supportsIdealCmsEnvelopeBits 128 selectedGlobalQueryBudget := by
  unfold supportsIdealCmsEnvelopeBits idealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
    selectedGlobalQueryBudget selectedGlobalQueryExponent transcriptHashBits
    aggregateErrorNumerator aggregateErrorDenominator epsilon1Numerator epsilon1Denominator
    epsilon2Numerator epsilon2Denominator epsilon3Numerator epsilon3Denominator
    epsilon4Numerator epsilon4Denominator goldilocksOrder decsEta rho
    piopConsistencyDiscrepancyDegree batchedConstraintPolynomialDegree relationDegree
    witnessPolynomialDegree packingFactor piopOpenings decsPolynomialDegree lvcsColumnCount
    unstackedColumnCount relationRows polynomialWidth constraintPolynomialDegree
    linearPolynomialDegree beta ceilDiv decsOpenings decsDomainSize fallingProduct
  decide

theorem v8_ideal_cms_at_2pow128_is_below_half :
    2 * idealCmsEnvelopeNumerator workQueryBudget < idealCmsEnvelopeDenominator := by
  unfold idealCmsEnvelopeNumerator idealCmsEnvelopeDenominator workQueryBudget
    workQueryExponent transcriptHashBits aggregateErrorNumerator aggregateErrorDenominator
    epsilon1Numerator epsilon1Denominator epsilon2Numerator epsilon2Denominator
    epsilon3Numerator epsilon3Denominator epsilon4Numerator epsilon4Denominator
    goldilocksOrder decsEta rho piopConsistencyDiscrepancyDegree
    batchedConstraintPolynomialDegree relationDegree witnessPolynomialDegree packingFactor
    piopOpenings decsPolynomialDegree lvcsColumnCount unstackedColumnCount relationRows
    polynomialWidth constraintPolynomialDegree linearPolynomialDegree beta ceilDiv
    decsOpenings decsDomainSize fallingProduct
  decide

/-!
The following receipt propositions deliberately have no checked-in constructors.  They name the
non-arithmetic obligations without manufacturing evidence for them from the ideal arithmetic
above.  The global query budget is likewise an input to be approved, not a value authorized by
the `2^64` calculation.
-/
inductive ExactSmz8TranscriptRefinement : Prop
inductive ConcreteSha512QromReduction : Prop
inductive Poseidon2PrimitiveSecurity : Prop
inductive AdaptiveWholeViewCompleteZeroKnowledge : Prop
inductive GlobalHistoryComposition : Prop
inductive IndependentComposedReview : Prop
inductive ApprovedGlobalQuantumQueryBudget : Nat → Prop

/-- Explicit non-arithmetic premises still required before the ideal bound can describe deployment. -/
structure DeployedV8QromPremises (Statement Witness : Type*) where
  exactCompiledRelationRefinement :
    Hegemon.Transaction.Poseidon2V8ConstraintRefinement.FullRelationCompilerRefinementReceipt
      Statement Witness
  exactSmz8TranscriptRefinement : ExactSmz8TranscriptRefinement
  concreteSha512QromReduction : ConcreteSha512QromReduction
  poseidon2PrimitiveSecurity : Poseidon2PrimitiveSecurity
  adaptiveWholeViewCompleteZeroKnowledge : AdaptiveWholeViewCompleteZeroKnowledge
  globalHistoryComposition : GlobalHistoryComposition
  globalQuantumQueryBudget : Nat
  globalQuantumQueryBudgetApproved :
    ApprovedGlobalQuantumQueryBudget globalQuantumQueryBudget
  independentReview : IndependentComposedReview

theorem deployed_v8_qrom_premises_are_unavailable
    (Statement Witness : Type*) :
    ¬ Nonempty (DeployedV8QromPremises Statement Witness) := by
  intro evidence
  rcases evidence with ⟨premises⟩
  exact
    (Hegemon.Transaction.Poseidon2V8ConstraintRefinement.full_relation_compiler_receipt_is_unavailable_from_checked_in_status
      Statement Witness) ⟨premises.exactCompiledRelationRefinement⟩

end V8QromAccounting
end SmallWood
end HegemonCrypto
