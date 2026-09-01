import HegemonCrypto.SmallWoodV8QromAccounting
import HegemonCrypto.SmallWoodSmz9ProofWire
import HegemonCrypto.SmallWoodHeterogeneousCmsQrom

/-!
# V8 SmallWood SMZ9 ideal-QROM accounting

This module preserves the historical SMZ8/open-5/q-19 ledger and separately instantiates the
fresh SMZ9/profile-6 arithmetic.  Its exact profile is rho 5, PIOP openings 6, beta 2, DECS
`N = 2^23`, `q = 20`, eta 5, relation rows 686, and proof columns 368.

The checked inequalities remain arithmetic.  They use the executable sampler's conservative
full-admissibility denominator, but they do not construct an HGV8RP03/SMZ9 instance of the existing
historical ideal logical oracle, a concrete SHA-512 or Poseidon2 reduction, compiled-relation or
transcript refinement, complete adaptive whole-view zero knowledge, an approved deployment query
budget/history model, independent review, or production authority.
-/

namespace HegemonCrypto
namespace SmallWood
namespace V8Smz9QromAccounting

set_option maxHeartbeats 0
set_option maxRecDepth 1000000
set_option exponentiation.threshold 4096

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
def piopOpenings : Nat := 6
def beta : Nat := 2
def decsEta : Nat := 5
def decsDomainSize : Nat := 2 ^ 23
def decsOpenings : Nat := 20
def transcriptHashBits : Nat := 512
def analysisGlobalQueryExponent : Nat := 64
def analysisGlobalQueryBudget : Nat := 2 ^ analysisGlobalQueryExponent
def workQueryExponent : Nat := 128
def workQueryBudget : Nat := 2 ^ workQueryExponent
def strongestConditionalWorkQueryExponent : Nat := 142
def firstFailingConditionalWorkQueryExponent : Nat := 143
def strongestConditionalWorkQueryBudget : Nat :=
  2 ^ strongestConditionalWorkQueryExponent
def firstFailingConditionalWorkQueryBudget : Nat :=
  2 ^ firstFailingConditionalWorkQueryExponent

def ceilDiv := V8QromAccounting.ceilDiv
def fallingProduct := V8QromAccounting.fallingProduct

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

def proofWireMagic : List Nat :=
  SmallWoodSmz9ProofWire.proofMagic.map Fin.val
def proofProfileWireId : Nat := 6
def openedLeafCount : Nat := SmallWoodSmz9ProofWire.openedLeafCount
def openedLeafTapeBytes : Nat := SmallWoodSmz9ProofWire.openedLeafTapeBytes
def openedLeafTapesBytes : Nat := SmallWoodSmz9ProofWire.openedLeafTapesBytes
def maximumAuthenticationPathDepth : Nat :=
  SmallWoodSmz9ProofWire.maximumAuthPathDepth
def maximumCompactAuthenticationNodes : Nat :=
  SmallWoodSmz9ProofWire.maximumCompactAuthenticationNodes
def maximumInnerProofBytes : Nat := SmallWoodSmz9ProofWire.maximumInnerProofBytes

def projectedHeaderBytes : Nat := 104
def projectedPpolBytes : Nat := 19324
def projectedPlinBytes : Nat := 5044
def projectedRcombiBytes : Nat := 1924
def projectedSubsetBytes : Nat := 20484
def projectedPartialBytes : Nat := 1924
def projectedAuthenticationBytes : Nat :=
  2 + openedLeafCount + maximumCompactAuthenticationNodes * SmallWoodProofWire.digestBytes
def projectedTapesBytes : Nat := openedLeafTapesBytes
def projectedMaskingBytes : Nat := 804
def projectedHighBytes : Nat := 14724
def projectedOpenedWitnessBytes : Nat := 33421
def projectedInnerProofBytes : Nat :=
  projectedHeaderBytes + projectedPpolBytes + projectedPlinBytes + projectedRcombiBytes +
    projectedSubsetBytes + projectedPartialBytes + projectedAuthenticationBytes +
    projectedTapesBytes + projectedMaskingBytes + projectedHighBytes +
    projectedOpenedWitnessBytes
def projectedTwoOutputActionBytes : Nat := projectedInnerProofBytes + 5434

theorem exact_smz9_profile_geometry_and_projection :
    relationRows = 686 ∧ proofGeometryColumns = 368 ∧ relationDegree = 8 ∧
      rho = 5 ∧ piopOpenings = 6 ∧ beta = 2 ∧ decsEta = 5 ∧
      decsDomainSize = 8388608 ∧ decsOpenings = 20 ∧
      witnessPolynomialDegree = 69 ∧ batchedConstraintPolynomialDegree = 552 ∧
      constraintPolynomialDegree = 488 ∧ linearPolynomialDegree = 132 ∧
      polynomialWidth witnessPolynomialDegree = 1 ∧
      polynomialWidth constraintPolynomialDegree = 8 ∧
      polynomialWidth linearPolynomialDegree = 2 ∧
      unstackedColumnCount = 736 ∧ lvcsRowCount = 140 ∧
      lvcsColumnCount = proofGeometryColumns ∧ decsPolynomialDegree = 387 ∧
      proofWireMagic = [83, 77, 90, 57] ∧ proofProfileWireId = 6 ∧
      openedLeafCount = 20 ∧ openedLeafTapesBytes = 1280 ∧
      maximumAuthenticationPathDepth = 23 ∧ maximumCompactAuthenticationNodes = 372 ∧
      maximumInnerProofBytes = 131072 ∧ projectedInnerProofBytes = 122863 ∧
      projectedTwoOutputActionBytes = 128297 := by
  decide

/--
The ideal heterogeneous theorem currently imports the historical logical-oracle response, not the
SMZ9 response.  This exact mismatch is a reduction gap, not a numerical security loss that can be
silently added to the ledger.
-/
theorem smz9_is_not_the_modeled_heterogeneous_logical_oracle_profile :
    piopOpenings ≠ HeterogeneousCmsQrom.modeledPiopOpeningCount ∧
      decsOpenings ≠ HeterogeneousCmsQrom.modeledDecsOpeningCount ∧
      lvcsRowCount ≠ HeterogeneousCmsQrom.modeledDecsRowWidth := by
  decide

def pcsUnstackAdditionalForbiddenValues : Nat := 68
def correctionPolynomialDegree : Nat := piopOpenings
def openingAdmissibilityBadTupleCoefficient : Nat :=
  correctionPolynomialDegree +
    piopOpenings * pcsUnstackAdditionalForbiddenValues
def distinctOutsideOpeningTupleCount : Nat :=
  fallingProduct (goldilocksOrder - packingFactor) piopOpenings
def admissibilityRejectedTupleUpperBound : Nat :=
  openingAdmissibilityBadTupleCoefficient * goldilocksOrder ^ (piopOpenings - 1)
def correctionAwareOpeningTupleLowerBound : Nat :=
  distinctOutsideOpeningTupleCount - admissibilityRejectedTupleUpperBound

theorem exact_opening_admissibility_inventory :
    correctionPolynomialDegree = 6 ∧
      pcsUnstackAdditionalForbiddenValues = 68 ∧
      openingAdmissibilityBadTupleCoefficient = 414 ∧
      0 < correctionAwareOpeningTupleLowerBound := by
  decide

private theorem exact_goldilocks_order :
    goldilocksOrder = 18446744069414584321 := by
  decide

private theorem exact_arithmetic_parameters :
    packingFactor = 64 ∧ piopOpenings = 6 ∧ decsEta = 5 ∧ rho = 5 ∧
      decsDomainSize = 8388608 ∧ decsOpenings = 20 ∧
      piopConsistencyDiscrepancyDegree = 552 ∧ decsPolynomialDegree = 387 ∧
      openingAdmissibilityBadTupleCoefficient = 414 := by
  decide

def epsilon1Numerator : Nat := 1
def epsilon1Denominator : Nat := goldilocksOrder ^ decsEta
def epsilon2Numerator : Nat := 1
def epsilon2Denominator : Nat := goldilocksOrder ^ rho
def epsilon3Numerator : Nat :=
  fallingProduct piopConsistencyDiscrepancyDegree piopOpenings
def epsilon3Denominator : Nat :=
  correctionAwareOpeningTupleLowerBound
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

/-!
Materialize the four component ratios independently.  Keeping the short falling products and the
large final multiplications in separate kernel proofs avoids one monolithic normalization term.
-/

theorem exact_epsilon1_denominator :
    epsilon1Denominator =
      2135987033434293902082969833143585405490115481162544232032811052120416417467265840012020259225601 := by
  rw [show epsilon1Denominator = goldilocksOrder ^ decsEta by rfl,
    exact_goldilocks_order, exact_arithmetic_parameters.2.2.1]
  norm_num

theorem exact_epsilon2_denominator :
    epsilon2Denominator =
      2135987033434293902082969833143585405490115481162544232032811052120416417467265840012020259225601 := by
  rw [show epsilon2Denominator = goldilocksOrder ^ rho by rfl,
    exact_goldilocks_order, exact_arithmetic_parameters.2.2.2.1]
  norm_num

theorem exact_epsilon3_numerator :
    epsilon3Numerator = 27529200278078400 := by
  rw [show epsilon3Numerator = fallingProduct piopConsistencyDiscrepancyDegree piopOpenings by rfl,
    exact_arithmetic_parameters.2.2.2.2.2.2.1,
    exact_arithmetic_parameters.2.1]
  norm_num [fallingProduct, V8QromAccounting.fallingProduct, List.range, List.range.loop,
    List.foldl]

theorem exact_distinct_outside_opening_tuple_count :
    distinctOutsideOpeningTupleCount =
      39402006141350511621114225210673602986862412529333074377438760896144125701637148142975581610924276996129155465239040 := by
  rw [show distinctOutsideOpeningTupleCount =
    fallingProduct (goldilocksOrder - packingFactor) piopOpenings by rfl,
    exact_goldilocks_order, exact_arithmetic_parameters.1, exact_arithmetic_parameters.2.1]
  norm_num [fallingProduct, V8QromAccounting.fallingProduct, List.range, List.range.loop, List.foldl]

theorem exact_admissibility_rejected_tuple_upper_bound :
    admissibilityRejectedTupleUpperBound =
      884298631841797675462349510921444357872907809201293312061583775577852396831448057764976387319398814 := by
  rw [show admissibilityRejectedTupleUpperBound =
    openingAdmissibilityBadTupleCoefficient * goldilocksOrder ^ (piopOpenings - 1) by rfl,
    exact_arithmetic_parameters.2.2.2.2.2.2.2.2,
    exact_goldilocks_order, exact_arithmetic_parameters.2.1]
  norm_num

theorem exact_epsilon3_denominator :
    epsilon3Denominator =
      39402006141350510736815593368875927524512901607888716504530951694850813640053372565123184779476219231152768145840226 := by
  unfold epsilon3Denominator correctionAwareOpeningTupleLowerBound
  rw [exact_distinct_outside_opening_tuple_count,
    exact_admissibility_rejected_tuple_upper_bound]

theorem exact_epsilon4_numerator :
    epsilon4Numerator = 3446081924452734077144379159486112710902808576000000 := by
  rw [show epsilon4Numerator = fallingProduct decsPolynomialDegree decsOpenings by rfl,
    exact_arithmetic_parameters.2.2.2.2.2.2.2.1,
    exact_arithmetic_parameters.2.2.2.2.2.1]
  norm_num [fallingProduct, V8QromAccounting.fallingProduct, List.range, List.range.loop,
    List.foldl]

theorem exact_epsilon4_denominator :
    epsilon4Denominator =
      2977063984099242154112801316122936927563321662098868437378195530556677758206033918562850975748176384541108944047982110932956288018022400000 := by
  rw [show epsilon4Denominator = fallingProduct decsDomainSize decsOpenings by rfl,
    exact_arithmetic_parameters.2.2.2.2.1,
    exact_arithmetic_parameters.2.2.2.2.2.1]
  norm_num [fallingProduct, V8QromAccounting.fallingProduct, List.range, List.range.loop,
    List.foldl]

private theorem exact_aggregate_error_numerator :
    aggregateErrorNumerator =
      619499779969849527970346154671815787250051171051310355998838484598881170501607624419960455125018828740987567901389541763999449787085585694868912472167797268267792407641649113821276060401860688847416215207646673406582086648082220055224092870917423592802753411865163818500539248675179355146560910848673932415645172712658993275972733584477260207374886030540800000 := by
  unfold aggregateErrorNumerator epsilon1Numerator epsilon2Numerator
  rw [exact_epsilon1_denominator, exact_epsilon2_denominator, exact_epsilon3_numerator,
    exact_epsilon3_denominator, exact_epsilon4_numerator, exact_epsilon4_denominator]

private theorem exact_aggregate_error_denominator :
    aggregateErrorDenominator =
      535184746632387671103848945462699990515626670442562285487139809864746420693175452640373852859316824612838401672934089544206319215275065796559531375344120169391041645883700833292108081884341394169914070516256560783897073527154492225380245033441265194160022708174969849268583844476821020785722965610705479318045109440425265359565324386856208319811727846353141670508403831390399888061320622955230110363269021778293303975200839999054562577507942400000 := by
  unfold aggregateErrorDenominator
  rw [exact_epsilon1_denominator, exact_epsilon2_denominator, exact_epsilon3_denominator,
    exact_epsilon4_denominator]

/-- Materialize the exact SMZ9 aggregate ratio once so later kernel proofs do not repeatedly
normalize the same falling products and thousand-digit common denominator. -/
theorem exact_aggregate_error_ratio :
    aggregateErrorNumerator =
      619499779969849527970346154671815787250051171051310355998838484598881170501607624419960455125018828740987567901389541763999449787085585694868912472167797268267792407641649113821276060401860688847416215207646673406582086648082220055224092870917423592802753411865163818500539248675179355146560910848673932415645172712658993275972733584477260207374886030540800000 ∧
    aggregateErrorDenominator =
      535184746632387671103848945462699990515626670442562285487139809864746420693175452640373852859316824612838401672934089544206319215275065796559531375344120169391041645883700833292108081884341394169914070516256560783897073527154492225380245033441265194160022708174969849268583844476821020785722965610705479318045109440425265359565324386856208319811727846353141670508403831390399888061320622955230110363269021778293303975200839999054562577507942400000 := by
  exact ⟨exact_aggregate_error_numerator, exact_aggregate_error_denominator⟩

def supportsInteractiveBits (bits : Nat) : Prop :=
  2 ^ bits * aggregateErrorNumerator ≤ aggregateErrorDenominator

theorem smz9_interactive_aggregate_supports_288_bits :
    supportsInteractiveBits 288 := by
  unfold supportsInteractiveBits
  rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
  norm_num

theorem smz9_interactive_aggregate_does_not_support_289_bits :
    ¬ supportsInteractiveBits 289 := by
  unfold supportsInteractiveBits
  rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
  norm_num

def idealCmsEnvelopeNumerator (queries : Nat) : Nat :=
  12 * queries ^ 2 * aggregateErrorNumerator * 2 ^ transcriptHashBits +
    (48 * queries ^ 3 + 2 * decsDomainSize ^ 2) * aggregateErrorDenominator

def idealCmsEnvelopeDenominator : Nat :=
  aggregateErrorDenominator * 2 ^ transcriptHashBits

def supportsIdealCmsEnvelopeBits (bits queries : Nat) : Prop :=
  2 ^ bits * idealCmsEnvelopeNumerator queries ≤ idealCmsEnvelopeDenominator

theorem smz9_ideal_cms_at_2pow64_supports_157_bits :
    supportsIdealCmsEnvelopeBits 157 analysisGlobalQueryBudget := by
  unfold supportsIdealCmsEnvelopeBits idealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
    analysisGlobalQueryBudget analysisGlobalQueryExponent transcriptHashBits decsDomainSize
  rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
  norm_num

theorem smz9_ideal_cms_at_2pow64_does_not_support_158_bits :
    ¬ supportsIdealCmsEnvelopeBits 158 analysisGlobalQueryBudget := by
  unfold supportsIdealCmsEnvelopeBits idealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
    analysisGlobalQueryBudget analysisGlobalQueryExponent transcriptHashBits decsDomainSize
  rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
  norm_num

def projectedPendingActionBytes : Nat := projectedTwoOutputActionBytes + 225
def blockActionByteCap : Nat := 64 * 1024 * 1024
def projectedMaximumRecordByteQuotientDiagnostic : Nat :=
  blockActionByteCap / projectedPendingActionBytes
def consensusProofActionsPerBlock : Nat := 512
def analysisHistoryBlocks : Nat := 4096
def analysisHistoryProofInteractions : Nat :=
  consensusProofActionsPerBlock * analysisHistoryBlocks

/-- Every honest output exposed by the conservative eager programming screen for an explicit
number `T` of observed/generated honest proof views: all `2 * N - 1` DECS tree points plus the
exact final-PIOP point.  The canonical accepted-proof count does not inhabit this parameter. -/
def honestProgramEventCount (proofViews : Nat) : Nat :=
  (2 * decsDomainSize) * proofViews

/-- Canonical-count arithmetic specialization only; not an observed-view exposure receipt. -/
def allFullHistoryProgramEventCount : Nat :=
  honestProgramEventCount analysisHistoryProofInteractions

def totalSha512OracleExposuresFor (queries proofViews : Nat) : Nat :=
  queries + honestProgramEventCount proofViews

/-- The executable V8 relation has 125 live Poseidon2 calls per proof view. -/
def poseidon2LiveCallsPerProof : Nat := 125

/-- The executable trace also evaluates the three fixed padding permutations, so the
conservative primitive accounting charges all 128 evaluated rows per proof view. -/
def poseidon2EvaluationsPerProof : Nat := 128

def poseidon2HonestEvaluationCount (proofViews : Nat) : Nat :=
  poseidon2EvaluationsPerProof * proofViews

def totalPoseidon2ExposuresFor (queries proofViews : Nat) : Nat :=
  queries + poseidon2HonestEvaluationCount proofViews

/-- The SHA-512 collision screen must charge adversarial quantum queries and honest programmed
outputs in the same oracle exposure count. -/
def totalSha512OracleExposures (queries : Nat) : Nat :=
  totalSha512OracleExposuresFor queries analysisHistoryProofInteractions

def historyUnionEnvelopeNumerator : Nat :=
  analysisHistoryProofInteractions * idealCmsEnvelopeNumerator analysisGlobalQueryBudget

def supportsHistoryUnionBits (bits : Nat) : Prop :=
  2 ^ bits * historyUnionEnvelopeNumerator ≤ idealCmsEnvelopeDenominator

theorem smz9_analysis_history_has_exact_interaction_count :
    projectedPendingActionBytes = 128522 ∧
      projectedMaximumRecordByteQuotientDiagnostic = 522 ∧
      blockActionByteCap % projectedPendingActionBytes = 20380 ∧
      consensusProofActionsPerBlock = 512 ∧
      analysisHistoryProofInteractions = 2097152 := by
  decide

theorem exact_analysis_history_proof_interactions :
    analysisHistoryProofInteractions = 2097152 :=
  smz9_analysis_history_has_exact_interaction_count.2.2.2.2

theorem exact_full_history_program_and_2pow64_oracle_exposure_counts :
    allFullHistoryProgramEventCount = 35184372088832 ∧
      totalSha512OracleExposures analysisGlobalQueryBudget = 18446779258081640448 ∧
      analysisGlobalQueryBudget < totalSha512OracleExposures analysisGlobalQueryBudget ∧
      totalSha512OracleExposures analysisGlobalQueryBudget < 2 ^ 65 := by
  norm_num [allFullHistoryProgramEventCount, totalSha512OracleExposures,
    totalSha512OracleExposuresFor, honestProgramEventCount,
    analysisHistoryProofInteractions, consensusProofActionsPerBlock, analysisHistoryBlocks,
    decsDomainSize, analysisGlobalQueryBudget, analysisGlobalQueryExponent]

theorem exact_full_history_poseidon2_exposure_counts :
    poseidon2LiveCallsPerProof = 125 ∧ poseidon2EvaluationsPerProof = 128 ∧
      poseidon2HonestEvaluationCount analysisHistoryProofInteractions = 268435456 ∧
      totalPoseidon2ExposuresFor analysisGlobalQueryBudget
        analysisHistoryProofInteractions = 18446744073977987072 := by
  norm_num [poseidon2LiveCallsPerProof, poseidon2HonestEvaluationCount,
    poseidon2EvaluationsPerProof,
    totalPoseidon2ExposuresFor, analysisHistoryProofInteractions,
    consensusProofActionsPerBlock, analysisHistoryBlocks, analysisGlobalQueryBudget,
    analysisGlobalQueryExponent]

theorem smz9_ideal_cms_history_union_supports_136_bits :
    supportsHistoryUnionBits 136 := by
  unfold supportsHistoryUnionBits historyUnionEnvelopeNumerator
    analysisHistoryProofInteractions consensusProofActionsPerBlock analysisHistoryBlocks
    idealCmsEnvelopeNumerator idealCmsEnvelopeDenominator analysisGlobalQueryBudget
    analysisGlobalQueryExponent transcriptHashBits decsDomainSize
  rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
  norm_num

theorem smz9_ideal_cms_history_union_does_not_support_137_bits :
    ¬ supportsHistoryUnionBits 137 := by
  unfold supportsHistoryUnionBits historyUnionEnvelopeNumerator
    analysisHistoryProofInteractions consensusProofActionsPerBlock analysisHistoryBlocks
    idealCmsEnvelopeNumerator idealCmsEnvelopeDenominator analysisGlobalQueryBudget
    analysisGlobalQueryExponent transcriptHashBits decsDomainSize
  rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
  norm_num

theorem smz9_ideal_cms_at_2pow128_is_below_half :
    2 * idealCmsEnvelopeNumerator workQueryBudget < idealCmsEnvelopeDenominator := by
  unfold idealCmsEnvelopeNumerator idealCmsEnvelopeDenominator workQueryBudget
    workQueryExponent transcriptHashBits decsDomainSize
  rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
  norm_num

/-! ## Exact conditional global-query composition -/

structure CompositionRatio where
  numerator : Nat
  denominator : Nat
deriving DecidableEq, Repr

namespace CompositionRatio

def add (left right : CompositionRatio) : CompositionRatio where
  numerator := left.numerator * right.denominator + right.numerator * left.denominator
  denominator := left.denominator * right.denominator

def scale (ratio : CompositionRatio) (factor : Nat) : CompositionRatio where
  numerator := factor * ratio.numerator
  denominator := ratio.denominator

abbrev supportsBits (ratio : CompositionRatio) (bits : Nat) : Prop :=
  2 ^ bits * ratio.numerator ≤ ratio.denominator

abbrev strictlyBelowBits (ratio : CompositionRatio) (bits : Nat) : Prop :=
  ratio.numerator * 2 ^ bits < ratio.denominator

abbrev belowHalf (ratio : CompositionRatio) : Prop :=
  2 * ratio.numerator < ratio.denominator

/--
Kernel-friendly composition lemma.  The left term is below `15/32` and the right term is below
`1/32`, so their exact common-denominator sum is strictly below `1/2`.
-/
theorem add_below_half_of_scaled_bounds
    (left right : CompositionRatio)
    (leftBound : 32 * left.numerator < 15 * left.denominator)
    (rightBound : 32 * right.numerator < right.denominator) :
    (left.add right).belowHalf := by
  have rightDenominatorPositive : 0 < right.denominator := by omega
  have leftDenominatorPositive : 0 < left.denominator := by omega
  have leftScaled := Nat.mul_lt_mul_of_pos_right leftBound rightDenominatorPositive
  have rightScaled := Nat.mul_lt_mul_of_pos_right rightBound leftDenominatorPositive
  unfold add belowHalf
  dsimp
  ring_nf at leftScaled rightScaled ⊢
  omega

/-- A lower bound from the first summand survives exact nonnegative ratio addition. -/
theorem add_not_below_half_of_left
    (left right : CompositionRatio)
    (leftAtLeastHalf : left.denominator ≤ 2 * left.numerator) :
    ¬ (left.add right).belowHalf := by
  have leftScaled := Nat.mul_le_mul_right right.denominator leftAtLeastHalf
  unfold add belowHalf
  dsimp
  intro composedBelowHalf
  ring_nf at leftScaled composedBelowHalf
  omega

/-- Avoid normalizing a product of large common denominators: if both summands are below
`1 / (2k)`, their exact rational sum is below `1 / k`. -/
theorem add_scaled_bound_of_double
    (left right : CompositionRatio) (k : Nat)
    (leftBound : 2 * k * left.numerator < left.denominator)
    (rightBound : 2 * k * right.numerator < right.denominator) :
    k * (left.add right).numerator < (left.add right).denominator := by
  have rightDenominatorPositive : 0 < right.denominator := by omega
  have leftDenominatorPositive : 0 < left.denominator := by omega
  have leftScaled := Nat.mul_lt_mul_of_pos_right leftBound rightDenominatorPositive
  have rightScaled := Nat.mul_lt_mul_of_pos_right rightBound leftDenominatorPositive
  unfold add
  dsimp
  ring_nf at leftScaled rightScaled ⊢
  omega

end CompositionRatio

def idealCmsRatio (queries : Nat) : CompositionRatio where
  numerator := idealCmsEnvelopeNumerator queries
  denominator := idealCmsEnvelopeDenominator

/-- Global-history version of the CMS envelope.  Both query-dependent CMS terms use the total
SHA-512 exposure count `Q + H`; the tape-database term keeps its source-derived role. -/
def globalIdealCmsEnvelopeNumerator (queries proofViews : Nat) : Nat :=
  12 * (totalSha512OracleExposuresFor queries proofViews) ^ 2 * aggregateErrorNumerator *
      2 ^ transcriptHashBits +
    (48 * (totalSha512OracleExposuresFor queries proofViews) ^ 3 + 2 * decsDomainSize ^ 2) *
      aggregateErrorDenominator

def globalIdealCmsRatio (queries proofViews : Nat) : CompositionRatio where
  numerator := globalIdealCmsEnvelopeNumerator queries proofViews
  denominator := idealCmsEnvelopeDenominator

def sha512PreimageRatio (queries : Nat) : CompositionRatio where
  numerator := queries ^ 2
  denominator := 2 ^ transcriptHashBits

def globalSha512PreimageRatio (queries proofViews : Nat) : CompositionRatio :=
  sha512PreimageRatio (totalSha512OracleExposuresFor queries proofViews)

def poseidon2DigestCardinality : Nat := goldilocksOrder ^ 7

def poseidon2CollisionRatio (queries : Nat) : CompositionRatio where
  numerator := queries ^ 3
  denominator := poseidon2DigestCardinality

def poseidon2PreimageRatio (queries : Nat) : CompositionRatio where
  numerator := queries ^ 2
  denominator := poseidon2DigestCardinality

def primitiveRemainderRatio (queries proofViews : Nat) : CompositionRatio :=
  ((globalSha512PreimageRatio queries proofViews).add
      (poseidon2CollisionRatio (totalPoseidon2ExposuresFor queries proofViews))).add
    (poseidon2PreimageRatio (totalPoseidon2ExposuresFor queries proofViews))

def fieldXofRequestedWords : Nat := 102365
def fieldXofCandidateWords : Nat := 102400
def fieldXofMinimumRejections : Nat := 36
def fieldXofRequestUnion : Nat := 2 ^ 25

/-- Kernel-friendly conservative envelope for the exact binomial rejection tail. -/
def conservativeFieldXofAbortRatio : CompositionRatio where
  numerator := 1
  denominator := 2 ^ 500

private theorem mul4_le_mul4 {a b c d a' b' c' d' : Nat}
    (ha : a ≤ a') (hb : b ≤ b') (hc : c ≤ c') (hd : d ≤ d') :
    a * b * c * d ≤ a' * b' * c' * d' :=
  Nat.mul_le_mul (Nat.mul_le_mul (Nat.mul_le_mul ha hb) hc) hd

private theorem field_xof_choose_bound : Nat.choose 102400 36 ≤ 102400 ^ 36 :=
  Nat.choose_le_pow 102400 36

private theorem field_xof_candidate_power_bound :
    102400 ^ 36 ≤ (2 ^ 17) ^ 36 :=
  Nat.pow_le_pow_left (by norm_num) 36

private theorem field_xof_rejection_power_bound :
    (2 ^ 32 - 1) ^ 36 ≤ (2 ^ 32) ^ 36 :=
  Nat.pow_le_pow_left (by omega) 36

private theorem field_xof_product_choose_bound :
    2 ^ 25 * Nat.choose 102400 36 * (2 ^ 32 - 1) ^ 36 * 2 ^ 500 ≤
      2 ^ 25 * 102400 ^ 36 * (2 ^ 32 - 1) ^ 36 * 2 ^ 500 := by
  exact mul4_le_mul4 (Nat.le_refl (2 ^ 25)) field_xof_choose_bound
    (Nat.le_refl ((2 ^ 32 - 1) ^ 36)) (Nat.le_refl (2 ^ 500))

private theorem field_xof_product_candidate_bound :
    2 ^ 25 * 102400 ^ 36 * (2 ^ 32 - 1) ^ 36 * 2 ^ 500 ≤
      2 ^ 25 * (2 ^ 17) ^ 36 * (2 ^ 32 - 1) ^ 36 * 2 ^ 500 := by
  exact mul4_le_mul4 (Nat.le_refl (2 ^ 25)) field_xof_candidate_power_bound
    (Nat.le_refl ((2 ^ 32 - 1) ^ 36)) (Nat.le_refl (2 ^ 500))

private theorem field_xof_product_rejection_bound :
    2 ^ 25 * (2 ^ 17) ^ 36 * (2 ^ 32 - 1) ^ 36 * 2 ^ 500 ≤
      2 ^ 25 * (2 ^ 17) ^ 36 * (2 ^ 32) ^ 36 * 2 ^ 500 := by
  exact mul4_le_mul4 (Nat.le_refl (2 ^ 25)) (Nat.le_refl ((2 ^ 17) ^ 36))
    field_xof_rejection_power_bound (Nat.le_refl (2 ^ 500))

private theorem field_xof_power_ceiling :
    2 ^ 25 * (2 ^ 17) ^ 36 * (2 ^ 32) ^ 36 * 2 ^ 500 ≤
      2 ^ (64 * 36) := by
  norm_num [← pow_mul, ← pow_add]

private theorem field_xof_direct_bound :
    2 ^ 25 * Nat.choose 102400 36 * (2 ^ 32 - 1) ^ 36 * 2 ^ 500 ≤
      2 ^ (64 * 36) := by
  calc
    2 ^ 25 * Nat.choose 102400 36 * (2 ^ 32 - 1) ^ 36 * 2 ^ 500 ≤
        2 ^ 25 * 102400 ^ 36 * (2 ^ 32 - 1) ^ 36 * 2 ^ 500 :=
      field_xof_product_choose_bound
    _ ≤ 2 ^ 25 * (2 ^ 17) ^ 36 * (2 ^ 32 - 1) ^ 36 * 2 ^ 500 :=
      field_xof_product_candidate_bound
    _ ≤ 2 ^ 25 * (2 ^ 17) ^ 36 * (2 ^ 32) ^ 36 * 2 ^ 500 :=
      field_xof_product_rejection_bound
    _ ≤ 2 ^ (64 * 36) := field_xof_power_ceiling

private theorem exact_field_xof_parameters :
    fieldXofRequestUnion = 2 ^ 25 ∧ fieldXofCandidateWords = 102400 ∧
      fieldXofMinimumRejections = 36 := by
  decide

private structure FieldXofAbortRatioCertificate where
  numerator : Nat
  denominator : Nat
  numeratorExact :
    numerator = 2 ^ 25 * Nat.choose 102400 36 * (2 ^ 32 - 1) ^ 36
  denominatorExact : denominator = 2 ^ (64 * 36)
  conservativeBound : numerator * 2 ^ 500 ≤ 1 * denominator

private irreducible_def fieldXofAbortRatioCertificate : FieldXofAbortRatioCertificate := {
  numerator := 2 ^ 25 * Nat.choose 102400 36 * (2 ^ 32 - 1) ^ 36
  denominator := 2 ^ (64 * 36)
  numeratorExact := rfl
  denominatorExact := rfl
  conservativeBound := by simpa only [one_mul] using field_xof_direct_bound
}

def fieldXofAbortRatio : CompositionRatio where
  numerator := fieldXofAbortRatioCertificate.numerator
  denominator := fieldXofAbortRatioCertificate.denominator

/-- The irreducible definition stores the executable binomial expression itself, not a numerical
replacement.  Its generated equation theorem remains available for explicit unfolding, while the
certificate fields expose the exact values and the kernel-checked conservative bound without
repeatedly normalizing `Nat.choose 102400 36`. -/
theorem exact_field_xof_abort_ratio_numerator :
    fieldXofAbortRatio.numerator =
      fieldXofRequestUnion * Nat.choose fieldXofCandidateWords fieldXofMinimumRejections *
        (2 ^ 32 - 1) ^ fieldXofMinimumRejections := by
  calc
    fieldXofAbortRatio.numerator =
        2 ^ 25 * Nat.choose 102400 36 * (2 ^ 32 - 1) ^ 36 :=
      fieldXofAbortRatioCertificate.numeratorExact
    _ = fieldXofRequestUnion *
          Nat.choose fieldXofCandidateWords fieldXofMinimumRejections *
          (2 ^ 32 - 1) ^ fieldXofMinimumRejections := by
      rw [exact_field_xof_parameters.1, exact_field_xof_parameters.2.1,
        exact_field_xof_parameters.2.2]

theorem exact_field_xof_abort_ratio_denominator :
    fieldXofAbortRatio.denominator = 2 ^ (64 * fieldXofMinimumRejections) := by
  calc
    fieldXofAbortRatio.denominator = 2 ^ (64 * 36) :=
      fieldXofAbortRatioCertificate.denominatorExact
    _ = 2 ^ (64 * fieldXofMinimumRejections) := by
      rw [exact_field_xof_parameters.2.2]

theorem exact_field_xof_abort_is_bounded_by_conservative_envelope :
    fieldXofAbortRatio.numerator * conservativeFieldXofAbortRatio.denominator ≤
      conservativeFieldXofAbortRatio.numerator * fieldXofAbortRatio.denominator :=
  fieldXofAbortRatioCertificate.conservativeBound

def canonicalPiopNonceBadPerTrial : Nat := 813
def canonicalPiopNonceTrialCount : Nat := 16

def canonicalPiopOpeningAbortRatio : CompositionRatio where
  numerator := canonicalPiopNonceBadPerTrial ^ canonicalPiopNonceTrialCount
  denominator := goldilocksOrder ^ canonicalPiopNonceTrialCount

def fixedDecsCandidateCount : Nat := 50
def fixedDecsMinimumBadDraws : Nat := 31

def fixedDecsSamplerAbortRatio : CompositionRatio where
  numerator :=
    2 ^ fixedDecsCandidateCount *
      fixedDecsCandidateCount ^ fixedDecsMinimumBadDraws
  denominator := decsDomainSize ^ fixedDecsMinimumBadDraws

/-- SMZ9 has no proof-of-work challenge grinding; nonce trials are canonical abort handling. -/
def grindingRatio : CompositionRatio where
  numerator := 0
  denominator := 1

def allAbortRatio : CompositionRatio :=
  ((fieldXofAbortRatio.add canonicalPiopOpeningAbortRatio).add
    fixedDecsSamplerAbortRatio).add grindingRatio

def conservativeAllAbortRatio : CompositionRatio :=
  ((conservativeFieldXofAbortRatio.add canonicalPiopOpeningAbortRatio).add
    fixedDecsSamplerAbortRatio).add grindingRatio

/-- Soundness/forgery terms under one global query budget; fail-closed aborts are excluded. -/
def conditionalGlobalQueryFiniteHistoryRatio (queries proofInteractions : Nat) : CompositionRatio :=
  (globalIdealCmsRatio queries proofInteractions).add
    (primitiveRemainderRatio queries proofInteractions)

/-- Fail-closed completeness/liveness loss over the finite accepted-proof history. -/
def conditionalCompletenessAbortFiniteHistoryRatio
    (proofInteractions : Nat) : CompositionRatio :=
  conservativeAllAbortRatio.scale proofInteractions

/-- Diagnostic total failure, not a forgery advantage. -/
def conditionalTotalFailureFiniteHistoryRatio
    (queries proofInteractions : Nat) : CompositionRatio :=
  (conditionalGlobalQueryFiniteHistoryRatio queries proofInteractions).add
    (conditionalCompletenessAbortFiniteHistoryRatio proofInteractions)

theorem exact_abort_and_no_grinding_parameters :
    fieldXofRequestedWords = 102365 ∧ fieldXofCandidateWords = 102400 ∧
      fieldXofMinimumRejections = 36 ∧ canonicalPiopNonceBadPerTrial = 813 ∧
      canonicalPiopNonceTrialCount = 16 ∧ fixedDecsCandidateCount = 50 ∧
      fixedDecsMinimumBadDraws = 31 ∧ grindingRatio.numerator = 0 ∧
      grindingRatio.denominator = 1 := by
  decide

theorem conditional_global_query_finite_history_at_2pow128_is_below_half :
    (conditionalGlobalQueryFiniteHistoryRatio workQueryBudget
      analysisHistoryProofInteractions).belowHalf := by
  apply CompositionRatio.add_below_half_of_scaled_bounds
  · unfold globalIdealCmsRatio globalIdealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
      totalSha512OracleExposuresFor honestProgramEventCount
      analysisHistoryProofInteractions consensusProofActionsPerBlock analysisHistoryBlocks
      workQueryBudget workQueryExponent transcriptHashBits decsDomainSize
    rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
    norm_num
  · unfold primitiveRemainderRatio globalSha512PreimageRatio sha512PreimageRatio
      totalSha512OracleExposuresFor honestProgramEventCount totalPoseidon2ExposuresFor
      poseidon2HonestEvaluationCount poseidon2EvaluationsPerProof poseidon2CollisionRatio
      workQueryBudget workQueryExponent
    apply CompositionRatio.add_scaled_bound_of_double
    · apply CompositionRatio.add_scaled_bound_of_double
      · rw [exact_analysis_history_proof_interactions]
        norm_num [sha512PreimageRatio, transcriptHashBits, decsDomainSize]
      · rw [exact_analysis_history_proof_interactions]
        unfold poseidon2DigestCardinality
        rw [exact_goldilocks_order]
        norm_num [poseidon2CollisionRatio]
    · rw [exact_analysis_history_proof_interactions]
      unfold poseidon2PreimageRatio poseidon2DigestCardinality
      rw [exact_goldilocks_order]
      norm_num

theorem conditional_global_query_finite_history_at_2pow142_is_below_half :
    (conditionalGlobalQueryFiniteHistoryRatio strongestConditionalWorkQueryBudget
      analysisHistoryProofInteractions).belowHalf := by
  apply CompositionRatio.add_below_half_of_scaled_bounds
  · unfold globalIdealCmsRatio globalIdealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
      totalSha512OracleExposuresFor honestProgramEventCount
      analysisHistoryProofInteractions consensusProofActionsPerBlock analysisHistoryBlocks
      strongestConditionalWorkQueryBudget strongestConditionalWorkQueryExponent
      transcriptHashBits decsDomainSize
    rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
    norm_num
  · unfold primitiveRemainderRatio globalSha512PreimageRatio sha512PreimageRatio
      totalSha512OracleExposuresFor honestProgramEventCount totalPoseidon2ExposuresFor
      poseidon2HonestEvaluationCount poseidon2EvaluationsPerProof poseidon2CollisionRatio
      strongestConditionalWorkQueryBudget strongestConditionalWorkQueryExponent
    apply CompositionRatio.add_scaled_bound_of_double
    · apply CompositionRatio.add_scaled_bound_of_double
      · rw [exact_analysis_history_proof_interactions]
        norm_num [sha512PreimageRatio, transcriptHashBits, decsDomainSize]
      · rw [exact_analysis_history_proof_interactions]
        unfold poseidon2DigestCardinality
        rw [exact_goldilocks_order]
        norm_num [poseidon2CollisionRatio]
    · rw [exact_analysis_history_proof_interactions]
      unfold poseidon2PreimageRatio poseidon2DigestCardinality
      rw [exact_goldilocks_order]
      norm_num

theorem conditional_global_query_finite_history_at_2pow143_is_not_below_half :
    ¬ (conditionalGlobalQueryFiniteHistoryRatio firstFailingConditionalWorkQueryBudget
      analysisHistoryProofInteractions).belowHalf := by
  apply CompositionRatio.add_not_below_half_of_left
  unfold globalIdealCmsRatio globalIdealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
    totalSha512OracleExposuresFor honestProgramEventCount
    analysisHistoryProofInteractions consensusProofActionsPerBlock analysisHistoryBlocks
    firstFailingConditionalWorkQueryBudget firstFailingConditionalWorkQueryExponent
    transcriptHashBits decsDomainSize
  rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
  norm_num

/-! ## Direct adaptive-reprogramming route: exact current-wire no-go -/

def currentFirstProgramEntropyBits : Nat := 256
def minimumEvenFirstProgramEntropyBitsForFiniteHistory : Nat := 366
def minimumByteAlignedFirstProgramEntropyBitsForFiniteHistory : Nat := 368
def minimumByteAlignedFirstProgramEntropyBytesForFiniteHistory : Nat := 46
def currentFirstProgramEntropyBytes : Nat := 32
def minimumAdditionalFirstProgramEntropyBytes : Nat := 14
def deployedSaltWireAlignmentBytes : Nat := 8
def minimumWireAlignedFirstProgramEntropyBytesForFiniteHistory : Nat := 48
def minimumWireAlignedFirstProgramEntropyBitsForFiniteHistory : Nat := 384
def minimumAdditionalWireAlignedFirstProgramEntropyBytes : Nat := 16

/-- Honest programmed SHA-512 steps make `Q + H` strictly exceed `2^q`; `q+1` is the exact
power-of-two ceiling used by the dyadic adaptive screen. -/
def totalSha512OracleExposureExponentCeiling (queryExponent : Nat) : Nat := queryExponent + 1

/--
The dyadic specialization of the GHHM adaptive-reprogramming expression.  The deployed `2^64`
adversarial budget is increased to the power-of-two ceiling `2^65` for `Q + H`, where `H` counts
all honest programmed SHA-512 steps.  This is arithmetic for that proposed reduction route, not a
proof that the paper's hypotheses match SMZ9.
-/
def ghhmAdaptiveProgrammingRatioAtQueryExponent
    (entropyBits queryExponent proofInteractions : Nat) : CompositionRatio where
  numerator := 3 * proofInteractions
  denominator := 2 ^ (1 + (entropyBits - queryExponent) / 2)

def ghhmFirstProgramRatio (entropyBits proofInteractions : Nat) : CompositionRatio :=
  ghhmAdaptiveProgrammingRatioAtQueryExponent entropyBits
    (totalSha512OracleExposureExponentCeiling analysisGlobalQueryExponent)
    proofInteractions

theorem current_256_bit_first_program_fails_one_proof_128_bit_target :
    ¬ (ghhmFirstProgramRatio currentFirstProgramEntropyBits 1).strictlyBelowBits 128 := by
  norm_num [ghhmFirstProgramRatio, ghhmAdaptiveProgrammingRatioAtQueryExponent,
    totalSha512OracleExposureExponentCeiling, currentFirstProgramEntropyBits,
    analysisGlobalQueryExponent]

theorem current_256_bit_first_program_fails_finite_history_128_bit_target :
    ¬ (ghhmFirstProgramRatio currentFirstProgramEntropyBits
      analysisHistoryProofInteractions).strictlyBelowBits 128 := by
  rw [exact_analysis_history_proof_interactions]
  norm_num [ghhmFirstProgramRatio, ghhmAdaptiveProgrammingRatioAtQueryExponent,
    totalSha512OracleExposureExponentCeiling, currentFirstProgramEntropyBits,
    analysisGlobalQueryExponent]

theorem first_program_364_bits_still_fails_finite_history_128_bit_target :
    ¬ (ghhmFirstProgramRatio 364
      analysisHistoryProofInteractions).strictlyBelowBits 128 := by
  rw [exact_analysis_history_proof_interactions]
  norm_num [ghhmFirstProgramRatio, ghhmAdaptiveProgrammingRatioAtQueryExponent,
    totalSha512OracleExposureExponentCeiling, analysisGlobalQueryExponent]

theorem first_program_366_bits_is_the_minimum_even_finite_history_repair :
    (ghhmFirstProgramRatio minimumEvenFirstProgramEntropyBitsForFiniteHistory
      analysisHistoryProofInteractions).strictlyBelowBits 128 ∧
      ¬ (ghhmFirstProgramRatio
        (minimumEvenFirstProgramEntropyBitsForFiniteHistory - 2)
        analysisHistoryProofInteractions).strictlyBelowBits 128 := by
  rw [exact_analysis_history_proof_interactions]
  norm_num [ghhmFirstProgramRatio, ghhmAdaptiveProgrammingRatioAtQueryExponent,
    totalSha512OracleExposureExponentCeiling,
    minimumEvenFirstProgramEntropyBitsForFiniteHistory, analysisGlobalQueryExponent]

theorem exact_byte_aligned_first_program_repair :
    minimumByteAlignedFirstProgramEntropyBitsForFiniteHistory = 368 ∧
      minimumByteAlignedFirstProgramEntropyBytesForFiniteHistory = 46 ∧
      currentFirstProgramEntropyBytes = 32 ∧
      minimumAdditionalFirstProgramEntropyBytes = 14 := by
  norm_num [minimumByteAlignedFirstProgramEntropyBitsForFiniteHistory,
    minimumByteAlignedFirstProgramEntropyBytesForFiniteHistory,
    currentFirstProgramEntropyBytes, minimumAdditionalFirstProgramEntropyBytes]

/--
The Rust transcript absorbs salt as 64-bit words.  Thus the smallest wire-compatible salt
enlargement is
48 bytes, even though the information-theoretic byte ceiling of 366 bits is 46 bytes.
-/
theorem exact_wire_aligned_first_program_repair :
    deployedSaltWireAlignmentBytes = 8 ∧
      minimumWireAlignedFirstProgramEntropyBytesForFiniteHistory = 48 ∧
      minimumWireAlignedFirstProgramEntropyBitsForFiniteHistory = 384 ∧
      currentFirstProgramEntropyBytes = 32 ∧
      minimumAdditionalWireAlignedFirstProgramEntropyBytes = 16 := by
  norm_num [deployedSaltWireAlignmentBytes,
    minimumWireAlignedFirstProgramEntropyBytesForFiniteHistory,
    minimumWireAlignedFirstProgramEntropyBitsForFiniteHistory, currentFirstProgramEntropyBytes,
    minimumAdditionalWireAlignedFirstProgramEntropyBytes]

/-! ## Conservative hypothetical eager DECS-tree programming schedule -/

def fullDecsTreeProgramsPerProof : Nat := 2 * decsDomainSize - 1
def fullDecsTreeProgrammingEvents : Nat :=
  fullDecsTreeProgramsPerProof * analysisHistoryProofInteractions
def conditionalFullTreeEntropyBits : Nat := 512
def minimumEvenFullTreeEntropyBitsForFiniteHistory : Nat := 414
def minimumByteFullTreeEntropyBitsForFiniteHistory : Nat := 416
def minimumByteFullTreeEntropyBytesForFiniteHistory : Nat := 52
def minimumWireFullTreeEntropyBitsForFiniteHistory : Nat := 448
def minimumWireFullTreeEntropyBytesForFiniteHistory : Nat := 56
def minimumAdditionalWireFullTreeEntropyBytes : Nat := 24

/--
If a hypothetical eager simulator programmed every honest leaf, internal node, and root, and each
input had 512 bits of conditional min-entropy, the direct GHHM-shaped union charges
`2 * 2^23 - 1` programs per accepted proof.  This is deliberately conservative arithmetic, not a
description of the executable lazy simulator.  The scheduling, input-recording, leaf-fiber, and
hidden-child propagation hypotheses are not proved by this theorem.
-/
theorem conditional_512_bit_full_tree_programming_supports_exactly_177_bits :
    (ghhmFirstProgramRatio conditionalFullTreeEntropyBits
      fullDecsTreeProgrammingEvents).strictlyBelowBits 177 ∧
      ¬ (ghhmFirstProgramRatio conditionalFullTreeEntropyBits
        fullDecsTreeProgrammingEvents).strictlyBelowBits 178 := by
  unfold fullDecsTreeProgrammingEvents
  rw [exact_analysis_history_proof_interactions]
  norm_num [ghhmFirstProgramRatio, ghhmAdaptiveProgrammingRatioAtQueryExponent,
    totalSha512OracleExposureExponentCeiling, conditionalFullTreeEntropyBits,
    fullDecsTreeProgrammingEvents,
    fullDecsTreeProgramsPerProof, decsDomainSize, analysisGlobalQueryExponent]

theorem full_tree_414_bits_is_the_minimum_even_finite_history_repair :
    (ghhmFirstProgramRatio minimumEvenFullTreeEntropyBitsForFiniteHistory
      fullDecsTreeProgrammingEvents).strictlyBelowBits 128 ∧
      ¬ (ghhmFirstProgramRatio
        (minimumEvenFullTreeEntropyBitsForFiniteHistory - 2)
        fullDecsTreeProgrammingEvents).strictlyBelowBits 128 := by
  unfold fullDecsTreeProgrammingEvents
  rw [exact_analysis_history_proof_interactions]
  norm_num [ghhmFirstProgramRatio, ghhmAdaptiveProgrammingRatioAtQueryExponent,
    totalSha512OracleExposureExponentCeiling,
    minimumEvenFullTreeEntropyBitsForFiniteHistory, fullDecsTreeProgrammingEvents,
    fullDecsTreeProgramsPerProof, decsDomainSize, analysisGlobalQueryExponent]

theorem exact_full_tree_entropy_and_wire_inventory :
    fullDecsTreeProgramsPerProof = 16777215 ∧
      fullDecsTreeProgrammingEvents = 35184369991680 ∧
      minimumEvenFullTreeEntropyBitsForFiniteHistory = 414 ∧
      minimumByteFullTreeEntropyBitsForFiniteHistory = 416 ∧
      minimumByteFullTreeEntropyBytesForFiniteHistory = 52 ∧
      deployedSaltWireAlignmentBytes = 8 ∧
      minimumWireFullTreeEntropyBitsForFiniteHistory = 448 ∧
      minimumWireFullTreeEntropyBytesForFiniteHistory = 56 ∧
      minimumAdditionalWireFullTreeEntropyBytes = 24 := by
  unfold fullDecsTreeProgrammingEvents
  rw [exact_analysis_history_proof_interactions]
  norm_num [fullDecsTreeProgramsPerProof, fullDecsTreeProgrammingEvents, decsDomainSize,
    minimumEvenFullTreeEntropyBitsForFiniteHistory,
    minimumByteFullTreeEntropyBitsForFiniteHistory, minimumByteFullTreeEntropyBytesForFiniteHistory,
    deployedSaltWireAlignmentBytes, minimumWireFullTreeEntropyBitsForFiniteHistory,
    minimumWireFullTreeEntropyBytesForFiniteHistory, minimumAdditionalWireFullTreeEntropyBytes]

/--
Strongest combined arithmetic screen: the exact global-query soundness/primitive ledger plus one
ideal 512-bit final-PIOP program and the conservative hypothetical eager schedule of every ideal
512-bit DECS-tree program.  Fail-closed completeness aborts are intentionally excluded.  For odd
entropy gaps the integer half-gap rounds the denominator down, giving a conservative rational upper
bound.  Applicability remains constructor-free below.
-/
def idealAdaptiveRemainderRatio (queryExponent : Nat) : CompositionRatio :=
  ((primitiveRemainderRatio (2 ^ queryExponent) analysisHistoryProofInteractions).add
    (ghhmAdaptiveProgrammingRatioAtQueryExponent conditionalFullTreeEntropyBits
      (totalSha512OracleExposureExponentCeiling queryExponent) analysisHistoryProofInteractions)).add
    (ghhmAdaptiveProgrammingRatioAtQueryExponent conditionalFullTreeEntropyBits
      (totalSha512OracleExposureExponentCeiling queryExponent)
      fullDecsTreeProgrammingEvents)

def conditionalGlobalQueryFiniteHistoryWithIdealAdaptiveRatio
    (queryExponent : Nat) : CompositionRatio :=
  (globalIdealCmsRatio (2 ^ queryExponent) analysisHistoryProofInteractions).add
    (idealAdaptiveRemainderRatio queryExponent)

theorem conditional_combined_global_query_at_2pow128_is_below_half :
    (conditionalGlobalQueryFiniteHistoryWithIdealAdaptiveRatio 128).belowHalf := by
  apply CompositionRatio.add_below_half_of_scaled_bounds
  · unfold globalIdealCmsRatio globalIdealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
      totalSha512OracleExposuresFor honestProgramEventCount
      analysisHistoryProofInteractions consensusProofActionsPerBlock analysisHistoryBlocks
      transcriptHashBits decsDomainSize
    rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
    norm_num
  · unfold idealAdaptiveRemainderRatio primitiveRemainderRatio globalSha512PreimageRatio
      sha512PreimageRatio totalSha512OracleExposuresFor honestProgramEventCount
      totalPoseidon2ExposuresFor poseidon2HonestEvaluationCount poseidon2EvaluationsPerProof
      poseidon2CollisionRatio poseidon2PreimageRatio
    apply CompositionRatio.add_scaled_bound_of_double
    · apply CompositionRatio.add_scaled_bound_of_double
      · apply CompositionRatio.add_scaled_bound_of_double
        · apply CompositionRatio.add_scaled_bound_of_double
          · rw [exact_analysis_history_proof_interactions]
            norm_num [sha512PreimageRatio, transcriptHashBits, decsDomainSize]
          · rw [exact_analysis_history_proof_interactions]
            unfold poseidon2DigestCardinality
            rw [exact_goldilocks_order]
            norm_num [poseidon2CollisionRatio]
        · rw [exact_analysis_history_proof_interactions]
          unfold poseidon2DigestCardinality
          rw [exact_goldilocks_order]
          norm_num [poseidon2PreimageRatio]
      · norm_num [ghhmAdaptiveProgrammingRatioAtQueryExponent,
          totalSha512OracleExposureExponentCeiling, conditionalFullTreeEntropyBits,
          analysisHistoryProofInteractions, consensusProofActionsPerBlock, analysisHistoryBlocks]
    · norm_num [ghhmAdaptiveProgrammingRatioAtQueryExponent, conditionalFullTreeEntropyBits,
        totalSha512OracleExposureExponentCeiling,
        fullDecsTreeProgrammingEvents, fullDecsTreeProgramsPerProof, decsDomainSize,
        analysisHistoryProofInteractions, consensusProofActionsPerBlock, analysisHistoryBlocks]

theorem conditional_combined_global_query_at_2pow142_is_below_half :
    (conditionalGlobalQueryFiniteHistoryWithIdealAdaptiveRatio 142).belowHalf := by
  apply CompositionRatio.add_below_half_of_scaled_bounds
  · unfold globalIdealCmsRatio globalIdealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
      totalSha512OracleExposuresFor honestProgramEventCount
      analysisHistoryProofInteractions consensusProofActionsPerBlock analysisHistoryBlocks
      transcriptHashBits decsDomainSize
    rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
    norm_num
  · unfold idealAdaptiveRemainderRatio primitiveRemainderRatio globalSha512PreimageRatio
      sha512PreimageRatio totalSha512OracleExposuresFor honestProgramEventCount
      totalPoseidon2ExposuresFor poseidon2HonestEvaluationCount poseidon2EvaluationsPerProof
      poseidon2CollisionRatio poseidon2PreimageRatio
    apply CompositionRatio.add_scaled_bound_of_double
    · apply CompositionRatio.add_scaled_bound_of_double
      · apply CompositionRatio.add_scaled_bound_of_double
        · apply CompositionRatio.add_scaled_bound_of_double
          · rw [exact_analysis_history_proof_interactions]
            norm_num [sha512PreimageRatio, transcriptHashBits, decsDomainSize]
          · rw [exact_analysis_history_proof_interactions]
            unfold poseidon2DigestCardinality
            rw [exact_goldilocks_order]
            norm_num [poseidon2CollisionRatio]
        · rw [exact_analysis_history_proof_interactions]
          unfold poseidon2DigestCardinality
          rw [exact_goldilocks_order]
          norm_num [poseidon2PreimageRatio]
      · norm_num [ghhmAdaptiveProgrammingRatioAtQueryExponent,
          totalSha512OracleExposureExponentCeiling, conditionalFullTreeEntropyBits,
          analysisHistoryProofInteractions, consensusProofActionsPerBlock, analysisHistoryBlocks]
    · norm_num [ghhmAdaptiveProgrammingRatioAtQueryExponent, conditionalFullTreeEntropyBits,
        totalSha512OracleExposureExponentCeiling,
        fullDecsTreeProgrammingEvents, fullDecsTreeProgramsPerProof, decsDomainSize,
        analysisHistoryProofInteractions, consensusProofActionsPerBlock, analysisHistoryBlocks]

theorem conditional_combined_global_query_at_2pow143_is_not_below_half :
    ¬ (conditionalGlobalQueryFiniteHistoryWithIdealAdaptiveRatio 143).belowHalf := by
  apply CompositionRatio.add_not_below_half_of_left
  unfold globalIdealCmsRatio globalIdealCmsEnvelopeNumerator idealCmsEnvelopeDenominator
    totalSha512OracleExposuresFor honestProgramEventCount
    analysisHistoryProofInteractions consensusProofActionsPerBlock analysisHistoryBlocks
    transcriptHashBits decsDomainSize
  rw [exact_aggregate_error_numerator, exact_aggregate_error_denominator]
  norm_num

/-! ## Source-recorded lazy Merkle abstraction -/

def maximumLazyMerkleProgramsPerProof : Nat := maximumCompactAuthenticationNodes + 1
def maximumLazyLeafProgramsPerProof : Nat := openedLeafCount
def lazyLeafAndFinalProgramsPerProof : Nat := maximumLazyLeafProgramsPerProof + 1
def lazyInternalNodeProgramsPerProof : Nat := maximumCompactAuthenticationNodes
def lazyLeafAndFinalProgrammingEvents : Nat :=
  lazyLeafAndFinalProgramsPerProof * analysisHistoryProofInteractions
def lazyInternalNodeProgrammingEvents : Nat :=
  lazyInternalNodeProgramsPerProof * analysisHistoryProofInteractions
def lazyLeafAndFinalEntropyBits : Nat := 512
def lazyInternalNodeEntropyBits : Nat := 1024

def conditionalLazyLeafAndFinalProgrammingRatio : CompositionRatio :=
  ghhmFirstProgramRatio lazyLeafAndFinalEntropyBits lazyLeafAndFinalProgrammingEvents

def conditionalLazyInternalNodeProgrammingRatio : CompositionRatio :=
  ghhmFirstProgramRatio lazyInternalNodeEntropyBits lazyInternalNodeProgrammingEvents

def conditionalLazyCombinedProgrammingRatio : CompositionRatio :=
  conditionalLazyLeafAndFinalProgrammingRatio.add conditionalLazyInternalNodeProgrammingRatio

private theorem exact_lazy_wire_parameters :
    openedLeafCount = 20 ∧ maximumCompactAuthenticationNodes = 372 := by
  decide

/-- Exact arithmetic for the wire-neutral lazy record.  Internal nodes are deliberately
overcounted: all 372 compact nodes are charged at the ideal two-fresh-child 1024-bit entropy while
up to 20 leaf siblings plus final PIOP are charged separately at 512 bits. -/
theorem exact_lazy_programming_event_and_entropy_screen :
    maximumLazyMerkleProgramsPerProof = 373 ∧
      lazyLeafAndFinalProgrammingEvents = 44040192 ∧
      lazyInternalNodeProgrammingEvents = 780140544 ∧
      (conditionalLazyLeafAndFinalProgrammingRatio.strictlyBelowBits 197 ∧
        ¬ conditionalLazyLeafAndFinalProgrammingRatio.strictlyBelowBits 198) ∧
      (conditionalLazyInternalNodeProgrammingRatio.strictlyBelowBits 448 ∧
        ¬ conditionalLazyInternalNodeProgrammingRatio.strictlyBelowBits 449) ∧
      (conditionalLazyCombinedProgrammingRatio.strictlyBelowBits 197 ∧
        ¬ conditionalLazyCombinedProgrammingRatio.strictlyBelowBits 198) := by
  unfold maximumLazyMerkleProgramsPerProof conditionalLazyCombinedProgrammingRatio
    conditionalLazyLeafAndFinalProgrammingRatio conditionalLazyInternalNodeProgrammingRatio
    lazyLeafAndFinalProgrammingEvents lazyLeafAndFinalProgramsPerProof
    maximumLazyLeafProgramsPerProof lazyInternalNodeProgrammingEvents
    lazyInternalNodeProgramsPerProof
  rw [exact_analysis_history_proof_interactions, exact_lazy_wire_parameters.1,
    exact_lazy_wire_parameters.2]
  norm_num [
    lazyLeafAndFinalEntropyBits, lazyInternalNodeEntropyBits, ghhmFirstProgramRatio,
    ghhmAdaptiveProgrammingRatioAtQueryExponent, totalSha512OracleExposureExponentCeiling,
    analysisGlobalQueryExponent,
    CompositionRatio.add]

/-- Constructor-free all-points conditioning/refinement boundary. -/
inductive GhhmAdaptiveReprogrammingAppliesToAllExactSmz9TreePrograms : Prop

theorem ghhm_all_tree_program_points_applicability_is_unavailable :
    ¬ GhhmAdaptiveReprogrammingAppliesToAllExactSmz9TreePrograms := by
  intro applicability
  exact nomatch applicability

/-- Constructor-free applicability boundary for the direct GHHM route above. -/
inductive GhhmAdaptiveReprogrammingAppliesToExactSmz9FirstProgram : Prop

theorem ghhm_adaptive_reprogramming_applicability_is_unavailable :
    ¬ GhhmAdaptiveReprogrammingAppliesToExactSmz9FirstProgram := by
  intro applicability
  exact nomatch applicability

/-- Typed executable route choice: the lazy program table contains only role-framed Merkle
input/output records and the final PIOP point, never the diagnostic salt-only point above. -/
inductive ExecutableSmz9ProgramInventoryExcludesSaltOnlyFirstPoint : Prop

inductive ExactSmz9TranscriptRefinement : Prop
inductive ConcreteSha512QromReduction : Prop
inductive Poseidon2PrimitiveSecurity : Prop
inductive AdaptiveSmz9WholeViewCompleteZeroKnowledge : Prop
inductive ExecutableSimulatorRngToFreshLazyInputsRefinement : Prop
inductive AdaptiveLazyMerkleCompletionQromReduction : Prop
inductive ApprovedGlobalQuantumQueryAndHistoryBudget : Nat → Nat → Prop
inductive GlobalHistoryComposition : Prop
inductive IndependentComposedReview : Prop

theorem executable_rng_to_fresh_lazy_inputs_refinement_is_unavailable :
    ¬ ExecutableSimulatorRngToFreshLazyInputsRefinement := by
  intro refinement
  exact nomatch refinement

theorem adaptive_lazy_merkle_completion_qrom_reduction_is_unavailable :
    ¬ AdaptiveLazyMerkleCompletionQromReduction := by
  intro reduction
  exact nomatch reduction

structure DeployedSmz9QromPremises (Statement Witness : Type*) where
  exactCompiledRelationRefinement :
    Hegemon.Transaction.Poseidon2V8ConstraintRefinement.FullRelationCompilerRefinementReceipt
      Statement Witness
  exactSmz9TranscriptRefinement : ExactSmz9TranscriptRefinement
  exactSmz9IndexedLogicalOracleInstantiation :
    HeterogeneousCmsQrom.ExactSmz9IndexedLogicalOracleInstantiation
  sha512ToIndexedProductOracleReduction :
    HeterogeneousCmsQrom.Sha512ToIndexedProductOracleReduction
  concreteSha512QromReduction : ConcreteSha512QromReduction
  poseidon2PrimitiveSecurity : Poseidon2PrimitiveSecurity
  adaptiveWholeViewCompleteZeroKnowledge : AdaptiveSmz9WholeViewCompleteZeroKnowledge
  executableSimulatorRngToFreshLazyInputsRefinement :
    ExecutableSimulatorRngToFreshLazyInputsRefinement
  adaptiveLazyMerkleCompletionQromReduction : AdaptiveLazyMerkleCompletionQromReduction
  executableProgramInventoryExcludesSaltOnlyFirstPoint :
    ExecutableSmz9ProgramInventoryExcludesSaltOnlyFirstPoint
  ghhmAdaptiveAllTreeProgramPointsApplicability :
    GhhmAdaptiveReprogrammingAppliesToAllExactSmz9TreePrograms
  globalQuantumQueries : Nat
  globalProofInteractions : Nat
  globalBudgetApproved :
    ApprovedGlobalQuantumQueryAndHistoryBudget globalQuantumQueries globalProofInteractions
  globalHistoryComposition : GlobalHistoryComposition
  independentReview : IndependentComposedReview

theorem deployed_smz9_qrom_premises_are_unavailable
    (Statement Witness : Type*) :
    ¬ Nonempty (DeployedSmz9QromPremises Statement Witness) := by
  intro evidence
  rcases evidence with ⟨premises⟩
  exact
    (Hegemon.Transaction.Poseidon2V8ConstraintRefinement.full_relation_compiler_receipt_is_unavailable_from_checked_in_status
      Statement Witness) ⟨premises.exactCompiledRelationRefinement⟩

end V8Smz9QromAccounting
end SmallWood
end HegemonCrypto
