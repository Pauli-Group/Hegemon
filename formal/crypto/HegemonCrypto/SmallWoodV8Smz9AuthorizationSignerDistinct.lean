import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerPairDifferenceLookup
import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerPairScaledLookup
import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerPairInverseLookup
import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerPairMinusOneLookup
import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerPairRootLookup
import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerPairRootMember

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle
open HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonical
open HegemonCrypto.SmallWood.V8Smz9AuthorizationOrderTail
open HegemonCrypto.SmallWood.V8Smz9AuthorizationRoleNonzero
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem accepted_active_signer_first_words_distinct {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) {left right : Nat}
    (ordered : left < right)
    (rightActive : right < (projectAuthorization packed).current.signerCount) :
    wordAt ((projectAuthorization packed).policySignerTags.getD left []) 0 ≠
      wordAt ((projectAuthorization packed).policySignerTags.getD right []) 0 := by
  have signerBound := (accepted_non_single_signer_count_bounds accepted mode).2
  change _ ≤ 6 at signerBound
  have leftBound : left < 6 := by omega
  have rightBound : right < 6 := by omega
  have leftActive : left < (projectAuthorization packed).current.signerCount := by omega
  let pair := signerPairIndexLookup left right
  let activeNode := 1853 + 9 * pair
  let differenceNode := 1854 + 9 * pair
  let scaledNode := 1855 + 9 * pair
  let inverseProductNode := 1856 + 9 * pair
  let minusOneNode := 1857 + 9 * pair
  let root := 1858 + 9 * pair
  have activeExact : exactNonlinearExpressions[activeNode]? =
      some (signerPairActiveExpressionLookup left right) := by
    simpa only [activeNode, pair] using
      signer_pair_active_exact ordered leftBound rightBound
  have differenceExact : exactNonlinearExpressions[differenceNode]? =
      some (.sub (320 + 5 * left) (320 + 5 * right)) := by
    simpa only [differenceNode, pair] using
      signer_pair_difference_exact ordered leftBound rightBound
  have scaledExact : exactNonlinearExpressions[scaledNode]? = some (.mul 1234 activeNode) := by
    simpa only [scaledNode, activeNode, pair] using
      signer_pair_scaled_exact ordered leftBound rightBound
  have inverseProductExact : exactNonlinearExpressions[inverseProductNode]? =
      some (.mul (356 + pair) differenceNode) := by
    simpa only [inverseProductNode, differenceNode, pair] using
      signer_pair_inverse_exact ordered leftBound rightBound
  have minusOneExact : exactNonlinearExpressions[minusOneNode]? =
      some (.sub inverseProductNode 1) := by
    simpa only [minusOneNode, inverseProductNode, pair] using
      signer_pair_minus_one_exact ordered leftBound rightBound
  have rootExact : exactNonlinearExpressions[root]? = some (.mul scaledNode minusOneNode) := by
    simpa only [root, scaledNode, minusOneNode, pair] using
      signer_pair_root_exact ordered leftBound rightBound
  have rootMember : root ∈ exactNonlinearRoots := by
    simpa only [root, pair] using
      signer_pair_root_member ordered leftBound rightBound
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := root) (by decide) rootMember
  have gateOne := authorization_trace_gate_one accepted equations (Or.inr ⟨rfl, mode⟩)
  have leftSuffix := accepted_signer_suffix_trace equations leftBound
  have rightSuffix := accepted_signer_suffix_trace equations rightBound
  have leftSum := (accepted_signer_suffix_sum accepted mode leftBound).1 leftActive
  have rightSum := (accepted_signer_suffix_sum accepted mode rightBound).1 rightActive
  rw [leftSum, Nat.cast_one] at leftSuffix
  rw [rightSum, Nat.cast_one] at rightSuffix
  have activeValue := equations activeNode
    (signerPairActiveExpressionLookup left right) activeExact
  have leftTag := equations (320 + 5 * left) (.witnessRow (196 + 5 * left)) (by
    interval_cases left <;> decide)
  have rightTag := equations (320 + 5 * right) (.witnessRow (196 + 5 * right)) (by
    interval_cases right <;> decide)
  have difference := equations differenceNode
    (.sub (320 + 5 * left) (320 + 5 * right)) differenceExact
  have scaled := equations scaledNode (.mul 1234 activeNode) scaledExact
  have inverseProduct := equations inverseProductNode
    (.mul (356 + pair) differenceNode) inverseProductExact
  have one := equations 1 (.constant 1) (by decide)
  have minusOne := equations minusOneNode (.sub inverseProductNode 1) minusOneExact
  have rootValue := equations root (.mul scaledNode minusOneNode) rootExact
  have activeOne : (values.getD activeNode 0 : F) = 1 := by
    by_cases final : right = 5
    · have finalSuffix : (values.getD (signerSuffixNode 5) 0 : F) = 1 := by
        simpa only [final] using rightSuffix
      simpa only [signerPairActiveExpressionLookup, final, if_true, expressionField,
        leftSuffix, finalSuffix, one_mul] using activeValue
    · simpa only [signerPairActiveExpressionLookup, final, if_false, expressionField,
        leftSuffix, rightSuffix, one_mul] using activeValue
  simp only [expressionField,
    authorization_lane_zero_word packed (by omega : 196 + 5 * left < 686)] at leftTag
  simp only [expressionField,
    authorization_lane_zero_word packed (by omega : 196 + 5 * right < 686)] at rightTag
  simp only [expressionField, leftTag, rightTag] at difference
  simp only [expressionField, gateOne, activeOne, one_mul] at scaled
  simp only [expressionField, difference] at inverseProduct
  simp only [expressionField, Nat.cast_one] at one
  simp only [expressionField, inverseProduct, one] at minusOne
  simp only [expressionField, scaled, minusOne, one_mul] at rootValue
  have inverseEquation :
      (values.getD (356 + pair) 0 : F) *
        ((authorizationRawWord packed (196 + 5 * left) : F) -
          (authorizationRawWord packed (196 + 5 * right) : F)) = 1 := by
    exact sub_eq_zero.mp (rootValue.symm.trans rootZero)
  rw [project_authorization_signer_tag packed leftBound,
    project_authorization_signer_tag packed rightBound]
  simp [authorizationRawSignerTag, wordAt, List.getD_eq_getElem?_getD]
  intro equal
  rw [equal, sub_self, mul_zero] at inverseEquation
  exact zero_ne_one inverseEquation

end HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints
