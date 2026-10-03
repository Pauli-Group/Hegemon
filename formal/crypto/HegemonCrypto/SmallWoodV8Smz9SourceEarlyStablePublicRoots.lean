import HegemonCrypto.SmallWoodV8Smz9SourceEarlyPublicBooleans
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoin

namespace HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem exact_stable_public_root_indices :
    (exactNonlinearRoots.drop 7).take 6 = [827,835,836,837,838,839] := by decide

theorem canonical_compatibility_links (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    statement.compatibility.assetId = statement.stablecoin.assetId ∧
    statement.compatibility.policyVersion = statement.stablecoin.policyVersion ∧
    statement.compatibility.issuanceMagnitude = statement.stablecoin.magnitude ∧
    statement.compatibility.enabled = (if statement.stablecoin.direction = .disabled then 0 else 1) ∧
    statement.compatibility.issuanceSign = (if statement.stablecoin.direction = .mint then 1 else 0) := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,compatibility,_⟩ := canonical
  cases mode : statement.stablecoin.direction <;>
    simp [CanonicalCompatibility,mode] at compatibility ⊢ <;> omega

noncomputable section

def stableDirectionField (pub : Nat → F) : F := pub 83
def stableEnabledPolynomial (pub : Nat → F) : F := (2 : F)⁻¹ * (pub 83 * (3 - pub 83))
def stableMintPolynomial (pub : Nat → F) : F := pub 83 * (2 - pub 83)

theorem actual_stable_direction_terms (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 827 = pub 83 * (pub 83 - 1) * (pub 83 - 2) ∧
    fieldAt exactNonlinearExpressions pub rows 832 = stableEnabledPolynomial pub ∧
    fieldAt exactNonlinearExpressions pub rows 834 = stableMintPolynomial pub := by
  have one := (actual_source_constants pub rows).2.1
  have two := actual_node_field_equation pub rows (node := 2) (expression := .constant 2) (by decide)
  have three := actual_node_field_equation pub rows (node := 829) (expression := .constant 3) (by decide)
  have direction := actual_source_public pub rows (index := 83) (by decide)
  have n824 := actual_node_field_equation pub rows (node := 824) (expression := .sub 87 1) (by decide)
  have n825 := actual_node_field_equation pub rows (node := 825) (expression := .sub 87 2) (by decide)
  have n826 := actual_node_field_equation pub rows (node := 826) (expression := .mul 87 824) (by decide)
  have n827 := actual_node_field_equation pub rows (node := 827) (expression := .mul 825 826) (by decide)
  have n828 := actual_node_field_equation pub rows (node := 828) (expression := .inverse 2) (by decide)
  have n830 := actual_node_field_equation pub rows (node := 830) (expression := .sub 829 87) (by decide)
  have n831 := actual_node_field_equation pub rows (node := 831) (expression := .mul 87 830) (by decide)
  have n832 := actual_node_field_equation pub rows (node := 832) (expression := .mul 828 831) (by decide)
  have n833 := actual_node_field_equation pub rows (node := 833) (expression := .sub 2 87) (by decide)
  have n834 := actual_node_field_equation pub rows (node := 834) (expression := .mul 87 833) (by decide)
  simp only [expressionField,Nat.cast_ofNat,source_inverse_cast] at two three n824 n825 n826 n827 n828 n830 n831 n832 n833 n834
  rw [direction,one] at n824
  rw [direction,two] at n825
  rw [direction,n824] at n826
  rw [n825,n826] at n827
  rw [two] at n828
  rw [three,direction] at n830
  rw [direction,n830] at n831
  rw [n828,n831] at n832
  rw [two,direction] at n833
  rw [direction,n833] at n834
  exact ⟨n827.trans (by ring),n832,n834⟩

theorem actual_stable_compatibility_root_formulas (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 835 = pub 58 - stableEnabledPolynomial pub ∧
    fieldAt exactNonlinearExpressions pub rows 836 = pub 61 - stableMintPolynomial pub ∧
    fieldAt exactNonlinearExpressions pub rows 837 = pub 59 - pub 84 ∧
    fieldAt exactNonlinearExpressions pub rows 838 = pub 60 - pub 85 ∧
    fieldAt exactNonlinearExpressions pub rows 839 = pub 62 - pub 86 := by
  have terms := actual_stable_direction_terms pub rows
  have n835 := actual_node_field_equation pub rows (node := 835) (expression := .sub 62 832) (by decide)
  have n836 := actual_node_field_equation pub rows (node := 836) (expression := .sub 65 834) (by decide)
  have n837 := actual_node_field_equation pub rows (node := 837) (expression := .sub 63 88) (by decide)
  have n838 := actual_node_field_equation pub rows (node := 838) (expression := .sub 64 89) (by decide)
  have n839 := actual_node_field_equation pub rows (node := 839) (expression := .sub 66 90) (by decide)
  simp only [expressionField] at n835 n836 n837 n838 n839
  have p58 : fieldAt exactNonlinearExpressions pub rows 62 = pub 58 := actual_source_public pub rows (index := 58) (by decide)
  have p59 : fieldAt exactNonlinearExpressions pub rows 63 = pub 59 := actual_source_public pub rows (index := 59) (by decide)
  have p60 : fieldAt exactNonlinearExpressions pub rows 64 = pub 60 := actual_source_public pub rows (index := 60) (by decide)
  have p61 : fieldAt exactNonlinearExpressions pub rows 65 = pub 61 := actual_source_public pub rows (index := 61) (by decide)
  have p62 : fieldAt exactNonlinearExpressions pub rows 66 = pub 62 := actual_source_public pub rows (index := 62) (by decide)
  have p84 : fieldAt exactNonlinearExpressions pub rows 88 = pub 84 := actual_source_public pub rows (index := 84) (by decide)
  have p85 : fieldAt exactNonlinearExpressions pub rows 89 = pub 85 := actual_source_public pub rows (index := 85) (by decide)
  have p86 : fieldAt exactNonlinearExpressions pub rows 90 = pub 86 := actual_source_public pub rows (index := 86) (by decide)
  rw [p58,terms.2.1] at n835
  rw [p61,terms.2.2] at n836
  rw [p59,p84] at n837
  rw [p60,p85] at n838
  rw [p62,p86] at n839
  exact ⟨n835,n836,n837,n838,n839⟩

theorem encoded_stable_direction_field (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    encodedPublicField statement 83 = (statement.stablecoin.direction.word : F) := by
  have encoded := encoded_stable_public_word statement canonical 0
  change (encodePublicStatement statement).getD 83 0 = statement.stablecoin.direction.word at encoded
  exact congrArg (fun n : Nat => (n : F)) encoded

theorem canonical_stable_enabled_and_mint (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    stableEnabledPolynomial (encodedPublicField statement) = (statement.compatibility.enabled : F) ∧
    stableMintPolynomial (encodedPublicField statement) = (statement.compatibility.issuanceSign : F) := by
  have links := canonical_compatibility_links statement canonical
  unfold stableEnabledPolynomial stableMintPolynomial
  rw [encoded_stable_direction_field statement canonical,links.2.2.2.1,links.2.2.2.2]
  cases statement.stablecoin.direction <;>
    norm_num [StableDirection.word,show StableDirection.disabled ≠ .mint by decide,
      show StableDirection.mint ≠ .disabled by decide,show StableDirection.burn ≠ .disabled by decide,
      show StableDirection.burn ≠ .mint by decide,inv_mul_cancel₀ (by decide : (2 : F) ≠ 0)]

theorem canonical_stable_public_roots_zero (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) (rows : Nat → F) :
    fieldAt exactNonlinearExpressions (encodedPublicField statement) rows 827 = 0 ∧
    fieldAt exactNonlinearExpressions (encodedPublicField statement) rows 835 = 0 ∧
    fieldAt exactNonlinearExpressions (encodedPublicField statement) rows 836 = 0 ∧
    fieldAt exactNonlinearExpressions (encodedPublicField statement) rows 837 = 0 ∧
    fieldAt exactNonlinearExpressions (encodedPublicField statement) rows 838 = 0 ∧
    fieldAt exactNonlinearExpressions (encodedPublicField statement) rows 839 = 0 := by
  have direction := actual_stable_direction_terms (encodedPublicField statement) rows
  have roots := actual_stable_compatibility_root_formulas (encodedPublicField statement) rows
  have links := canonical_compatibility_links statement canonical
  have flags := canonical_stable_enabled_and_mint statement canonical
  have p58 := encoded_compatibility_scalar statement canonical (index := 0) (by decide)
  have p59 := encoded_compatibility_scalar statement canonical (index := 1) (by decide)
  have p60 := encoded_compatibility_scalar statement canonical (index := 2) (by decide)
  have p61 := encoded_compatibility_scalar statement canonical (index := 3) (by decide)
  have p62 := encoded_compatibility_scalar statement canonical (index := 4) (by decide)
  have p84 := encoded_stable_public_word statement canonical 1
  have p85 := encoded_stable_public_word statement canonical 2
  have p86 := encoded_stable_public_word statement canonical 3
  change (encodePublicStatement statement).getD 58 0 = statement.compatibility.enabled at p58
  change (encodePublicStatement statement).getD 59 0 = statement.compatibility.assetId at p59
  change (encodePublicStatement statement).getD 60 0 = statement.compatibility.policyVersion at p60
  change (encodePublicStatement statement).getD 61 0 = statement.compatibility.issuanceSign at p61
  change (encodePublicStatement statement).getD 62 0 = statement.compatibility.issuanceMagnitude at p62
  change (encodePublicStatement statement).getD 84 0 = statement.stablecoin.assetId at p84
  change (encodePublicStatement statement).getD 85 0 = statement.stablecoin.policyVersion at p85
  change (encodePublicStatement statement).getD 86 0 = statement.stablecoin.magnitude at p86
  refine ⟨?_,?_,?_,?_,?_,?_⟩
  · rw [direction.1,encoded_stable_direction_field statement canonical]
    cases statement.stablecoin.direction <;> norm_num [StableDirection.word]
  · rw [roots.1,flags.1]
    simp only [encodedPublicField,p58,sub_self]
  · rw [roots.2.1,flags.2]
    simp only [encodedPublicField,p61,sub_self]
  · rw [roots.2.2.1]
    simp only [encodedPublicField,p59,p84,links.1,sub_self]
  · rw [roots.2.2.2.1]
    simp only [encodedPublicField,p60,p85,links.2.1,sub_self]
  · rw [roots.2.2.2.2]
    simp only [encodedPublicField,p62,p86,links.2.2.1,sub_self]

theorem full_candidate_stable_public_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (slot : Fin 6) :
    (exactNonlinearRoots[7 + slot.val]?).map
      (fieldAt exactNonlinearExpressions (encodedPublicField statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  have all := canonical_stable_public_roots_zero statement valid.1
    (laneField (fullTypedSourceCandidate statement witness) lane.val)
  have indices : ∀ s : Fin 6, exactNonlinearRoots[7 + s.val]? =
      [827,835,836,837,838,839][s.val]? := by decide
  rw [indices slot]
  fin_cases slot <;> simp_all










end
end HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
