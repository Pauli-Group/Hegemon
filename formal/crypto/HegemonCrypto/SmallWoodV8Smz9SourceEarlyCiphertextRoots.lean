import HegemonCrypto.SmallWoodV8Smz9SourceEarlyPathRoots
import HegemonCrypto.SmallWoodV8Smz9SourceEarlyReservedRoots

namespace HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem canonical_encoded_ciphertext_word (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    (output : Fin 2) (limb : Fin 6) :
    (encodePublicStatement statement).getD (32 + output.val * 6 + limb.val) 0 =
      (statement.ciphertextCommitments.getD output.val []).getD limb.val 0 := by
  obtain ⟨inputLength,outputLength,nullifierLength,commitmentLength,ciphertextLength,_,_⟩ :=
    admitted_public_lengths statement canonical
  have shape := canonical.2.2.2.2.2.2.2.2.1
  have words := canonical.2.2.2.2.2.2.2.2.2.1
  let leading := statement.inputFlags ++ statement.outputFlags ++ statement.nullifiers.flatten ++
    statement.commitments.flatten
  have leadingLength : leading.length = 32 := by
    simp [leading,inputLength,outputLength,nullifierLength,commitmentLength]
  have encoded : encodePublicStatement statement = leading ++
      (statement.ciphertextCommitments.flatten ++
        ([statement.fee,statement.valueBalanceSign,statement.valueBalanceMagnitude] ++
          statement.merkleRoot ++ statement.balanceAssets ++ encodeCompatibility statement.compatibility ++
          [statement.version,statement.cryptoSuite] ++ encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement,leading,List.append_assoc]
  rw [encoded,List.getD_append_right _ _ _ _ (by omega),leadingLength]
  have offset : 32 + output.val * 6 + limb.val - 32 = output.val * 6 + limb.val := by omega
  rw [offset,List.getD_append _ _ _ _ (by omega : output.val * 6 + limb.val < statement.ciphertextCommitments.flatten.length)]
  obtain ⟨left,right,ciphertexts⟩ := List.length_eq_two.mp shape
  have leftLength : left.length = 6 := (words left (by simp [ciphertexts])).1
  have rightLength : right.length = 6 := (words right (by simp [ciphertexts])).1
  rw [ciphertexts]
  fin_cases output
  · simp only [List.flatten_cons,List.flatten_nil,List.append_nil,List.getD_cons_zero,Nat.zero_mul,Nat.zero_add]
    rw [List.getD_append _ _ _ _ (by omega : limb.val < left.length)]
  · simp only [List.flatten_cons,List.flatten_nil,List.append_nil,List.getD_cons_succ,List.getD_cons_zero,Nat.one_mul]
    rw [List.getD_append_right _ _ _ _ (by omega),leftLength,Nat.add_sub_cancel_left]

theorem canonical_inactive_ciphertext_zero (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    (output : Fin 2) (limb : Fin 6) :
    flagAt statement.outputFlags output.val = 0 →
      (encodePublicStatement statement).getD (32 + output.val * 6 + limb.val) 0 = 0 := by
  intro inactive
  rw [canonical_encoded_ciphertext_word statement canonical output limb]
  have facts := canonical
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,slots,_⟩ := facts
  rcases (slots output.val output.isLt).2 with zero | active
  · exact zero_words_getD _ zero.2.2 limb.val
  · omega

def ciphertextRootIndex (output limb : Nat) : Nat := if output = 0 then 98 + limb else 105 + limb
def ciphertextRootNode (output limb : Nat) : Nat := if output = 0 then 1006 + limb else 1025 + limb
def ciphertextInactiveNode (output : Nat) : Nat := if output = 0 then 1005 else 1024
def ciphertextSourceRow (output limb : Nat) : Nat := 70 + 12 * output + limb

theorem exact_ciphertext_root_nodes (output : Fin 2) (limb : Fin 6) :
    exactNonlinearExpressions[ciphertextInactiveNode output.val]? = some (.sub 1 (6 + output.val)) ∧
    exactNonlinearExpressions[124 + ciphertextSourceRow output.val limb.val]? =
      some (.witnessRow (ciphertextSourceRow output.val limb.val)) ∧
    exactNonlinearExpressions[ciphertextRootNode output.val limb.val]? =
      some (.mul (124 + ciphertextSourceRow output.val limb.val) (ciphertextInactiveNode output.val)) ∧
    exactNonlinearRoots[ciphertextRootIndex output.val limb.val]? =
      some (ciphertextRootNode output.val limb.val) := by
  have finite : ∀ o : Fin 2, ∀ l : Fin 6,
      exactNonlinearExpressions[ciphertextInactiveNode o.val]? = some (.sub 1 (6 + o.val)) ∧
      exactNonlinearExpressions[124 + ciphertextSourceRow o.val l.val]? = some (.witnessRow (ciphertextSourceRow o.val l.val)) ∧
      exactNonlinearExpressions[ciphertextRootNode o.val l.val]? = some (.mul (124 + ciphertextSourceRow o.val l.val) (ciphertextInactiveNode o.val)) ∧
      exactNonlinearRoots[ciphertextRootIndex o.val l.val]? = some (ciphertextRootNode o.val l.val) := by decide
  exact finite output limb

noncomputable section

theorem actual_ciphertext_root_formula (pub rows : Nat → F) (output : Fin 2) (limb : Fin 6) :
    fieldAt exactNonlinearExpressions pub rows (ciphertextRootNode output.val limb.val) =
      rows (ciphertextSourceRow output.val limb.val) * (1 - pub (2 + output.val)) := by
  obtain ⟨inactiveNode,sourceNode,rootNode,_⟩ := exact_ciphertext_root_nodes output limb
  have one := (actual_source_constants pub rows).2.1
  have flag := actual_source_public pub rows (index := 2 + output.val) (by omega)
  rw [show 4 + (2 + output.val) = 6 + output.val by omega] at flag
  have inactive := actual_node_field_equation pub rows inactiveNode
  have source := actual_node_field_equation pub rows sourceNode
  have root := actual_node_field_equation pub rows rootNode
  simp only [expressionField] at inactive source root
  rw [one,flag] at inactive
  rw [source,inactive] at root
  exact root

theorem full_candidate_ciphertext_source_readback (statement : V8PublicStatement) (witness : V8Witness)
    (output : Fin 2) (limb : Fin 6) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val (ciphertextSourceRow output.val limb.val) =
      encodedPublicField statement (32 + output.val * 6 + limb.val) := by
  rw [full_candidate_raw_field_readback statement witness
    (⟨ciphertextSourceRow output.val limb.val,by unfold ciphertextSourceRow; omega⟩ : Fin 92) lane]
  change (sourceWord statement witness (ciphertextSourceRow output.val limb.val) : F) = _
  have address : ciphertextSourceRow output.val limb.val = 68 + 12 * output.val + (2 + limb.val) := by
    unfold ciphertextSourceRow
    omega
  rw [address,source_output_word statement witness output.val (2 + limb.val) output.isLt (by omega)]
  simp only [outputWord,if_neg (by omega : ¬2 + limb.val = 0),
    if_neg (by omega : ¬2 + limb.val = 1),if_pos (by omega : 2 + limb.val < 8),
    Nat.add_sub_cancel_left,encodedPublicField]

theorem full_candidate_inactive_ciphertext_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (output : Fin 2) (limb : Fin 6) :
    (exactNonlinearRoots[ciphertextRootIndex output.val limb.val]?).map
      (fieldAt exactNonlinearExpressions (encodedPublicField statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [(exact_ciphertext_root_nodes output limb).2.2.2,Option.map_some,actual_ciphertext_root_formula,
    full_candidate_ciphertext_source_readback]
  have flag := encoded_output_flag statement valid.1 output.isLt
  have boolean := V8Smz9SourceTailRolesCanonical.boolean_getD statement.outputFlags valid.1.2.2.2.1 output.val
  change BooleanWord (flagAt statement.outputFlags output.val) at boolean
  rcases boolean with inactive | active
  · simp only [encodedPublicField,canonical_inactive_ciphertext_zero statement valid.1 output limb inactive,
      Nat.cast_zero,zero_mul]
  · simp only [encodedPublicField,flag,active,Nat.cast_one,sub_self,mul_zero]








end
end HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
