import HegemonCrypto.SmallWoodV8Smz9SourceEarlyStablePublicRoots

namespace HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem zero_words_getD (words : List Nat) (zero : ZeroWords words) (index : Nat) :
    words.getD index 0 = 0 := by
  cases found : words[index]? with
  | none => simp only [List.getD_eq_getElem?_getD,found,Option.getD_none]
  | some value =>
      have valueZero := zero value (List.mem_of_getElem? found)
      simp only [List.getD_eq_getElem?_getD,found,Option.getD_some,valueZero]

theorem canonical_encoded_reserved_zero (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) (slot : Fin 18) :
    (encodePublicStatement statement).getD (63 + slot.val) 0 = 0 := by
  obtain ⟨inputLength,outputLength,nullifierLength,commitmentLength,ciphertextLength,rootLength,assetLength⟩ :=
    admitted_public_lengths statement canonical
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,compatibility,_⟩ := canonical
  obtain ⟨_,_,_,legacyLength,legacyWords,_⟩ := compatibility
  have legacyFlat := flatten_length_uniform 6 statement.compatibility.reservedLegacyCommitments
    (by intro words member; exact (legacyWords words member).1.1)
  have legacyFlatLength : statement.compatibility.reservedLegacyCommitments.flatten.length = 18 := by
    simpa only [legacyLength] using legacyFlat
  have flatZero : ZeroWords statement.compatibility.reservedLegacyCommitments.flatten := by
    intro value member
    obtain ⟨words,wordsMember,valueMember⟩ := List.mem_flatten.mp member
    exact (legacyWords words wordsMember).2 value valueMember
  let leading := statement.inputFlags ++ statement.outputFlags ++ statement.nullifiers.flatten ++
    statement.commitments.flatten ++ statement.ciphertextCommitments.flatten ++
    [statement.fee,statement.valueBalanceSign,statement.valueBalanceMagnitude] ++
    statement.merkleRoot ++ statement.balanceAssets ++
    [statement.compatibility.enabled,statement.compatibility.assetId,statement.compatibility.policyVersion,
      statement.compatibility.issuanceSign,statement.compatibility.issuanceMagnitude]
  have leadingLength : leading.length = 63 := by
    simp [leading,inputLength,outputLength,nullifierLength,commitmentLength,ciphertextLength,rootLength,assetLength]
  have encoded : encodePublicStatement statement = leading ++
      (statement.compatibility.reservedLegacyCommitments.flatten ++
        ([statement.version,statement.cryptoSuite] ++ encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement,encodeCompatibility,leading,List.append_assoc]
  rw [encoded,List.getD_append_right _ _ _ _ (by omega),leadingLength,Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ (by omega : slot.val < statement.compatibility.reservedLegacyCommitments.flatten.length)]
  exact zero_words_getD _ flatZero slot.val

theorem exact_reserved_root_identity (slot : Fin 18) :
    exactNonlinearRoots[13 + slot.val]? = some (67 + slot.val) ∧
    exactNonlinearIdentities[13 + slot.val]? =
      some ⟨1025,[13 + slot.val,slot.val,0,0],"base.reserved_compatibility_zero"⟩ := by
  have finite : ∀ s : Fin 18, exactNonlinearRoots[13 + s.val]? = some (67 + s.val) ∧
      exactNonlinearIdentities[13 + s.val]? =
        some ⟨1025,[13 + s.val,s.val,0,0],"base.reserved_compatibility_zero"⟩ := by decide
  exact finite slot

noncomputable section

theorem actual_reserved_root_formula (pub rows : Nat → F) (slot : Fin 18) :
    fieldAt exactNonlinearExpressions pub rows (67 + slot.val) = pub (63 + slot.val) := by
  have source := actual_source_public pub rows (index := 63 + slot.val) (by omega)
  rw [show 4 + (63 + slot.val) = 67 + slot.val by omega] at source
  exact source

theorem full_candidate_reserved_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (slot : Fin 18) :
    (exactNonlinearRoots[13 + slot.val]?).map
      (fieldAt exactNonlinearExpressions (encodedPublicField statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [(exact_reserved_root_identity slot).1,Option.map_some,actual_reserved_root_formula]
  simp only [encodedPublicField,canonical_encoded_reserved_zero statement valid.1 slot,Nat.cast_zero]

theorem reserved_one_negative_control (rows : Nat → F) :
    fieldAt exactNonlinearExpressions (fun _ => 1) rows 67 = 1 := by
  exact actual_reserved_root_formula _ rows (⟨0,by decide⟩ : Fin 18)








end
end HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
