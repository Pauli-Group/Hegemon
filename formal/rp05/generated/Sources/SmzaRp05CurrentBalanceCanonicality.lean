import SmzaRp04BalanceCore

/-! Public-layout projections needed by RP05 balance transport, generalized
over the selected primitive record. These facts inspect only the public
statement layout and balance/compatibility fields; action-intent semantics are
not equated with the historical primitive. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentBalanceCanonicality

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open scoped Classical

set_option autoImplicit false

theorem admitted_public_lengths_for {primitives : V8SemanticPrimitives}
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement primitives statement) :
    statement.inputFlags.length = 2 ∧ statement.outputFlags.length = 2 ∧
      statement.nullifiers.flatten.length = 14 ∧
      statement.commitments.flatten.length = 14 ∧
      statement.ciphertextCommitments.flatten.length = 12 ∧
      statement.merkleRoot.length = 7 ∧ statement.balanceAssets.length = 4 := by
  rcases canonical with ⟨inputLength, outputLength, _, _, nullifierLength,
    nullifierWords, commitmentLength, commitmentWords, ciphertextLength,
    ciphertextWords, _, _, _, rootWords, assets, _⟩
  have nullifierFlat := flatten_length_uniform 7 statement.nullifiers
    (by intro words member; exact (nullifierWords words member).1)
  have commitmentFlat := flatten_length_uniform 7 statement.commitments
    (by intro words member; exact (commitmentWords words member).1)
  have ciphertextFlat := flatten_length_uniform 6 statement.ciphertextCommitments
    (by intro words member; exact (ciphertextWords words member).1)
  refine ⟨inputLength, outputLength, ?_, ?_, ?_, rootWords.1, assets.1⟩
  · simpa only [nullifierLength, inputCount] using nullifierFlat
  · simpa only [commitmentLength, outputCount] using commitmentFlat
  · simpa only [ciphertextLength, outputCount] using ciphertextFlat

theorem encoded_input_flag_for {primitives : V8SemanticPrimitives}
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement primitives statement)
    {input : Nat} (bound : input < 2) :
    (encodePublicStatement statement).getD input 0 = flagAt statement.inputFlags input := by
  have inputBound : input < statement.inputFlags.length := by
    rw [(admitted_public_lengths_for statement canonical).1]
    exact bound
  simp only [encodePublicStatement, List.append_assoc]
  rw [List.getD_append _ _ _ _ inputBound]
  rfl

theorem encoded_output_flag_for {primitives : V8SemanticPrimitives}
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement primitives statement)
    {output : Nat} (bound : output < 2) :
    (encodePublicStatement statement).getD (2 + output) 0 =
      flagAt statement.outputFlags output := by
  have lengths := admitted_public_lengths_for statement canonical
  have outputBound : output < statement.outputFlags.length := by omega
  simp only [encodePublicStatement, List.append_assoc]
  rw [List.getD_append_right _ _ _ _ (by omega), lengths.1]
  simp only [Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ outputBound]
  rfl

theorem encoded_balance_asset_for {primitives : V8SemanticPrimitives}
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement primitives statement)
    {slot : Nat} (bound : slot < 4) :
    (encodePublicStatement statement).getD (54 + slot) 0 =
      wordAt statement.balanceAssets slot := by
  obtain ⟨inputLength, outputLength, nullifierLength, commitmentLength,
    ciphertextLength, rootLength, assetLength⟩ :=
    admitted_public_lengths_for statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags ++
    statement.nullifiers.flatten ++ statement.commitments.flatten ++
    statement.ciphertextCommitments.flatten ++
    [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
    statement.merkleRoot
  have prefixLength : publicPrefix.length = 54 := by
    simp [publicPrefix, inputLength, outputLength, nullifierLength,
      commitmentLength, ciphertextLength, rootLength]
  have encoded : encodePublicStatement statement = publicPrefix ++
      (statement.balanceAssets ++
        (encodeCompatibility statement.compatibility ++
          [statement.version, statement.cryptoSuite] ++
          encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  simp only [Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ (by omega)]
  rfl

theorem encoded_balance_scalar_for {primitives : V8SemanticPrimitives}
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement primitives statement)
    {index : Nat} (bound : index < 3) :
    (encodePublicStatement statement).getD (44 + index) 0 =
      [statement.fee, statement.valueBalanceSign,
        statement.valueBalanceMagnitude].getD index 0 := by
  obtain ⟨inputLength, outputLength, nullifierLength, commitmentLength,
    ciphertextLength, _, _⟩ := admitted_public_lengths_for statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags ++
    statement.nullifiers.flatten ++ statement.commitments.flatten ++
    statement.ciphertextCommitments.flatten
  have prefixLength : publicPrefix.length = 44 := by
    simp [publicPrefix, inputLength, outputLength, nullifierLength,
      commitmentLength, ciphertextLength]
  have encoded : encodePublicStatement statement = publicPrefix ++
      ([statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
        (statement.merkleRoot ++ statement.balanceAssets ++
          encodeCompatibility statement.compatibility ++
          [statement.version, statement.cryptoSuite] ++
          encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  simp only [Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ (by simpa only [List.length_cons, List.length_nil] using bound)]

theorem encoded_compatibility_scalar_for {primitives : V8SemanticPrimitives}
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement primitives statement)
    {index : Nat} (bound : index < 5) :
    (encodePublicStatement statement).getD (58 + index) 0 =
      [statement.compatibility.enabled, statement.compatibility.assetId,
        statement.compatibility.policyVersion, statement.compatibility.issuanceSign,
        statement.compatibility.issuanceMagnitude].getD index 0 := by
  obtain ⟨inputLength, outputLength, nullifierLength, commitmentLength,
    ciphertextLength, rootLength, assetLength⟩ :=
    admitted_public_lengths_for statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags ++
    statement.nullifiers.flatten ++ statement.commitments.flatten ++
    statement.ciphertextCommitments.flatten ++
    [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
    statement.merkleRoot ++ statement.balanceAssets
  have prefixLength : publicPrefix.length = 58 := by
    simp [publicPrefix, inputLength, outputLength, nullifierLength,
      commitmentLength, ciphertextLength, rootLength, assetLength]
  have encoded : encodePublicStatement statement = publicPrefix ++
      ([statement.compatibility.enabled, statement.compatibility.assetId,
        statement.compatibility.policyVersion, statement.compatibility.issuanceSign,
        statement.compatibility.issuanceMagnitude] ++
        (statement.compatibility.reservedLegacyCommitments.flatten ++
          [statement.version, statement.cryptoSuite] ++
          encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement, encodeCompatibility, publicPrefix,
      List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  simp only [Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ (by simpa only [List.length_cons, List.length_nil] using bound)]

theorem admitted_input_flag_one_for {primitives : V8SemanticPrimitives}
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement primitives statement)
    {input : Nat} (bound : input < 2)
    (active : flagAt statement.inputFlags input ≠ 0) :
    flagAt statement.inputFlags input = 1 := by
  have inputBound : input < statement.inputFlags.length := by
    rw [(admitted_public_lengths_for statement canonical).1]
    exact bound
  have member : flagAt statement.inputFlags input ∈ statement.inputFlags := by
    simp [flagAt, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem inputBound]
  rcases canonical with ⟨_, _, inputBoolean, _, _, _, _, _, _, _, _, _, _, _, _, _⟩
  rcases inputBoolean _ member with zero | one
  · exact False.elim (active zero)
  · exact one

theorem admitted_output_flag_one_for {primitives : V8SemanticPrimitives}
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement primitives statement)
    {output : Nat} (bound : output < 2)
    (active : flagAt statement.outputFlags output ≠ 0) :
    flagAt statement.outputFlags output = 1 := by
  have outputBound : output < statement.outputFlags.length := by
    rw [(admitted_public_lengths_for statement canonical).2.1]
    exact bound
  have member : flagAt statement.outputFlags output ∈ statement.outputFlags := by
    simp [flagAt, List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem outputBound]
  rcases canonical with ⟨_, _, _, outputBoolean, _, _, _, _, _, _, _, _, _, _, _, _⟩
  rcases outputBoolean _ member with zero | one
  · exact False.elim (active zero)
  · exact one

end HegemonCrypto.SmallWood.SmzaRp05CurrentBalanceCanonicality
