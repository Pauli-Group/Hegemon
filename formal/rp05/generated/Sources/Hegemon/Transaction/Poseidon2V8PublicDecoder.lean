import Hegemon.Transaction.Poseidon2V8SemanticSpecification

/-!
# Exact HGV8RP03 public-statement decoder

The executable HGV8RP03 program receives 120 public Goldilocks words.  This
module gives that fixed layout a typed inverse.  It is deliberately only a
layout decoder: proving that an accepted executable program makes the decoded
statement canonical and semantically valid is a separate refinement theorem.
-/

namespace Hegemon
namespace Transaction
namespace Poseidon2V8PublicDecoder

open Poseidon2V8SemanticSpecification

def decodeStableDirection? : Nat → Option StableDirection
  | 0 => some .disabled
  | 1 => some .mint
  | 2 => some .burn
  | _ => none

theorem decode_stable_direction_word (direction : StableDirection) :
    decodeStableDirection? direction.word = some direction := by
  cases direction <;> rfl

private def slice (words : List Nat) (offset count : Nat) : List Nat :=
  (words.drop offset).take count

/--
Decode the exact 120-word layout used by
`SmallwoodPoseidon2V8PublicStatement::to_public_words`.

Only the total length and the three-valued stablecoin direction are structural
decode conditions.  Field canonicality and the transaction invariants belong
to `CanonicalPublicStatement` and the executable relation, not to this parser.
-/
def decodePublicStatement? (words : List Nat) : Option V8PublicStatement := do
  if words.length = publicWordCount then
    let direction ← decodeStableDirection? (words.getD 83 3)
    some
      { inputFlags := slice words 0 2
        outputFlags := slice words 2 2
        nullifiers := [slice words 4 7, slice words 11 7]
        commitments := [slice words 18 7, slice words 25 7]
        ciphertextCommitments := [slice words 32 6, slice words 38 6]
        fee := words.getD 44 0
        valueBalanceSign := words.getD 45 0
        valueBalanceMagnitude := words.getD 46 0
        merkleRoot := slice words 47 7
        balanceAssets := slice words 54 4
        compatibility :=
          { enabled := words.getD 58 0
            assetId := words.getD 59 0
            policyVersion := words.getD 60 0
            issuanceSign := words.getD 61 0
            issuanceMagnitude := words.getD 62 0
            reservedLegacyCommitments :=
              [slice words 63 6, slice words 69 6, slice words 75 6] }
        version := words.getD 81 0
        cryptoSuite := words.getD 82 0
        stablecoin :=
          { direction
            assetId := words.getD 84 0
            policyVersion := words.getD 85 0
            magnitude := words.getD 86 0
            actionIntent := slice words 87 7
            parentHeight := words.getD 94 0
            beforeRoot := slice words 95 7
            afterRoot := slice words 102 7
            after :=
              { epochId := words.getD 109 0
                mintedInEpoch := words.getD 110 0
                totalDebt := words.getD 111 0
                sequence := words.getD 112 0 }
            issuerAuthorization := slice words 113 7 } }
  else
    none

theorem exact_public_offsets_cover_the_wire :
    2 + 2 + 2 * 7 + 2 * 7 + 2 * 6 + 3 + 7 + 4 + (5 + 3 * 6) + 2 +
      (4 + 7 + 1 + 7 + 7 + 4 + 7) = publicWordCount := by
  decide

private theorem pair_of_length_two {α : Type} (values : List α)
    (lengthExact : values.length = 2) :
    ∃ first second, values = [first, second] := by
  cases values with
  | nil => simp at lengthExact
  | cons first tail =>
      cases tail with
      | nil => simp at lengthExact
      | cons second suffix =>
          cases suffix with
          | nil => exact ⟨first, second, rfl⟩
          | cons extra suffix => simp at lengthExact

private theorem triple_of_length_three {α : Type} (values : List α)
    (lengthExact : values.length = 3) :
    ∃ first second third, values = [first, second, third] := by
  cases values with
  | nil => simp at lengthExact
  | cons first tail =>
      cases tail with
      | nil => simp at lengthExact
      | cons second tail =>
          cases tail with
          | nil => simp at lengthExact
          | cons third suffix =>
              cases suffix with
              | nil => exact ⟨first, second, third, rfl⟩
              | cons extra suffix => simp at lengthExact

private theorem quadruple_of_length_four {α : Type} (values : List α)
    (lengthExact : values.length = 4) :
    ∃ first second third fourth, values = [first, second, third, fourth] := by
  cases values with
  | nil => simp at lengthExact
  | cons first tail =>
      cases tail with
      | nil => simp at lengthExact
      | cons second tail =>
          cases tail with
          | nil => simp at lengthExact
          | cons third tail =>
              cases tail with
              | nil => simp at lengthExact
              | cons fourth suffix =>
                  cases suffix with
                  | nil => exact ⟨first, second, third, fourth, rfl⟩
                  | cons extra suffix => simp at lengthExact

/-- The layout decoder is a left inverse of the encoder for every exact-shaped statement. -/
theorem decode_encode_of_exact_shape
    (statement : V8PublicStatement)
    (inputFlagsLength : statement.inputFlags.length = 2)
    (outputFlagsLength : statement.outputFlags.length = 2)
    (nullifiersLength : statement.nullifiers.length = 2)
    (nullifierLengths : ∀ digest, digest ∈ statement.nullifiers → digest.length = 7)
    (commitmentsLength : statement.commitments.length = 2)
    (commitmentLengths : ∀ digest, digest ∈ statement.commitments → digest.length = 7)
    (ciphertextCommitmentsLength : statement.ciphertextCommitments.length = 2)
    (ciphertextCommitmentLengths :
      ∀ digest, digest ∈ statement.ciphertextCommitments → digest.length = 6)
    (merkleRootLength : statement.merkleRoot.length = 7)
    (balanceAssetsLength : statement.balanceAssets.length = 4)
    (reservedCommitmentsLength :
      statement.compatibility.reservedLegacyCommitments.length = 3)
    (reservedCommitmentLengths :
      ∀ digest, digest ∈ statement.compatibility.reservedLegacyCommitments →
        digest.length = 6)
    (actionIntentLength : statement.stablecoin.actionIntent.length = 7)
    (beforeRootLength : statement.stablecoin.beforeRoot.length = 7)
    (afterRootLength : statement.stablecoin.afterRoot.length = 7)
    (issuerAuthorizationLength : statement.stablecoin.issuerAuthorization.length = 7) :
    decodePublicStatement? (encodePublicStatement statement) = some statement := by
  rcases pair_of_length_two statement.inputFlags inputFlagsLength with
    ⟨input0, input1, inputFlags⟩
  rcases pair_of_length_two statement.outputFlags outputFlagsLength with
    ⟨output0, output1, outputFlags⟩
  rcases pair_of_length_two statement.nullifiers nullifiersLength with
    ⟨nullifier0, nullifier1, nullifiers⟩
  rcases pair_of_length_two statement.commitments commitmentsLength with
    ⟨commitment0, commitment1, commitments⟩
  rcases pair_of_length_two statement.ciphertextCommitments ciphertextCommitmentsLength with
    ⟨ciphertext0, ciphertext1, ciphertextCommitments⟩
  rcases quadruple_of_length_four statement.balanceAssets balanceAssetsLength with
    ⟨asset0, asset1, asset2, asset3, balanceAssets⟩
  rcases triple_of_length_three statement.compatibility.reservedLegacyCommitments
      reservedCommitmentsLength with
    ⟨reserved0, reserved1, reserved2, reservedCommitments⟩
  have nullifier0Length : nullifier0.length = 7 := by
    apply nullifierLengths nullifier0
    simp [nullifiers]
  have nullifier1Length : nullifier1.length = 7 := by
    apply nullifierLengths nullifier1
    simp [nullifiers]
  have commitment0Length : commitment0.length = 7 := by
    apply commitmentLengths commitment0
    simp [commitments]
  have commitment1Length : commitment1.length = 7 := by
    apply commitmentLengths commitment1
    simp [commitments]
  have ciphertext0Length : ciphertext0.length = 6 := by
    apply ciphertextCommitmentLengths ciphertext0
    simp [ciphertextCommitments]
  have ciphertext1Length : ciphertext1.length = 6 := by
    apply ciphertextCommitmentLengths ciphertext1
    simp [ciphertextCommitments]
  have reserved0Length : reserved0.length = 6 := by
    apply reservedCommitmentLengths reserved0
    simp [reservedCommitments]
  have reserved1Length : reserved1.length = 6 := by
    apply reservedCommitmentLengths reserved1
    simp [reservedCommitments]
  have reserved2Length : reserved2.length = 6 := by
    apply reservedCommitmentLengths reserved2
    simp [reservedCommitments]
  have compatibilityRebuild :
      { enabled := statement.compatibility.enabled
        assetId := statement.compatibility.assetId
        policyVersion := statement.compatibility.policyVersion
        issuanceSign := statement.compatibility.issuanceSign
        issuanceMagnitude := statement.compatibility.issuanceMagnitude
        reservedLegacyCommitments := [reserved0, reserved1, reserved2] } =
        statement.compatibility := by
    cases compatibility : statement.compatibility
    simp_all
  simp [decodePublicStatement?, encodePublicStatement, encodeCompatibility,
      encodeStablecoinPublic, slice, publicWordCount, List.drop_append, List.take_append,
      List.drop_eq_nil_of_le, List.take_of_length_le,
      decode_stable_direction_word,
      inputFlags, outputFlags,
      nullifiers, commitments, ciphertextCommitments, balanceAssets,
      reservedCommitments, nullifier0Length,
      nullifier1Length, commitment0Length, commitment1Length,
      ciphertext0Length, ciphertext1Length, merkleRootLength,
      reserved0Length, reserved1Length, reserved2Length, actionIntentLength,
      beforeRootLength, afterRootLength, issuerAuthorizationLength,
      compatibilityRebuild]
  cases statement
  simp_all

/-- Every canonical transaction statement round-trips through the exact public decoder. -/
theorem decode_encode_of_canonical
    (primitives : V8SemanticPrimitives)
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement primitives statement) :
    decodePublicStatement? (encodePublicStatement statement) = some statement := by
  rcases canonical with
    ⟨inputFlagsLength, outputFlagsLength, _inputFlagsCanonical,
      _outputFlagsCanonical, nullifiersLength, nullifiersCanonical,
      commitmentsLength, commitmentsCanonical, ciphertextCommitmentsLength,
      ciphertextCommitmentsCanonical, _feeCanonical, _balanceSignCanonical,
      _balanceMagnitudeCanonical, merkleRootCanonical, balanceAssetsCanonical,
      compatibilityCanonical, _versionCanonical, _cryptoSuiteCanonical,
      _parentHeightCanonical, actionIntentCanonical, beforeRootCanonical,
      afterRootCanonical, issuerAuthorizationCanonical, _slotShape,
      _nullifiersDistinct, _actionIntentBound, _encodedCanonical⟩
  rcases balanceAssetsCanonical with ⟨balanceAssetsLength, _⟩
  rcases compatibilityCanonical with
    ⟨_compatibilityEnabledCanonical, _issuanceSignCanonical,
      _issuanceMagnitudeCanonical, reservedCommitmentsLength,
      reservedCommitmentsCanonical, _directionPolicy⟩
  apply decode_encode_of_exact_shape statement
  · simpa [inputCount] using inputFlagsLength
  · simpa [outputCount] using outputFlagsLength
  · simpa [inputCount] using nullifiersLength
  · intro digest membership
    exact (nullifiersCanonical digest membership).1
  · simpa [outputCount] using commitmentsLength
  · intro digest membership
    exact (commitmentsCanonical digest membership).1
  · simpa [outputCount] using ciphertextCommitmentsLength
  · intro digest membership
    exact (ciphertextCommitmentsCanonical digest membership).1
  · exact merkleRootCanonical.1
  · simpa [balanceSlotCount] using balanceAssetsLength
  · exact reservedCommitmentsLength
  · intro digest membership
    exact (reservedCommitmentsCanonical digest membership).1.1
  · exact actionIntentCanonical.1
  · exact beforeRootCanonical.1
  · exact afterRootCanonical.1
  · exact issuerAuthorizationCanonical.1

/-- Canonical HGV8RP03 public words bind one typed transaction statement. -/
theorem encode_injective_of_canonical
    (primitives : V8SemanticPrimitives)
    {left right : V8PublicStatement}
    (leftCanonical : CanonicalPublicStatement primitives left)
    (rightCanonical : CanonicalPublicStatement primitives right)
    (sameEncoding : encodePublicStatement left = encodePublicStatement right) :
    left = right := by
  have sameDecoded := congrArg decodePublicStatement? sameEncoding
  rw [decode_encode_of_canonical primitives left leftCanonical,
    decode_encode_of_canonical primitives right rightCanonical] at sameDecoded
  exact Option.some.inj sameDecoded

end Poseidon2V8PublicDecoder
end Transaction
end Hegemon
