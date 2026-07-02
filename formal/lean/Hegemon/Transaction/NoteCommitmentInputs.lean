import Hegemon.Bytes

namespace Hegemon
namespace Transaction
namespace NoteCommitmentInputs

def fieldModulus : Nat := 18446744069414584321
def noteDomainTag : Nat := 1
def balanceSlotPaddingAssetId : Nat := 18446744073709551615
def balanceSlotPaddingFieldId : Nat := balanceSlotPaddingAssetId % fieldModulus

def canonicalAssetId (assetId : Nat) : Bool :=
  assetId < fieldModulus && assetId != balanceSlotPaddingFieldId

def beBytesToNat : List Byte -> Nat
  | [] => 0
  | byte :: rest => Hegemon.byte byte * 256 ^ rest.length + beBytesToNat rest

def bytes32ToFelts (bytes : List Byte) : List Nat :=
  [
    beBytesToNat (bytes.take 8),
    beBytesToNat ((bytes.drop 8).take 8),
    beBytesToNat ((bytes.drop 16).take 8),
    beBytesToNat ((bytes.drop 24).take 8)
  ]

def noteCommitmentInputs
    (value assetId : Nat)
    (pkRecipient rho randomness pkAuth : List Byte) : List Nat :=
  [value, assetId]
    ++ bytes32ToFelts pkRecipient
    ++ bytes32ToFelts rho
    ++ bytes32ToFelts randomness
    ++ bytes32ToFelts pkAuth

theorem note_commitment_domain_tag_is_one :
    noteDomainTag = 1 := by
  rfl

theorem bytes32_to_felts_has_four_limbs (bytes : List Byte) :
    (bytes32ToFelts bytes).length = 4 := by
  simp [bytes32ToFelts]

theorem note_commitment_inputs_have_eighteen_limbs
    (value assetId : Nat)
    (pkRecipient rho randomness pkAuth : List Byte) :
    (noteCommitmentInputs value assetId pkRecipient rho randomness pkAuth).length = 18 := by
  simp [noteCommitmentInputs, bytes32ToFelts]

theorem note_commitment_inputs_start_with_value_and_asset
    (value assetId : Nat)
    (pkRecipient rho randomness pkAuth : List Byte) :
    (noteCommitmentInputs value assetId pkRecipient rho randomness pkAuth).take 2 =
      [value, assetId] := by
  simp [noteCommitmentInputs, bytes32ToFelts]

theorem note_commitment_inputs_absorb_recipient_rho_randomness_auth
    (value assetId : Nat)
    (pkRecipient rho randomness pkAuth : List Byte) :
    (noteCommitmentInputs value assetId pkRecipient rho randomness pkAuth).drop 2 =
      bytes32ToFelts pkRecipient
        ++ bytes32ToFelts rho
        ++ bytes32ToFelts randomness
        ++ bytes32ToFelts pkAuth := by
  simp [noteCommitmentInputs, bytes32ToFelts]

theorem native_asset_id_is_canonical :
    canonicalAssetId 0 = true := by
  decide

theorem padding_asset_id_is_not_canonical :
    canonicalAssetId balanceSlotPaddingAssetId = false := by
  decide

theorem padding_field_alias_is_not_canonical :
    canonicalAssetId balanceSlotPaddingFieldId = false := by
  decide

theorem field_modulus_is_not_canonical :
    canonicalAssetId fieldModulus = false := by
  decide

theorem ordinary_asset_id_is_canonical :
    canonicalAssetId 7 = true := by
  decide

end NoteCommitmentInputs
end Transaction
end Hegemon
