import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05GroupedSuffix
import HegemonCrypto.FiniteOracleDatabase
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle
import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleInstrument

/-! A stored finite grouped vector is the literal byte oracle on every
counter coordinate of its canonical role prefix.  This bridge uses the same
finite grouped key and its checked inclusion; it introduces no second table
or route equation. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedOracleVector

open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05GroupedSuffix (CanonicalRolePrefix GroupCounter GroupKey groupKeyOf
  groupCounterOf groupEncode group_address_encode)
open HegemonCrypto.FiniteOracleDatabase (Database)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

def finiteGroupedDatabaseOracle {Result : Type} (program : Program Result)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (fallback : RawDigest) : RawInput → RawDigest := fun raw =>
  match database (encode program raw) with
  | none => fallback
  | some vector => vectorOutputBytes (groupCounterOf raw) vector

private theorem encode_eq_key_of_group_member {Result : Type}
    (program : Program Result) (raw : RawInput)
    (member : groupKeyOf raw ∈ insert (groupKeyOf [])
      (SmzaRp05ExecutableAddressCompiler.groups program)) :
    encode program raw = ⟨groupKeyOf raw, member⟩ := by
  apply Subtype.ext
  unfold encode
  rw [dif_pos member]

/-- If a complete stored vector is present at the finite key for one
canonical role prefix, the database oracle agrees with the literal decoded
vector at every counter of that same group. -/
theorem stored_group_vector_answers_every_counter {Result : Type}
    (program : Program Result)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (fallback : RawDigest) (key : Key program)
    (rolePrefix : CanonicalRolePrefix)
    (keyIdentity : included program key = Sum.inl rolePrefix)
    (vector : VectorOutput GroupCounter)
    (stored : database key = some vector) (counter : GroupCounter) :
    finiteGroupedDatabaseOracle program database fallback
      (groupEncode (rolePrefix, counter)) =
        rawDigestBits.symm (vector counter) := by
  have keyValue : key.val = Sum.inl rolePrefix := keyIdentity
  have rawGroup :
      groupKeyOf (groupEncode (rolePrefix, counter)) = Sum.inl rolePrefix := by
    exact congrArg Prod.fst (group_address_encode rolePrefix counter)
  have rawMember : groupKeyOf (groupEncode (rolePrefix, counter)) ∈
      insert (groupKeyOf []) (SmzaRp05ExecutableAddressCompiler.groups program) := by
    rw [rawGroup, ← keyValue]
    exact key.property
  have encoded : encode program (groupEncode (rolePrefix, counter)) = key := by
    calc
      encode program (groupEncode (rolePrefix, counter)) =
          ⟨groupKeyOf (groupEncode (rolePrefix, counter)), rawMember⟩ :=
        encode_eq_key_of_group_member program _ rawMember
      _ = key := by
        apply Subtype.ext
        exact rawGroup.trans keyValue.symm
  have coordinate :
      groupCounterOf (groupEncode (rolePrefix, counter)) = counter := by
    exact congrArg Prod.snd (group_address_encode rolePrefix counter)
  simp only [finiteGroupedDatabaseOracle, encoded, stored, coordinate,
    vectorOutputBytes]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedOracleVector
