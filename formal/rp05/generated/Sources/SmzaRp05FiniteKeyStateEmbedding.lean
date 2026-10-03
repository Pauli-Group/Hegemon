import SmzaRp05CurrentFiniteGroupedProgram

/-! A reachable-group equality identifies the finite CMS key types exactly.
This is deliberately narrower than embedding a smaller key space into a
strictly larger one: when a suffix adds no ex-ante groups, the two compressed
oracle carriers can be transported by ordinary dependent equality. -/

namespace HegemonCrypto.SmallWood.SmzaRp05FiniteKeyStateEmbedding

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableAddressCompiler (groups)
open SmzaRp05CurrentFiniteGroupedProgram (Key included encode)
open SmzaRp05GroupedSuffix (GroupKey groupKeyOf)
open V8SmzaOracleParser (RawInput)
open scoped Classical

set_option autoImplicit false

private theorem included_cast_universe_eq
    (left right : Finset GroupKey) (same : left = right)
    (key : { key : GroupKey // key ∈ insert (groupKeyOf []) left }) :
    (cast (congrArg (fun keys : Finset GroupKey =>
      { key : GroupKey // key ∈ insert (groupKeyOf []) keys }) same) key).val =
      key.val := by
  cases same
  rfl

private theorem encode_cast_universe_eq
    (left right : Finset GroupKey) (same : left = right) (raw : RawInput) :
    cast (congrArg (fun keys : Finset GroupKey =>
      { key : GroupKey // key ∈ insert (groupKeyOf []) keys }) same)
      (if member : groupKeyOf raw ∈ insert (groupKeyOf []) left then
        ⟨groupKeyOf raw, member⟩
      else ⟨groupKeyOf [], Finset.mem_insert_self _ _⟩) =
      (if member : groupKeyOf raw ∈ insert (groupKeyOf []) right then
        ⟨groupKeyOf raw, member⟩
      else ⟨groupKeyOf [], Finset.mem_insert_self _ _⟩) := by
  cases same
  rfl

/-- Equality of the all-branch reachable group sets gives equality of the
program-indexed finite key types, including their common fallback key. -/
theorem key_type_eq_of_groups_eq {α β : Type}
    (first : Program α) (joint : Program β)
    (groupsEq : groups first = groups joint) :
    Key first = Key joint := by
  change
    { key : GroupKey // key ∈ insert (groupKeyOf []) (groups first) } =
      { key : GroupKey // key ∈ insert (groupKeyOf []) (groups joint) }
  apply congrArg (fun keys : Finset GroupKey =>
    { key : GroupKey // key ∈ keys })
  exact congrArg (insert (groupKeyOf [])) groupsEq

/-- The canonical inclusion into `GroupKey` is unchanged by transport along
the reachable-group equality. -/
@[simp]
theorem included_cast_key_type_eq_of_groups_eq {α β : Type}
    (first : Program α) (joint : Program β)
    (groupsEq : groups first = groups joint) (key : Key first) :
    included joint (cast (key_type_eq_of_groups_eq first joint groupsEq) key) =
      included first key := by
  have castEq : key_type_eq_of_groups_eq first joint groupsEq =
      congrArg (fun keys : Finset GroupKey =>
        { key : GroupKey // key ∈ insert (groupKeyOf []) keys }) groupsEq :=
    Subsingleton.elim _ _
  unfold included
  rw [castEq]
  exact included_cast_universe_eq (groups first) (groups joint) groupsEq key

/-- The canonical raw-input encoder also commutes with this exact key-type
transport. Proof fields in the subtype are irrelevant; the underlying grouped
address and fallback choice are identical. -/
@[simp]
theorem encode_cast_key_type_eq_of_groups_eq {α β : Type}
    (first : Program α) (joint : Program β)
    (groupsEq : groups first = groups joint) (raw : RawInput) :
    cast (key_type_eq_of_groups_eq first joint groupsEq) (encode first raw) =
      encode joint raw := by
  have castEq : key_type_eq_of_groups_eq first joint groupsEq =
      congrArg (fun keys : Finset GroupKey =>
        { key : GroupKey // key ∈ insert (groupKeyOf []) keys }) groupsEq :=
    Subsingleton.elim _ _
  rw [castEq]
  exact encode_cast_universe_eq (groups first) (groups joint) groupsEq raw

end HegemonCrypto.SmallWood.SmzaRp05FiniteKeyStateEmbedding
