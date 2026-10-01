import SmzaRp05ConcreteSuffix
import SmzaRp05GroupedSuffix
import SmzaRp05CurrentGroupedRecordReadback
import SmzaRp05TracePrefixes

/-! # Actual finite-prefix routes into the grouped counter space

The current event interface accepts arbitrary embeddings.  This module
constructs the specific value-preserving embeddings used by the finite grouped
database, from the existing model-width protocol bound and role-cap lemmas.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedRoutes

open SmzaRp05ConcreteSuffix
  (ModelWithinProtocol protocolBlockCap protocol_block_caps_exact
    route_read_count_le_protocol_cap)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter groupBlockCap group_block_cap_eq
    group_address_injective group_address_encode)
open SmzaRp05TracePrefixes (RelationModel Routes TypedRoutes)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9AdaptiveFiniteAccounting.Historical (piopOpenings)
open V8SmzaOracleParser (RawInput)

noncomputable section
set_option autoImplicit false

/-- Each source role cap fits in the common PIOP grouped counter range. -/
theorem protocol_role_cap_le_group_block_cap (role : SmzaChallengeStageTargets.Role) :
    protocolBlockCap role ≤ groupBlockCap := by
  cases role with
  | decsMatrix =>
      rw [protocol_block_caps_exact.1, group_block_cap_eq]
      decide
  | piopMatrix =>
      rfl
  | piopOpening =>
      rw [protocol_block_caps_exact.2.2.1, group_block_cap_eq]
      decide
  | decsSample =>
      rw [protocol_block_caps_exact.2.2.2, group_block_cap_eq]
      decide

private def intoGroupCounter {n : Nat} (bound : n ≤ groupBlockCap) : Fin n ↪ GroupCounter :=
  { toFun := fun index => ⟨index.val, Nat.lt_of_lt_of_le index.isLt bound⟩
    inj' := by
      intro left right same
      apply Fin.ext
      exact congrArg (fun value : GroupCounter => value.val) same }

/-- The actual finite-context routes: each role reads its source's ordinary
prefix of the common grouped vector, with unchanged numeric coordinates. -/
def currentGroupedRoutes (model : RelationModel)
    (bounded : ModelWithinProtocol model) : TypedRoutes model GroupCounter :=
  fun statement =>
    { decsMatrix := intoGroupCounter (le_trans
        (route_read_count_le_protocol_cap model bounded statement .decsMatrix)
        (protocol_role_cap_le_group_block_cap .decsMatrix))
      piopMatrix := intoGroupCounter (le_trans
        (route_read_count_le_protocol_cap model bounded statement .piopMatrix)
        (protocol_role_cap_le_group_block_cap .piopMatrix))
      piopOpening := intoGroupCounter (le_trans
        (route_read_count_le_protocol_cap model bounded statement .piopOpening)
        (protocol_role_cap_le_group_block_cap .piopOpening))
      decsSample := intoGroupCounter (le_trans
        (route_read_count_le_protocol_cap model bounded statement .decsSample)
        (protocol_role_cap_le_group_block_cap .decsSample)) }

@[simp] theorem currentGroupedRoutes_decsMatrix_val
    (model : RelationModel)
    (bounded : ModelWithinProtocol model) (statement : SmzaRp05StatementNamespace.Statement)
    (index : Fin (digestCallCap (140 * 5))) :
    ((currentGroupedRoutes model bounded statement).decsMatrix index).val = index.val := rfl

@[simp] theorem currentGroupedRoutes_piopMatrix_val
    (model : RelationModel)
    (bounded : ModelWithinProtocol model) (statement : SmzaRp05StatementNamespace.Statement)
    (index : Fin (digestCallCap (5 * model.width statement))) :
    ((currentGroupedRoutes model bounded statement).piopMatrix index).val = index.val := rfl

@[simp] theorem currentGroupedRoutes_piopOpening_val
    (model : RelationModel)
    (bounded : ModelWithinProtocol model) (statement : SmzaRp05StatementNamespace.Statement)
    (index : Fin (digestCallCap piopOpenings)) :
    ((currentGroupedRoutes model bounded statement).piopOpening index).val = index.val := rfl

@[simp] theorem currentGroupedRoutes_decsSample_val
    (model : RelationModel)
    (bounded : ModelWithinProtocol model) (statement : SmzaRp05StatementNamespace.Statement)
    (index : Fin (digestCallCap SmzaRp04RawRoleSampling.q38CandidateCount)) :
    ((currentGroupedRoutes model bounded statement).decsSample index).val = index.val := rfl

/-- The byte parser is deterministic: a key can carry only one role, target,
nonce, and source counter receipt. -/
theorem parseStageQuery_unique (input : RawInput) {left right : SmzaChallengeStageTargets.StageQuery}
    (leftRead : SmzaChallengeStageTargets.parseStageQuery input = some left)
    (rightRead : SmzaChallengeStageTargets.parseStageQuery input = some right) :
    left = right := by
  rw [leftRead] at rightRead
  exact Option.some.inj rightRead

/-- A raw call with the actual finite group address is exactly that group's
counter-coordinate input, not merely another call routed to the same table. -/
theorem input_eq_groupEncode_of_group_address
    (input : RawInput) (rolePrefix : CanonicalRolePrefix) (counter : GroupCounter)
    (address : SmzaRp05GroupedSuffix.groupAddress input = (Sum.inl rolePrefix, counter)) :
    input = SmzaRp05GroupedSuffix.groupEncode (rolePrefix, counter) :=
  group_address_injective (address.trans
    (group_address_encode rolePrefix counter).symm)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedRoutes
