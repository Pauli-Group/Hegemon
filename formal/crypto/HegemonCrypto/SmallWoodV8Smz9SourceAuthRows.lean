import HegemonCrypto.SmallWoodV8Smz9SourceAuthInputs

/-!
The source authorization materializer's 155 replicated rows, relative to
global row 92. The per-call digest accessor remains explicit and canonical.
No accepted witness, successful evaluator, or desired-row equality is an input.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (packedWitnessLaneRows packingFactor relationRowCount)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

def authBit (condition : Prop) [Decidable condition] : Nat := if condition then 1 else 0

theorem auth_bit_canonical (condition : Prop) [Decidable condition] :
    authBit condition < fieldModulus := by
  unfold authBit
  split_ifs <;> decide

def authModeFlag (mode : V8AuthorizationMode) (index : Nat) : Nat :=
  match mode with
  | .singleKey => authBit (index = 0)
  | .approvalStep => authBit (index = 1)
  | .finalThresholdSpend => authBit (index = 2)

/-- Inactive input selection is performed before mode-dependent hash selection. -/
def authInputPrf (statement : V8PublicStatement) (auth : V8AuthorizationWitness)
    (hashes : AuthHashFinals) (input : Nat) : Nat :=
  if flagAt statement.inputFlags input = 0 then 0 else
    match auth.mode with
    | .singleKey => authHashWord hashes 0 0
    | .approvalStep =>
        if input = 0 then authHashWord hashes 100 4 else authHashWord hashes 0 0
    | .finalThresholdSpend =>
        if input = 0 then authHashWord hashes 105 4 else authHashWord hashes 100 4

def authInputKey (statement : V8PublicStatement) (auth : V8AuthorizationWitness)
    (hashes : AuthHashFinals) (input limb : Nat) : Nat :=
  if flagAt statement.inputFlags input = 0 then 0 else
    match auth.mode with
    | .singleKey => authHashWord hashes 0 (1 + limb)
    | .approvalStep =>
        if input = 0 then authHashWord hashes 100 limb else authHashWord hashes 0 (1 + limb)
    | .finalThresholdSpend =>
        if input = 0 then authHashWord hashes 105 limb else authHashWord hashes 100 limb

def authPolicyWord (auth : V8AuthorizationWitness) (hashes : AuthHashFinals) (limb : Nat) : Nat :=
  if auth.mode = .singleKey then 0 else authHashWord hashes 97 limb

def authScalar (auth : V8AuthorizationWitness) (offset : Nat) : Nat :=
  if offset = 0 then auth.current.threshold
  else if offset = 1 then auth.current.signerCount
  else if offset = 2 then auth.current.approvalCount
  else if offset < 9 then wordAt auth.current.approvedSlots (offset - 3)
  else if offset = 9 then auth.next.approvalCount
  else if offset < 16 then wordAt auth.next.approvedSlots (offset - 10)
  else 0

def authThresholdFlag (auth : V8AuthorizationWitness) (slot : Nat) : Nat :=
  if auth.mode = .singleKey then 0 else authBit (auth.current.threshold = slot + 1)

def authSignerFlag (auth : V8AuthorizationWitness) (slot : Nat) : Nat :=
  if auth.mode = .singleKey then 0 else authBit (auth.current.signerCount = slot + 1)

def authCurrentCountFlag (auth : V8AuthorizationWitness) (slot : Nat) : Nat :=
  if auth.mode = .singleKey then 0 else authBit (auth.current.approvalCount = slot)

/-- Final spend deliberately materializes count_flags(0), not seven zero flags. -/
def authNextCountFlag (auth : V8AuthorizationWitness) (slot : Nat) : Nat :=
  match auth.mode with
  | .singleKey => 0
  | .approvalStep => authBit (auth.next.approvalCount = slot)
  | .finalThresholdSpend => authBit (0 = slot)

def authSlotActive (auth : V8AuthorizationWitness) (slot : Nat) : Nat :=
  ((List.range (6 - slot)).map fun offset => authSignerFlag auth (slot + offset)).sum

def authMembership (auth : V8AuthorizationWitness) (hashes : AuthHashFinals) (slot : Nat) : Nat :=
  authBit (auth.mode = .approvalStep ∧ authSlotActive auth slot = 1 ∧
    auth.policySignerTags.getD slot [] =
      List.ofFn (fun limb : Fin 5 => authHashWord hashes 0 limb.val))

/-- The source's increasing-left, increasing-right nested-loop order. -/
def authPairs : List (Nat × Nat) :=
  (List.range 6).flatMap fun left =>
    (List.range (5 - left)).map fun offset => (left, left + 1 + offset)

theorem auth_pairs_exact :
    authPairs = [(0,1),(0,2),(0,3),(0,4),(0,5),
      (1,2),(1,3),(1,4),(1,5),(2,3),(2,4),(2,5),(3,4),(3,5),(4,5)] := by decide

theorem auth_pairs_length : authPairs.length = 15 := by decide

def authDistinctInverse (auth : V8AuthorizationWitness) (pair : Nat) : Nat :=
  let indices := authPairs.getD pair (0,0)
  if auth.mode ≠ .singleKey ∧ authSlotActive auth indices.1 = 1 ∧
      authSlotActive auth indices.2 = 1 then
    Hegemon.Transaction.Poseidon2V8RelationProgram.fieldInverse
      (Hegemon.Transaction.Poseidon2V8RelationProgram.fieldSub
        (wordAt (auth.policySignerTags.getD indices.1 []) 0)
        (wordAt (auth.policySignerTags.getD indices.2 []) 0))
  else 0

/-- Every branch is the corresponding source-owned relative row family. -/
def sourceAuthRow (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (offset : Nat) : Nat :=
  let auth := witness.authorization
  if offset < 3 then authModeFlag auth.mode offset
  else if offset < 5 then authInputPrf statement auth hashes (offset - 3)
  else if offset < 13 then authInputKey statement auth hashes ((offset - 5) / 4) ((offset - 5) % 4)
  else if offset < 18 then authHashWord hashes 0 (offset - 13)
  else if offset < 25 then authHashWord hashes 100 (offset - 18)
  else if offset < 32 then authHashWord hashes 103 (offset - 25)
  else if offset < 39 then authHashWord hashes 105 (offset - 32)
  else if offset < 46 then authHashWord hashes 93 (offset - 39)
  else if offset < 53 then authPolicyWord auth hashes (offset - 46)
  else if offset < 60 then wordAt auth.current.intentDigest (offset - 53)
  else if offset < 78 then authScalar auth (offset - 60)
  else if offset < 84 then authThresholdFlag auth (offset - 78)
  else if offset < 90 then authSignerFlag auth (offset - 84)
  else if offset < 97 then authCurrentCountFlag auth (offset - 90)
  else if offset < 104 then authNextCountFlag auth (offset - 97)
  else if offset < 134 then wordAt (auth.policySignerTags.getD ((offset - 104) / 5) []) ((offset - 104) % 5)
  else if offset < 140 then authMembership auth hashes (offset - 134)
  else if offset < 155 then authDistinctInverse auth (offset - 140)
  else 0

def sourceAuthScalars (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) : List Nat :=
  List.ofFn fun row : Fin 155 => sourceAuthRow statement witness hashes row.val

/-- Exactly 155 row-major rows, each replicated across all 64 lanes. -/
def sourceAuthPacked (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) : List Nat :=
  List.ofFn fun slot : Fin 9920 => sourceAuthRow statement witness hashes (slot.val / 64)

def embedSourceAuth (before after : List Nat) (statement : V8PublicStatement)
    (witness : V8Witness) (hashes : AuthHashFinals) : List Nat :=
  before ++ (sourceAuthPacked statement witness hashes ++ after)

theorem source_auth_shape (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) :
    (sourceAuthScalars statement witness hashes).length = 155 ∧
      (sourceAuthPacked statement witness hashes).length = 155 * 64 := by
  simp only [sourceAuthScalars, sourceAuthPacked, List.length_ofFn]
  decide

theorem source_auth_packed_getD (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (row : Fin 155) (lane : Fin 64) (fallback : Nat) :
    (sourceAuthPacked statement witness hashes).getD (row.val * 64 + lane.val) fallback =
      sourceAuthRow statement witness hashes row.val := by
  have bound : row.val * 64 + lane.val < 9920 := by omega
  have quotient : (row.val * 64 + lane.val) / 64 = row.val := by omega
  simp only [sourceAuthPacked, List.getD_eq_getElem?_getD, List.getElem?_ofFn,
    bound, dif_pos, Option.getD_some, quotient]

theorem source_auth_replicated (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (row : Fin 155) (left right : Fin 64) :
    (sourceAuthPacked statement witness hashes).getD (row.val * 64 + left.val) 0 =
      (sourceAuthPacked statement witness hashes).getD (row.val * 64 + right.val) 0 := by
  rw [source_auth_packed_getD, source_auth_packed_getD]

theorem source_auth_embedded_getD (before after : List Nat) (statement : V8PublicStatement)
    (witness : V8Witness) (hashes : AuthHashFinals) (row : Fin 155) (lane : Fin 64) (fallback : Nat) :
    (embedSourceAuth before after statement witness hashes).getD
        (before.length + row.val * 64 + lane.val) fallback =
      sourceAuthRow statement witness hashes row.val := by
  have bound : row.val * 64 + lane.val < (sourceAuthPacked statement witness hashes).length := by
    rw [(source_auth_shape statement witness hashes).2]
    omega
  simp only [embedSourceAuth, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_right (by omega)]
  have address : before.length + row.val * 64 + lane.val - before.length =
      row.val * 64 + lane.val := by omega
  rw [address, List.getElem?_append_left bound]
  exact source_auth_packed_getD statement witness hashes row lane fallback

theorem source_auth_global_lane_readback (before after : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 5888) (row : Fin 155) (lane : Fin 64) :
    (packedWitnessLaneRows (embedSourceAuth before after statement witness hashes) lane.val).getD
        (92 + row.val) 0 = sourceAuthRow statement witness hashes row.val := by
  have rowBound : 92 + row.val < 686 := by omega
  have address : (92 + row.val) * 64 + lane.val =
      before.length + row.val * 64 + lane.val := by omega
  simp only [packedWitnessLaneRows, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range, relationRowCount, rowBound,
    Option.map_some, Option.getD_some, packingFactor]
  rw [address]
  exact source_auth_embedded_getD before after statement witness hashes row lane 0

theorem auth_input_prf_canonical (statement : V8PublicStatement) (auth : V8AuthorizationWitness)
    (hashes : AuthHashFinals) (canonical : HashFinalsCanonical hashes) (input : Nat) :
    authInputPrf statement auth hashes input < fieldModulus := by
  by_cases inactive : flagAt statement.inputFlags input = 0
  · simp only [authInputPrf, if_pos inactive]
    decide
  · unfold authInputPrf
    rw [if_neg inactive]
    cases auth.mode <;> dsimp only <;> (try split_ifs) <;>
      exact auth_hash_word_canonical hashes canonical _ _

theorem auth_input_key_canonical (statement : V8PublicStatement) (auth : V8AuthorizationWitness)
    (hashes : AuthHashFinals) (canonical : HashFinalsCanonical hashes) (input limb : Nat) :
    authInputKey statement auth hashes input limb < fieldModulus := by
  by_cases inactive : flagAt statement.inputFlags input = 0
  · simp only [authInputKey, if_pos inactive]
    decide
  · unfold authInputKey
    rw [if_neg inactive]
    cases auth.mode <;> dsimp only <;> (try split_ifs) <;>
      exact auth_hash_word_canonical hashes canonical _ _

theorem auth_scalar_canonical (auth : V8AuthorizationWitness) (canonical : AuthTypedSourceCanonical auth)
    (offset : Nat) : authScalar auth offset < fieldModulus := by
  unfold authScalar
  split_ifs with zero one two low nine high
  · exact canonical.1.2.1
  · exact canonical.1.2.2.1
  · exact canonical.1.2.2.2.1
  · exact canonical.1.2.2.2.2 _ (by omega)
  · exact canonical.2.1.2.2.2.1
  · exact canonical.2.1.2.2.2.2 _ (by omega)
  · decide

theorem auth_distinct_inverse_canonical (auth : V8AuthorizationWitness) (pair : Nat) :
    authDistinctInverse auth pair < fieldModulus := by
  unfold authDistinctInverse
  dsimp only
  split_ifs
  · unfold Hegemon.Transaction.Poseidon2V8RelationProgram.fieldInverse
    split_ifs
    · decide
    · exact Nat.mod_lt _ (by decide)
  · decide

theorem source_auth_row_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (hashCanonical : HashFinalsCanonical hashes)
    (typedCanonical : AuthTypedSourceCanonical witness.authorization) (offset : Nat) :
    sourceAuthRow statement witness hashes offset < fieldModulus := by
  unfold sourceAuthRow
  dsimp only
  by_cases h3 : offset < 3
  · rw [if_pos h3]
    cases witness.authorization.mode <;> exact auth_bit_canonical _
  rw [if_neg h3]
  by_cases h5 : offset < 5
  · rw [if_pos h5]
    exact auth_input_prf_canonical statement _ hashes hashCanonical _
  rw [if_neg h5]
  by_cases h13 : offset < 13
  · rw [if_pos h13]
    exact auth_input_key_canonical statement _ hashes hashCanonical _ _
  rw [if_neg h13]
  by_cases h18 : offset < 18
  · rw [if_pos h18]
    exact auth_hash_word_canonical hashes hashCanonical _ _
  rw [if_neg h18]
  by_cases h25 : offset < 25
  · rw [if_pos h25]
    exact auth_hash_word_canonical hashes hashCanonical _ _
  rw [if_neg h25]
  by_cases h32 : offset < 32
  · rw [if_pos h32]
    exact auth_hash_word_canonical hashes hashCanonical _ _
  rw [if_neg h32]
  by_cases h39 : offset < 39
  · rw [if_pos h39]
    exact auth_hash_word_canonical hashes hashCanonical _ _
  rw [if_neg h39]
  by_cases h46 : offset < 46
  · rw [if_pos h46]
    exact auth_hash_word_canonical hashes hashCanonical _ _
  rw [if_neg h46]
  by_cases h53 : offset < 53
  · rw [if_pos h53]
    unfold authPolicyWord
    split_ifs
    · decide
    · exact auth_hash_word_canonical hashes hashCanonical _ _
  rw [if_neg h53]
  by_cases h60 : offset < 60
  · rw [if_pos h60]
    exact typedCanonical.1.1 _
  rw [if_neg h60]
  by_cases h78 : offset < 78
  · rw [if_pos h78]
    exact auth_scalar_canonical _ typedCanonical _
  rw [if_neg h78]
  by_cases h84 : offset < 84
  · rw [if_pos h84]
    unfold authThresholdFlag
    split_ifs
    · decide
    · exact auth_bit_canonical _
  rw [if_neg h84]
  by_cases h90 : offset < 90
  · rw [if_pos h90]
    unfold authSignerFlag
    split_ifs
    · decide
    · exact auth_bit_canonical _
  rw [if_neg h90]
  by_cases h97 : offset < 97
  · rw [if_pos h97]
    unfold authCurrentCountFlag
    split_ifs
    · decide
    · exact auth_bit_canonical _
  rw [if_neg h97]
  by_cases h104 : offset < 104
  · rw [if_pos h104]
    unfold authNextCountFlag
    cases witness.authorization.mode <;> dsimp only
    · decide
    · exact auth_bit_canonical _
    · exact auth_bit_canonical _
  rw [if_neg h104]
  by_cases h134 : offset < 134
  · rw [if_pos h134]
    exact typedCanonical.2.2 _ (by omega) _
  rw [if_neg h134]
  by_cases h140 : offset < 140
  · rw [if_pos h140]
    exact auth_bit_canonical _
  rw [if_neg h140]
  by_cases h155 : offset < 155
  · rw [if_pos h155]
    exact auth_distinct_inverse_canonical _ _
  rw [if_neg h155]
  decide

theorem valid_source_auth_packed_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (hashCanonical : HashFinalsCanonical hashes) :
    ∀ word, word ∈ sourceAuthPacked statement witness hashes → word < fieldModulus := by
  intro word member
  obtain ⟨slot, rfl⟩ := List.mem_ofFn.mp member
  exact source_auth_row_canonical statement witness hashes hashCanonical
    (valid_auth_typed_source_canonical statement witness valid) _


end HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
