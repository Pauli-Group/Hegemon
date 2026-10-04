import HegemonCrypto.SmallWoodV8Smz9SourceTailAux
import HegemonCrypto.SmallWoodV8Smz9SourceAuthRows

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTail

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (fieldNormalize fieldSub fieldInverse)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
  (AuthHashFinals HashFinalsCanonical authHashWord authSlotActive)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

def sourceUnitWord (limb : Nat) : Nat := if limb = 0 then 1 else 0

def sourceStablePairs : List (Nat × Nat) :=
  (List.range 5).flatMap fun left =>
    (List.range (4 - left)).map fun offset => (left,left + 1 + offset)

def sourceCommitmentWord (witness : V8StablecoinWitness) (role limb : Nat) : Nat :=
  if limb < 7 then stableWitnessWord witness ([6,24,31,38,48].getD role 0 + limb) else 0

def sourceStableRoleWord (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness)
    (role limb : Nat) : Nat :=
  let config := decodeV8StablecoinConfig witness
  if stablePublic.direction = .disabled then sourceUnitWord limb
  else if role < 5 then sourceCommitmentWord witness role limb
  else if role < 15 then
    let pair := sourceStablePairs.getD (role - 5) (0,0)
    fieldSub (sourceCommitmentWord witness pair.1 limb) (sourceCommitmentWord witness pair.2 limb)
  else if role = 15 then
    if stablePublic.direction = .mint then
      if limb < 7 then stableWitnessWord witness (87 + limb) else 0
    else sourceUnitWord limb
  else if role = 16 then if limb = 0 then fieldNormalize stablePublic.magnitude else 0
  else if role = 17 then
    if stablePublic.direction = .mint then
      if limb = 0 then fieldNormalize config.oraclePriceNumerator else 0
    else sourceUnitWord limb
  else if role = 18 then
    if stablePublic.direction = .mint then
      if limb = 0 then fieldNormalize config.oraclePriceDenominator else 0
    else sourceUnitWord limb
  else if role = 19 then if limb = 0 then fieldNormalize stablePublic.assetId else 0
  else if role = 20 then wordAt stablePublic.actionIntent limb
  else sourceUnitWord limb

/-- Parent auth overwrites roles 21..29; the remaining lanes stay the source unit. -/
def sourceRoleWord (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (role limb : Nat) : Nat :=
  if role < 21 then sourceStableRoleWord statement.stablecoin witness.stablecoin role limb
  else if role = 21 then
    if flagAt statement.inputFlags 0 = 1 ∨ flagAt statement.inputFlags 1 = 1 then
      wordAt (selectedTransactionSpendKey statement witness) limb
    else sourceUnitWord limb
  else if role = 22 then
    if witness.authorization.mode = .singleKey then sourceUnitWord limb
    else authHashWord hashes 97 limb
  else if role = 23 then
    if witness.authorization.mode = .singleKey then sourceUnitWord limb
    else wordAt witness.authorization.current.intentDigest limb
  else if role < 30 then
    if authSlotActive witness.authorization (role - 24) = 1 then
      wordAt (witness.authorization.policySignerTags.getD (role - 24) []) limb
    else sourceUnitWord limb
  else sourceUnitWord limb

/-- First nonzero limb. The impossible-all-zero case totalizes to 6; no admission is inferred. -/
def sourceRoleSelector (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (role : Nat) : Nat :=
  if sourceRoleWord statement witness hashes role 0 ≠ 0 then 0
  else if sourceRoleWord statement witness hashes role 1 ≠ 0 then 1
  else if sourceRoleWord statement witness hashes role 2 ≠ 0 then 2
  else if sourceRoleWord statement witness hashes role 3 ≠ 0 then 3
  else if sourceRoleWord statement witness hashes role 4 ≠ 0 then 4
  else if sourceRoleWord statement witness hashes role 5 ≠ 0 then 5 else 6

def sourceRoleInverse (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (role : Nat) : Nat :=
  fieldInverse (sourceRoleWord statement witness hashes role
    (sourceRoleSelector statement witness hashes role))

theorem source_stable_pairs_exact :
    sourceStablePairs = [(0,1),(0,2),(0,3),(0,4),(1,2),(1,3),(1,4),(2,3),(2,4),(3,4)] := by decide

theorem source_role_selector_bound (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (role : Nat) :
    sourceRoleSelector statement witness hashes role < 7 := by
  unfold sourceRoleSelector
  split_ifs <;> decide

theorem source_inverse_canonical (value : Nat) : fieldInverse value < fieldModulus := by
  unfold fieldInverse
  split_ifs
  · decide
  · exact Nat.mod_lt _ (by decide)

theorem source_role_inverse_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (role : Nat) :
    sourceRoleInverse statement witness hashes role < fieldModulus :=
  source_inverse_canonical _

theorem source_unused_roles_unit (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (role limb : Nat) (unused : 30 ≤ role) :
    sourceRoleWord statement witness hashes role limb = sourceUnitWord limb := by
  simp only [sourceRoleWord, if_neg (show ¬role < 21 by omega),
    if_neg (show ¬role = 21 by omega), if_neg (show ¬role = 22 by omega),
    if_neg (show ¬role = 23 by omega), if_neg (show ¬role < 30 by omega)]

theorem source_unused_selector_zero (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (role : Nat) (unused : 30 ≤ role) :
    sourceRoleSelector statement witness hashes role = 0 := by
  unfold sourceRoleSelector
  rw [source_unused_roles_unit statement witness hashes role 0 unused]
  have unit : sourceUnitWord 0 = 1 := rfl
  rw [unit, if_pos (by decide : (1 : Nat) ≠ 0)]

theorem source_unused_inverse_one (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (role : Nat) (unused : 30 ≤ role) :
    sourceRoleInverse statement witness hashes role = 1 := by
  unfold sourceRoleInverse
  rw [source_unused_roles_unit statement witness hashes role _ unused,
    source_unused_selector_zero statement witness hashes role unused]
  change fieldInverse 1 = 1
  have normalized : fieldNormalize 1 = 1 := by decide
  rw [fieldInverse, normalized, if_neg (by decide : ¬(1 : Nat) = 0), one_pow, normalized]

theorem source_disabled_stable_roles_unit (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) (disabled : stablePublic.direction = .disabled)
    (role limb : Nat) : sourceStableRoleWord stablePublic witness role limb = sourceUnitWord limb := by
  simp only [sourceStableRoleWord, if_pos disabled]


end HegemonCrypto.SmallWood.V8Smz9SourceStableTail

