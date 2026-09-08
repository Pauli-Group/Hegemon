import HegemonCrypto.SmallWoodV8Smz9SourceStableDigestForward

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableStateForward
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceStablePathFrames
open HegemonCrypto.SmallWood.V8Smz9SourceStableLeafFrames
open HegemonCrypto.SmallWood.V8Smz9SourceStableIssuerFrames
open HegemonCrypto.SmallWood.V8Smz9SourceStableDigestForward
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
attribute [local irreducible] Poseidon2Width16Kernel.permutation poseidon2V8Compress14

def typedCounters (statement : V8PublicStatement) (witness : V8Witness) (which : Nat) :
    V8StablecoinCounters :=
  if which=0 then decodeV8StablecoinBefore witness.stablecoin else statement.stablecoin.after

theorem scheduled_stable_leaf_digest (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) :
    finalDigest (scheduledFinal statement witness) (113+which.val) =
      exactV8StablecoinLeaf (statement.stablecoin.assetId%16)
        (exactV8StablecoinConfigDigest (decodeV8StablecoinConfig witness.stablecoin))
        (typedCounters statement witness which.val) := by
  have leaf := scheduled_compress_digest statement witness valid ⟨113+which.val,by omega⟩ _ _ _
    (actual_stable_leaf_frame statement witness which)
  change finalDigest (scheduledFinal statement witness) (113+which.val) = _ at leaf
  rw [leaf,scheduled_config_digest statement witness valid]
  fin_cases which <;>
    simp [exactV8StablecoinLeaf,typedCounters,stableLeafRight,sourceCounterWords,
      stableBeforeWords,stableWitnessSlice,decodeV8StablecoinBefore,List.range_succ]

def sourceStateStep (statement : V8PublicStatement) (witness : V8Witness)
    (current : List Nat) (level : Nat) : List Nat :=
  if (statement.stablecoin.assetId%16/2^level)%2=0 then
    poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level) current (stableSibling witness level)
  else poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level) (stableSibling witness level) current

theorem scheduled_stable_path_digest (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (level : Fin 4) (which : Fin 2) :
    finalDigest (scheduledFinal statement witness) (115+2*level.val+which.val) =
      sourceStateStep statement witness
        (finalDigest (scheduledFinal statement witness) (113+2*level.val+which.val)) level.val := by
  have path := scheduled_compress_digest statement witness valid ⟨115+2*level.val+which.val,by omega⟩ _ _ _
    (actual_stable_path_frame statement witness level which)
  change finalDigest (scheduledFinal statement witness) (115+2*level.val+which.val) = _ at path
  rw [path,orient_is_source_bit,stable_asset_mask_exact]
  by_cases bit : (statement.stablecoin.assetId%16/2^level.val)%2=0
  all_goals simp only [sourceStateStep,bit,↓reduceIte]

theorem scheduled_stable_state_fold (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2)
    (count : Nat) (bound : count ≤ 4) :
    finalDigest (scheduledFinal statement witness) (113+2*count+which.val) =
      (List.range count).foldl (sourceStateStep statement witness)
        (exactV8StablecoinLeaf (statement.stablecoin.assetId%16)
          (exactV8StablecoinConfigDigest (decodeV8StablecoinConfig witness.stablecoin))
          (typedCounters statement witness which.val)) := by
  induction count with
  | zero => simpa only [Nat.mul_zero,Nat.add_zero,List.range_zero,List.foldl_nil] using
      scheduled_stable_leaf_digest statement witness valid which
  | succ count ih =>
    have prior := ih (by omega)
    rw [List.range_succ,List.foldl_append,List.foldl_cons,List.foldl_nil,← prior]
    rw [show 113+2*(count+1)+which.val=115+2*count+which.val by omega]
    exact scheduled_stable_path_digest statement witness valid ⟨count,by omega⟩ which

theorem stable_sibling_decoded (witness : V8Witness) (level : Nat) (bound : level<4) :
    (decodeV8StablecoinSiblings witness.stablecoin).getD level [] = stableSibling witness level := by
  simp [decodeV8StablecoinSiblings,stableSibling,stablecoinV8Depth,digestWords,
    List.getD_eq_getElem?_getD,bound]

theorem state_fold_functions_agree (left right : List Nat → Nat → List Nat)
    (levels : List Nat) (initial : List Nat)
    (agree : ∀ level, level ∈ levels → ∀ state, left state level=right state level) :
    levels.foldl left initial=levels.foldl right initial := by
  induction levels generalizing initial with
  | nil => rfl
  | cons head tail ih =>
    simp only [List.foldl_cons]
    rw [agree head List.mem_cons_self initial]
    exact ih _ (by intro level member state; exact agree level (List.mem_cons_of_mem _ member) state)

theorem source_state_fold_exact (statement : V8PublicStatement) (witness : V8Witness)
    (config : List Nat) (counters : V8StablecoinCounters) :
    (List.range 4).foldl (sourceStateStep statement witness)
        (exactV8StablecoinLeaf (statement.stablecoin.assetId%16) config counters) =
      exactV8StablecoinRoot statement.stablecoin.assetId config counters
        (decodeV8StablecoinSiblings witness.stablecoin) := by
  unfold exactV8StablecoinRoot
  change _ = (List.range 4).foldl (fun current level =>
    if (statement.stablecoin.assetId%16/2^level)%2=0 then
      poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level) current
        ((decodeV8StablecoinSiblings witness.stablecoin).getD level [])
    else poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level)
      ((decodeV8StablecoinSiblings witness.stablecoin).getD level []) current)
      (exactV8StablecoinLeaf (statement.stablecoin.assetId%16) config counters)
  apply state_fold_functions_agree
  intro level member current
  rw [stable_sibling_decoded witness level (List.mem_range.mp member)]
  rfl

theorem scheduled_stable_state_root_digest (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) :
    finalDigest (scheduledFinal statement witness) (121+which.val) =
      exactV8StablecoinRoot statement.stablecoin.assetId
        (exactV8StablecoinConfigDigest (decodeV8StablecoinConfig witness.stablecoin))
        (typedCounters statement witness which.val) (decodeV8StablecoinSiblings witness.stablecoin) :=
  (scheduled_stable_state_fold statement witness valid which 4 (by decide)).trans
    (source_state_fold_exact statement witness _ _)

theorem scheduled_stable_issuer_commitment_digest (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    finalDigest (scheduledFinal statement witness) 123 =
      exactV8StablecoinIssuerCommitment statement.stablecoin.assetId statement.stablecoin.policyVersion
        (decodeV8StablecoinIssuerSecret witness.stablecoin) := by
  exact scheduled_compress_digest statement witness valid ⟨123,by decide⟩ _ _ _
    (actual_stable_issuer_frame statement witness ⟨0,by decide⟩)

theorem scheduled_stable_issuer_authorization_digest (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    finalDigest (scheduledFinal statement witness) 124 =
      exactV8StablecoinIssuerAuthorization statement.stablecoin.actionIntent
        (decodeV8StablecoinIssuerSecret witness.stablecoin) := by
  have source := scheduled_compress_digest statement witness valid ⟨124,by decide⟩ _ _ _
    (actual_stable_issuer_frame statement witness ⟨1,by decide⟩)
  change finalDigest (scheduledFinal statement witness) 124 =
    poseidon2V8Compress14 stablecoinV8DomainIssuerAuthorization
      (decodeV8StablecoinIssuerSecret witness.stablecoin) (fixedWords 7 statement.stablecoin.actionIntent) at source
  have shape : statement.stablecoin.actionIntent.length=7 := by
    obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,intent,_⟩ := valid.1
    exact intent.1
  rw [fixed_words_exact 7 _ shape] at source
  exact source

end HegemonCrypto.SmallWood.V8Smz9SourceStableStateForward
