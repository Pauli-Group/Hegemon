import HegemonCrypto.SmallWoodV8Smz9MixedFinalSourceBridge
import HegemonCrypto.SmallWoodV8Smz9MixedAdapterAccounting
import HegemonCrypto.SmallWoodV8Smz9PostFinalQueryBudget

/-! The transported final-event program has the same conservative complete
request query bound as the chronological source. Every fixed leaf write is
charged, as are all nonce/index failures and the complete future program. -/

namespace HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame V8Smz9DynamicRequest
open V8Smz9HonestHybrid V8Smz9HonestOpeningSchedule V8Smz9DynamicTransport
open V8Smz9CurrentPublicContext V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution
open V8Smz9SourceQueryBudget V8Smz9PostFinalQueryBudget V8Smz9RawCounterCompiler
open V8Smz9WholeViewObservation
open V8Smz9HonestWholeViewGames (GameState)
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

theorem prefinal_shape_fixed_read_bound {Other : Type} (shape : PrefinalShape Other)
    (response : DecsFullCoefficients Goldilocks) (decsBound piopBound : Nat)
    (decs : ∀ digest, NonleafProgram.readCount (shape.decs digest) ≤ decsBound)
    (piop : ∀ digest, NonleafProgram.readCount (shape.piop digest) ≤ piopBound) :
    NonleafProgram.readCount (shape.fixed response) ≤
      NonleafProgram.readCount shape.build + (decsBound + (piopBound + 1 + 1) + 1) := by
  unfold PrefinalShape.fixed
  apply nonleaf_read_count_bind_le
  intro built
  apply nonleaf_read_count_read_le
  intro firstHash
  let nextGamma : Option (List FieldWord) → NonleafProgram Other PrefinalResult := fun gamma =>
    .read (shape.rootKey built.1) fun hashMt =>
      .read (shape.piopKey hashMt response) fun hashFpp =>
        NonleafProgram.bind (shape.piop hashFpp) fun batching =>
          .done ⟨built.2, hashMt, gamma, hashFpp, batching⟩
  have countBound := nonleaf_read_count_bind_le (shape.decs firstHash) nextGamma (piopBound + 1 + 1)
    (by
      intro gamma
      apply nonleaf_read_count_read_le
      intro hashMt
      apply nonleaf_read_count_read_le
      intro hashFpp
      exact (nonleaf_read_count_map_le _ _).trans (piop hashFpp))
  exact countBound.trans (Nat.add_le_add_right (decs firstHash) _)

theorem source_fixed_prefinal_read_bound (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605) :
    NonleafProgram.readCount (sourcePrefinal bound largeEnough statementBinding bindingFits
      salt labels response retainedRows rowBound) ≤ 8401585 := by
  rw [source_prefinal_is_shape]
  have countBound := prefinal_shape_fixed_read_bound
    (sourcePrefinalShape bound largeEnough statementBinding bindingFits salt labels retainedRows rowBound)
    response 92 12883
    (by intro digest; unfold sourcePrefinalShape; exact source_field_xof_query_bound _ _ _ _ _ 700 (by norm_num))
    (by intro digest; unfold sourcePrefinalShape; exact (source_field_xof_query_bound _ _ _ _ _ _
          (by unfold sourceGammaWordRequest; omega)).trans
          (source_gamma_all_rows_digest_cap retainedRows rowBound))
  have tree := all_source_merkle_read_bound bound (by omega) labels
  change NonleafProgram.readCount (allSourceMerkleLevels bound (by omega) labels) + _ ≥ _ at countBound
  omega

variable {Work : Type} [Fintype Work] {bound : Nat}

theorem random_pair_query_bound (A B : Type) [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (next : A → B → MixedProgram (FullRawInput bound) Work) (queries : Nat)
    (remaining : ∀ first second, V8Smz9MixedMaskCompiler.queryCount (next first second) ≤ queries) :
    V8Smz9MixedMaskCompiler.queryCount (randomPair A B next) ≤ queries := by
  exact Finset.sup_le fun first _ => Finset.sup_le fun second _ => remaining first second

attribute [local irreducible] sourcePrefinal nonleafCompile V8Smz9MixedMaskCompiler.actualLeafWrites

theorem after_final_query_bound (context : RequestContext bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (next : ByteResult → MixedProgram (FullRawInput bound) Work)
    (queries : Nat) (remaining : ∀ bytes, V8Smz9MixedMaskCompiler.queryCount (next bytes) ≤ queries) :
    V8Smz9MixedMaskCompiler.queryCount
      (afterFinal context labels stage response transcript digest next) ≤ 8388705 + queries := by
  unfold afterFinal
  apply random_pair_query_bound
  intro base tapes
  rw [V8Smz9MixedMaskCompiler.actual_leaf_writes_query_count]
  have countBound := nonleaf_compile_query_bound
    (postFinalBytes context base stage response transcript digest tapes) next queries remaining
  have sourceBound : NonleafProgram.readCount
      (postFinalBytes context base stage response transcript digest tapes) ≤ 97 := by
    unfold postFinalBytes
    apply source_post_final_read_bound
  omega

theorem operational_request_query_bound (context : RequestContext bound)
    (next : ByteResult → MixedProgram (FullRawInput bound) Work)
    (queries : Nat) (remaining : ∀ bytes, V8Smz9MixedMaskCompiler.queryCount (next bytes) ≤ queries) :
    V8Smz9MixedMaskCompiler.queryCount (operationalRequest context next) ≤ 16790291 + queries := by
  unfold operationalRequest
  apply random_pair_query_bound
  intro labels response
  apply Nat.le_trans (m := NonleafProgram.readCount
    (sourcePrefinal bound (by have := context.largeEnough; omega) context.statementBinding context.bindingFits
      context.salt labels response context.retainedRows context.rowBound) + (8388706 + queries))
  · apply nonleaf_compile_query_bound
    intro stage
    simp only [selectedFinal, V8Smz9MixedMaskCompiler.queryCount]
    apply Nat.le_trans (m := (8388705 + queries) + 1)
    · apply Nat.add_le_add_right
      apply Finset.sup_le
      intro transcript _
      apply Finset.sup_le
      intro digest _
      exact after_final_query_bound context labels stage response transcript digest next queries remaining
    · omega
  · have sourceBound := source_fixed_prefinal_read_bound bound (by have := context.largeEnough; omega)
      context.statementBinding context.bindingFits context.salt labels response context.retainedRows context.rowBound
    omega

theorem measured_fixed_future_request_derived_query_bound (context : RequestContext bound)
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := FullRawInput bound) (Work := Work))
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (initial : GameState (Input := FullRawInput bound) (Work := Work))
    (queries : Nat) (normalized : ‖initial‖ = 1)
    (remaining : ∀ bytes, V8Smz9HonestWholeViewGames.queryCount (next bytes) ≤ queries) :
    |V8Smz9MixedMaskCompiler.acceptance true
        (operationalRequest context (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))) initial -
      V8Smz9MixedMaskCompiler.acceptance false
        (operationalRequest context (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))) initial| ≤
      Real.sqrt (((16790291 + queries : Nat) : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹) +
        ((16790291 + queries : Nat) : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹ / 2 := by
  apply measured_fixed_future_request_bound context ghhm next initial (16790291 + queries) normalized
  apply operational_request_query_bound
  intro bytes
  rw [V8Smz9MixedMaskCompiler.fixed_program_query_count]
  exact remaining bytes

end
end HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational
