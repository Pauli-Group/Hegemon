import HegemonCrypto.SmallWoodV8Smz9DynamicTransport
import HegemonCrypto.SmallWoodV8Smz9HonestFutureCompiler

/-! Worst-branch raw read counts for the actual source request prefix.
Every exhausted sampler and every future branch is charged. These are
syntactic interpreter bounds, not an operational Rust refinement theorem. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceQueryBudget

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9HonestWholeViewGames V8Smz9HonestRequestSchedule V8Smz9HonestLeafBatch
open V8Smz9HonestFinalGame V8Smz9DynamicRequest V8Smz9DynamicTransport
open V8Smz9HonestFutureCompiler V8Smz9HiddenLeafQrom V8Smz9RawCounterCompiler
open V8Smz9EagerPrivacy V8Smz9RuntimeRandomness V8Smz9CurrentPublicContext
open V8Smz9RuntimeFieldLayout V8Smz9WholeViewObservation
open V8Smz9EagerOracleGame V8Smz9CurrentPrivacyGame V8Smz9HonestHybrid V8Smz9ZeroKnowledge
open V8Smz9HiddenPatch
open scoped Classical

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Other Result Next : Type}

theorem nonleaf_read_count_bind_le (program : NonleafProgram Other Result)
    (next : Result → NonleafProgram Other Next) (bound : Nat)
    (remaining : ∀ result, NonleafProgram.readCount (next result) ≤ bound) :
    NonleafProgram.readCount (NonleafProgram.bind program next) ≤
      NonleafProgram.readCount program + bound := by
  induction program with
  | done result => simpa only [NonleafProgram.bind, NonleafProgram.readCount, Nat.zero_add] using remaining result
  | read input rest ih =>
      change (Finset.univ.sup fun output => NonleafProgram.readCount (NonleafProgram.bind (rest output) next)) + 1 ≤
        (Finset.univ.sup fun output => NonleafProgram.readCount (rest output)) + 1 + bound
      have bounded : (Finset.univ.sup fun output => NonleafProgram.readCount (NonleafProgram.bind (rest output) next)) ≤
          (Finset.univ.sup fun output => NonleafProgram.readCount (rest output)) + bound := by
        apply Finset.sup_le
        intro output member
        exact (ih output).trans (Nat.add_le_add_right
          (Finset.le_sup (f := fun output => NonleafProgram.readCount (rest output)) member) bound)
      omega

theorem nonleaf_read_count_map_le (program : NonleafProgram Other Result) (f : Result → Next) :
    NonleafProgram.readCount (NonleafProgram.bind program (fun result => .done (f result))) ≤
      NonleafProgram.readCount program := by
  simpa only [Nat.add_zero] using nonleaf_read_count_bind_le program (fun result => .done (f result))
    0 (by intro result; exact Nat.le_refl 0)

theorem nonleaf_read_count_read_le (input : Other)
    (next : DigestRegister → NonleafProgram Other Result) (bound : Nat)
    (remaining : ∀ output, NonleafProgram.readCount (next output) ≤ bound) :
    NonleafProgram.readCount (.read input next) ≤ bound + 1 := by
  exact Nat.add_le_add_right (Finset.sup_le fun output _ => remaining output) 1

section Compiled
variable {Work : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]

omit [DecidableEq Other] in
theorem compiled_nonleaf_query_bound (program : NonleafProgram Other Result)
    (next : Result → Program (LeafInput ⊕ Other) Work) (queries : Nat)
    (remaining : ∀ result, queryCount (next result) ≤ queries) :
    queryCount (NonleafProgram.compile program next) ≤ NonleafProgram.readCount program + queries := by
  induction program with
  | done result => simpa only [NonleafProgram.compile, NonleafProgram.readCount, Nat.zero_add] using remaining result
  | read input rest ih =>
      change (Finset.univ.sup fun output => queryCount (NonleafProgram.compile (rest output) next)) + 1 ≤
        (Finset.univ.sup fun output => NonleafProgram.readCount (rest output)) + 1 + queries
      have bounded : (Finset.univ.sup fun output => queryCount (NonleafProgram.compile (rest output) next)) ≤
          (Finset.univ.sup fun output => NonleafProgram.readCount (rest output)) + queries := by
        apply Finset.sup_le
        intro output member
        exact (ih output).trans (Nat.add_le_add_right
          (Finset.le_sup (f := fun output => NonleafProgram.readCount (rest output)) member) queries)
      omega

omit [DecidableEq Other] in
theorem compiled_nonleaf_program_bound (program : NonleafProgram Other Result)
    (next : Result → Program (LeafInput ⊕ Other) Work) (programs : Nat)
    (remaining : ∀ result, programmingCount (next result) ≤ programs) :
    programmingCount (NonleafProgram.compile program next) ≤ programs := by
  induction program with
  | done result => exact remaining result
  | read input rest ih => exact Finset.sup_le fun output _ => ih output

end Compiled

attribute [local irreducible] sourceParentLevel sourceMerkleLevels allSourceMerkleLevels sourceFieldXof

theorem source_parent_level_read_bound (bound : Nat) (largeEnough : 249 ≤ bound)
    (count : Nat) (labels : Fin (2 * count) → DigestRegister) :
    NonleafProgram.readCount (sourceParentLevel bound largeEnough count labels) ≤ count := by
  induction count with
  | zero => simp only [sourceParentLevel, NonleafProgram.readCount, Nat.le_refl]
  | succ count ih =>
      rw [sourceParentLevel]
      apply nonleaf_read_count_read_le
      intro parent
      exact (nonleaf_read_count_map_le _ _).trans (ih _)

theorem source_merkle_levels_read_bound (bound : Nat) (largeEnough : 249 ≤ bound)
    (depth : Nat) (labels : Fin (2 ^ depth) → DigestRegister) :
    NonleafProgram.readCount (sourceMerkleLevels bound largeEnough depth labels) ≤ 2 ^ depth - 1 := by
  induction depth with
  | zero => simp only [sourceMerkleLevels, NonleafProgram.readCount]; norm_num
  | succ depth ih =>
      rw [sourceMerkleLevels]
      let childLabels : Fin (2 * 2 ^ depth) → DigestRegister :=
        fun i => labels ⟨i.val, by simpa only [pow_succ, Nat.mul_comm] using i.isLt⟩
      have combined := nonleaf_read_count_bind_le
        (sourceParentLevel bound largeEnough (2 ^ depth) childLabels)
        (fun parents => NonleafProgram.bind (sourceMerkleLevels bound largeEnough depth parents)
          (fun result => .done (result.1, List.ofFn labels :: result.2)))
        (2 ^ depth - 1)
        (by intro parents; exact (nonleaf_read_count_map_le _ _).trans (ih parents))
      have parent := source_parent_level_read_bound bound largeEnough (2 ^ depth) childLabels
      dsimp only [childLabels] at combined parent
      have positive : 0 < 2 ^ depth := by positivity
      have power : 2 ^ (depth + 1) = 2 ^ depth * 2 := pow_succ _ _
      omega

theorem all_source_merkle_read_bound (bound : Nat) (largeEnough : 249 ≤ bound)
    (labels : LeafIndex → DigestRegister) :
    NonleafProgram.readCount (allSourceMerkleLevels bound largeEnough labels) ≤ 8388607 := by
  unfold allSourceMerkleLevels
  exact source_merkle_levels_read_bound bound largeEnough 23 labels

theorem prefinal_shape_dynamic_read_bound (shape : PrefinalShape Other)
    (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks)
    (decsBound piopBound : Nat)
    (decs : ∀ digest, NonleafProgram.readCount (shape.decs digest) ≤ decsBound)
    (piop : ∀ digest, NonleafProgram.readCount (shape.piop digest) ≤ piopBound) :
    NonleafProgram.readCount (shape.dynamic respond) ≤
      NonleafProgram.readCount shape.build + (decsBound + (piopBound + 1 + 1) + 1) := by
  unfold PrefinalShape.dynamic
  apply nonleaf_read_count_bind_le
  intro built
  apply nonleaf_read_count_read_le
  intro firstHash
  let nextGamma : Option (List FieldWord) → NonleafProgram Other
      (PrefinalResult × DecsFullCoefficients Goldilocks) := fun gamma =>
    .read (shape.rootKey built.1) fun hashMt =>
      .read (shape.piopKey hashMt (respond gamma)) fun hashFpp =>
        NonleafProgram.bind (shape.piop hashFpp) fun batching =>
          .done (⟨built.2, hashMt, gamma, hashFpp, batching⟩, respond gamma)
  have bound := nonleaf_read_count_bind_le (shape.decs firstHash) nextGamma (piopBound + 1 + 1)
    (by
      intro gamma
      apply nonleaf_read_count_read_le
      intro hashMt
      apply nonleaf_read_count_read_le
      intro hashFpp
      exact (nonleaf_read_count_map_le _ _).trans (piop hashFpp))
  exact bound.trans (Nat.add_le_add_right (decs firstHash) _)

theorem source_gamma_all_rows_digest_cap (retainedRows : Nat) (bounded : retainedRows ≤ 20605) :
    digestCallCap (sourceGammaWordRequest retainedRows) ≤ 12883 := by
  unfold sourceGammaWordRequest digestCallCap
  split <;> omega

theorem source_dynamic_prefinal_read_bound (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605) :
    NonleafProgram.readCount (sourceDynamicPrefinal bound largeEnough statementBinding bindingFits
      salt labels respond retainedRows rowBound) ≤ 8401585 := by
  rw [source_dynamic_prefinal_is_shape]
  have boundCount := prefinal_shape_dynamic_read_bound
    (sourcePrefinalShape bound largeEnough statementBinding bindingFits salt labels retainedRows rowBound)
    respond 92 12883
    (by intro digest; exact source_field_xof_query_bound _ _ _ _ _ 700 _)
    (by intro digest; exact (source_field_xof_query_bound _ _ _ _ _ _ _).trans
          (source_gamma_all_rows_digest_cap retainedRows rowBound))
  have tree := all_source_merkle_read_bound bound (by omega) labels
  change NonleafProgram.readCount (allSourceMerkleLevels bound (by omega) labels) + _ ≥ _ at boundCount
  omega


section ActualPrefix
variable {Work : Type} [Fintype Work]
variable (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)

theorem source_computed_prefix_query_bound (labels : LeafIndex → DigestRegister)
    (next : PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (queries : Nat)
    (remaining : ∀ stageResult response transcript digest pending,
      queryCount (next stageResult response transcript digest pending) ≤ queries) :
    queryCount (sourceComputedPrefix bound largeEnough statementBinding bindingFits statement values
      base masks salt labels retainedRows rowBound next) ≤ 8401586 + queries := by
  unfold sourceComputedPrefix
  apply Nat.le_trans (m := NonleafProgram.readCount
    (sourceDynamicPrefinal bound largeEnough statementBinding bindingFits salt labels
      (sourceComputedDecsResponse values base masks) retainedRows rowBound) + (queries + 1))
  · apply compiled_nonleaf_query_bound
    intro computed
    exact Nat.add_le_add_right (Finset.sup_le fun digest _ => remaining _ _ _ digest _) 1
  · have readBound := source_dynamic_prefinal_read_bound bound largeEnough statementBinding bindingFits
      salt labels (sourceComputedDecsResponse values base masks) retainedRows rowBound
    omega

theorem source_computed_prefix_program_bound (labels : LeafIndex → DigestRegister)
    (next : PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (programs : Nat)
    (remaining : ∀ stageResult response transcript digest pending,
      programmingCount (next stageResult response transcript digest pending) ≤ programs) :
    programmingCount (sourceComputedPrefix bound largeEnough statementBinding bindingFits statement values
      base masks salt labels retainedRows rowBound next) ≤ programs := by
  unfold sourceComputedPrefix
  apply compiled_nonleaf_program_bound
  intro computed
  exact Finset.sup_le fun digest _ => remaining _ _ _ digest _

theorem source_all_leaves_computed_prefix_query_bound
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (queries : Nat)
    (remaining : ∀ tapes labels stageResult response transcript digest pending,
      queryCount (next tapes labels stageResult response transcript digest pending) ≤ queries) :
    queryCount (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits statement
      values base masks salt retainedRows rowBound next) ≤ 16790194 + queries := by
  unfold sourceAllLeavesThenComputedPrefix allCurrentSourceLeaves
  apply Nat.le_trans (m := 8388608 + (8401586 + queries))
  · apply source_leaf_batch_query_bound
    intro tapes labels
    exact source_computed_prefix_query_bound bound largeEnough statementBinding bindingFits statement
      values base masks salt retainedRows rowBound labels (next tapes labels) queries (remaining tapes labels)
  · omega

theorem source_all_leaves_computed_prefix_program_bound
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (programs : Nat)
    (remaining : ∀ tapes labels stageResult response transcript digest pending,
      programmingCount (next tapes labels stageResult response transcript digest pending) ≤ programs) :
    programmingCount (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits statement
      values base masks salt retainedRows rowBound next) ≤ 8388608 + programs := by
  unfold sourceAllLeavesThenComputedPrefix allCurrentSourceLeaves
  apply source_leaf_batch_program_bound
  intro tapes labels
  exact source_computed_prefix_program_bound bound largeEnough statementBinding bindingFits statement
    values base masks salt retainedRows rowBound labels (next tapes labels) programs (remaining tapes labels)

/-- Later fresh-input operations are sampled ordinary reads, so only the
current request's 2^23 leaf events are selected. Their complete future is still
charged in `queries`, including every error and measurement branch. -/
theorem source_leaf_reprogramming_with_honest_future_bound
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (initial : GameState (Input := FullRawInput bound) (Work := Work))
    (queries : Nat) (normalized : ‖initial‖ = 1)
    (remaining : ∀ tapes labels stageResult response transcript digest pending,
      queryCount (next tapes labels stageResult response transcript digest pending) ≤ queries) :
    let current := sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits statement
      values base masks salt retainedRows rowBound (fun tapes labels stageResult response transcript digest pending =>
        honestizeFreshInputs (next tapes labels stageResult response transcript digest pending))
    |acceptance true current initial - acceptance false current initial| ≤
      (8388608 : ℝ) * (Real.sqrt (((16790194 + queries : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹) +
        ((16790194 + queries : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) := by
  apply source_all_leaves_computed_prefix_reprogramming_bound (ghhm := ghhm)
  · intros
    exact honestized_input_mass_bound _ _
  · exact normalized
  · apply source_all_leaves_computed_prefix_query_bound
    intros
    rw [honestized_query_count]
    exact remaining _ _ _ _ _ _ _
  · simpa only [Nat.add_zero] using
      source_all_leaves_computed_prefix_program_bound bound largeEnough statementBinding bindingFits statement
        values base masks salt retainedRows rowBound
        (fun tapes labels stageResult response transcript digest pending =>
          honestizeFreshInputs (next tapes labels stageResult response transcript digest pending))
        0 (by intros; exact Nat.le_of_eq (honestized_programming_count_zero _))

end ActualPrefix


end
end HegemonCrypto.SmallWood.V8Smz9SourceQueryBudget
