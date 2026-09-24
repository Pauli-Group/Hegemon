import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewGames

/-! Exact batching of every source leaf. The fresh tape for each indexed
leaf is sampled before its digest, and every programmed point remains in the
oracle passed to the continuation. Product-coin rearrangement recovers the
source's eager tape-vector sampling, including on aborting continuations. -/

namespace HegemonCrypto.SmallWood.V8Smz9HonestLeafBatch

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9HonestWholeViewGames
open V8Smz9EagerPrivacy
open V8Smz9EagerOracleGame
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Other Work : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]

theorem uniform_average_product {A B : Type} [Fintype A] [Nonempty A]
    [Fintype B] [Nonempty B] (value : A → B → ℝ) :
    uniformAverage (fun pair : A × B => value pair.1 pair.2) =
      uniformAverage (fun a => uniformAverage (value a)) := by
  unfold uniformAverage
  simp only [uniformFintypePMF_apply, Fintype.card_prod, Nat.cast_mul,
    ENNReal.toReal_inv, ENNReal.toReal_mul, mul_inv_rev, Fintype.sum_prod_type, Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro a _
  apply Finset.sum_congr rfl
  intro b _
  ring

def splitCoins (A : Type) (count : Nat) :
    (Fin (count + 1) → A) ≃ A × (Fin count → A) where
  toFun := fun coins => (coins 0, fun i => coins i.succ)
  invFun := fun pair => Fin.cons pair.1 pair.2
  left_inv := by intro coins; funext i; exact Fin.cases rfl (fun _ => rfl) i
  right_inv := by intro pair; rfl

theorem uniform_average_fin_cons {A : Type} [Fintype A] [Nonempty A]
    (count : Nat) (value : (Fin (count + 1) → A) → ℝ) :
    uniformAverage value =
      uniformAverage (fun head : A => uniformAverage (fun tail : Fin count → A =>
        value (Fin.cons head tail))) := by
  rw [← uniform_average_equiv (splitCoins A count).symm value]
  exact uniform_average_product (fun head tail => value (Fin.cons head tail))

/-- Sequential persistent table updates. This is a computed table, not an
assumed endpoint correspondence. -/
def updateBatch : (count : Nat) → (Fin count → LeafInput ⊕ Other) →
    (Fin count → DigestRegister) → ((LeafInput ⊕ Other) → DigestRegister) →
    (LeafInput ⊕ Other) → DigestRegister
  | 0, _, _, oracle => oracle
  | count + 1, inputs, outputs, oracle =>
      updateBatch count (fun i => inputs i.succ) (fun i => outputs i.succ)
        (Function.update oracle (inputs 0) (outputs 0))

/-- No adversarial interleaving occurs inside this atomic honest batch.
The arbitrary continuation may include failure, later requests and queries. -/
def sourceLeafBatch : (count : Nat) → (Fin count → LeafIndex) →
    (Fin count → LeafHeader) → (Fin count → LeafSuffix) →
    ((Fin count → LeafTape) → (Fin count → DigestRegister) →
      Program (LeafInput ⊕ Other) Work) → Program (LeafInput ⊕ Other) Work
  | 0, _, _, _, next => next Fin.elim0 Fin.elim0
  | count + 1, indices, headers, payloads, next =>
      sourceLeaf (headers 0) (payloads 0) (indices 0) fun tape output =>
        sourceLeafBatch count (fun i => indices i.succ) (fun i => headers i.succ)
          (fun i => payloads i.succ) fun tapes outputs =>
            next (Fin.cons tape tapes) (Fin.cons output outputs)

omit [DecidableEq Other] in
theorem source_leaf_batch_mass (count : Nat) (indices : Fin count → LeafIndex)
    (headers : Fin count → LeafHeader) (payloads : Fin count → LeafSuffix)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) →
      Program (LeafInput ⊕ Other) Work)
    (remaining : ∀ tapes outputs, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next tapes outputs)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
      (sourceLeafBatch count indices headers payloads next) := by
  induction count with
  | zero => exact remaining _ _
  | succ count ih =>
      apply source_leaf_preserves_input_mass_bound
      intro tape output
      exact ih _ _ _ _ (fun tapes outputs => remaining _ _)

theorem source_leaf_batch_honest_execution (count : Nat)
    (indices : Fin count → LeafIndex) (headers : Fin count → LeafHeader)
    (payloads : Fin count → LeafSuffix)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) →
      Program (LeafInput ⊕ Other) Work)
    (oracle : (LeafInput ⊕ Other) → DigestRegister)
    (state : GameState (Input := LeafInput ⊕ Other) (Work := Work)) :
    run false (sourceLeafBatch count indices headers payloads next) oracle state =
      uniformAverage (fun tapes : Fin count → LeafTape =>
        run false (next tapes (fun i => oracle (Sum.inl
          (sourceLeafInput (headers i) (payloads i) (indices i) (tapes i))))) oracle state) := by
  induction count with
  | zero =>
      have empty : ∀ tapes : Fin 0 → LeafTape, tapes = Fin.elim0 := fun _ => Subsingleton.elim _ _
      simp only [sourceLeafBatch, empty, uniform_average_const]
      congr 2
      exact Subsingleton.elim _ _
  | succ count ih =>
      rw [sourceLeafBatch, source_leaf_honest_execution]
      conv_rhs => rw [uniform_average_fin_cons count]
      apply congrArg uniformAverage
      funext tape
      rw [ih]
      apply congrArg uniformAverage
      funext tapes
      congr 2
      funext i
      exact Fin.cases rfl (fun _ => rfl) i

theorem source_leaf_batch_randomized_execution (count : Nat)
    (indices : Fin count → LeafIndex) (headers : Fin count → LeafHeader)
    (payloads : Fin count → LeafSuffix)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) →
      Program (LeafInput ⊕ Other) Work)
    (oracle : (LeafInput ⊕ Other) → DigestRegister)
    (state : GameState (Input := LeafInput ⊕ Other) (Work := Work)) :
    run true (sourceLeafBatch count indices headers payloads next) oracle state =
      uniformAverage (fun tapes : Fin count → LeafTape =>
        uniformAverage (fun outputs : Fin count → DigestRegister =>
          run true (next tapes outputs)
            (updateBatch count (fun i => Sum.inl
              (sourceLeafInput (headers i) (payloads i) (indices i) (tapes i))) outputs oracle) state)) := by
  induction count generalizing oracle with
  | zero =>
      have tapes : ∀ xs : Fin 0 → LeafTape, xs = Fin.elim0 := fun _ => Subsingleton.elim _ _
      have outputs : ∀ xs : Fin 0 → DigestRegister, xs = Fin.elim0 := fun _ => Subsingleton.elim _ _
      simp only [sourceLeafBatch, updateBatch, tapes, outputs, uniform_average_const]
  | succ count ih =>
      rw [sourceLeafBatch, source_leaf_randomized_execution]
      conv_rhs => rw [uniform_average_fin_cons count]
      apply congrArg uniformAverage
      funext tape
      simp_rw [ih]
      rw [uniform_average_comm]
      apply congrArg uniformAverage
      funext tapes
      conv_rhs => rw [uniform_average_fin_cons count]
      apply congrArg uniformAverage
      funext output
      apply congrArg uniformAverage
      funext outputs
      rfl

omit [Fintype Other] in
theorem update_batch_outside (count : Nat)
    (inputs : Fin count → LeafInput ⊕ Other) (outputs : Fin count → DigestRegister)
    (oracle : (LeafInput ⊕ Other) → DigestRegister) (input : LeafInput ⊕ Other)
    (outside : ∀ i, input ≠ inputs i) :
    updateBatch count inputs outputs oracle input = oracle input := by
  induction count generalizing oracle with
  | zero => rfl
  | succ count ih =>
      rw [updateBatch, ih _ _ _ (fun i => outside i.succ)]
      exact Function.update_of_ne (outside 0) _ _

omit [Fintype Other] in
theorem update_batch_at (count : Nat)
    (inputs : Fin count → LeafInput ⊕ Other) (outputs : Fin count → DigestRegister)
    (oracle : (LeafInput ⊕ Other) → DigestRegister) (distinct : Function.Injective inputs)
    (i : Fin count) : updateBatch count inputs outputs oracle (inputs i) = outputs i := by
  induction count generalizing oracle with
  | zero => exact Fin.elim0 i
  | succ count ih =>
      refine Fin.cases ?_ (fun i => ?_) i
      · rw [updateBatch, update_batch_outside]
        · exact Function.update_self _ _ _
        · intro i same
          have impossible := distinct same
          exact Fin.succ_ne_zero _ impossible.symm
      · exact ih _ _ _ (fun a b same => Fin.succ_injective _ (distinct same)) i

omit [DecidableEq Other] in
theorem source_leaf_batch_query_bound (count : Nat) (indices : Fin count → LeafIndex)
    (headers : Fin count → LeafHeader) (payloads : Fin count → LeafSuffix)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) →
      Program (LeafInput ⊕ Other) Work) (queries : Nat)
    (remaining : ∀ tapes outputs, queryCount (next tapes outputs) ≤ queries) :
    queryCount (sourceLeafBatch count indices headers payloads next) ≤ count + queries := by
  induction count with
  | zero => simpa only [sourceLeafBatch, Nat.zero_add] using remaining Fin.elim0 Fin.elim0
  | succ count ih =>
      change (Finset.univ.sup fun tape : LeafTape => Finset.univ.sup fun output : DigestRegister =>
        queryCount (sourceLeafBatch count (fun i => indices i.succ) (fun i => headers i.succ)
          (fun i => payloads i.succ) fun tapes outputs =>
            next (Fin.cons tape tapes) (Fin.cons output outputs))) + 1 ≤ count + 1 + queries
      have bounded : (Finset.univ.sup fun tape : LeafTape => Finset.univ.sup fun output : DigestRegister =>
        queryCount (sourceLeafBatch count (fun i => indices i.succ) (fun i => headers i.succ)
          (fun i => payloads i.succ) fun tapes outputs =>
            next (Fin.cons tape tapes) (Fin.cons output outputs))) ≤ count + queries := by
        apply Finset.sup_le
        intro tape _
        apply Finset.sup_le
        intro output _
        exact ih _ _ _ _ (fun tapes outputs => remaining _ _)
      omega

omit [DecidableEq Other] in
theorem source_leaf_batch_program_bound (count : Nat) (indices : Fin count → LeafIndex)
    (headers : Fin count → LeafHeader) (payloads : Fin count → LeafSuffix)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) →
      Program (LeafInput ⊕ Other) Work) (programs : Nat)
    (remaining : ∀ tapes outputs, programmingCount (next tapes outputs) ≤ programs) :
    programmingCount (sourceLeafBatch count indices headers payloads next) ≤ count + programs := by
  induction count with
  | zero => simpa only [sourceLeafBatch, Nat.zero_add] using remaining Fin.elim0 Fin.elim0
  | succ count ih =>
      change (Finset.univ.sup fun tape : LeafTape => Finset.univ.sup fun output : DigestRegister =>
        programmingCount (sourceLeafBatch count (fun i => indices i.succ) (fun i => headers i.succ)
          (fun i => payloads i.succ) fun tapes outputs =>
            next (Fin.cons tape tapes) (Fin.cons output outputs))) + 1 ≤ count + 1 + programs
      have bounded : (Finset.univ.sup fun tape : LeafTape => Finset.univ.sup fun output : DigestRegister =>
        programmingCount (sourceLeafBatch count (fun i => indices i.succ) (fun i => headers i.succ)
          (fun i => payloads i.succ) fun tapes outputs =>
            next (Fin.cons tape tapes) (Fin.cons output outputs))) ≤ count + programs := by
        apply Finset.sup_le
        intro tape _
        apply Finset.sup_le
        intro output _
        exact ih _ _ _ _ (fun tapes outputs => remaining _ _)
      omega

attribute [irreducible] updateBatch sourceLeafBatch

omit [Fintype Other] [DecidableEq Other] in
theorem source_leaf_inputs_distinct (headers : LeafIndex → LeafHeader)
    (payloads : LeafIndex → LeafSuffix) (tapes : LeafIndex → LeafTape) :
    Function.Injective (fun i => (Sum.inl
      (sourceLeafInput (headers i) (payloads i) i (tapes i)) : LeafInput ⊕ Other)) := by
  intro left right same
  have raw := Sum.inl.inj same
  have indices := congrArg rawInputIndex raw
  simpa only [source_leaf_index_projection] using indices

/-! The finite-sequence lemma keeps the sequence length symbolic in its
kernel proof. The actual full source instance is obtained without evaluating
the 2^23-step recursive program. -/

omit [Fintype Other] in
theorem source_updates_are_full_overlay (count : Nat) (indices : Fin count → LeafIndex)
    (distinct : Function.Injective indices) (programmed : Finset LeafIndex)
    (covered : ∀ index, index ∈ programmed ↔ ∃ i, indices i = index)
    (headers : LeafIndex → LeafHeader) (payloads : LeafIndex → LeafSuffix)
    (tapes : LeafIndex → LeafTape) (outputs : LeafIndex → DigestRegister)
    (oracle : (LeafInput ⊕ Other) → DigestRegister) :
    updateBatch count (fun i => Sum.inl
      (sourceLeafInput (headers (indices i)) (payloads (indices i)) (indices i) (tapes (indices i))))
      (fun i => outputs (indices i)) oracle =
      fullSourceOverlay (fun input => oracle (Sum.inl input))
        (fun input => oracle (Sum.inr input)) outputs programmed headers payloads tapes := by
  funext input
  cases input with
  | inl input =>
      by_cases present : input ∈ sourcePatchSupport programmed headers payloads tapes
      · have indexed : ∃ index, index ∈ programmed ∧
            sourceLeafInput (headers index) (payloads index) index (tapes index) = input := by
          exact Finset.mem_image.mp present
        obtain ⟨index, member, same⟩ := indexed
        obtain ⟨i, rfl⟩ := (covered index).mp member
        have result := update_batch_at count
          (fun i => (Sum.inl (sourceLeafInput (headers (indices i)) (payloads (indices i))
            (indices i) (tapes (indices i))) : LeafInput ⊕ Other))
          (fun i => outputs (indices i)) oracle
          ((source_leaf_inputs_distinct headers payloads tapes).comp distinct) i
        have projected : rawInputIndex input = indices i := by
          rw [← same]
          exact source_leaf_index_projection _ _ _ _
        rw [same] at result
        exact result.trans (by simp only [fullSourceOverlay, Sum.elim_inl, sourceOverlay,
          if_pos present, projected])
      · have outside : ∀ i : Fin count, (Sum.inl input : LeafInput ⊕ Other) ≠
            Sum.inl (sourceLeafInput (headers (indices i)) (payloads (indices i))
              (indices i) (tapes (indices i))) := by
          intro i same
          apply present
          exact Finset.mem_image.mpr ⟨indices i, (covered _).mpr ⟨i, rfl⟩, (Sum.inl.inj same).symm⟩
        exact (update_batch_outside count _ _ oracle (Sum.inl input) outside).trans
          (by simp only [fullSourceOverlay, Sum.elim_inl, sourceOverlay, if_neg present])
  | inr input =>
      exact update_batch_outside count _ _ oracle (Sum.inr input) (fun _ => Sum.inr_ne_inl)

omit [Fintype Other] in
theorem all_source_updates_are_full_overlay
    (headers : LeafIndex → LeafHeader) (payloads : LeafIndex → LeafSuffix)
    (tapes : LeafIndex → LeafTape) (outputs : LeafIndex → DigestRegister)
    (oracle : (LeafInput ⊕ Other) → DigestRegister) :
    updateBatch 8388608 (fun i => Sum.inl
      (sourceLeafInput (headers i) (payloads i) i (tapes i))) outputs oracle =
      fullSourceOverlay (fun input => oracle (Sum.inl input))
        (fun input => oracle (Sum.inr input)) outputs Finset.univ headers payloads tapes :=
  source_updates_are_full_overlay 8388608 id Function.injective_id Finset.univ
    (fun index => ⟨fun _ => ⟨index, rfl⟩, fun _ => Finset.mem_univ _⟩)
    headers payloads tapes outputs oracle

/-- The actual source batch, with the original joint Q/M masks and the
physical source serializer at all 2^23 leaves. -/
def allCurrentSourceLeaves
    (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes)
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      Program (LeafInput ⊕ Other) Work) : Program (LeafInput ⊕ Other) Work :=
  sourceLeafBatch 8388608 id (fun _ => canonicalLeafHeader salt)
    (fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2) next

end
end HegemonCrypto.SmallWood.V8Smz9HonestLeafBatch
