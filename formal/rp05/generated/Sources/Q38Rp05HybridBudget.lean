import Q38Rp05WholePrivacy
import Q38Rp05AdaptiveScheduler
import Q38Rp05CountedNonleaf
import Q38Rp05BranchBind

/-!
# Exact output-support transport for the unchanged adaptive query budget

This is the algebraic branch-pullback step, not yet an all-hybrid budget
theorem. The remaining join must retain the cost of every arbitrary-answer
nonleaf branch; fixed-oracle equality alone does not establish a syntactic
queryCount bound. No query allowance or proof bytes are changed here.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05HybridBudget

open V8Smz9RuntimeRandomness V8Smz9EagerPrivacy V8Smz9EagerSimulator
open V8Smz9CurrentProgramOpeningBinding
open V8Smz9HiddenLeafQrom V8Smz9HonestRequestSchedule Q38MeasuredCmsNonleaf
open Q38Rp05CountedNonleaf
open Q38Rp05BranchBind
open V8SmzaMathPrivacy V8SmzaRemainingAlgebra
open Q38Rp05ChronologicalAlgebra Q38Rp05WholePrivacy
open SmzaRp05StatementNamespace SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram (certifyOpening)
open scoped BigOperators Classical

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000


abbrev SourceCoordinates (PublicBranch : Type*) :=
  RemainingCoins Goldilocks × Q × D × PublicBranch

abbrev PublicCoordinates (PublicBranch : Type*) :=
  D × PublicBranch × Q × RemainingView Goldilocks

abbrev ObservedCoordinates (PublicBranch : Type*) :=
  D × PublicBranch × Q × PartialView Goldilocks

private theorem finite_sum_product_four
    {A B C E X : Type*}
    [Fintype A] [Fintype B] [Fintype C] [Fintype E]
    [AddCommMonoid X]
    (f : A × B × C × E → X) :
    (∑ tuple : A × B × C × E, f tuple) =
      ∑ a : A, ∑ b : B, ∑ c : C, ∑ e : E, f (a, b, c, e) := by
  simp only [Fintype.sum_prod_type]

section Request
variable {PublicBranch : Type*} [Fintype PublicBranch]
variable (dsl : RelationDsl) (statement : Statement)
variable (gamma : Gamma Goldilocks) (values : WitnessPackingValues Goldilocks)
variable (parameters : D → PublicBranch → Parameters dsl statement)
variable (points : D → PublicBranch → Q → Fin 6 → Goldilocks)
variable (choose : ∀ reply branch transcript,
  WitnessOpeningView Goldilocks → SourcePcsView Goldilocks → Earlier Goldilocks →
    Option (Targets (points reply branch transcript)))

def sourceCoordinates (coins : SourceCoordinates PublicBranch) :
    ObservedCoordinates PublicBranch :=
  let base := coins.1
  let q := coins.2.1
  let m := coins.2.2.1
  let branch := coins.2.2.2
  let reply := V8SmzaMathPrivacy.response gamma
    (currentHeads values base q) base.2.2 m
  let transcript := Q38Rp05ChronologicalAlgebra.response dsl statement
    (parameters reply branch) (sourceWitnessPolynomials values base.1) q
  (reply, branch, transcript,
    partialChronologicalView values (points reply branch transcript)
      (fun _witness => pcsBase (points reply branch transcript) q reply)
      (fun witness pcs => physicalHeads (sourceWitnessPolynomials values witness) q pcs)
      (choose reply branch transcript) base)

def publicCoordinates (coins : PublicCoordinates PublicBranch) :
    ObservedCoordinates PublicBranch :=
  (coins.1, coins.2.1, coins.2.2.1,
    abortProjection (choose coins.1 coins.2.1 coins.2.2.1) coins.2.2.2)

/-- Every public response/trace/transcript/partial-view tuple has a source
coin preimage. The trace is retained exactly, and index-abort projection is
included. PublicBranch may be a finite arbitrary-answer trace rather than
an oracle-consistent branch. The source coins may depend on the entire target.

These are precisely the existing interpolation premises of the source
opening transport; no support equality or budget hypothesis is introduced. -/
theorem public_coordinates_have_source_preimage
    (admissible : ∀ reply branch transcript,
      Smz9WitnessInterpolationAdmissible (points reply branch transcript))
    (pointsNonzero : ∀ reply branch transcript opening,
      points reply branch transcript opening ≠ 0)
    (fallback : ∀ reply branch transcript, Targets (points reply branch transcript))
    (target : PublicCoordinates PublicBranch) :
    ∃ origin : SourceCoordinates PublicBranch,
      sourceCoordinates dsl statement gamma values parameters points choose origin =
        publicCoordinates points choose target := by
  classical
  letI : Fintype Goldilocks :=
    @ZMod.fintype
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus
      HegemonCrypto.SmallWood.V8Smz9CappedRawSampler.instNeZeroNatSourceFieldSize
  refine preimage_of_kernel_sums
    (source := sourceCoordinates dsl statement gamma values parameters points choose)
    (simulated := publicCoordinates points choose) ?_ target
  intro observe
  rw [finite_sum_product_four, finite_sum_product_four]
  simpa only [sourceCoordinates, publicCoordinates] using
    request_public_opening_state_kernel_sum (Value := Nat)
      dsl statement gamma values parameters points admissible pointsNonzero fallback choose
      (fun reply branch transcript view => observe (reply, branch, transcript, view))

end Request


section ActualCompiler
variable {bound : Nat} {Work Result : Type} [Fintype Work]
open Q38Rp05RawInputPartition

theorem write_batch_count (count : Nat)
    (keys : Fin count → Rp05FullRawInput bound)
    (labels : Fin count → DigestRegister)
    (next : V8Smz9MixedMaskCompiler.MixedProgram (Rp05FullRawInput bound) Work) :
    V8Smz9MixedMaskCompiler.queryCount
        (Q38Rp05AdaptiveScheduler.writeBatch count keys labels next) =
      count + V8Smz9MixedMaskCompiler.queryCount next := by
  induction count with
  | zero => exact (Nat.zero_add _).symm
  | succ count ih =>
      simp only [Q38Rp05AdaptiveScheduler.writeBatch, V8Smz9MixedMaskCompiler.queryCount, ih]
      omega

/-- An arbitrary choice of all real tapes and all real leaf answers is an
actual syntactic branch. Its complete continuation cost is retained, and
every one of the count honest leaf reads is charged. -/
theorem real_leaf_branch_count_le (count : Nat)
    (indices : Fin count → V8Smz9HiddenPatch.LeafIndex)
    (statement : Statement) (salt : V8Smz9EagerOracleGame.SaltBytes)
    (data : Fin count → Fin 1176 → Byte)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) →
      V8Smz9MixedMaskCompiler.MixedProgram (Rp05FullRawInput bound) Work)
    (tapes : Fin count → LeafTape) (labels : Fin count → DigestRegister) :
    count + V8Smz9MixedMaskCompiler.queryCount (next tapes labels) ≤
      V8Smz9MixedMaskCompiler.queryCount
        (Q38Rp05AdaptiveScheduler.realLeafBatch count indices statement salt data next) := by
  induction count with
  | zero =>
      change 0 + V8Smz9MixedMaskCompiler.queryCount (next tapes labels) ≤
        V8Smz9MixedMaskCompiler.queryCount (next Fin.elim0 Fin.elim0)
      rw [Nat.zero_add]
      exact le_of_eq (congrArg V8Smz9MixedMaskCompiler.queryCount
        (congrArg₂ next (Subsingleton.elim _ _) (Subsingleton.elim _ _)))
  | succ count ih =>
      let rest := fun tape answer => Q38Rp05AdaptiveScheduler.realLeafBatch count
        (fun i => indices i.succ) statement salt (fun i => data i.succ)
        (fun ts ls => next (Fin.cons tape ts) (Fin.cons answer ls))
      have tailCost := ih (fun i => indices i.succ) (fun i => data i.succ)
        (fun ts ls => next (Fin.cons (tapes 0) ts) (Fin.cons (labels 0) ls))
        (fun i => tapes i.succ) (fun i => labels i.succ)
      have tapeEq : Fin.cons (tapes 0) (fun i => tapes i.succ) = tapes :=
        Fin.cons_self_tail tapes
      have labelEq : Fin.cons (labels 0) (fun i => labels i.succ) = labels :=
        Fin.cons_self_tail labels
      rw [tapeEq, labelEq] at tailCost
      have answerBound := Finset.le_sup
        (f := fun answer => V8Smz9MixedMaskCompiler.queryCount (rest (tapes 0) answer))
        (Finset.mem_univ (labels 0))
      have tapeBound := Finset.le_sup
        (f := fun tape => (Finset.univ.sup fun answer =>
          V8Smz9MixedMaskCompiler.queryCount (rest tape answer)) + 1)
        (Finset.mem_univ (tapes 0))
      change count + V8Smz9MixedMaskCompiler.queryCount (next tapes labels) ≤
        V8Smz9MixedMaskCompiler.queryCount (rest (tapes 0) (labels 0)) at tailCost
      change count + 1 + V8Smz9MixedMaskCompiler.queryCount (next tapes labels) ≤
        Finset.univ.sup (fun tape => (Finset.univ.sup fun answer =>
          V8Smz9MixedMaskCompiler.queryCount (rest tape answer)) + 1)
      omega

/-- Connect the callback-sensitive branch score to the actual scheduler's
compiler. This is an equality of counters, not an estimated request cost. -/
theorem mixed_nonleaf_count_eq_weighted
    (program : NonleafProgram (Rp05OtherRawInput bound) Result)
    (next : Result → V8Smz9MixedMaskCompiler.MixedProgram (Rp05FullRawInput bound) Work) :
    V8Smz9MixedMaskCompiler.queryCount (Q38Rp05AdaptiveScheduler.mixedNonleaf program next) =
      weightedReadCount (fun result => V8Smz9MixedMaskCompiler.queryCount (next result))
        program := by
  induction program with
  | done result => rfl
  | read input tail ih =>
      simp only [Q38Rp05AdaptiveScheduler.mixedNonleaf,
        V8Smz9MixedMaskCompiler.queryCount, weightedReadCount, ih]

/-- The exact actual mixed nonleaf budget is equivalent to a bound on its
successful arbitrary-answer traces, with each trace's spent reads retained.
There is no bound on callbacks at impossible results and no changed T. -/
theorem mixed_nonleaf_budget_iff_counted_traces
    (program : NonleafProgram (Rp05OtherRawInput bound) Result)
    (next : Result → V8Smz9MixedMaskCompiler.MixedProgram (Rp05FullRawInput bound) Work)
    (fuel : Nat) (enough : NonleafProgram.readCount program ≤ fuel) (total : Nat) :
    V8Smz9MixedMaskCompiler.queryCount (Q38Rp05AdaptiveScheduler.mixedNonleaf program next)
        ≤ total ↔
      ∀ trace result, traceResult fuel program trace = some result →
        traceReads fuel trace + V8Smz9MixedMaskCompiler.queryCount (next result) ≤ total := by
  rw [mixed_nonleaf_count_eq_weighted]
  constructor
  · intro bounded trace result decoded
    exact (read_branch_score_le
      (counted_trace_is_read_branch fuel program trace result decoded) _).trans bounded
  · intro branches
    obtain ⟨result, used, branch, cost⟩ := weighted_read_count_attained program
      (fun result => V8Smz9MixedMaskCompiler.queryCount (next result))
    have usedBound : used ≤ NonleafProgram.readCount program := by
      simpa only [Nat.add_zero, weighted_read_count_zero] using
        read_branch_score_le branch (fun _ => 0)
    obtain ⟨trace, decoded, counted⟩ :=
      read_branch_has_counted_trace branch fuel (usedBound.trans enough)
    rw [cost]
    simpa only [counted] using branches trace result decoded

end ActualCompiler

section SelectedPullback
open Q38Rp05RawInputPartition Q38Rp05CurrentPostfinal Q38Rp05PostFinalCompiler
open Q38Rp05SelectedContinuation V8Smz9AdjacentComposition
open V8Smz9PrivacyGameComposition V8Smz9EagerOracleGame V8Smz9HonestOpeningSchedule
open Q38Rp05OpeningSchedule


/-- Literal selected-postfinal branch pullback. The whole selector result is
reused, including its challenge, raw sampler result, index exhaustion and
latched failure flag. The same arbitrary-answer trace runs in both trees.
Consequently the bytes/error and read count agree exactly, not merely in
distribution. The source coin witness is obtained from the proven coordinate
transport, rather than postulated as a branch-matching premise. -/
theorem selected_postfinal_branch_has_source_preimage
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (values : WitnessPackingValues Goldilocks)
    (reply : D) (transcript : Q) (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (view : RemainingView Goldilocks) (job : SelectionResult opening.points)
    (used : Nat)
    (branch : ReadBranch
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points transcript view.1 view.2.1)
        view.2.2.1 opening.pendingFailure) job used) :
    ∃ (base : RemainingCoins Goldilocks) (q : Q) (m : D),
      V8SmzaMathPrivacy.response gamma (currentHeads values base q) base.2.2 m = reply ∧
      Q38Rp05ChronologicalAlgebra.response dsl statement parameters
        (sourceWitnessPolynomials values base.1) q = transcript ∧
      ReadBranch
        (currentHonestSelectedProgram bound largeEnough dsl statement parameters opening
          values base q gamma reply transcript digest salt tree tapes)
        (selectedBytes dsl statement parameters opening gamma reply transcript digest salt tree tapes
          (view.1, view.2.1, view.2.2.1, job.targets.map fun _ => view.2.2.2) job) used := by
  obtain ⟨trace, decoded, counted⟩ := read_branch_has_counted_trace branch used (Nat.le_refl _)
  let choose := fun (s : Q) witness pcs early =>
    (traceResult used
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points s witness pcs)
        early opening.pendingFailure) trace).bind fun selected =>
      selected.targets.map Q38Rp05PostFinalCompiler.targetValues
  have chosen : choose transcript view.1 view.2.1 view.2.2.1 =
      job.targets.map Q38Rp05PostFinalCompiler.targetValues := by
    dsimp only [choose]
    rw [decoded]
    rfl
  let fallback : Targets opening.points :=
    ⟨indexedPoints defaultIndices,
      indexed_targets_admissible opening.points (computed_opening_points_distinct opening)
        defaultIndices default_indices_injective⟩
  obtain ⟨origin, matched⟩ := public_coordinates_have_source_preimage
    (PublicBranch := Unit) dsl statement gamma values
    (fun _ _ => parameters) (fun _ _ _ => opening.points)
    (fun _ _ s => choose s)
    (fun _ _ _ => computed_opening_interpolation_admissible opening)
    (fun _ _ _ => computed_opening_points_nonzero opening)
    (fun _ _ _ => fallback) (reply, (), transcript, view)
  let base := origin.1
  let q := origin.2.1
  let m := origin.2.2.1
  have replyEq : V8SmzaMathPrivacy.response gamma (currentHeads values base q) base.2.2 m =
      reply := congrArg Prod.fst matched
  have transcriptEq : Q38Rp05ChronologicalAlgebra.response dsl statement parameters
      (sourceWitnessPolynomials values base.1) q = transcript :=
    congrArg (fun output => output.2.2.1) matched
  have viewEq := congrArg (fun output => output.2.2.2) matched
  change partialChronologicalView values opening.points
      (fun _ => pcsBase opening.points q
        (V8SmzaMathPrivacy.response gamma (currentHeads values base q) base.2.2 m))
      (fun witness pcs => physicalHeads (sourceWitnessPolynomials values witness) q pcs)
      (choose (Q38Rp05ChronologicalAlgebra.response dsl statement parameters
        (sourceWitnessPolynomials values base.1) q)) base =
    abortProjection (choose transcript) view at viewEq
  rw [replyEq, transcriptEq] at viewEq
  have witnessEq : sourceWitnessOpenings values opening.points base.1 = view.1 :=
    congrArg Prod.fst viewEq
  have pcsEq : sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1 =
      view.2.1 := congrArg (fun output => output.2.1) viewEq
  have earlyEq : earlier opening.points base.2.2 = view.2.2.1 :=
    congrArg (fun output => output.2.2.1) viewEq
  have sourceDecoded : traceResult used
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1))
        (earlier opening.points base.2.2) opening.pendingFailure) trace = some job := by
    simpa only [witnessEq, pcsEq, earlyEq] using decoded
  have physical : partialChronologicalView values opening.points
      (fun _ => pcsBase opening.points q reply)
      (fun witness pcs => physicalHeads (sourceWitnessPolynomials values witness) q pcs)
      (choose transcript) base = currentSelectedPhysicalView values base q reply job := by
    change (_, _, _, ((traceResult used _ trace).bind
      (fun selected : SelectionResult opening.points =>
        selected.targets.map Q38Rp05PostFinalCompiler.targetValues)).map
        (fun targets => fullSubset (currentHeads values base q) base.2.2 targets.val)) = _
    rw [sourceDecoded]
    change (_, _, _, (job.targets.map Q38Rp05PostFinalCompiler.targetValues).map
      (fun targets => fullSubset (currentHeads values base q) base.2.2 targets.val)) = _
    cases h : job.targets with
    | none => simp only [h, Option.map_none, currentSelectedPhysicalView]
    | some targets =>
        simp only [h, Option.map_some, currentSelectedPhysicalView,
          Q38Rp05PostFinalCompiler.targetValues]
  have projected : abortProjection (choose transcript) view =
      (view.1, view.2.1, view.2.2.1, job.targets.map fun _ => view.2.2.2) := by
    unfold abortProjection
    rw [chosen]
    cases job.targets <;> rfl
  rw [physical, projected] at viewEq
  refine ⟨base, q, m, replyEq, transcriptEq, ?_⟩
  have sourceBranch := counted_trace_is_read_branch used _ trace job sourceDecoded
  rw [counted] at sourceBranch
  have result := read_branch_map sourceBranch (fun selected =>
    selectedBytes dsl statement parameters opening gamma reply transcript digest salt tree tapes
      (currentSelectedPhysicalView values base q reply selected) selected)
  simpa only [currentHonestSelectedProgram, viewEq] using result

/-- Compose the selected pullback with the literal nonce-search branch.
The repeated winning-nonce XOF, earlier pending failures and every read in
the nonce prefix are unchanged. The selected branch includes index aborts. -/
theorem postfinal_opened_branch_has_source_preimage
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (values : WitnessPackingValues Goldilocks)
    (reply : D) (transcript : Q) (digest : DigestRegister) (pending : Bool)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (trial : OpeningResult) (opening : ComputedOpening)
    (nonceReads : Nat)
    (nonceBranch : ReadBranch (rp05ChooseOpening bound (by omega) digest pending) trial nonceReads)
    (opened : certifyOpening trial = some opening)
    (view : RemainingView Goldilocks) (job : SelectionResult opening.points)
    (selectedReads : Nat)
    (selectedBranch : ReadBranch
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points transcript view.1 view.2.1)
        view.2.2.1 opening.pendingFailure) job selectedReads) :
    ∃ (base : RemainingCoins Goldilocks) (q : Q) (m : D),
      V8SmzaMathPrivacy.response gamma (currentHeads values base q) base.2.2 m = reply ∧
      Q38Rp05ChronologicalAlgebra.response dsl statement parameters
        (sourceWitnessPolynomials values base.1) q = transcript ∧
      ReadBranch
        (currentHonestPostFinalProgram bound largeEnough dsl statement parameters values base q
          gamma reply transcript digest pending salt tree tapes)
        (selectedBytes dsl statement parameters opening gamma reply transcript digest salt tree tapes
          (view.1, view.2.1, view.2.2.1, job.targets.map fun _ => view.2.2.2) job)
        (nonceReads + selectedReads) := by
  obtain ⟨base, q, m, hD, hS, selected⟩ := selected_postfinal_branch_has_source_preimage
    bound largeEnough dsl statement parameters opening gamma values reply transcript digest salt
    tree tapes view job selectedReads selectedBranch
  refine ⟨base, q, m, hD, hS, ?_⟩
  unfold currentHonestPostFinalProgram
  apply read_branch_bind nonceBranch
  rw [opened]
  exact selected

/-- Nonce abort has no selected-index reads and no public leaf writes.
Translations of Q and M preserve any requested public D and S, so the
identical nonce-abort branch is realized by actual source coins as well. -/
theorem postfinal_nonce_abort_has_source_preimage
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (values : WitnessPackingValues Goldilocks)
    (reply : D) (transcript : Q) (digest : DigestRegister) (pending : Bool)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (trial : OpeningResult) (used : Nat)
    (branch : ReadBranch (rp05ChooseOpening bound (by omega) digest pending) trial used)
    (aborted : certifyOpening trial = none) :
    ∃ (base : RemainingCoins Goldilocks) (q : Q) (m : D),
      V8SmzaMathPrivacy.response gamma (currentHeads values base q) base.2.2 m = reply ∧
      Q38Rp05ChronologicalAlgebra.response dsl statement parameters
        (sourceWitnessPolynomials values base.1) q = transcript ∧
      ReadBranch
        (currentHonestPostFinalProgram bound largeEnough dsl statement parameters values base q
          gamma reply transcript digest pending salt tree tapes)
        (.error "smallwood opening nonce trial limit exhausted") used := by
  let base : RemainingCoins Goldilocks := 0
  let q := transcript - unmaskedResponse dsl statement parameters
    (sourceWitnessPolynomials values base.1)
  let m := reply - V8SmzaMathPrivacy.unmasked gamma (currentHeads values base q) base.2.2
  refine ⟨base, q, m, ?_, ?_, ?_⟩
  · dsimp only [V8SmzaMathPrivacy.response, m]
    exact (add_comm _ _).trans (sub_add_cancel _ _)
  · dsimp only [Q38Rp05ChronologicalAlgebra.response, q]
    exact (add_comm _ _).trans (sub_add_cancel _ _)
  · unfold currentHonestPostFinalProgram
    rw [← Nat.add_zero used]
    apply read_branch_bind branch
    rw [aborted]
    exact .done _

end SelectedPullback
end
end HegemonCrypto.SmallWood.Q38Rp05HybridBudget
