import Q38Rp05HybridBudget

/-! Count-preserving DECS -> D-indexed PIOP -> final -> postfinal branch
pullback. These are arbitrary-answer branches of the actual syntax, not
fixed-oracle traces and not an assumption about unreachable callbacks. -/
namespace HegemonCrypto.SmallWood.Q38Rp05PrefinalBudget

open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9HonestRequestSchedule
open V8Smz9EagerOracleGame V8Smz9EagerPrivacy V8Smz9RuntimeRandomness
open V8Smz9WholeViewObservation V8Smz9CurrentProgramOpeningBinding
open V8Smz9HonestWholeViewGames
open V8Smz9PrivacyGameComposition
open V8Smz9AdjacentComposition
open V8Smz9HonestOpeningSchedule (sourcePendingFailure)
open V8Smz9PostFinalProgram (certifyOpening)
open V8SmzaMathPrivacy V8SmzaRemainingAlgebra Q38MeasuredCmsNonleaf
open Q38Rp05RawInputPartition Q38Rp05RequestCompiler Q38Rp05CurrentPrefinal
open Q38Rp05CurrentPostfinal Q38Rp05PostFinalCompiler Q38Rp05CurrentCompleteRequest
open Q38Rp05ChronologicalAlgebra Q38Rp05RecordedRequest Q38Rp05SelectedContinuation
open Q38Rp05OpeningSchedule Q38Rp05OpenedOverlay Q38Rp05AdaptiveScheduler
open Q38Rp05CountedNonleaf Q38Rp05BranchBind Q38Rp05HybridBudget
open SmzaRp05StatementNamespace SmzaRp05RelationRefinement
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

private theorem source_bind_done {Other A B : Type}
    (a : A) (next : A → NonleafProgram Other B) :
    NonleafProgram.bind (.done a) next = next a := rfl

private theorem source_bind_read {Other A B : Type}
    (input : Other) (rest : DigestRegister → NonleafProgram Other A)
    (next : A → NonleafProgram Other B) :
    NonleafProgram.bind (.read input rest) next =
      .read input (fun answer => NonleafProgram.bind (rest answer) next) := rfl

private theorem source_bind_congr {Other A B : Type}
    (program : NonleafProgram Other A) {left right : A → NonleafProgram Other B}
    (same : ∀ a, left a = right a) :
    NonleafProgram.bind program left = NonleafProgram.bind program right :=
  congrArg (NonleafProgram.bind program) (funext same)

/-- Bind preserves any property shared by every possible returned value. -/
theorem read_branch_bind_property {Other A B : Type}
    (program : NonleafProgram Other A) (next : A → NonleafProgram Other B)
    (property : B → Prop)
    (tails : ∀ a b used, ReadBranch (next a) b used → property b)
    {b : B} {used : Nat} (branch : ReadBranch (NonleafProgram.bind program next) b used) :
    property b := by
  induction program generalizing used with
  | done a => exact tails a b used branch
  | read input tail ih =>
      cases branch with
      | read _ _ answer rest => exact ih answer rest

/-- Sampler rejection and the first DECS sample survive the whole PIOP
suffix unchanged; no pending-failure bit is reset. -/
theorem piop_branch_preserves_decs {Other : Type}
    (shape : Q38PrefinalShape Other) (stage : DecsStage) (reply : D)
    {computed : PrefinalResult} {used : Nat}
    (branch : ReadBranch (piopSuffix shape stage reply) computed used) :
    computed.decsGamma = stage.decsGamma := by
  cases branch with
  | read _ _ hashMt tail =>
    cases tail with
    | read _ _ hashFpp rest =>
      apply read_branch_bind_property (shape.piop hashFpp)
        (fun batching => .done (⟨stage.built.2, hashMt, stage.decsGamma, hashFpp,
          batching⟩ : PrefinalResult))
        (fun result : PrefinalResult => result.decsGamma = stage.decsGamma) ?_ rest
      intro batching result reads finished
      cases finished
      rfl

/-- The literal source byte-returning nonleaf tree after all leaf reads. -/
def sourceBytesProgram {bound : Nat} (data : Request bound)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister) :
    NonleafProgram (Rp05OtherRawInput bound) Bytes :=
  NonleafProgram.bind
    (rp05CurrentPrefinal bound data.largeEnough data.dsl data.statement data.salt labels
      data.witness base masks data.widthBound) fun computed =>
    let coefficients := Q38Rp05RequestCompiler.transcript data.dsl data.statement
      data.witness base masks computed.1.piopGamma
    .read (currentFinalKey bound (by have := data.largeEnough; omega)
      computed.1.hashFpp coefficients) fun digest =>
    currentHonestPostFinalProgram bound data.largeEnough data.dsl data.statement
      (decodedParameters data.dsl data.statement computed.1.piopGamma)
      data.witness base masks.1 (decodedQ38DecsGamma computed.1.decsGamma)
      computed.2 coefficients digest
      (sourcePendingFailure (sourcePendingFailure false computed.1.decsGamma)
        computed.1.piopGamma) data.salt computed.1.tree tapes

section RecordedSource
attribute [local irreducible] NonleafProgram.bind rp05CurrentPrefinal
  rp05ChooseOpening currentSelectIndices certifyOpening selectedBytes

theorem source_bytes_is_recorded {bound : Nat} (data : Request bound)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister) :
    sourceBytesProgram data base masks tapes labels =
      NonleafProgram.bind
        (recordedPrefix data.largeEnough data.dsl data.statement data.witness data.salt
          data.widthBound base masks labels)
        (fun record => .done
          (recordBytes data.dsl data.statement data.witness base masks.1 data.salt tapes record)) := by
  unfold sourceBytesProgram recordedPrefix
  rw [nonleaf_bind_assoc]
  apply source_bind_congr
  intro computed
  dsimp only
  rw [source_bind_read]
  apply congrArg (NonleafProgram.read _)
  funext digest
  unfold currentHonestPostFinalProgram recordedPostFinal
  rw [nonleaf_bind_assoc]
  apply source_bind_congr
  intro trial
  cases certifyOpening trial with
  | none => simp only [source_bind_done, recordBytes]
  | some opening =>
      unfold currentHonestSelectedProgram
      rw [nonleaf_bind_assoc]
      apply source_bind_congr
      intro selected
      have sameView :
          currentSelectedPhysicalView data.witness base masks.1 computed.2 selected =
            selectedPhysicalView data.witness base masks.1 computed.2 selected := by
        cases selected.targets <;> rfl
      simp only [source_bind_done, recordBytes, sameView]

end RecordedSource

/-- Given the postfinal coin preimage, all preceding actual reads prepend
without cost loss. D and S equality fixes the PIOP/final keys and preserves
both sampler failures, the tree, and every byte of the returned result. -/
theorem prepend_prefinal_branch {bound : Nat} (data : Request bound)
    (labels : LeafIndex → DigestRegister) (tapes : TapeTable)
    (stage : DecsStage) (computed : PrefinalResult) (reply : D) (coefficients : Q)
    (digest : DigestRegister) (decsReads piopReads postReads : Nat)
    (decsBranch : ReadBranch
      (decsPrefix (rp05CurrentPrefinalShape bound data.largeEnough data.dsl
        data.statement data.salt labels data.widthBound)) stage decsReads)
    (piopBranch : ReadBranch
      (piopSuffix (rp05CurrentPrefinalShape bound data.largeEnough data.dsl
        data.statement data.salt labels data.widthBound) stage reply) computed piopReads)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D) (bytes : Bytes)
    (sameD : V8SmzaMathPrivacy.response (decodedQ38DecsGamma computed.decsGamma)
      (currentHeads data.witness base q) base.2.2 m = reply)
    (sameS : Q38Rp05ChronologicalAlgebra.response data.dsl data.statement
      (decodedParameters data.dsl data.statement computed.piopGamma)
      (sourceWitnessPolynomials data.witness base.1) q = coefficients)
    (postBranch : ReadBranch
      (currentHonestPostFinalProgram bound data.largeEnough data.dsl data.statement
        (decodedParameters data.dsl data.statement computed.piopGamma) data.witness base q
        (decodedQ38DecsGamma computed.decsGamma) reply coefficients digest
        (sourcePendingFailure (sourcePendingFailure false computed.decsGamma) computed.piopGamma)
        data.salt computed.tree tapes) bytes postReads) :
    ReadBranch (sourceBytesProgram data base (q,m) tapes labels) bytes
      (decsReads + piopReads + 1 + postReads) := by
  have preserved := piop_branch_preserves_decs _ _ _ piopBranch
  have stageD : decsReply data.witness base (q,m) stage.decsGamma = reply := by
    unfold decsReply
    simpa only [preserved] using sameD
  have prefinal : ReadBranch
      (rp05CurrentPrefinal bound data.largeEnough data.dsl data.statement data.salt labels
        data.witness base (q,m) data.widthBound) (computed,reply) (decsReads + piopReads) := by
    unfold rp05CurrentPrefinal
    rw [dynamic_eq_decs_then_piop]
    apply read_branch_bind decsBranch
    rw [stageD]
    exact read_branch_map piopBranch (fun result => (result,reply))
  have countEq : decsReads + piopReads + 1 + postReads =
      (decsReads + piopReads) + (postReads + 1) := by omega
  rw [countEq]
  unfold sourceBytesProgram
  apply read_branch_bind prefinal
  simp only [Q38Rp05RequestCompiler.transcript, sameS]
  exact ReadBranch.read _ _ digest postBranch

theorem mixed_nonleaf_bind {bound : Nat} {Work A B : Type} [Fintype Work]
    (program : NonleafProgram (Rp05OtherRawInput bound) A)
    (tail : A → NonleafProgram (Rp05OtherRawInput bound) B)
    (next : B → MixedProgram (Rp05FullRawInput bound) Work) :
    mixedNonleaf (NonleafProgram.bind program tail) next =
      mixedNonleaf program (fun result => mixedNonleaf (tail result) next) := by
  induction program with
  | done result => rfl
  | read input rest ih =>
      simp only [NonleafProgram.bind, mixedNonleaf, ih]

/-- A selected source branch witnesses a lower bound on the ACTUAL request
counter, including all 2^23 preceding leaf reads and the exact callback. -/
theorem source_branch_cost_le_request {bound : Nat} {Work : Type} [Fintype Work]
    (data : Request bound) (next : Bytes → MixedProgram (Rp05FullRawInput bound) Work)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (bytes : Bytes) (used : Nat)
    (branch : ReadBranch (sourceBytesProgram data base masks tapes labels) bytes used) :
    8388608 + used + V8Smz9MixedMaskCompiler.queryCount (next bytes) ≤
      V8Smz9MixedMaskCompiler.queryCount (realRequest data next) := by
  have nonleaf := read_branch_score_le branch
    (fun bytes => V8Smz9MixedMaskCompiler.queryCount (next bytes))
  rw [← mixed_nonleaf_count_eq_weighted, source_bytes_is_recorded, mixed_nonleaf_bind]
    at nonleaf
  have leaf := real_leaf_branch_count_le 8388608 id data.statement data.salt
    (q38PhysicalSuffix (currentHeads data.witness base masks.1) base.2.2 masks.2)
    (fun tapes labels => mixedNonleaf
      (recordedPrefix data.largeEnough data.dsl data.statement data.witness data.salt
        data.widthBound base masks labels)
      (fun record => next
        (recordBytes data.dsl data.statement data.witness base masks.1 data.salt tapes record)))
    tapes labels
  have maskBound := Finset.le_sup
    (f := fun chosenMasks : Q × D => V8Smz9MixedMaskCompiler.queryCount
      (realLeafBatch 8388608 id data.statement data.salt
        (q38PhysicalSuffix (currentHeads data.witness base chosenMasks.1) base.2.2 chosenMasks.2)
        (fun tapes labels => mixedNonleaf
          (recordedPrefix data.largeEnough data.dsl data.statement data.witness data.salt
            data.widthBound base chosenMasks labels)
          (fun record => next (recordBytes data.dsl data.statement data.witness base
            chosenMasks.1 data.salt tapes record))))) (Finset.mem_univ masks)
  have baseBound := Finset.le_sup
    (f := fun chosenBase : RemainingCoins Goldilocks =>
      V8Smz9MixedMaskCompiler.queryCount
        (.random rp05JointMasksSource fun chosenMasks =>
          realLeafBatch 8388608 id data.statement data.salt
            (q38PhysicalSuffix (currentHeads data.witness chosenBase chosenMasks.1)
              chosenBase.2.2 chosenMasks.2)
            (fun tapes labels => mixedNonleaf
              (recordedPrefix data.largeEnough data.dsl data.statement data.witness data.salt
                data.widthBound chosenBase chosenMasks labels)
              (fun record => next (recordBytes data.dsl data.statement data.witness chosenBase
                chosenMasks.1 data.salt tapes record))))) (Finset.mem_univ base)
  change _ ≤ V8Smz9MixedMaskCompiler.queryCount (realRequest data next) at baseBound
  change _ ≤ V8Smz9MixedMaskCompiler.queryCount
    (.random rp05JointMasksSource fun chosenMasks => _) at maskBound
  dsimp only [mixedNonleaf] at nonleaf
  omega

theorem mixed_nonleaf_budget_offset {bound : Nat} {Work Result : Type} [Fintype Work]
    (program : NonleafProgram (Rp05OtherRawInput bound) Result)
    (next : Result → MixedProgram (Rp05FullRawInput bound) Work) (spent total : Nat)
    (branches : ∀ result used, ReadBranch program result used →
      spent + used + V8Smz9MixedMaskCompiler.queryCount (next result) ≤ total) :
    spent + V8Smz9MixedMaskCompiler.queryCount (mixedNonleaf program next) ≤ total := by
  obtain ⟨result, used, branch, attained⟩ := weighted_read_count_attained program
    (fun result => V8Smz9MixedMaskCompiler.queryCount (next result))
  rw [mixed_nonleaf_count_eq_weighted, attained]
  simpa only [Nat.add_assoc] using branches result used branch

theorem mixed_random_budget_offset {Input Work : Type} [Fintype Input] [Fintype Work]
    (source : RandomSource) (next : source.Coins → MixedProgram Input Work)
    (spent total : Nat)
    (branches : ∀ coins, spent + V8Smz9MixedMaskCompiler.queryCount (next coins) ≤ total) :
    spent + V8Smz9MixedMaskCompiler.queryCount (.random source next) ≤ total := by
  have initial : spent ≤ total := le_trans (Nat.le_add_right _ _)
    (branches (Classical.choice source.inhabited))
  have bounded : (Finset.univ.sup fun coins =>
      V8Smz9MixedMaskCompiler.queryCount (next coins)) ≤ total - spent := by
    apply Finset.sup_le
    intro coins _
    have := branches coins
    omega
  change spent + (Finset.univ.sup fun coins =>
    V8Smz9MixedMaskCompiler.queryCount (next coins)) ≤ total
  omega

theorem mixed_read_budget_offset {Input Work : Type} [Fintype Input] [Fintype Work]
    (input : Input) (next : DigestRegister → MixedProgram Input Work) (spent total : Nat)
    (branches : ∀ answer,
      spent + 1 + V8Smz9MixedMaskCompiler.queryCount (next answer) ≤ total) :
    spent + V8Smz9MixedMaskCompiler.queryCount (.honestRead input next) ≤ total := by
  have initial : spent + 1 ≤ total := le_trans (Nat.le_add_right _ _) (branches 0)
  have bounded : (Finset.univ.sup fun answer =>
      V8Smz9MixedMaskCompiler.queryCount (next answer)) ≤ total - (spent + 1) := by
    apply Finset.sup_le
    intro answer _
    have := branches answer
    omega
  change spent + ((Finset.univ.sup fun answer =>
    V8Smz9MixedMaskCompiler.queryCount (next answer)) + 1) ≤ total
  omega

theorem public_opened_count_le {bound : Nat} {Work : Type} [Fintype Work]
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (coefficients : Q)
    (salt : SaltBytes) (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks) (selected : SelectionResult opening.points)
    (next : MixedProgram (Rp05FullRawInput bound) Work) :
    V8Smz9MixedMaskCompiler.queryCount
      (publicOpenedWrites dsl statement parameters opening gamma reply coefficients
        salt tapes labels view selected next) ≤
      38 + V8Smz9MixedMaskCompiler.queryCount next := by
  unfold publicOpenedWrites
  split
  · exact le_of_eq (write_batch_count 38 _ _ next)
  · omega

section PublicRequestCount
attribute [local irreducible] V8Smz9MixedMaskCompiler.queryCount realRequest
  realLeafBatch rp05ChooseOpening currentSelectIndices certifyOpening selectedBytes

/-- Every arbitrary-answer public request path has a source path with the
same complete bytes/error and at least its charged query cost. In particular,
the 38 retained writes are paid out of the actual 2^23 real leaf reads; no
additional allowance, accepted-byte callback cap, or all-hybrid assumption
is introduced. Even inconsistent repeated-key answers are retained. -/
theorem public_request_count_le_real {bound : Nat} {Work : Type} [Fintype Work]
    (data : Request bound) (next : Bytes → MixedProgram (Rp05FullRawInput bound) Work) :
    V8Smz9MixedMaskCompiler.queryCount
      (publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound next) ≤
      V8Smz9MixedMaskCompiler.queryCount (realRequest data next) := by
  rw [← Nat.zero_add (V8Smz9MixedMaskCompiler.queryCount
    (publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound next))]
  unfold publicRequest
  apply mixed_random_budget_offset (Input := Rp05FullRawInput bound) (Work := Work)
    (spent := 0)
  intro labels
  apply mixed_random_budget_offset (Input := Rp05FullRawInput bound) (Work := Work)
  intro tapes
  apply mixed_nonleaf_budget_offset (bound := bound) (Work := Work)
  intro stage decsReads decsBranch
  apply mixed_random_budget_offset (Input := Rp05FullRawInput bound) (Work := Work)
  intro reply
  apply mixed_nonleaf_budget_offset (bound := bound) (Work := Work)
  intro computed piopReads piopBranch
  apply mixed_random_budget_offset (Input := Rp05FullRawInput bound) (Work := Work)
  intro coefficients
  unfold publicPostfinal
  apply mixed_read_budget_offset (Input := Rp05FullRawInput bound) (Work := Work)
  intro digest
  apply mixed_nonleaf_budget_offset (bound := bound) (Work := Work)
  intro trial nonceReads nonceBranch
  split
  next aborted =>
    obtain ⟨base, q, m, sameD, sameS, postBranch⟩ :=
      postfinal_nonce_abort_has_source_preimage bound data.largeEnough data.dsl data.statement
        (decodedParameters data.dsl data.statement computed.piopGamma)
        (decodedQ38DecsGamma computed.decsGamma) data.witness reply coefficients digest
        (sourcePendingFailure (sourcePendingFailure false computed.decsGamma) computed.piopGamma)
        data.salt computed.tree tapes trial nonceReads nonceBranch aborted
    have complete := prepend_prefinal_branch data labels tapes stage computed reply coefficients
      digest decsReads piopReads nonceReads decsBranch piopBranch base q m _ sameD sameS postBranch
    have cost := source_branch_cost_le_request data next base (q,m) tapes labels _ _ complete
    omega
  next opening opened =>
    apply mixed_random_budget_offset (Input := Rp05FullRawInput bound) (Work := Work)
    intro view
    apply mixed_nonleaf_budget_offset (bound := bound) (Work := Work)
    intro selected selectedReads selectedBranch
    obtain ⟨base, q, m, sameD, sameS, postBranch⟩ :=
      postfinal_opened_branch_has_source_preimage bound data.largeEnough data.dsl data.statement
        (decodedParameters data.dsl data.statement computed.piopGamma)
        (decodedQ38DecsGamma computed.decsGamma) data.witness reply coefficients digest
        (sourcePendingFailure (sourcePendingFailure false computed.decsGamma) computed.piopGamma)
        data.salt computed.tree tapes trial opening nonceReads nonceBranch opened
        view selected selectedReads selectedBranch
    have complete := prepend_prefinal_branch data labels tapes stage computed reply coefficients
      digest decsReads piopReads (nonceReads + selectedReads) decsBranch piopBranch
      base q m _ sameD sameS postBranch
    have cost := source_branch_cost_le_request data next base (q,m) tapes labels _ _ complete
    have writes := public_opened_count_le (bound := bound) data.dsl data.statement
      (decodedParameters data.dsl data.statement computed.piopGamma) opening
      (decodedQ38DecsGamma computed.decsGamma) reply coefficients data.salt tapes labels
      (view.1, view.2.1, view.2.2.1, selected.targets.map fun _ => view.2.2.2) selected
      (next (selectedBytes data.dsl data.statement
        (decodedParameters data.dsl data.statement computed.piopGamma) opening
        (decodedQ38DecsGamma computed.decsGamma) reply coefficients digest data.salt
        computed.tree tapes
        (view.1, view.2.1, view.2.2.1, selected.targets.map fun _ => view.2.2.2) selected))
    dsimp only
    omega

end PublicRequestCount

theorem univ_sup_mono {A : Type} [Fintype A] (left right : A → Nat)
    (bounded : ∀ a, left a ≤ right a) : Finset.univ.sup left ≤ Finset.univ.sup right := by
  apply Finset.sup_le
  intro a _
  exact (bounded a).trans (Finset.le_sup (Finset.mem_univ a))

theorem mixed_nonleaf_count_mono {bound : Nat} {Work Result : Type} [Fintype Work]
    (program : NonleafProgram (Rp05OtherRawInput bound) Result)
    (left right : Result → MixedProgram (Rp05FullRawInput bound) Work)
    (bounded : ∀ result, V8Smz9MixedMaskCompiler.queryCount (left result) ≤
      V8Smz9MixedMaskCompiler.queryCount (right result)) :
    V8Smz9MixedMaskCompiler.queryCount (mixedNonleaf program left) ≤
      V8Smz9MixedMaskCompiler.queryCount (mixedNonleaf program right) := by
  induction program with
  | done result => exact bounded result
  | read input tail ih =>
      exact Nat.add_le_add_right (univ_sup_mono _ _ ih) 1

theorem real_leaf_count_mono {bound : Nat} {Work : Type} [Fintype Work]
    (count : Nat) (indices : Fin count → LeafIndex) (statement : Statement) (salt : SaltBytes)
    (data : Fin count → Fin 1176 → Byte)
    (left right : (Fin count → LeafTape) → (Fin count → DigestRegister) →
      MixedProgram (Rp05FullRawInput bound) Work)
    (bounded : ∀ tapes labels, V8Smz9MixedMaskCompiler.queryCount (left tapes labels) ≤
      V8Smz9MixedMaskCompiler.queryCount (right tapes labels)) :
    V8Smz9MixedMaskCompiler.queryCount (realLeafBatch count indices statement salt data left) ≤
      V8Smz9MixedMaskCompiler.queryCount (realLeafBatch count indices statement salt data right) := by
  induction count with
  | zero => exact bounded _ _
  | succ count ih =>
      apply univ_sup_mono
      intro tape
      apply Nat.add_le_add_right
      apply univ_sup_mono
      intro answer
      apply ih
      intro tapes labels
      exact bounded _ _

theorem real_request_count_mono {bound : Nat} {Work : Type} [Fintype Work]
    (data : Request bound) (left right : Bytes → MixedProgram (Rp05FullRawInput bound) Work)
    (bounded : ∀ bytes, V8Smz9MixedMaskCompiler.queryCount (left bytes) ≤
      V8Smz9MixedMaskCompiler.queryCount (right bytes)) :
    V8Smz9MixedMaskCompiler.queryCount (realRequest data left) ≤
      V8Smz9MixedMaskCompiler.queryCount (realRequest data right) := by
  apply univ_sup_mono
  intro base
  apply univ_sup_mono
  intro masks
  apply real_leaf_count_mono
  intro tapes labels
  apply mixed_nonleaf_count_mono
  intro record
  exact bounded _

/-- Public replacements cannot increase the actual expanded worst-branch
counter, even when the byte/error response selects the remaining schedule. -/
theorem hybrid_count_le_all_real {bound : Nat} {Work : Type} [Fintype Work]
    {requests : Nat} (schedule : Schedule bound Work requests) (real : Nat) :
    V8Smz9MixedMaskCompiler.queryCount (hybrid real schedule) ≤
      V8Smz9MixedMaskCompiler.queryCount (hybrid requests schedule) := by
  induction schedule generalizing real with
  | finish event => exact Nat.le_refl _
  | gate operation next ih => exact ih real
  | quantumQuery next ih => exact Nat.add_le_add_right (ih real) 1
  | honestRead input next ih => exact Nat.add_le_add_right (univ_sup_mono _ _ (fun a => ih a real)) 1
  | instrument operation next ih => exact univ_sup_mono _ _ (fun a => ih a real)
  | random source next ih => exact univ_sup_mono _ _ (fun a => ih a real)
  | request data next ih =>
      cases real with
      | zero =>
          exact (public_request_count_le_real data
            (fun bytes => hybrid 0 (next bytes))).trans
              (real_request_count_mono data (fun bytes => hybrid 0 (next bytes))
                (fun bytes => hybrid _ (next bytes)) (fun bytes => ih bytes 0))
      | succ real => exact real_request_count_mono data _ _ (fun bytes => ih bytes real)

/-- Original T, original Schedule and original WithinBudget definition.
There is no separate premise about simulated branches or impossible bytes. -/
theorem within_budget_of_all_real {bound : Nat} {Work : Type} [Fintype Work]
    {requests : Nat} (schedule : Schedule bound Work requests) (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests schedule) ≤ total) :
    WithinBudget schedule total :=
  fun real _ => (hybrid_count_le_all_real schedule real).trans budget

end
end HegemonCrypto.SmallWood.Q38Rp05PrefinalBudget
