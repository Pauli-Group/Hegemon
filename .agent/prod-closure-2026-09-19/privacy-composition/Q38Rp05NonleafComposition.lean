import Q38Rp05AdaptiveOpening
import Q38Rp05PostFinalCompiler

/-!
Exact current-partition nonleaf selection, followed by retained-opening
erasure. This source has not been compiled. It does not claim the complete
adaptive-privacy endpoint: the actual whole-request recorded-outcome compiler
and chronological P10 identification must still be assembled.

The useful distinction from the generic adaptive selector theorem is that
`NonleafProgram` performs ONLY honest reads of `Sum.inr` inputs. Consequently
the leaf overlay cannot affect this prefix at all. Its honest reads still
count in the lifetime ledger, but incur no selection-feedback error.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05NonleafComposition

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.V8Smz9MeasuredOracleHybrid
open HegemonCrypto.SmallWood.V8Smz9MeasuredSourceHiddenPatch
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.V8SmzaSelectionFeedback
open HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false

local notation "Statement" =>
  HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "Tapes" => HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening.Tapes

variable {Other Work Job : Type}
variable [Fintype Other] [DecidableEq Other] [Fintype Work]

omit [Fintype Other] in
/-- On the corrected disjoint partition, every leaf patch preserves every
nonleaf answer, including on an arbitrary old oracle. -/
theorem leaf_overlay_nonleaf_function
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (labels : LeafIndex → DigestRegister)
    (statement : Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (programmed : Finset LeafIndex) (tapes : Tapes) :
    (fun input : Other => overlay old other labels statement salt data
      programmed tapes (Sum.inr input)) = other := by
  funext input
  have outside : (Sum.inr input : Rp05LeafInput ⊕ Other) ∉
      support statement salt data programmed tapes := by
    intro member
    obtain ⟨index, _, impossible⟩ := Finset.mem_image.mp member
    cases impossible
  simp only [overlay, if_neg outside, Sum.elim_inr]

/-- The actual nonleaf selection executes once. Its recorded result and
residual workspace are identical before and after removing the leaf patch.
This is an execution equality, not a supplied indistinguishability premise. -/
theorem current_nonleaf_feedback_exact
    (selector : NonleafProgram Other Job)
    (kernel : PhysicalKernel
      (Input := Rp05LeafInput ⊕ Other) (Work := Work) Job)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (labels : LeafIndex → DigestRegister)
    (statement : Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (programmed : Finset LeafIndex) (tapes : Tapes)
    (state : GameState (Input := Rp05LeafInput ⊕ Other) (Work := Work)) :
    execute (asSelection selector) kernel.observe
        (overlay old other labels statement salt data programmed tapes) state =
      kernel.observe (NonleafProgram.interpret other selector) state := by
  rw [execute_as_selection]
  rw [leaf_overlay_nonleaf_function]

/-- Exact P8/P9 composition for a current-partition nonleaf prefix. All
measurements in the prefix are its actual honest reads. The retained set
comes from that prefix's recorded result; no second selector is executed.
Taking `unopened = univ` handles nonce/index aborts with no dummy writes. -/
theorem current_nonleaf_retained_opening_bound_mass
    (randomized : Bool) (selector : NonleafProgram Other Job)
    (unopened : Job → Finset LeafIndex)
    (anchor : ∀ job, Unopened (unopened job))
    (program : (job : Job) → (Opened (unopened job) → LeafTape) →
      Program (Rp05LeafInput ⊕ Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (labels : LeafIndex → DigestRegister)
    (statement : Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (queries : Nat) (bounded : ∀ job visible,
      queryCount (program job visible) ≤ queries)
    (state : GameState (Input := Rp05LeafInput ⊕ Other) (Work := Work)) :
    |fullGame randomized (asSelection selector) unopened program
        old other labels statement salt data state -
      publicGame randomized (asSelection selector) unopened program
        old other labels statement salt data state| ≤
      (4 * (queries : ℝ) / (2 : ℝ)^256) * ‖state‖^2 := by
  let result := NonleafProgram.interpret other selector
  have realCollapse :
      fullGame randomized (asSelection selector) unopened program
        old other labels statement salt data state =
      uniformAverage (fun tapes : Tapes =>
        run randomized (revealProgram (unopened result) (program result) tapes)
          (realOracle old other labels statement salt data tapes) state) := by
    unfold fullGame
    apply congrArg uniformAverage
    funext tapes
    rw [show realOracle old other labels statement salt data tapes =
      overlay old other labels statement salt data Finset.univ tapes from rfl]
    rw [current_nonleaf_feedback_exact]
    rfl
  have publicCollapse :
      publicGame randomized (asSelection selector) unopened program
        old other labels statement salt data state =
      uniformAverage (fun tapes : Tapes =>
        run randomized (revealProgram (unopened result) (program result) tapes)
          (overlay old other labels statement salt data
            (unopened result)ᶜ tapes) state) := by
    unfold publicGame
    apply congrArg uniformAverage
    funext tapes
    rw [execute_as_selection]
    rfl
  rw [realCollapse, publicCollapse]
  have erased := averaged_reveal_bound randomized (unopened result)
    (anchor result) (program result) old other labels statement salt data
    queries (bounded result) state
  simpa only [queryLoss, sqrt_source_tape_cap, div_eq_mul_inv, mul_assoc]
    using erased

end
end HegemonCrypto.SmallWood.Q38Rp05NonleafComposition
