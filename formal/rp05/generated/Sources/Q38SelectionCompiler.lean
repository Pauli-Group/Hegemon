import Q38SelectionFeedback

/-! Exact embedding of the adaptive selection/reveal experiment into the
existing complete physical Program. Ordinary reads and instruments execute
in source order, and revelation never replaces the persistent oracle. -/
namespace HegemonCrypto.SmallWood.V8SmzaSelectionCompiler
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9HonestWholeViewGames
open V8Smz9CurrentPrivacyGame V8SmzaSelectionFeedback
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Input Work Job : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

def compile : Selection Input Work Job → (Job → Program Input Work) → Program Input Work
  | .reveal job, next => next job
  | .gate operation tail, next => .gate operation (compile tail next)
  | .quantumQuery tail, next => .quantumQuery (compile tail next)
  | .honestRead input tail, next => .honestRead input (fun answer => compile (tail answer) next)
  | .instrument operation tail, next => .instrument operation (fun branch => compile (tail branch) next)
  | .random source tail, next => .random source (fun coin => compile (tail coin) next)

theorem compiled_selection_executes (randomized : Bool) (selecPrefix : Selection Input Work Job)
    (next : Job → Program Input Work) (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run randomized (compile selecPrefix next) oracle state =
      execute selecPrefix (programKernel randomized next (fun _ => oracle)).observe oracle state := by
  induction selecPrefix generalizing state with
  | reveal job => rfl
  | gate operation tail ih => exact ih (operation state)
  | quantumQuery tail ih => exact ih (query oracle state)
  | honestRead input tail ih => exact ih (oracle input) state
  | instrument operation tail ih =>
    exact Finset.sum_congr rfl fun branch _ => ih branch (operation.branch branch state)
  | random source tail ih => exact congrArg uniformAverage (funext fun coin => ih coin state)

set_option linter.unusedSectionVars false in
/-- Every oracle exposure in the selection prefix is charged in the same
Program as the reveal continuation; branch maxima cover all possible paths. -/
theorem compiled_query_bound (selecPrefix : Selection Input Work Job) (next : Job → Program Input Work)
    (queries : Nat) (bounded : ∀ job, queryCount (next job) ≤ queries) :
    queryCount (compile selecPrefix next) ≤ exposures selecPrefix + queries := by
  induction selecPrefix with
  | reveal job => simpa only [compile, exposures, Nat.zero_add] using bounded job
  | gate operation tail ih => exact ih
  | quantumQuery tail ih =>
    simp only [compile, queryCount, exposures]
    omega
  | honestRead input tail ih =>
    simp only [compile, queryCount, exposures]
    have bound : (Finset.univ.sup fun answer => queryCount (compile (tail answer) next)) ≤
        (Finset.univ.sup fun answer => exposures (tail answer)) + queries := by
      apply Finset.sup_le
      intro answer _
      exact (ih answer).trans (Nat.add_le_add_right
        (Finset.le_sup (f := fun answer => exposures (tail answer))
          (Finset.mem_univ answer)) queries)
    omega
  | instrument operation tail ih =>
    simp only [compile, queryCount, exposures]
    apply Finset.sup_le
    intro branch _
    exact (ih branch).trans (Nat.add_le_add_right
      (Finset.le_sup (f := fun branch => exposures (tail branch))
        (Finset.mem_univ branch)) queries)
  | random source tail ih =>
    simp only [compile, queryCount, exposures]
    apply Finset.sup_le
    intro coin _
    exact (ih coin).trans (Nat.add_le_add_right
      (Finset.le_sup (f := fun coin => exposures (tail coin))
        (Finset.mem_univ coin)) queries)

end
end HegemonCrypto.SmallWood.V8SmzaSelectionCompiler
