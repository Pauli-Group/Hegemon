import SmzaRp05SourceReadSchedule

/-!
# Adaptive source-program read-budget composition

These structural lemmas account for every decoded answer path of `Program`.
The result carried by a selector may contain arbitrary family identifiers,
statements, metadata, and proof bytes. No fixed statement or family is assumed.
A uniform continuation budget composes additively with the selector's own
worst-path budget. A finite adaptive history similarly sums stage budgets.

This file supplies read accounting only. It does not identify a security event,
prove a probability or QROM bound, bind these programs to Rust execution, or
establish a protocol lifetime exposure cap. It uses no fixed proof geometry.
-/

set_option autoImplicit false

namespace HegemonCrypto.NativeLaunchGlobalQueryReadBudget

open SmallWood.SmzaRp05ExecutableMerkleVerifier (Program)
open SmallWood.SmzaRp05SourceReadSchedule (readBudget)
open SmallWood.V8SmzaOracleParser (RawInput RawDigest)
open SmallWood.V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section

variable {Counter Result Next State : Type}
variable [Fintype Counter] [DecidableEq Counter]

/-- Uniform continuation budgets cover adaptive result selection without
requiring a finite or predetermined set of metadata or family identifiers. -/
theorem readBudget_bind_le
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (next : Result → Program Next)
    (budget : Nat)
    (continuationBound : ∀ result, readBudget decode (next result) ≤ budget) :
    readBudget decode (program.bind next) ≤ readBudget decode program + budget := by
  induction program with
  | done result =>
      cases result with
      | none => simp [Program.bind, readBudget]
      | some value => simpa [Program.bind, readBudget] using continuationBound value
  | read raw cont ih =>
      simp only [Program.bind, readBudget]
      have below :
          (Finset.univ.sup fun answer : VectorOutput Counter =>
            readBudget decode ((cont (decode raw answer)).bind next)) ≤
          (Finset.univ.sup fun answer : VectorOutput Counter =>
            readBudget decode (cont (decode raw answer))) + budget := by
        apply Finset.sup_le
        intro answer _member
        have one : readBudget decode (cont (decode raw answer)) ≤
            (Finset.univ.sup fun output : VectorOutput Counter =>
              readBudget decode (cont (decode raw output))) :=
          Finset.le_sup (f := fun output : VectorOutput Counter =>
            readBudget decode (cont (decode raw output))) (Finset.mem_univ answer)
        exact (ih (decode raw answer)).trans
          (Nat.add_le_add_right one budget)
      omega

/-- Explicit selector-plus-dispatch accounting. `Result` can include both
the selected family and its answer-adaptively selected public statement. -/
theorem readBudget_select_dispatch_le
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (selector : Program Result) (dispatch : Result → Program Next)
    (selectionBudget dispatchBudget : Nat)
    (selectionBound : readBudget decode selector ≤ selectionBudget)
    (dispatchBound : ∀ selected, readBudget decode (dispatch selected) ≤ dispatchBudget) :
    readBudget decode (selector.bind dispatch) ≤ selectionBudget + dispatchBudget :=
  (readBudget_bind_le decode selector dispatch dispatchBudget dispatchBound).trans
    (Nat.add_le_add_right selectionBound dispatchBudget)

/-- Each stage receives the actual result of the preceding stage. A failed
stage stops execution; its reads are still included in the worst-path budget. -/
def adaptiveHistory : List (State → Program State) → State → Program State
  | [], state => .done (some state)
  | stage :: rest, state => (stage state).bind (adaptiveHistory rest)

/-- A finite history of answer-adaptive state transitions consumes at most
the sum of uniform stage budgets, with no multiplication by path count. -/
theorem readBudget_adaptiveHistory_le
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (stages : List (State → Program State))
    (budget : (State → Program State) → Nat)
    (stageBound : ∀ stage ∈ stages, ∀ state, readBudget decode (stage state) ≤ budget stage)
    (initial : State) :
    readBudget decode (adaptiveHistory stages initial) ≤ (stages.map budget).sum := by
  induction stages generalizing initial with
  | nil => simp [adaptiveHistory, readBudget]
  | cons stage rest ih =>
      have tailBound : ∀ next ∈ rest, ∀ state,
          readBudget decode (next state) ≤ budget next := by
        intro next member state
        exact stageBound next (List.mem_cons_of_mem stage member) state
      have continuationBound : ∀ state,
          readBudget decode (adaptiveHistory rest state) ≤ (rest.map budget).sum :=
        fun state => ih tailBound state
      have headBound := stageBound stage (List.mem_cons_self) initial
      exact (readBudget_bind_le decode (stage initial) (adaptiveHistory rest)
        (rest.map budget).sum continuationBound).trans (by
          simpa only [List.map_cons, List.sum_cons] using
            Nat.add_le_add_right headBound (rest.map budget).sum)

end
end HegemonCrypto.NativeLaunchGlobalQueryReadBudget
