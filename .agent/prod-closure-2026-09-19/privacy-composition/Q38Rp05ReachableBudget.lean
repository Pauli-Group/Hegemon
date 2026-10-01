import Q38Rp05PrefinalBudget
import Q38Rp05StoppedRefinement

/-! The request-count ledger is derived from the actual stopped read tree.
Unused type-index fuel and callbacks at impossible bytes create no pivots.
All source requests, including later nonce/index/sampler aborts, pay their
unconditional complete leaf batch before reaching the recorded nonleaf tail. -/
namespace HegemonCrypto.SmallWood.Q38Rp05ReachableBudget

open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9HonestWholeViewGames V8Smz9HonestRequestSchedule
open V8Smz9PrivacyGameComposition
open V8Smz9EagerPrivacy V8SmzaRemainingAlgebra V8SmzaMathPrivacy
open Q38Rp05RawInputPartition Q38Rp05ChronologicalAlgebra Q38Rp05RequestCompiler
open Q38Rp05RecordedRequest Q38Rp05AdaptiveScheduler Q38Rp05StoppedMass
open Q38Rp05StoppedRefinement Q38Rp05PrefinalBudget Q38Rp05CountedNonleaf
open SmzaRp05StatementNamespace
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000
universe u
variable {Input Work : Type} {Job : Type u}
variable [Fintype Input] [DecidableEq Input] [Fintype Work] [DecidableEq Work]
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

/-- Every actual syntactic path to a pivot, with its exact spent-query count.
No path exists through a result that the actual returning request cannot emit. -/
def AtCost (property : Job → Nat → Prop) : Prefix Input Work Job → Nat → Prop
  | .finish _, _ => True
  | .pivot job, used => property job used
  | .gate _ next, used => AtCost property next used
  | .quantumQuery next, used => AtCost property next (used + 1)
  | .honestRead _ next, used => ∀ answer, AtCost property (next answer) (used + 1)
  | .instrument _ next, used => ∀ outcome, AtCost property (next outcome) used
  | .random _ next, used => ∀ coins, AtCost property (next coins) used

omit [DecidableEq Input] [DecidableEq Work] in
theorem at_cost_combine (P Q R : Job → Nat → Prop)
    (stopped : Prefix Input Work Job) (spent : Nat)
    (left : AtCost P stopped spent) (right : AtCost Q stopped spent)
    (combine : ∀ job used, P job used → Q job used → R job used) :
    AtCost R stopped spent := by
  induction stopped generalizing spent with
  | finish event => trivial
  | pivot job => exact combine job spent left right
  | gate operation next ih => exact ih spent left right
  | quantumQuery next ih => exact ih (spent + 1) left right
  | honestRead input next ih => exact fun a => ih a (spent + 1) (left a) (right a)
  | instrument operation next ih => exact fun a => ih a spent (left a) (right a)
  | random source next ih => exact fun a => ih a spent (left a) (right a)

omit [DecidableEq Input] [DecidableEq Work] in
theorem at_cost_mono (P Q : Job → Nat → Prop) (stopped : Prefix Input Work Job)
    (spent : Nat) (all : AtCost P stopped spent)
    (implication : ∀ job used, P job used → Q job used) : AtCost Q stopped spent :=
  at_cost_combine P P Q stopped spent all all (fun j u h _ => implication j u h)

omit [DecidableEq Input] [DecidableEq Work] in
theorem mixed_budget_at_cost (stopped : Prefix Input Work Job)
    (future : Job → MixedProgram Input Work) (total spent : Nat)
    (capacity : spent + V8Smz9MixedMaskCompiler.queryCount (mixedPrefix stopped future) ≤ total) :
    AtCost (fun job used => used + V8Smz9MixedMaskCompiler.queryCount (future job) ≤ total)
      stopped spent := by
  induction stopped generalizing spent with
  | finish event => trivial
  | pivot job => exact capacity
  | gate operation next ih => exact ih spent capacity
  | quantumQuery next ih =>
      apply ih (spent + 1)
      change spent + (V8Smz9MixedMaskCompiler.queryCount (mixedPrefix next future) + 1) ≤ total
        at capacity
      omega
  | honestRead input next ih =>
      intro answer
      apply ih answer (spent + 1)
      have branch := Finset.le_sup
        (f := fun a => V8Smz9MixedMaskCompiler.queryCount (mixedPrefix (next a) future))
        (Finset.mem_univ answer)
      change spent + ((Finset.univ.sup fun a =>
        V8Smz9MixedMaskCompiler.queryCount (mixedPrefix (next a) future)) + 1) ≤ total at capacity
      omega
  | instrument operation next ih =>
      intro outcome
      apply ih outcome spent
      have branch := Finset.le_sup
        (f := fun a => V8Smz9MixedMaskCompiler.queryCount (mixedPrefix (next a) future))
        (Finset.mem_univ outcome)
      exact (Nat.add_le_add_left branch spent).trans capacity
  | random source next ih =>
      intro coins
      apply ih coins spent
      have branch := Finset.le_sup
        (f := fun a => V8Smz9MixedMaskCompiler.queryCount (mixedPrefix (next a) future))
        (Finset.mem_univ coins)
      exact (Nat.add_le_add_left branch spent).trans capacity

omit [DecidableEq Input] [DecidableEq Work] in
/-- If no actual path reaches a pivot, changing its callback is exact syntax
equality. This is stronger than zero statistical/quantum distance. -/
theorem mixed_prefix_eq_of_no_pivot (stopped : Prefix Input Work Job) (spent : Nat)
    (impossible : AtCost (fun _ _ => False) stopped spent)
    (left right : Job → MixedProgram Input Work) :
    mixedPrefix stopped left = mixedPrefix stopped right := by
  induction stopped generalizing spent with
  | finish event => rfl
  | pivot job => exact impossible.elim
  | gate operation next ih => exact congrArg (MixedProgram.gate operation) (ih spent impossible)
  | quantumQuery next ih => exact congrArg MixedProgram.quantumQuery (ih (spent + 1) impossible)
  | honestRead input next ih =>
      exact congrArg (MixedProgram.honestRead input) (funext fun a => ih a (spent + 1) (impossible a))
  | instrument operation next ih =>
      exact congrArg (MixedProgram.instrument operation) (funext fun a => ih a spent (impossible a))
  | random source next ih =>
      exact congrArg (MixedProgram.random source) (funext fun a => ih a spent (impossible a))

section Current
variable {bound : Nat}
local notation "CurrentInput" => Rp05FullRawInput bound

omit [DecidableEq Work] in
theorem nonleaf_cost_lower {Result : Type} (property : Job → Nat → Prop)
    (program : NonleafProgram (Rp05OtherRawInput bound) Result)
    (next : Result → Prefix CurrentInput Work Job) (spent : Nat)
    (tails : ∀ result used, spent ≤ used → AtCost property (next result) used) :
    AtCost property (nonleafPrefix program next) spent := by
  induction program generalizing spent with
  | done result => exact tails result spent le_rfl
  | read input rest ih =>
      intro answer
      apply ih answer (spent + 1)
      intro result used enough
      exact tails result used (by omega)

omit [DecidableEq Work] in
theorem real_leaf_cost_lower (property : Job → Nat → Prop)
    (count : Nat) (indices : Fin count → LeafIndex) (statement : Statement) (salt : SaltBytes)
    (data : Fin count → Fin 1176 → Byte)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) → Prefix CurrentInput Work Job)
    (spent : Nat)
    (tails : ∀ tapes labels used, spent + count ≤ used → AtCost property (next tapes labels) used) :
    AtCost property (realLeafPrefix count indices statement salt data next) spent := by
  induction count generalizing spent with
  | zero => exact tails _ _ spent (by omega)
  | succ count ih =>
      intro tape answer
      apply ih (fun i => indices i.succ) (fun i => data i.succ)
        (fun tapes labels => next (Fin.cons tape tapes) (Fin.cons answer labels)) (spent + 1)
      intro tapes labels used enough
      exact tails _ _ used (by omega)

-- Keep the concrete 2^23-leaf request behind the generic, proved cost IR.
-- The constructor inductions above remain transparent; their callers must
-- not normalize millions of reads merely to match the resulting theorem.
attribute [local irreducible] realLeafPrefix nonleafPrefix

omit [DecidableEq Work] in
theorem real_request_cost_lower (property : Job → Nat → Prop) (data : Request bound)
    (next : Bytes → Prefix CurrentInput Work Job) (spent : Nat)
    (tails : ∀ bytes used, spent + 8388608 ≤ used → AtCost property (next bytes) used) :
    AtCost property (realRequestPrefix data next) spent := by
  intro base masks
  apply real_leaf_cost_lower
  intro tapes labels used enough
  apply nonleaf_cost_lower
  intro record more grows
  exact tails _ more (enough.trans grows)

attribute [local irreducible] realRequestPrefix

omit [DecidableEq Work] in
/-- The k-th pivot can only be reached after k complete honest requests.
Aborts in those requests do not evade the leaf charge; they occur later. -/
theorem stop_before_cost_lower {requests : Nat} (schedule : Schedule bound Work requests)
    (skip spent : Nat) :
    AtCost (fun _ used => spent + skip * 8388608 ≤ used) (stopBefore skip schedule) spent := by
  induction schedule generalizing skip spent with
  | finish event => trivial
  | gate operation next ih => exact ih skip spent
  | quantumQuery next ih =>
      exact at_cost_mono _ _ _ (spent + 1) (ih skip (spent + 1)) (by intros; omega)
  | honestRead input next ih =>
      intro answer
      exact at_cost_mono _ _ _ (spent + 1) (ih answer skip (spent + 1)) (by intros; omega)
  | instrument operation next ih => exact fun outcome => ih outcome skip spent
  | random source next ih => exact fun coins => ih coins skip spent
  | request data next ih =>
      cases skip with
      | zero =>
          change spent + 0 * 8388608 ≤ spent
          omega
      | succ skip =>
          apply real_request_cost_lower
          intro bytes used enough
          exact at_cost_mono _ _ _ used (ih bytes skip used) (by
            intro job final bound
            omega)

attribute [local irreducible] V8Smz9MixedMaskCompiler.queryCount realRequest realLeafBatch

omit [DecidableEq Work] in
/-- Every real request pays its leaves before any nonleaf rejection/abort.
No relation-acceptance, success, or continuation premise is needed. -/
theorem real_request_leaf_charge (data : Request bound)
    (next : Bytes → MixedProgram CurrentInput Work) :
    8388608 ≤ V8Smz9MixedMaskCompiler.queryCount (realRequest data next) := by
  let base : RemainingCoins Goldilocks := 0
  let masks : Q × D := 0
  let tapes : TapeTable := fun _ _ => 0
  let labels : LeafIndex → DigestRegister := 0
  obtain ⟨bytes, used, branch, _⟩ := weighted_read_count_attained
    (sourceBytesProgram data base masks tapes labels) (fun _ => 0)
  have paid := source_branch_cost_le_request data next base masks tapes labels bytes used branch
  omega

omit [DecidableEq Work] in
/-- Beyond the query-funded request count, adjacent hybrids are literally
identical programs. Early stop and all impossible callback branches vanish. -/
theorem adjacent_hybrid_eq_over_budget {requests : Nat}
    (schedule : Schedule bound Work requests) (total skip : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests schedule) ≤ total)
    (over : total < (skip + 1) * 8388608) :
    hybrid (skip + 1) schedule = hybrid skip schedule := by
  have capacity : V8Smz9MixedMaskCompiler.queryCount
      (mixedPrefix (stopBefore skip schedule) realPivot) ≤ total := by
    rw [(stopped_hybrid_pair schedule skip).1]
    exact (hybrid_count_le_all_real schedule (skip + 1)).trans budget
  have upper := mixed_budget_at_cost (stopBefore skip schedule) realPivot total 0
    (by simpa only [Nat.zero_add] using capacity)
  have lower := stop_before_cost_lower schedule skip 0
  have impossible := at_cost_combine _ _ (fun _ _ => False)
    (stopBefore skip schedule) 0 lower upper (by
      intro job used charged remaining
      have current := real_request_leaf_charge job.1 job.2
      change used + V8Smz9MixedMaskCompiler.queryCount (realRequest job.1 job.2) ≤ total at remaining
      omega)
  have equality := mixed_prefix_eq_of_no_pivot (stopBefore skip schedule) 0 impossible
    realPivot publicPivot
  simpa only [(stopped_hybrid_pair schedule skip).1, (stopped_hybrid_pair schedule skip).2]
    using equality

/-- A resource-derived effective request bound, not a caller premise. -/
def effectiveRequests (requests total : Nat) : Nat := min requests (total / 8388608)

theorem effective_requests_ledger (requests total : Nat) :
    effectiveRequests requests total * 8388608 ≤ total :=
  (Nat.mul_le_mul_right 8388608 (Nat.min_le_right _ _)).trans (Nat.div_mul_le_self _ _)

omit [DecidableEq Work] in
theorem all_real_eq_effective {requests : Nat} (schedule : Schedule bound Work requests)
    (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests schedule) ≤ total) :
    hybrid requests schedule = hybrid (effectiveRequests requests total) schedule := by
  have saturated (n : Nat) (above : effectiveRequests requests total ≤ n) (below : n ≤ requests) :
      hybrid n schedule = hybrid (effectiveRequests requests total) schedule := by
    induction n with
    | zero => have same : effectiveRequests requests total = 0 := by omega
              rw [same]
    | succ n ih =>
        by_cases equal : n + 1 = effectiveRequests requests total
        · rw [equal]
        · have divisor : total / 8388608 ≤ n := by
            unfold effectiveRequests at above equal
            omega
          have over : total < (n + 1) * 8388608 := by omega
          rw [adjacent_hybrid_eq_over_budget schedule total n budget over]
          exact ih (by omega) (by omega)
  exact saturated requests (Nat.min_le_left _ _) le_rfl

end Current
end
end HegemonCrypto.SmallWood.Q38Rp05ReachableBudget
