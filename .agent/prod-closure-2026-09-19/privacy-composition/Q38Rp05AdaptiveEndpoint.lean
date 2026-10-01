import Q38Rp05ActualPivot
import Q38Rp05ReachableBudget

/-! Whole finite adaptive scheduler endpoint. Source-only until serial Lean
validation. Every local privacy estimate is instantiated below, not assumed. -/
namespace HegemonCrypto.SmallWood.Q38Rp05AdaptiveEndpoint

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05MaskRecovery (rp05PackValues)
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
open HegemonCrypto.SmallWood.Q38Rp05StoppedMass
open HegemonCrypto.SmallWood.Q38Rp05StoppedSupport
open HegemonCrypto.SmallWood.Q38Rp05StoppedRefinement
open HegemonCrypto.SmallWood.Q38Rp05PhaseStoppingBound
open HegemonCrypto.SmallWood.Q38Rp05ActualPivot
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.SmzaRp05CsrNormalization
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
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

def EveryJob (property : Job → Prop) : Prefix Input Work Job → Prop
  | .finish _ => True
  | .pivot job => property job
  | .gate _ next => EveryJob property next
  | .quantumQuery next => EveryJob property next
  | .honestRead _ next => ∀ answer, EveryJob property (next answer)
  | .instrument _ next => ∀ outcome, EveryJob property (next outcome)
  | .random _ next => ∀ coins, EveryJob property (next coins)

omit [DecidableEq Input] [DecidableEq Work] in
theorem every_job_budget (stopped : Prefix Input Work Job)
    (future : Job → MixedProgram Input Work) (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount (mixedPrefix stopped future) ≤ total) :
    EveryJob (fun job => V8Smz9MixedMaskCompiler.queryCount (future job) ≤ total) stopped := by
  induction stopped with
  | finish event => trivial
  | pivot job => exact budget
  | gate operation next ih => exact ih budget
  | quantumQuery next ih =>
      apply ih
      change V8Smz9MixedMaskCompiler.queryCount (mixedPrefix next future) + 1 ≤ total at budget
      omega
  | honestRead input next ih =>
      intro answer
      apply ih answer
      have member := Finset.le_sup
        (f := fun output => V8Smz9MixedMaskCompiler.queryCount (mixedPrefix (next output) future))
        (Finset.mem_univ answer)
      change (Finset.univ.sup fun output =>
        V8Smz9MixedMaskCompiler.queryCount (mixedPrefix (next output) future)) + 1 ≤ total at budget
      omega
  | instrument operation next ih =>
      intro outcome
      exact ih outcome ((Finset.le_sup
        (f := fun output => V8Smz9MixedMaskCompiler.queryCount
          (mixedPrefix (next output) future)) (Finset.mem_univ outcome)).trans budget)
  | random source next ih =>
      intro coins
      exact ih coins ((Finset.le_sup
        (f := fun output => V8Smz9MixedMaskCompiler.queryCount
          (mixedPrefix (next output) future)) (Finset.mem_univ coins)).trans budget)

omit [DecidableEq Work] in
theorem every_job_at_pivots (property : Job → Prop) (stopped : Prefix Input Work Job)
    (all : EveryJob property stopped) (spent : Nat) (state : ResponseCmsState Input Work) :
    AtPivots (fun job _ _ => property job) stopped spent state := by
  induction stopped generalizing spent state with
  | finish event => trivial
  | pivot job => exact all
  | gate operation next ih => exact ih all spent _
  | quantumQuery next ih => exact ih all (spent + 1) _
  | honestRead input next ih => exact fun answer => ih answer (all answer) (spent + 1) _
  | instrument operation next ih => exact fun outcome => ih outcome (all outcome) spent _
  | random source next ih => exact fun coins => ih coins (all coins) spent state

omit [DecidableEq Work] in
theorem at_pivots_combine
    (P Q R : Job → Nat → ResponseCmsState Input Work → Prop)
    (stopped : Prefix Input Work Job) (spent : Nat) (state : ResponseCmsState Input Work)
    (left : AtPivots P stopped spent state) (right : AtPivots Q stopped spent state)
    (combine : ∀ job used reached, P job used reached → Q job used reached → R job used reached) :
    AtPivots R stopped spent state := by
  induction stopped generalizing spent state with
  | finish event => trivial
  | pivot job => exact combine job spent state left right
  | gate operation next ih => exact ih spent _ left right
  | quantumQuery next ih => exact ih (spent + 1) _ left right
  | honestRead input next ih => exact fun answer => ih answer (spent + 1) _ (left answer) (right answer)
  | instrument operation next ih => exact fun outcome => ih outcome spent _ (left outcome) (right outcome)
  | random source next ih => exact fun coins => ih coins spent state (left coins) (right coins)

omit [DecidableEq Work] in
private theorem at_pivots_and
    (P Q : Job → Nat → ResponseCmsState Input Work → Prop)
    (stopped : Prefix Input Work Job) (spent : Nat) (state : ResponseCmsState Input Work)
    (left : AtPivots P stopped spent state) (right : AtPivots Q stopped spent state) :
    AtPivots (fun job used reached => P job used reached ∧ Q job used reached)
      stopped spent state :=
  at_pivots_combine P Q (fun job used reached => P job used reached ∧ Q job used reached)
    stopped spent state left right (fun _ _ _ a b => ⟨a, b⟩)

section Current
variable {bound : Nat}
local notation "CurrentInput" => Rp05FullRawInput bound
local notation "W" => Unit × Work

def RequestEligible (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat)
    (nodeDegree : Nat → Nat) (data : Request bound) : Prop :=
  data.dsl = normalizedDsl components nonlinearRoot nodeDegree ∧
    components.AcceptsPacked (currentPublicWords data.statement) (rp05PackValues data.witness)

def Eligible (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat)
    (nodeDegree : Nat → Nat) : {requests : Nat} → Schedule bound W requests → Prop
  | _, .finish _ => True
  | _, .gate _ next => Eligible components nonlinearRoot nodeDegree next
  | _, .quantumQuery next => Eligible components nonlinearRoot nodeDegree next
  | _, .honestRead _ next => ∀ answer, Eligible components nonlinearRoot nodeDegree (next answer)
  | _, .instrument _ next => ∀ outcome, Eligible components nonlinearRoot nodeDegree (next outcome)
  | _, .random _ next => ∀ coins, Eligible components nonlinearRoot nodeDegree (next coins)
  | _, .request data next => RequestEligible components nonlinearRoot nodeDegree data ∧
      ∀ bytes, Eligible components nonlinearRoot nodeDegree (next bytes)

omit [DecidableEq Work] in
theorem every_job_nonleaf {A : Type}
    (program : V8Smz9HonestRequestSchedule.NonleafProgram (Rp05OtherRawInput bound) A)
    (next : A → Prefix CurrentInput W Job) (P : Job → Prop)
    (all : ∀ result, EveryJob P (next result)) : EveryJob P (nonleafPrefix program next) := by
  induction program with
  | done result => exact all result
  | read input tail ih => exact fun answer => ih answer

omit [DecidableEq Work] in
private theorem every_job_real_leaf (P : Job → Prop)
    {count : Nat} (indices : Fin count → V8Smz9HiddenPatch.LeafIndex)
    (statement : SmzaRp05StatementNamespace.Statement) (salt : V8Smz9EagerOracleGame.SaltBytes)
    (payload : Fin count → Fin 1176 → HegemonCrypto.CanonicalBytes.Byte)
    (rest : (Fin count → V8Smz9HiddenLeafQrom.LeafTape) →
      (Fin count → DigestRegister) → Prefix CurrentInput W Job)
    (good : ∀ tapes labels, EveryJob P (rest tapes labels)) :
    EveryJob P (realLeafPrefix count indices statement salt payload rest) := by
  induction count with
  | zero => exact good _ _
  | succ count ih =>
      intro tape answer
      apply ih
      intro tapes labels
      exact good _ _

-- Constructor proofs stay generic; matching their concrete request callers
-- must not unfold the 2^23-read tree into a gigantic telescope.
attribute [local irreducible] realLeafPrefix nonleafPrefix

omit [DecidableEq Work] in
theorem every_job_real_request (data : Request bound)
    (next : Bytes → Prefix CurrentInput W Job) (P : Job → Prop)
    (all : ∀ bytes, EveryJob P (next bytes)) : EveryJob P (realRequestPrefix data next) := by
  intro base masks
  apply every_job_real_leaf
  intro tapes labels
  apply every_job_nonleaf
  intro record
  exact all _

attribute [local irreducible] realRequestPrefix

omit [DecidableEq Work] in
theorem stopped_jobs_eligible
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat)
    (nodeDegree : Nat → Nat) {requests : Nat} (schedule : Schedule bound W requests)
    (eligible : Eligible components nonlinearRoot nodeDegree schedule) (skip : Nat) :
    EveryJob (fun job : Pivot bound W => RequestEligible components nonlinearRoot nodeDegree job.1)
      (stopBefore skip schedule) := by
  induction schedule generalizing skip with
  | finish event => trivial
  | gate operation next ih => exact ih eligible skip
  | quantumQuery next ih => exact ih eligible skip
  | honestRead input next ih => exact fun answer => ih answer (eligible answer) skip
  | instrument operation next ih => exact fun outcome => ih outcome (eligible outcome) skip
  | random source next ih => exact fun coins => ih coins (eligible coins) skip
  | request data next ih =>
      cases skip with
      | zero => exact eligible.1
      | succ skip =>
          apply every_job_real_request
          intro bytes
          exact ih bytes (eligible.2 bytes) skip

attribute [local irreducible] V8Smz9MixedMaskCompiler.queryCount realRequest publicRequest

theorem actual_hybrid_phase_refinement {requests : Nat} (schedule : Schedule bound W requests)
    (skip : Nat) (reached : ResponseCmsState CurrentInput W)
    (supported : TotalDatabaseSupport (phaseDecode reached)) :
    phaseRun true (compiledHybrid (skip + 1) schedule) reached =
      phaseRun true (closePrefix (stopBefore skip schedule)
        (fun job => V8Smz9MixedMaskCompiler.compile (realPivot job) [])) reached ∧
    phaseRun true (compiledHybrid skip schedule) reached =
      phaseRun true (closePrefix (stopBefore skip schedule)
        (fun job => V8Smz9MixedMaskCompiler.compile (publicPivot job) [])) reached := by
  constructor <;> rw [phase_run_same_family _ reached supported,
    phase_run_same_family _ reached supported] <;>
    apply congrArg V8Smz9CurrentPrivacyGame.uniformAverage <;> funext oracle
  · rw [compiled_hybrid_executes, mixed_prefix_executes, (stopped_hybrid_pair schedule skip).1]
  · rw [compiled_hybrid_executes, mixed_prefix_executes, (stopped_hybrid_pair schedule skip).2]

theorem actual_adjacent_hybrid_bound
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates (normalizedDsl components nonlinearRoot nodeDegree))
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0) (abortTargets : Targets abortPoints)
    {requests : Nat} (schedule : Schedule bound W requests)
    (eligible : Eligible components nonlinearRoot nodeDegree schedule)
    (total skip : Nat) (budget : WithinBudget schedule total) (before : skip < requests)
    (initial : ResponseCmsState CurrentInput W) (emptyBound : BoundedState 0 initial)
    (supported : TotalDatabaseSupport (phaseDecode initial)) :
    |phaseRun true (compiledHybrid (skip + 1) schedule) initial -
      phaseRun true (compiledHybrid skip schedule) initial| ≤ loss total * normSquared initial := by
  let stopped := stopBefore skip schedule
  have refined := actual_hybrid_phase_refinement schedule skip initial supported
  rw [refined.1, refined.2, closed_difference_eq_pivot_fold]
  apply phase_gap_bound stopped _ (loss total) (loss_nonnegative total) 0 initial
  have capacity := (stopped_hybrid_budget schedule total skip budget before).1
  have support := closed_budget_bounds_every_pivot stopped
    (fun job => V8Smz9MixedMaskCompiler.compile (realPivot job) []) total 0 initial
    (by simpa using capacity) emptyBound
  have totals := total_support_at_every_pivot stopped 0 initial supported
  have realJobs := every_job_budget stopped realPivot total (by
    rw [(stopped_hybrid_pair schedule skip).1]
    exact budget (skip + 1) (by omega))
  have publicJobs := every_job_budget stopped publicPivot total (by
    rw [(stopped_hybrid_pair schedule skip).2]
    exact budget skip (by omega))
  have eligibility := every_job_at_pivots _ stopped
    (stopped_jobs_eligible components nonlinearRoot nodeDegree schedule eligible skip) 0 initial
  have qreal := every_job_at_pivots _ stopped realJobs 0 initial
  have qpublic := every_job_at_pivots _ stopped publicJobs 0 initial
  have together := at_pivots_and _ _ stopped 0 initial support totals
  have together := at_pivots_and _ _ stopped 0 initial together eligibility
  have together := at_pivots_and _ _ stopped 0 initial together qreal
  exact at_pivots_combine _ _ _ stopped 0 initial together qpublic (by
    intro job used reached data qpub
    rcases data with ⟨⟨⟨⟨bounded, remaining⟩, totalSupport⟩, ⟨currentDsl, accepted⟩⟩, qreal⟩
    exact actual_pivot_bound components nonlinearRoot nodeDegree certificates job.1
      currentDsl accepted abortPoints abortAdmissible abortNonzero abortTargets job.2
      total qreal qpub reached (bounded_state_mono (by omega) bounded) totalSupport)

/-- Actual outer reverse telescope. Its only security input is the local
current-request theorem applied above; no per-hop inequality is a premise. -/
theorem actual_adaptive_real_public_bound
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates (normalizedDsl components nonlinearRoot nodeDegree))
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0) (abortTargets : Targets abortPoints)
    {requests : Nat} (schedule : Schedule bound W requests)
    (eligible : Eligible components nonlinearRoot nodeDegree schedule)
    (total : Nat) (budget : WithinBudget schedule total)
    (initial : ResponseCmsState CurrentInput W) (emptyBound : BoundedState 0 initial)
    (supported : TotalDatabaseSupport (phaseDecode initial)) :
    |phaseRun true (compiledHybrid requests schedule) initial -
      phaseRun true (compiledHybrid 0 schedule) initial| ≤
      (Q38Rp05ReachableBudget.effectiveRequests requests total : ℝ) * loss total * normSquared initial := by
  have hops (n : Nat) (within : n ≤ requests) :
      |phaseRun true (compiledHybrid n schedule) initial -
        phaseRun true (compiledHybrid 0 schedule) initial| ≤
        (n : ℝ) * loss total * normSquared initial := by
    induction n with
    | zero => simp
    | succ n ih =>
      have adjacent := actual_adjacent_hybrid_bound components nonlinearRoot nodeDegree
        certificates abortPoints abortAdmissible abortNonzero abortTargets schedule eligible
        total n budget (by omega) initial emptyBound supported
      calc
        _ ≤ |phaseRun true (compiledHybrid (n + 1) schedule) initial -
              phaseRun true (compiledHybrid n schedule) initial| +
            |phaseRun true (compiledHybrid n schedule) initial -
              phaseRun true (compiledHybrid 0 schedule) initial| := abs_sub_le _ _ _
        _ ≤ _ := add_le_add adjacent (ih (by omega))
        _ = _ := by push_cast; ring
  have funded := Q38Rp05ReachableBudget.all_real_eq_effective schedule total
    (budget requests le_rfl)
  have compiled : compiledHybrid requests schedule =
      compiledHybrid (Q38Rp05ReachableBudget.effectiveRequests requests total) schedule :=
    congrArg (fun program => V8Smz9MixedMaskCompiler.compile program []) funded
  rw [compiled]
  exact hops _ (Nat.min_le_left _ _)

end Current
end
end HegemonCrypto.SmallWood.Q38Rp05AdaptiveEndpoint
