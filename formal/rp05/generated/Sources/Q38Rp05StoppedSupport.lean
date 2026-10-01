import Q38Rp05StoppedCore
import Q38CmsAdaptiveWholeViewApplication

/-! Actual Program-to-stopping-tree phase semantics and CMS support.
This is a structural adapter, not a per-history reachability assumption. -/
namespace HegemonCrypto.SmallWood.Q38Rp05StoppedSupport

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38Rp05StoppedMass
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option linter.unusedSectionVars false
set_option maxHeartbeats 1000000
universe u
variable {Input Work : Type} {Job : Type u}
variable [Fintype Input] [DecidableEq Input] [Fintype Work] [DecidableEq Work]

def closePrefix : Prefix Input Work Job → (Job → Program Input Work) → Program Input Work
  | .finish event, _ => .finish event
  | .pivot job, future => future job
  | .gate operation next, future => .gate operation (closePrefix next future)
  | .quantumQuery next, future => .quantumQuery (closePrefix next future)
  | .honestRead input next, future =>
      .honestRead input (fun answer => closePrefix (next answer) future)
  | .instrument operation next, future =>
      .instrument operation (fun outcome => closePrefix (next outcome) future)
  | .random source next, future => .random source (fun coins => closePrefix (next coins) future)

def phaseStop : Prefix Input Work Job →
    (Job → ResponseCmsState Input Work → ℝ) → ResponseCmsState Input Work → ℝ
  | .finish event, _, state => databaseBorn event (phaseDecode state)
  | .pivot job, future, state => future job state
  | .gate operation next, future, state => phaseStop next future (phaseGate operation state)
  | .quantumQuery next, future, state => phaseStop next future (phaseResponseQuery state)
  | .honestRead input next, future, state =>
      ∑ answer, phaseStop (next answer) future (phaseReadBranch input answer state)
  | .instrument operation next, future, state =>
      ∑ outcome, phaseStop (next outcome) future (phaseInstrumentBranch operation outcome state)
  | .random source next, future, state =>
      uniformAverage fun coins : source.Coins => phaseStop (next coins) future state

theorem close_prefix_phase_executes (stopped : Prefix Input Work Job)
    (future : Job → Program Input Work) (state : ResponseCmsState Input Work) :
    phaseRun true (closePrefix stopped future) state =
      phaseStop stopped (fun job => phaseRun true (future job)) state := by
  induction stopped generalizing state with
  | finish event => rfl
  | pivot job => rfl
  | gate operation next ih => exact ih _
  | quantumQuery next ih => exact ih _
  | honestRead input next ih =>
      simp only [closePrefix, phaseRun, phaseStop]
      exact Finset.sum_congr rfl fun answer _ => ih answer _
  | instrument operation next ih =>
      simp only [closePrefix, phaseRun, phaseStop]
      exact Finset.sum_congr rfl fun outcome _ => ih outcome _
  | random source next ih =>
      simp only [closePrefix, phaseRun, phaseStop]
      exact congrArg uniformAverage (funext fun coins => ih coins _)

/-- Signed pivot fold: already-stopped branches contribute exactly zero to an
adjacent-hybrid difference, while every continuing measured branch is retained. -/
def phaseGap : Prefix Input Work Job →
    (Job → ResponseCmsState Input Work → ℝ) → ResponseCmsState Input Work → ℝ
  | .finish _, _, _ => 0
  | .pivot job, gap, state => gap job state
  | .gate operation next, gap, state => phaseGap next gap (phaseGate operation state)
  | .quantumQuery next, gap, state => phaseGap next gap (phaseResponseQuery state)
  | .honestRead input next, gap, state =>
      ∑ answer, phaseGap (next answer) gap (phaseReadBranch input answer state)
  | .instrument operation next, gap, state =>
      ∑ outcome, phaseGap (next outcome) gap (phaseInstrumentBranch operation outcome state)
  | .random source next, gap, state =>
      uniformAverage fun coins : source.Coins => phaseGap (next coins) gap state

theorem closed_difference_eq_pivot_fold (stopped : Prefix Input Work Job)
    (left right : Job → Program Input Work) (state : ResponseCmsState Input Work) :
    phaseRun true (closePrefix stopped left) state -
        phaseRun true (closePrefix stopped right) state =
      phaseGap stopped (fun job reached =>
        phaseRun true (left job) reached - phaseRun true (right job) reached) state := by
  induction stopped generalizing state with
  | finish event => simp [closePrefix, phaseRun, phaseGap]
  | pivot job => rfl
  | gate operation next ih => exact ih _
  | quantumQuery next ih => exact ih _
  | honestRead input next ih =>
      simp only [closePrefix, phaseRun, phaseGap, ← Finset.sum_sub_distrib]
      exact Finset.sum_congr rfl fun answer _ => ih answer _
  | instrument operation next ih =>
      simp only [closePrefix, phaseRun, phaseGap, ← Finset.sum_sub_distrib]
      exact Finset.sum_congr rfl fun outcome _ => ih outcome _
  | random source next ih =>
      simp only [closePrefix, phaseRun, phaseGap, uniformAverage,
        ← Finset.sum_sub_distrib, ← mul_sub]
      exact Finset.sum_congr rfl fun coins _ => congrArg (fun value => _ * value) (ih coins _)

def AtPivots (property : Job → Nat → ResponseCmsState Input Work → Prop) :
    Prefix Input Work Job → Nat → ResponseCmsState Input Work → Prop
  | .finish _, _, _ => True
  | .pivot job, spent, state => property job spent state
  | .gate operation next, spent, state =>
      AtPivots property next spent (phaseGate operation state)
  | .quantumQuery next, spent, state =>
      AtPivots property next (spent + 1) (phaseResponseQuery state)
  | .honestRead input next, spent, state =>
      ∀ answer, AtPivots property (next answer) (spent + 1)
        (phaseReadBranch input answer state)
  | .instrument operation next, spent, state =>
      ∀ outcome, AtPivots property (next outcome) spent
        (phaseInstrumentBranch operation outcome state)
  | .random _ next, spent, state =>
      ∀ coins, AtPivots property (next coins) spent state

omit [Fintype Input] [DecidableEq Input] [Fintype Work] [DecidableEq Work] in
theorem supported_database_slice_zero (state : ResponseCmsState Input Work)
    (supported : TotalDatabaseSupport state) (database : Database Input DigestRegister)
    (absent : ¬ ∃ oracle : Input → DigestRegister, database = totalDatabase oracle) :
    databaseSlice state database = 0 := by
  ext basis
  exact supported _ absent

theorem total_support_gate (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (liftGate operation state) := by
  intro basis absent
  unfold liftGate
  rw [supported_database_slice_zero state supported basis.database absent, map_zero]
  rfl

theorem total_support_instrument {count : Nat} (operation : Instrument Input Work count)
    (outcome : Fin count) (state : ResponseCmsState Input Work)
    (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (liftInstrumentBranch operation outcome state) := by
  intro basis absent
  unfold liftInstrumentBranch
  rw [supported_database_slice_zero state supported basis.database absent, map_zero]
  rfl

omit [Fintype Input] [DecidableEq Input] [Fintype Work] [DecidableEq Work] in
theorem total_support_query (state : ResponseCmsState Input Work)
    (supported : TotalDatabaseSupport state) : TotalDatabaseSupport (databaseResponseQuery state) := by
  intro basis absent
  unfold databaseResponseQuery
  cases answer : basis.database basis.input with
  | none => exact supported basis absent
  | some value => exact supported _ absent

omit [Fintype Input] [DecidableEq Input] [Fintype Work] [DecidableEq Work] in
theorem total_support_read (input : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (databaseReadBranch input answer state) := by
  intro basis absent
  simp [databaseReadBranch, coordinateEventProjection, supported basis absent]

/-- Every reached branch still decomposes into the same physical total-oracle
fibers. This invariant follows from the read-only real stopped, not from an
oracle chosen independently after the history was observed. -/
theorem total_support_at_every_pivot (stopped : Prefix Input Work Job)
    (spent : Nat) (state : ResponseCmsState Input Work)
    (supported : TotalDatabaseSupport (phaseDecode state)) :
    AtPivots (fun _ _ reached => TotalDatabaseSupport (phaseDecode reached))
      stopped spent state := by
  induction stopped generalizing spent state with
  | finish event => trivial
  | pivot job => exact supported
  | gate operation next ih =>
      apply ih spent
      rw [phase_decode_gate]
      exact total_support_gate operation _ supported
  | quantumQuery next ih =>
      apply ih (spent + 1)
      rw [phase_decode_response_query]
      exact total_support_query _ supported
  | honestRead input next ih =>
      intro answer
      apply ih answer (spent + 1)
      rw [phase_decode_read_branch]
      exact total_support_read input answer _ supported
  | instrument operation next ih =>
      intro outcome
      apply ih outcome spent
      rw [phase_decode_instrument_branch]
      exact total_support_instrument operation outcome _ supported
  | random source next ih =>
      intro coins
      exact ih coins spent state supported

/-- The complete continuation's existing syntactic budget derives CMS support
at every actual stop. Honest reads charge one; instruments retain their exact
branches and are not normalized. No rawRun-list representation is needed. -/
theorem closed_budget_bounds_every_pivot
    (stopped : Prefix Input Work Job) (future : Job → Program Input Work)
    (total spent : Nat) (state : ResponseCmsState Input Work)
    (capacity : spent + queryCount (closePrefix stopped future) ≤ total)
    (bounded : BoundedState spent state) :
    AtPivots (fun job used reached =>
      BoundedState used reached ∧ used + queryCount (future job) ≤ total)
      stopped spent state := by
  induction stopped generalizing spent state with
  | finish event => trivial
  | pivot job => exact ⟨bounded, capacity⟩
  | gate operation next ih =>
      exact ih spent _ capacity (phase_gate_bounded operation bounded)
  | quantumQuery next ih =>
      have strict : spent < total := by
        simp only [closePrefix, queryCount] at capacity
        omega
      apply ih (spent + 1) _
      · simpa only [closePrefix, queryCount, Nat.add_assoc,
          Nat.add_comm, Nat.add_left_comm] using capacity
      · exact phase_response_query_bounded_succ total spent state strict bounded
  | honestRead input next ih =>
      intro answer
      apply ih answer (spent + 1) _
      · have branch := Finset.le_sup
          (f := fun output : DigestRegister => queryCount (closePrefix (next output) future))
          (Finset.mem_univ answer)
        simp only [closePrefix, queryCount] at capacity
        omega
      · exact phase_read_branch_bounded_succ input answer spent state bounded
  | instrument operation next ih =>
      intro outcome
      apply ih outcome spent _
      · have branch := Finset.le_sup
          (f := fun result => queryCount (closePrefix (next result) future))
          (Finset.mem_univ outcome)
        simp only [closePrefix, queryCount] at capacity
        omega
      · exact phase_instrument_branch_bounded operation outcome bounded
  | random source next ih =>
      intro coins
      apply ih coins spent state
      · have branch := Finset.le_sup
          (f := fun result : source.Coins => queryCount (closePrefix (next result) future))
          (Finset.mem_univ coins)
        simp only [closePrefix, queryCount] at capacity
        omega
      · exact bounded

end
end HegemonCrypto.SmallWood.Q38Rp05StoppedSupport
