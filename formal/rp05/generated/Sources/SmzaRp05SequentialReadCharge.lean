import SmzaRp05VectorReadCharge

/-!
# Sequential full-vector terminal read charging

Each selected public read uses the exact one-query full-vector circuit.  The
next branch is proved bounded and standard-total, so the charge induction
does not assume a per-branch support certificate.  This file does not assert
that a database-dependent current-role event commutes with recompression.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05SequentialReadCharge

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.DatabaseFiber
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.SmallWood.V8Smz9CoherentVectorMerkle
open HegemonCrypto.SmallWood.SmzaRp05PhysicalTerminalRead
open HegemonCrypto.SmallWood.SmzaRp05VectorReadCharge
open HegemonCrypto.SmallWood.SmzaRp05SuffixReadout

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

variable {Key Counter Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Work] [DecidableEq Work]

alias coordinate_projection_decompress_at_of_ne := SmzaRp05PhysicalReadSupport.coordinate_projection_decompress_at_of_ne
alias coordinate_projection_decompress_list_of_outside := SmzaRp05PhysicalReadSupport.coordinate_projection_decompress_list_of_outside
alias coordinate_projection_decompress_except := SmzaRp05PhysicalReadSupport.coordinate_projection_decompress_except
alias physical_read_branch_eq_selected := SmzaRp05PhysicalReadSupport.physical_read_branch_eq_selected
alias selected_physical_read_branch_bounded_succ := SmzaRp05PhysicalReadSupport.selected_physical_read_branch_bounded_succ
alias physical_read_branch_bounded_succ := SmzaRp05PhysicalReadSupport.physical_read_branch_bounded_succ

/-- Explicit sequential circuit.  The budget is advanced after each
measured query, and the next circuit acts on the previous answer branch. -/
def chargedReadTrace :
    (keys : List Key) →
      ReadAnswers (Input := Key) (Answer (Counter := Counter)) keys →
      Nat → VectorCmsState (Key := Key) (Counter := Counter) (Work := Work) →
        VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)
  | [], _, _, state => state
  | key :: keys, (answer, answers), bound, state =>
      chargedReadTrace keys answers (bound + 1)
        (globalDecompress
          (readoutAndRestore key answer
            (vectorFourierInverseState
              (globalDecompress
                (queryState vectorPhaseSystem (bound + 1)
                  (vectorFourierState (prepareZeroAt key state)))))))

/-- The whole physical terminal trace is exactly the ordered sequence of
charged full-vector CMS queries.  No branchwise support or totality premise
is supplied: both are propagated from the single initial state. -/
theorem charged_read_trace_eq_physical_read_trace
    (keys : List Key)
    (answers : ReadAnswers (Input := Key) (Answer (Counter := Counter)) keys)
    (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state)
    (total : TotalOn keys (globalDecompress state)) :
    chargedReadTrace keys answers bound state =
      physicalReadTrace keys answers state := by
  induction keys generalizing bound state with
  | nil => rfl
  | cons key keys ih =>
      rcases answers with ⟨answer, answers⟩
      simp only [chargedReadTrace, physicalReadTrace]
      rw [← physical_read_branch_eq_one_charged_vector_query
        key answer bound state bounded (total key (by simp))]
      exact ih answers (bound + 1) (physicalReadBranch key answer state)
        (physical_read_branch_bounded_succ key answer bound state bounded)
        (by
          intro selected member
          rw [physical_read_branch_standard_view]
          exact total_at_coordinate_event_projection selected key answer
            (globalDecompress state) (total selected (by simp [member])))

/-- The whole measured trace consumes at most one support slot per key,
including repeated keys.  Repeated reads may be redundant, but are not
silently declared free in the physical charge count. -/
theorem physical_read_trace_bounded_add_length
    (keys : List Key)
    (answers : ReadAnswers (Input := Key) (Answer (Counter := Counter)) keys)
    (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state) :
    BoundedState (bound + keys.length)
      (physicalReadTrace keys answers state) := by
  induction keys generalizing bound state with
  | nil => simpa [physicalReadTrace] using bounded
  | cons key keys ih =>
      rcases answers with ⟨answer, answers⟩
      simpa [physicalReadTrace, Nat.add_assoc, Nat.add_comm,
        Nat.add_left_comm] using
        (ih answers (bound + 1) (physicalReadBranch key answer state)
          (physical_read_branch_bounded_succ key answer bound state bounded))

theorem charged_read_trace_bounded_add_length
    (keys : List Key)
    (answers : ReadAnswers (Input := Key) (Answer (Counter := Counter)) keys)
    (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state) (total : TotalOn keys (globalDecompress state)) :
    BoundedState (bound + keys.length)
      (chargedReadTrace keys answers bound state) := by
  rw [charged_read_trace_eq_physical_read_trace
    keys answers bound state bounded total]
  exact physical_read_trace_bounded_add_length
    keys answers bound state bounded

/-- The terminal workspace/database event mass is unchanged when the
physical read trace is replaced by its exact sequential charged circuit. -/
theorem charged_read_trace_event_norm_eq
    (keys : List Key)
    (answers : ReadAnswers (Input := Key) (Answer (Counter := Counter)) keys)
    (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state) (total : TotalOn keys (globalDecompress state))
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop) :
    normSquared (workspaceEventProjection event
      (chargedReadTrace keys answers bound state)) =
      normSquared (workspaceEventProjection event
        (physicalReadTrace keys answers state)) := by
  rw [charged_read_trace_eq_physical_read_trace
    keys answers bound state bounded total]

/-- Equality also holds after summing every orthogonal answer trace, so the
sequential query charge introduces no postselection factor. -/
theorem sum_charged_read_trace_event_norm_eq
    (keys : List Key) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state) (total : TotalOn keys (globalDecompress state))
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop) :
    (∑ answers : ReadAnswers (Input := Key)
        (Answer (Counter := Counter)) keys,
      normSquared (workspaceEventProjection event
        (chargedReadTrace keys answers bound state))) =
      ∑ answers : ReadAnswers (Input := Key)
        (Answer (Counter := Counter)) keys,
        normSquared (workspaceEventProjection event
          (physicalReadTrace keys answers state)) := by
  apply Finset.sum_congr rfl
  intro answers _
  exact charged_read_trace_event_norm_eq
    keys answers bound state bounded total event

end
end HegemonCrypto.SmallWood.SmzaRp05SequentialReadCharge
