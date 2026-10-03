import SmzaRp05PartialReadout
import SmzaRp05SuffixReadout

/-!
# Physical RP05 terminal reads

The terminal database of a compressed CMS state is not a total classical
oracle.  An honest read is a measurement in the standard-oracle presentation,
followed by return to the compressed presentation.  The completeness premise
below is deliberately on that standard presentation, never on the sparse
compressed database.  Establishing it for the physical verifier execution is
an independent simulation invariant; it is not inferred from a query budget.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalTerminalRead

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.SmallWood.SmzaRp05SuffixReadout
open HegemonCrypto.SmallWood.SmzaRp05PartialReadout

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output Phase Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

/-- The exact standard-oracle totality invariant required by a physical
classical read.  It does not assert that the compressed database is total. -/
def StandardTotal
    (state : State Key Output Phase Work) : Prop :=
  ∀ key, TotalAt key (globalDecompress state)

/-- A persistent physical oracle family supplies standard totality.  The
family, not a populated compressed database, is the source of honest answers. -/
theorem standard_total_of_oracle_family
    (state : State Key Output Phase Work)
    (family : OracleRegisterFamily
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Work))
    (physical : globalDecompress state = totalOracleFamilyState family) :
    StandardTotal state := by
  intro key
  rw [physical]
  exact total_oracle_family_state_total_at family key

/-- Decompress, measure one actual oracle output, and recompress.  This is
the generic-vector analogue of `phaseReadBranch` / `measuredReadBranch` in the
Q38 physical interpreter.  No oracle value is read directly from a compressed
database slot. -/
def physicalReadBranch
    (key : Key) (answer : Output)
    (state : State Key Output Phase Work) :
    State Key Output Phase Work :=
  globalDecompress
    (coordinateEventProjection key answer (globalDecompress state))

theorem physical_read_branch_standard_view
    (key : Key) (answer : Output)
    (state : State Key Output Phase Work) :
    globalDecompress (physicalReadBranch key answer state) =
      coordinateEventProjection key answer (globalDecompress state) := by
  exact global_decompress_involutive _

/-- Every nonzero physical read branch records its reported answer in the
standard-oracle presentation. -/
theorem physical_read_branch_answer_known
    (key : Key) (answer : Output)
    (state : State Key Output Phase Work) :
    KnownAt key answer (globalDecompress
      (physicalReadBranch key answer state)) := by
  rw [physical_read_branch_standard_view]
  exact coordinate_event_projection_idempotent key answer
    (globalDecompress state)

/-- A physical read does not destroy standard-oracle totality at another
coordinate; it only projects amplitudes. -/
theorem physical_read_branch_standard_total
    (key : Key) (answer : Output)
    (state : State Key Output Phase Work)
    (total : StandardTotal state) :
    StandardTotal (physicalReadBranch key answer state) := by
  intro selected
  rw [physical_read_branch_standard_view]
  exact total_at_coordinate_event_projection selected key answer
    (globalDecompress state) (total selected)

/-- A predicate already fixed in the classical verifier workspace commutes
with the honest read and recompression.  This is the needed transport for an
accepted-transcript flag copied before the extractor's database measurement;
it makes no claim that a database-dependent current-role event commutes. -/
theorem workspace_projection_physical_read_branch
    (enabled : Work → Prop) (key : Key) (answer : Output)
    (state : State Key Output Phase Work) :
    workspaceOnlyProjection enabled (physicalReadBranch key answer state) =
      physicalReadBranch key answer
        (workspaceOnlyProjection enabled state) := by
  have coordinateCommute
      (source : State Key Output Phase Work) :
      workspaceOnlyProjection enabled
          (coordinateEventProjection key answer source) =
        coordinateEventProjection key answer
          (workspaceOnlyProjection enabled source) := by
    funext basis
    by_cases accepted : enabled basis.workspace <;>
      by_cases recorded : basis.database key = some answer <;>
      simp [workspaceOnlyProjection, workspaceEventProjection,
        coordinateEventProjection, accepted, recorded]
  unfold physicalReadBranch globalDecompress
  rw [workspace_only_projection_decompress_list,
    coordinateCommute, workspace_only_projection_decompress_list]

/-- The physical read instrument is exhaustive on a standard-total input.
The branch vectors are unnormalised; no postselection probability occurs. -/
theorem sum_physical_read_branch_norm_squared
    (key : Key) (state : State Key Output Phase Work)
    (total : StandardTotal state) :
    (∑ answer : Output,
      normSquared (physicalReadBranch key answer state)) =
      normSquared state := by
  calc
    _ = ∑ answer : Output,
        normSquared
          (coordinateEventProjection key answer (globalDecompress state)) := by
      apply Finset.sum_congr rfl
      intro answer _
      exact decompress_list_preserves_norm_squared
        (Finset.univ : Finset Key).toList _
    _ = normSquared (globalDecompress state) :=
      sum_database_read_branch_norm_squared key (globalDecompress state)
        (total key)
    _ = normSquared state :=
      decompress_list_preserves_norm_squared
        (Finset.univ : Finset Key).toList state

/-- In the standard-oracle basis, a physical answer measurement does not
amplify an arbitrary diagonal workspace/database event when all answer
branches are retained. The event and answer projectors commute pointwise.
This does not commute the event through the surrounding compression maps;
that is the separate readout-transport obligation. -/
theorem sum_standard_answer_event_mass
    (key : Key) (event : Work → Database Key Output → Prop)
    (state : State Key Output Phase Work)
    (total : TotalAt key state) :
    (∑ answer : Output,
      normSquared (workspaceEventProjection event
        (coordinateEventProjection key answer state))) =
      normSquared (workspaceEventProjection event state) := by
  have commute (answer : Output) :
      workspaceEventProjection event
          (coordinateEventProjection key answer state) =
        coordinateEventProjection key answer
          (workspaceEventProjection event state) := by
    funext basis
    by_cases enabled : event basis.workspace basis.database <;>
      by_cases selected : basis.database key = some answer <;>
      simp [workspaceEventProjection, coordinateEventProjection,
        enabled, selected]
  have totalEvent : TotalAt key (workspaceEventProjection event state) := by
    intro basis absent
    simp [workspaceEventProjection, total basis absent]
  simp_rw [commute]
  exact sum_database_read_branch_norm_squared key
    (workspaceEventProjection event state) totalEvent

/-- One actual decompress/measure/recompress read has the same event-mass
identity when the event is evaluated in its standard-oracle presentation.
The compressed-side role event still needs the existing transport estimate. -/
theorem sum_physical_read_standard_event_mass
    (key : Key) (event : Work → Database Key Output → Prop)
    (state : State Key Output Phase Work)
    (total : StandardTotal state) :
    (∑ answer : Output,
      normSquared (workspaceEventProjection event
        (globalDecompress (physicalReadBranch key answer state)))) =
      normSquared (workspaceEventProjection event
        (globalDecompress state)) := by
  simp_rw [physical_read_branch_standard_view]
  exact sum_standard_answer_event_mass key event
    (globalDecompress state) (total key)

/-- Sequential physical reads, including every answer branch.  The recursive
state is the previous measured compressed branch, not the original CMS state. -/
def physicalReadTrace :
    (keys : List Key) → ReadAnswers (Input := Key) Output keys →
      State Key Output Phase Work → State Key Output Phase Work
  | [], _, state => state
  | key :: keys, (answer, answers), state =>
      physicalReadTrace keys answers (physicalReadBranch key answer state)

theorem workspace_projection_physical_read_trace
    (enabled : Work → Prop) (keys : List Key)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work) :
    workspaceOnlyProjection enabled (physicalReadTrace keys answers state) =
      physicalReadTrace keys answers
        (workspaceOnlyProjection enabled state) := by
  induction keys generalizing state with
  | nil => rfl
  | cons key keys inductionHypothesis =>
      rcases answers with ⟨answer, answers⟩
      simp only [physicalReadTrace]
      rw [inductionHypothesis,
        workspace_projection_physical_read_branch]

theorem sum_physical_read_trace_norm_squared
    (keys : List Key) (state : State Key Output Phase Work)
    (total : StandardTotal state) :
    (∑ answers : ReadAnswers (Input := Key) Output keys,
      normSquared (physicalReadTrace keys answers state)) =
      normSquared state := by
  induction keys generalizing state with
  | nil => simp [physicalReadTrace, ReadAnswers]
  | cons key keys inductionHypothesis =>
      change
        (∑ answers : Output × ReadAnswers (Input := Key) Output keys,
          normSquared (physicalReadTrace (key :: keys) answers state)) = _
      rw [Fintype.sum_prod_type]
      simp only [physicalReadTrace]
      calc
        (∑ answer : Output,
          ∑ answers : ReadAnswers (Input := Key) Output keys,
            normSquared (physicalReadTrace keys answers
              (physicalReadBranch key answer state))) =
            ∑ answer : Output,
              normSquared (physicalReadBranch key answer state) := by
          apply Finset.sum_congr rfl
          intro answer _
          exact inductionHypothesis _
            (physical_read_branch_standard_total key answer state total)
        _ = normSquared state :=
          sum_physical_read_branch_norm_squared key state total

/-- The entire sequential physical read instrument preserves the mass of
any diagonal database/workspace event in the standard-oracle presentation,
after summing all unnormalised answer branches. This isolates the genuine
remaining soundness work to transporting the certified compressed-side role
event across the physical read circuit, not to a branch-count factor. -/
theorem sum_physical_read_trace_standard_event_mass
    (keys : List Key) (event : Work → Database Key Output → Prop)
    (state : State Key Output Phase Work)
    (total : StandardTotal state) :
    (∑ answers : ReadAnswers (Input := Key) Output keys,
      normSquared (workspaceEventProjection event
        (globalDecompress (physicalReadTrace keys answers state)))) =
      normSquared (workspaceEventProjection event
        (globalDecompress state)) := by
  induction keys generalizing state with
  | nil => simp [physicalReadTrace, ReadAnswers]
  | cons key keys inductionHypothesis =>
      change
        (∑ answers : Output × ReadAnswers (Input := Key) Output keys,
          normSquared (workspaceEventProjection event
            (globalDecompress
              (physicalReadTrace (key :: keys) answers state)))) = _
      rw [Fintype.sum_prod_type]
      simp only [physicalReadTrace]
      calc
        (∑ answer : Output,
          ∑ answers : ReadAnswers (Input := Key) Output keys,
            normSquared (workspaceEventProjection event
              (globalDecompress (physicalReadTrace keys answers
                (physicalReadBranch key answer state))))) =
            ∑ answer : Output,
              normSquared (workspaceEventProjection event
                (globalDecompress (physicalReadBranch key answer state))) := by
          apply Finset.sum_congr rfl
          intro answer _
          exact inductionHypothesis _
            (physical_read_branch_standard_total key answer state total)
        _ = normSquared (workspaceEventProjection event
              (globalDecompress state)) :=
          sum_physical_read_standard_event_mass key event state total

/-- In the standard-oracle presentation, the physical trace is exactly the
ordinary sequence of recorded-answer projectors.  The compressed database is
never inspected to obtain any answer. -/
theorem physical_read_trace_standard_view
    (keys : List Key)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work) :
    globalDecompress (physicalReadTrace keys answers state) =
      retainedReadBranch keys answers (globalDecompress state) := by
  induction keys generalizing state with
  | nil => rfl
  | cons key keys inductionHypothesis =>
      rcases answers with ⟨answer, answers⟩
      simp only [physicalReadTrace, retainedReadBranch]
      rw [inductionHypothesis, physical_read_branch_standard_view]

/-- Every claim actually recorded by a duplicate-free honest read trace is
known in the standard-oracle branch, with no `KnownAt` hypothesis about the
initial compressed database. -/
theorem physical_read_trace_claim_known
    (keys : List Key) (nodup : keys.Nodup)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work)
    (claim : Key × Output) (member : claim ∈ branchClaims keys answers) :
    KnownAt claim.1 claim.2
      (globalDecompress (physicalReadTrace keys answers state)) := by
  rw [physical_read_trace_standard_view]
  exact branch_claim_known_at keys nodup answers
    (globalDecompress state) claim member

/-- Recompressing the complete standard-oracle presentation recovers the
same physical branch.  The all-key schedule is finite, duplicate-free and
contains every claim key. -/
theorem physical_read_trace_claim_failure_le
    (keys : List Key) (nodup : keys.Nodup)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work) :
    let finalState := physicalReadTrace keys answers state
    normSquared
        (claimFailureProjection (branchClaims keys answers) finalState) ≤
      ((2 * (branchClaims keys answers).toFinset.card : Nat) : ℝ) /
          Fintype.card Output * normSquared finalState := by
  dsimp only
  let finalState := physicalReadTrace keys answers state
  let standardState := globalDecompress finalState
  have known : ∀ claim ∈ branchClaims keys answers,
      KnownAt claim.1 claim.2 standardState := by
    intro claim member
    exact physical_read_trace_claim_known keys nodup answers state claim member
  have factorization : ∀ claim ∈ branchClaims keys answers,
      ∃ otherInputs : List Key,
        claim.1 ∉ otherInputs ∧
          finalState = decompressList otherInputs
            (decompressAt claim.1 standardState) := by
    intro claim member
    obtain ⟨otherInputs, outside, factor⟩ :=
      nodup_decompress_list_selected_factorization
        claim.1 (Finset.univ : Finset Key).toList standardState
        (by simp) (Finset.nodup_toList _)
    refine ⟨otherInputs, outside, ?_⟩
    have recompressed :
        decompressList (Finset.univ : Finset Key).toList standardState =
          finalState := global_decompress_involutive finalState
    exact recompressed.symm.trans factor
  have bound := known_claims_partial_decompress_failure_le
    (branchClaims keys answers) standardState finalState known factorization
  have normEq : normSquared standardState = normSquared finalState :=
    decompress_list_preserves_norm_squared
      (Finset.univ : Finset Key).toList finalState
  simpa [normEq] using bound

theorem physical_branch_claims_length
    (keys : List Key)
    (answers : ReadAnswers (Input := Key) Output keys) :
    (branchClaims keys answers).length = keys.length := by
  induction keys with
  | nil => rfl
  | cons key keys inductionHypothesis =>
      rcases answers with ⟨answer, answers⟩
      simp [branchClaims, inductionHypothesis answers]

/-- All physical answer branches together incur the vector-retention loss
only once.  The sole totality premise concerns the actual standard-oracle
family; it does not claim a populated compressed database. -/
theorem sum_physical_read_trace_claim_failure_le
    (keys : List Key) (nodup : keys.Nodup)
    (state : State Key Output Phase Work)
    (total : StandardTotal state) :
    (∑ answers : ReadAnswers (Input := Key) Output keys,
      normSquared
        (claimFailureProjection (branchClaims keys answers)
          (physicalReadTrace keys answers state))) ≤
      ((2 * keys.length : Nat) : ℝ) / Fintype.card Output *
        normSquared state := by
  calc
    _ ≤ ∑ answers : ReadAnswers (Input := Key) Output keys,
        (((2 * keys.length : Nat) : ℝ) / Fintype.card Output) *
          normSquared (physicalReadTrace keys answers state) := by
      apply Finset.sum_le_sum
      intro answers _
      refine (physical_read_trace_claim_failure_le keys nodup answers state).trans ?_
      apply mul_le_mul_of_nonneg_right
      · apply div_le_div_of_nonneg_right
        · have countLe : (branchClaims keys answers).toFinset.card ≤
              keys.length :=
            (List.toFinset_card_le (branchClaims keys answers)).trans_eq
              (physical_branch_claims_length keys answers)
          exact_mod_cast Nat.mul_le_mul_left 2 countLe
        · positivity
      · unfold normSquared
        exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
    _ = ((2 * keys.length : Nat) : ℝ) / Fintype.card Output *
          normSquared state := by
      rw [← Finset.mul_sum,
        sum_physical_read_trace_norm_squared keys state total]

/-- Only scheduled coordinates need standard totality. This applies after
a disjoint compressed-X measurement, where global totality can fail. -/
theorem sum_physical_read_trace_norm_squared_of_total_on
    (keys : List Key) (state : State Key Output Phase Work)
    (total : TotalOn keys (globalDecompress state)) :
    (∑ answers : ReadAnswers (Input := Key) Output keys,
      normSquared (physicalReadTrace keys answers state)) = normSquared state := by
  have standardMass : ∀ answers : ReadAnswers (Input := Key) Output keys,
      normSquared (physicalReadTrace keys answers state) =
        normSquared (retainedReadBranch keys answers (globalDecompress state)) := by
    intro answers
    have view := physical_read_trace_standard_view keys answers state
    rw [← view]
    exact (decompress_list_preserves_norm_squared
      (Finset.univ : Finset Key).toList _).symm
  simp_rw [standardMass]
  rw [sum_retained_read_branch_norm_squared keys (globalDecompress state) total]
  exact decompress_list_preserves_norm_squared
    (Finset.univ : Finset Key).toList state


end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalTerminalRead
