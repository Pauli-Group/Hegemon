import SmzaRp05GroupedSuffix
import SmzaRp05VectorRetention
import SmzaRp05PartialReadout
import Q38WholeViewCmsSemantics

/-!
# Exact terminal suffix readout

`databaseReadBranch` is the literal diagonal public-read instrument.  This
file records all of its outcomes in a finite branch register, proves that the
branches are orthogonal and exhaustive on total support, and then instantiates
the concrete deduplicated RP05 suffix and selected-coordinate compression.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05SuffixReadout

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open SmzaRp05PartialReadout SmzaRp05ConcreteSuffix SmzaRp05GroupedSuffix
open SmzaRp05VectorRetention
open SmzaRp05ExtractionSuffix SmzaChallengeStageTargets
open SmzaRp05LeafNamespace V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

variable {Input Output Phase Workspace : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Finite classical outcome register for sequential reads. -/
def ReadAnswers (Output : Type) : List Input → Type
  | [] => PUnit
  | _ :: inputs => Output × ReadAnswers Output inputs

noncomputable instance readAnswersFintype (inputs : List Input) :
    Fintype (ReadAnswers Output inputs) := by
  induction inputs with
  | nil =>
      change Fintype PUnit
      infer_instance
  | cons _ tail ih =>
      letI : Fintype (ReadAnswers Output tail) := ih
      change Fintype (Output × ReadAnswers Output tail)
      infer_instance

/-- One branch of the sequential public-read instrument. -/
def retainedReadBranch :
    (inputs : List Input) → ReadAnswers Output inputs →
      State Input Output Phase Workspace → State Input Output Phase Workspace
  | [], _, state => state
  | input :: inputs, (answer, answers), state =>
      retainedReadBranch inputs answers
        (coordinateEventProjection input answer state)

def TotalOn (inputs : List Input)
    (state : State Input Output Phase Workspace) : Prop :=
  ∀ input ∈ inputs, TotalAt input state

/-- A successful read projection preserves total support at every coordinate;
it only removes amplitudes and never changes a database key. -/
theorem total_at_coordinate_event_projection
    (preserved read : Input) (answer : Output)
    (state : State Input Output Phase Workspace)
    (total : TotalAt preserved state) :
    TotalAt preserved (coordinateEventProjection read answer state) := by
  intro basis absent
  unfold coordinateEventProjection
  by_cases selected : basis.database read = some answer
  · simp [selected, total basis absent]
  · simp [selected]

/-- The complete outcomes of one literal database read partition the state
norm exactly on total support. -/
theorem sum_database_read_branch_norm_squared
    (input : Input) (state : State Input Output Phase Workspace)
    (total : TotalAt input state) :
    (∑ answer : Output,
      normSquared (coordinateEventProjection input answer state)) =
      normSquared state := by
  unfold normSquared coordinateEventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro basis _
  cases recorded : basis.database input with
  | none =>
      have zero := total basis recorded
      simp [zero]
  | some value =>
      rw [Finset.sum_eq_single value]
      · simp
      · intro other _ different
        have notEqual : some value ≠ some other := by
          intro equal
          exact different (Option.some.inj equal).symm
        simp [notEqual]
      · simp

/-- Sequential public reads are an isometry into the finite retained-answer
register.  The sum is over orthogonal classical branches and is never divided
by a branch probability. -/
theorem sum_retained_read_branch_norm_squared
    (inputs : List Input) (state : State Input Output Phase Workspace)
    (total : TotalOn inputs state) :
    (∑ answers : ReadAnswers Output inputs,
      normSquared (retainedReadBranch inputs answers state)) =
      normSquared state := by
  induction inputs generalizing state with
  | nil => simp [retainedReadBranch, ReadAnswers]
  | cons input inputs inductionHypothesis =>
      change
        (∑ answers : Output × ReadAnswers Output inputs,
          normSquared (retainedReadBranch (input :: inputs) answers state)) = _
      rw [Fintype.sum_prod_type]
      simp only [retainedReadBranch]
      calc
        (∑ answer : Output,
          ∑ answers : ReadAnswers Output inputs,
            normSquared
              (retainedReadBranch inputs answers
                (coordinateEventProjection input answer state))) =
          ∑ answer : Output,
            normSquared (coordinateEventProjection input answer state) := by
              apply Finset.sum_congr rfl
              intro answer _
              apply inductionHypothesis
              intro preserved member
              exact total_at_coordinate_event_projection preserved input answer state
                (total preserved (by simp [member]))
        _ = normSquared state :=
          sum_database_read_branch_norm_squared input state
            (total input (by simp))
/-! ## Grouped finite-key readout -/

variable {Key : Type} [Fintype Key] [DecidableEq Key]

/-- The query schedule contains exactly the deduplicated grouped cells read
for the selected role.  The compression schedule is ex-ante: it contains all
finite implementation keys tagged with that role, independent of the batch. -/
abbrev groupedRoleReads
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey) (role : Role) : List Key :=
  pulledGroupedRoleReadSchedule nameSpace batch keyGroup role

abbrev groupedRoleCompression
    (keyGroup : Key → GroupKey) (role : Role) : List Key :=
  fixedRoleCompressionSchedule keyGroup role

/-- Claims carried by one orthogonal retained-answer branch. -/
def branchClaims :
    (inputs : List Key) → ReadAnswers (Input := Key) Output inputs →
      List (Key × Output)
  | [], _ => []
  | input :: inputs, (answer, answers) =>
      (input, answer) :: branchClaims inputs answers

theorem branch_claims_length
    (inputs : List Key) (answers : ReadAnswers (Input := Key) Output inputs) :
    (branchClaims inputs answers).length = inputs.length := by
  induction inputs with
  | nil => simp [branchClaims]
  | cons input inputs ih =>
      rcases answers with ⟨answer, answers⟩
      simp [branchClaims, ih answers]

theorem branch_claim_key_mem
    (inputs : List Key) (answers : ReadAnswers (Input := Key) Output inputs)
    (claim : Key × Output) (member : claim ∈ branchClaims inputs answers) :
    claim.1 ∈ inputs := by
  induction inputs with
  | nil => simp [branchClaims] at member
  | cons input inputs ih =>
      rcases answers with ⟨answer, answers⟩
      simp only [branchClaims, List.mem_cons] at member
      rcases member with rfl | member
      · simp
      · exact List.mem_cons_of_mem input (ih answers member)

theorem retained_branch_preserves_known_of_not_mem
    (inputs : List Key) (answers : ReadAnswers (Input := Key) Output inputs)
    (state : State Key Output Phase Workspace) (key : Key) (value : Output)
    (outside : key ∉ inputs) (known : KnownAt key value state) :
    KnownAt key value (retainedReadBranch inputs answers state) := by
  induction inputs generalizing state with
  | nil => exact known
  | cons input inputs ih =>
      rcases answers with ⟨answer, answers⟩
      apply ih
      · intro member
        exact outside (by simp [member])
      · apply known_at_coordinate_event_projection_of_ne
          key value input answer state
        · intro same
          exact outside (by simp [same])
        · exact known

theorem branch_claim_known_at
    (inputs : List Key) (nodup : inputs.Nodup)
    (answers : ReadAnswers (Input := Key) Output inputs)
    (state : State Key Output Phase Workspace)
    (claim : Key × Output) (member : claim ∈ branchClaims inputs answers) :
    KnownAt claim.1 claim.2 (retainedReadBranch inputs answers state) := by
  induction inputs generalizing state with
  | nil => simp [branchClaims] at member
  | cons input inputs ih =>
      rcases answers with ⟨answer, answers⟩
      simp only [branchClaims, List.mem_cons] at member
      rcases member with rfl | member
      · exact retained_branch_preserves_known_of_not_mem inputs answers
          (coordinateEventProjection input answer state) input answer
          (List.nodup_cons.mp nodup).1
          (coordinate_event_projection_idempotent input answer state)
      · exact ih nodup.tail answers
          (coordinateEventProjection input answer state) member

def branchFinalState
    (compression : List Key) (reads : List Key)
    (answers : ReadAnswers (Input := Key) Output reads)
    (state : State Key Output Phase Workspace) :
    State Key Output Phase Workspace :=
  decompressList compression (retainedReadBranch reads answers state)

/-- One actual read-outcome branch, followed by compression of every selected
role coordinate.  Unknown selected-role keys are in `compression`; retained
claims are only the charged queried subset `reads`. -/
theorem branch_terminal_claim_failure_le
    (reads compression : List Key) (readNodup : reads.Nodup)
    (compressionNodup : compression.Nodup)
    (included : ∀ key ∈ reads, key ∈ compression)
    (answers : ReadAnswers (Input := Key) Output reads)
    (state : State Key Output Phase Workspace) :
    normSquared
        (claimFailureProjection (branchClaims reads answers)
          (branchFinalState compression reads answers state)) ≤
      ((2 * (branchClaims reads answers).toFinset.card : Nat) : ℝ) /
          Fintype.card Output *
        normSquared (retainedReadBranch reads answers state) := by
  apply known_claims_partial_decompress_failure_le
    (branchClaims reads answers) (retainedReadBranch reads answers state)
    (branchFinalState compression reads answers state)
  · intro claim member
    exact branch_claim_known_at reads readNodup answers state claim member
  · intro claim member
    obtain ⟨other, outside, factor⟩ :=
      nodup_decompress_list_selected_factorization claim.1 compression
        (retainedReadBranch reads answers state)
        (included claim.1 (branch_claim_key_mem reads answers claim member))
        compressionNodup
    exact ⟨other, outside, factor⟩

/-- Complete orthogonal readout endpoint.  All classical outcomes are summed;
there is no externally selected oracle branch or per-branch normalization. -/
theorem sum_branch_terminal_claim_failure_le
    (reads compression : List Key) (readNodup : reads.Nodup)
    (compressionNodup : compression.Nodup)
    (included : ∀ key ∈ reads, key ∈ compression)
    (state : State Key Output Phase Workspace) (total : TotalOn reads state) :
    (∑ answers : ReadAnswers (Input := Key) Output reads,
      normSquared
        (claimFailureProjection (branchClaims reads answers)
          (branchFinalState compression reads answers state))) ≤
      ((2 * reads.length : Nat) : ℝ) / Fintype.card Output *
        normSquared state := by
  calc
    _ ≤ ∑ answers : ReadAnswers (Input := Key) Output reads,
        (((2 * reads.length : Nat) : ℝ) / Fintype.card Output) *
          normSquared (retainedReadBranch reads answers state) := by
      apply Finset.sum_le_sum
      intro answers _
      refine (branch_terminal_claim_failure_le reads compression readNodup
        compressionNodup included answers state).trans ?_
      apply mul_le_mul_of_nonneg_right
      · apply div_le_div_of_nonneg_right
        · have bound := Nat.mul_le_mul_left 2
            (List.toFinset_card_le (branchClaims reads answers))
          rw [branch_claims_length reads answers] at bound
          exact_mod_cast bound
        · positivity
      · unfold normSquared
        exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
    _ = ((2 * reads.length : Nat) : ℝ) / Fintype.card Output *
          normSquared state := by
      rw [← Finset.mul_sum,
        sum_retained_read_branch_norm_squared reads state total]

/-- Concrete grouped RP05 instantiation.  Actual retained reads are charged
by the expanded physical suffix, while analytical decompression covers the
full ex-ante selected-role domain. -/
theorem grouped_current_role_readout_failure_le_digest
    {Counter : Type} [Fintype Counter] [DecidableEq Counter]
    (counter : Counter)
    (nameSpace : Namespace) (batch : List ProofView)
    (keyGroup : Key → GroupKey)
    (pullback : FiniteGroupPullback nameSpace batch Key keyGroup) (role : Role)
    (state : State Key (VectorOutput Counter) Phase Workspace)
    (total : TotalOn
      (groupedRoleReads nameSpace batch keyGroup role) state) :
    (∑ answers : ReadAnswers (Input := Key) (VectorOutput Counter)
        (groupedRoleReads nameSpace batch keyGroup role),
      normSquared
        (claimFailureProjection
          (branchClaims
            (groupedRoleReads nameSpace batch keyGroup role) answers)
          (branchFinalState
            (groupedRoleCompression keyGroup role)
            (groupedRoleReads nameSpace batch keyGroup role)
            answers state))) ≤
      (2 * ((expandedPhysicalReadSchedule nameSpace batch).length : ℝ)) /
          (2 : ℝ)^512 * normSquared state := by
  let reads := groupedRoleReads nameSpace batch keyGroup role
  let compression := groupedRoleCompression keyGroup role
  have readBound : reads.length ≤
      (expandedPhysicalReadSchedule nameSpace batch).length :=
    pulled_grouped_role_read_count_le_physical_reads nameSpace batch keyGroup
      pullback role
  have selected := sum_branch_terminal_claim_failure_le
    reads compression
    (pulled_grouped_role_read_schedule_nodup nameSpace batch keyGroup role)
    (fixed_role_compression_schedule_nodup keyGroup role)
    (fun key member => pulled_grouped_role_read_mem_fixed_role_compression
      nameSpace batch keyGroup role key member)
    state total
  refine selected.trans ?_
  apply mul_le_mul_of_nonneg_right
  · exact (vector_retention_loss_le_digest counter reads.length).trans (by
      gcongr)
  · unfold normSquared
    exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _

end
end HegemonCrypto.SmallWood.SmzaRp05SuffixReadout
