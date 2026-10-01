import SmzaRp05TerminalKnownClaims
import Q38WholeViewCmsSemantics

/-!
# Partial terminal readout for the RP05 extractor

This file fixes the order of the terminal extractor operations used by the
direct DynamicBad route.

* `X` is measured once, into private classical workspace, after public
  acceptance.  There are no later `X` queries, marks, or writes.
* The deduplicated full-vector reads used by a selected role are then retained
  in workspace.  The selected-role CMS decompressions act only on the role
  keys.
* Consequently the already-measured `X` event and every event depending only
  on classical workspace commute exactly with selected-role decompression.
  Their enabled squared norm is unchanged.
* A workspace-computed failed-role event is contained pointwise in
  `DynamicBad ∪ terminal-claim-failure`.  Orthogonality of computational
  basis events therefore gives an additive, rather than square-root, bound.

The final section applies `SmzaRp05TerminalKnownClaims` to an explicit rest
coordinate containing the measured-X register.  It does not postselect or
normalize workspace branches.  The concrete suffix still has to supply the
deduplicated claim tuple and prove that all of its physical full-vector reads
are included in the global query ledger.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05PartialReadout

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.SmallWood.SmzaRp05TerminalKnownClaims
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom (DigestRegister)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

variable {Input Output Phase Workspace : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- The diagonal projector for the already-measured, retained X claims. -/
def xMeasuredProjection
    (xClaims : List (Input × Output))
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  databaseEventProjection (ClaimsDatabaseEvent xClaims) state

/-- The complementary outcome of the same terminal X measurement. -/
def xRejectedProjection
    (xClaims : List (Input × Output))
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  databaseEventProjection (fun database =>
    ¬ClaimsDatabaseEvent xClaims database) state

/-- An event computed entirely from the private classical workspace. -/
def workspaceOnlyProjection
    (enabled : Workspace → Prop)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  workspaceEventProjection (fun workspace _ => enabled workspace) state

/-- Simultaneously retain the measured-X outcome and a workspace event. -/
def partialReadoutProjection
    (xClaims : List (Input × Output))
    (enabled : Workspace → Prop)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  workspaceEventProjection (fun workspace database =>
    enabled workspace ∧ ClaimsDatabaseEvent xClaims database) state

/-- A successful measured-X branch has exactly zero support in the rejected
outcome.  This is the literal diagonal `G → B` zero, not a probabilistic
independence assertion. -/
theorem x_rejected_after_measured_zero
    (xClaims : List (Input × Output))
    (state : State Input Output Phase Workspace) :
    xRejectedProjection xClaims (xMeasuredProjection xClaims state) = 0 := by
  funext basis
  by_cases records : ClaimsDatabaseEvent xClaims basis.database
  · simp [xRejectedProjection,
      databaseEventProjection, records]
  · simp [xRejectedProjection, xMeasuredProjection,
      databaseEventProjection, records]

/-- Decompression never changes the private workspace coordinate, so an
arbitrary workspace-only event commutes with one decompression exactly. -/
theorem workspace_only_projection_decompress_at
    (enabled : Workspace → Prop)
    (input : Input)
    (state : State Input Output Phase Workspace) :
    workspaceOnlyProjection enabled (decompressAt input state) =
      decompressAt input (workspaceOnlyProjection enabled state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold workspaceOnlyProjection workspaceEventProjection
  by_cases accepted : enabled target.workspace
  · rw [if_pos accepted, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro source _
    simp [accepted]
  · rw [if_neg accepted]
    symm
    apply Finset.sum_eq_zero
    intro source _
    simp [accepted]

theorem workspace_only_projection_decompress_list
    (enabled : Workspace → Prop)
    (inputs : List Input)
    (state : State Input Output Phase Workspace) :
    workspaceOnlyProjection enabled (decompressList inputs state) =
      decompressList inputs (workspaceOnlyProjection enabled state) := by
  induction inputs with
  | nil => rfl
  | cons input remaining inductionHypothesis =>
      rw [decompress_list_cons, workspace_only_projection_decompress_at,
        inductionHypothesis, decompress_list_cons]

/-- Thus selected-role compression cannot change the norm of an event already
computed into classical workspace.  The measured X register may be part of
that workspace. -/
theorem workspace_enabled_norm_preserved
    (enabled : Workspace → Prop)
    (inputs : List Input)
    (state : State Input Output Phase Workspace) :
    normSquared
        (workspaceOnlyProjection enabled (decompressList inputs state)) =
      normSquared (workspaceOnlyProjection enabled state) := by
  rw [workspace_only_projection_decompress_list]
  exact decompress_list_preserves_norm_squared inputs _

/-- Selected-role decompression commutes with the successful X measurement
provided its keys are disjoint from all measured-X keys. -/
theorem x_measured_projection_decompress_list
    (xClaims : List (Input × Output))
    (roleInputs : List Input)
    (state : State Input Output Phase Workspace)
    (disjoint : ∀ input ∈ roleInputs,
      input ∉ xClaims.map Prod.fst) :
    xMeasuredProjection xClaims (decompressList roleInputs state) =
      decompressList roleInputs (xMeasuredProjection xClaims state) := by
  induction roleInputs with
  | nil => rfl
  | cons input remaining inductionHypothesis =>
      have inputOutside : input ∉ xClaims.map Prod.fst :=
        disjoint input (by simp)
      have remainingOutside :
          ∀ selected ∈ remaining, selected ∉ xClaims.map Prod.fst := by
        intro selected member
        exact disjoint selected (by simp [member])
      rw [decompress_list_cons]
      unfold xMeasuredProjection
      rw [claims_event_projection_decompress_at_of_not_mem
        xClaims input (decompressList remaining state) inputOutside]
      change decompressAt input
        (xMeasuredProjection xClaims (decompressList remaining state)) =
          decompressList (input :: remaining)
            (xMeasuredProjection xClaims state)
      rw [inductionHypothesis remainingOutside]
      rfl

theorem partial_readout_projection_eq
    (xClaims : List (Input × Output))
    (enabled : Workspace → Prop)
    (state : State Input Output Phase Workspace) :
    partialReadoutProjection xClaims enabled state =
      workspaceOnlyProjection enabled (xMeasuredProjection xClaims state) := by
  funext basis
  by_cases enabledHere : enabled basis.workspace <;>
    by_cases records : ClaimsDatabaseEvent xClaims basis.database <;>
      simp [partialReadoutProjection, workspaceOnlyProjection,
        xMeasuredProjection, workspaceEventProjection,
        databaseEventProjection, enabledHere, records]

/-- Exact partial-readout commutation.  In particular, measuring X first and
then compressing only the selected role gives the same enabled vector as doing
those operations in the opposite order. -/
theorem partial_readout_decompress_list
    (xClaims : List (Input × Output))
    (enabled : Workspace → Prop)
    (roleInputs : List Input)
    (state : State Input Output Phase Workspace)
    (disjoint : ∀ input ∈ roleInputs,
      input ∉ xClaims.map Prod.fst) :
    partialReadoutProjection xClaims enabled
        (decompressList roleInputs state) =
      decompressList roleInputs
        (partialReadoutProjection xClaims enabled state) := by
  rw [partial_readout_projection_eq,
    x_measured_projection_decompress_list xClaims roleInputs state disjoint,
    workspace_only_projection_decompress_list,
    partial_readout_projection_eq]

theorem partial_readout_norm_preserved
    (xClaims : List (Input × Output))
    (enabled : Workspace → Prop)
    (roleInputs : List Input)
    (state : State Input Output Phase Workspace)
    (disjoint : ∀ input ∈ roleInputs,
      input ∉ xClaims.map Prod.fst) :
    normSquared
        (partialReadoutProjection xClaims enabled
          (decompressList roleInputs state)) =
      normSquared (partialReadoutProjection xClaims enabled state) := by
  rw [partial_readout_decompress_list xClaims enabled roleInputs state disjoint]
  exact decompress_list_preserves_norm_squared roleInputs _

/-! ## Additive failed-role decomposition -/

/-- The database branches on which one or more retained full-vector claims
are absent or different. -/
def claimFailureProjection
    (claims : List (Input × Output))
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  databaseEventProjection (fun database =>
    ¬ClaimsDatabaseEvent claims database) state

/-- Literal support assertion created by retaining one actual full-vector
oracle read: every nonzero database basis records that full answer. -/
def KnownAt
    (input : Input) (output : Output)
    (state : State Input Output Phase Workspace) : Prop :=
  coordinateEventProjection input output state = state

theorem coordinate_event_projection_idempotent
    (input : Input) (output : Output)
    (state : State Input Output Phase Workspace) :
    KnownAt input output
      (coordinateEventProjection input output state) := by
  unfold KnownAt
  funext basis
  unfold coordinateEventProjection
  by_cases recorded : basis.database input = some output <;>
    simp [recorded]

/-- Projecting a later honest read at another key preserves the support of an
already-retained read. -/
theorem known_at_coordinate_event_projection_of_ne
    (input : Input) (output : Output)
    (otherInput : Input) (otherOutput : Output)
    (state : State Input Output Phase Workspace)
    (_different : otherInput ≠ input)
    (known : KnownAt input output state) :
    KnownAt input output
      (coordinateEventProjection otherInput otherOutput state) := by
  unfold KnownAt at known ⊢
  funext basis
  have knownAtBasis := congrFun known basis
  unfold coordinateEventProjection at knownAtBasis ⊢
  by_cases firstRecorded : basis.database input = some output <;>
    by_cases otherRecorded : basis.database otherInput = some otherOutput <;>
      simp [firstRecorded, otherRecorded] at knownAtBasis ⊢
  all_goals exact knownAtBasis

/-- `databaseReadBranch` is exactly the coordinate projector, so an actual
successful public classical read branch establishes `KnownAt`. -/
theorem database_read_branch_known_at
    {Work : Type} [Fintype Work] [DecidableEq Work]
    (input : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) :
    KnownAt input answer (databaseReadBranch input answer state) := by
  exact coordinate_event_projection_idempotent input answer state

/-- Later concrete public reads at other keys preserve the earlier retained
answer support. -/
theorem database_read_branch_preserves_known_at_of_ne
    {Work : Type} [Fintype Work] [DecidableEq Work]
    (input : Input) (answer : DigestRegister)
    (otherInput : Input) (otherAnswer : DigestRegister)
    (state : ResponseCmsState Input Work)
    (different : otherInput ≠ input)
    (known : KnownAt input answer state) :
    KnownAt input answer
      (databaseReadBranch otherInput otherAnswer state) := by
  exact known_at_coordinate_event_projection_of_ne
    input answer otherInput otherAnswer state different known

/-- Complementary projector for one retained physical full-vector cell. -/
def coordinateFailureProjection
    (input : Input) (output : Output)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  databaseEventProjection (fun database =>
    database input ≠ some output) state

/-- The concrete CMS matrix sends a state supported on `D(input)=Some output`
back to that same recorded outcome with amplitude `1-1/|Y|`. -/
theorem known_at_decompress_success_amplitude
    (input : Input) (output : Output)
    (state : State Input Output Phase Workspace)
    (known : KnownAt input output state) :
    coordinateEventProjection input output (decompressAt input state) =
      fun basis =>
        (retainedAmplitude (Output := Output) 1 : ℂ) * state basis := by
  funext target
  unfold coordinateEventProjection
  by_cases targetRecords : target.database input = some output
  · rw [if_pos targetRecords, decompress_at_eq_sum_kernel]
    rw [Finset.sum_eq_single (some output)]
    · have current :
          setDatabaseCoordinate target.database input (some output) =
            target.database := by
        rw [← targetRecords]
        exact set_database_coordinate_current target.database input
      rw [current, targetRecords, decompress_kernel_some_some]
      unfold retainedAmplitude inverseCard recordedRowCoefficient
      cases target
      simp [mul_comm]
    · intro source _ sourceDifferent
      have sourceNotRecorded :
          (setDatabaseCoordinate target.database input source) input ≠
            some output := by
        simpa using sourceDifferent
      have supportZero := congrFun known
        { input := target.input
          phase := target.phase
          workspace := target.workspace
          database := setDatabaseCoordinate target.database input source }
      unfold coordinateEventProjection at supportZero
      rw [if_neg sourceNotRecorded] at supportZero
      rw [← supportZero]
      simp
    · simp
  · rw [if_neg targetRecords]
    have supportZero := congrFun known target
    unfold coordinateEventProjection at supportZero
    rw [if_neg targetRecords] at supportZero
    rw [← supportZero]
    simp

/-- Exact success mass for one actual retained cell. -/
theorem known_at_decompress_success_norm
    (input : Input) (output : Output)
    (state : State Input Output Phase Workspace)
    (known : KnownAt input output state) :
    normSquared
        (coordinateEventProjection input output (decompressAt input state)) =
      retainedAmplitude (Output := Output) 1 ^ 2 * normSquared state := by
  rw [known_at_decompress_success_amplitude input output state known]
  unfold normSquared
  simp_rw [Complex.normSq_mul, Complex.normSq_ofReal]
  rw [Finset.mul_sum]
  simp only [pow_two]

/-- A diagonal event and its complement partition squared norm exactly. -/
theorem coordinate_success_add_failure_norm
    (input : Input) (output : Output)
    (state : State Input Output Phase Workspace) :
    normSquared (coordinateEventProjection input output state) +
        normSquared (coordinateFailureProjection input output state) =
      normSquared state := by
  unfold normSquared coordinateEventProjection
  unfold coordinateFailureProjection databaseEventProjection
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_congr rfl
  intro basis _
  by_cases recorded : basis.database input = some output <;>
    simp [recorded]

/-- State-level terminal retention for one actual CMS database coordinate.
This is the missing physical projector bridge: its left side is the literal
failed database measurement after the concrete decompression. -/
theorem known_at_decompress_failure_le
    (input : Input) (output : Output)
    (state : State Input Output Phase Workspace)
    (known : KnownAt input output state) :
    normSquared
        (coordinateFailureProjection input output
          (decompressAt input state)) ≤
      (2 : ℝ) / Fintype.card Output * normSquared state := by
  have partition := coordinate_success_add_failure_norm
    input output (decompressAt input state)
  have totalNorm := decompress_at_preserves_norm_squared input state
  have successNorm := known_at_decompress_success_norm
    input output state known
  have failureExact :
      normSquared
          (coordinateFailureProjection input output
            (decompressAt input state)) =
        (1 - retainedAmplitude (Output := Output) 1 ^ 2) *
          normSquared state := by
    rw [successNorm, totalNorm] at partition
    linarith
  rw [failureExact]
  have factorBound :
      1 - retainedAmplitude (Output := Output) 1 ^ 2 ≤
        (2 : ℝ) / Fintype.card Output := by
    have concrete := fiber_failure_mass_le
      (Output := Output) 1 1 (by rfl) (1 : ℂ)
    simpa [fiberFailureMass] using concrete
  exact mul_le_mul_of_nonneg_right factorBound
    (by
      unfold normSquared
      exact Finset.sum_nonneg fun basis _ =>
        Complex.normSq_nonneg (state basis))

/-- A failure event at one retained cell commutes with decompression at a
different oracle input. -/
theorem coordinate_failure_projection_decompress_at_of_ne
    (input : Input) (output : Output) (changed : Input)
    (state : State Input Output Phase Workspace)
    (different : changed ≠ input) :
    coordinateFailureProjection input output (decompressAt changed state) =
      decompressAt changed
        (coordinateFailureProjection input output state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold coordinateFailureProjection databaseEventProjection
  by_cases failed : target.database input ≠ some output
  · rw [if_pos failed, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro source _
    have sourceFailed :
        (setDatabaseCoordinate target.database changed source) input ≠
          some output := by
      simpa [set_database_coordinate_other target.database
        (Ne.symm different) source] using failed
    rw [if_pos sourceFailed]
  · rw [if_neg failed]
    symm
    apply Finset.sum_eq_zero
    intro source _
    have sourceGood :
        ¬(setDatabaseCoordinate target.database changed source) input ≠
          some output := by
      simpa [set_database_coordinate_other target.database
        (Ne.symm different) source] using failed
    rw [if_neg sourceGood]
    simp

theorem coordinate_failure_norm_decompress_list_of_outside
    (input : Input) (output : Output)
    (otherInputs : List Input)
    (state : State Input Output Phase Workspace)
    (outside : input ∉ otherInputs) :
    normSquared
        (coordinateFailureProjection input output
          (decompressList otherInputs state)) =
      normSquared (coordinateFailureProjection input output state) := by
  induction otherInputs with
  | nil => rfl
  | cons changed remaining inductionHypothesis =>
      have changedDifferent : changed ≠ input := by
        intro same
        apply outside
        simp [same]
      have remainingOutside : input ∉ remaining := by
        intro member
        apply outside
        simp [member]
      rw [decompress_list_cons,
        coordinate_failure_projection_decompress_at_of_ne
          input output changed (decompressList remaining state)
          changedDifferent,
        decompress_at_preserves_norm_squared,
        inductionHypothesis remainingOutside]

/-- One retained cell keeps the same `2/|Y|` failure bound when every other
selected-role coordinate is decompressed around it. -/
theorem known_at_partial_decompress_failure_le
    (input : Input) (output : Output)
    (otherInputs : List Input)
    (state : State Input Output Phase Workspace)
    (outside : input ∉ otherInputs)
    (known : KnownAt input output state) :
    normSquared
        (coordinateFailureProjection input output
          (decompressList otherInputs (decompressAt input state))) ≤
      (2 : ℝ) / Fintype.card Output * normSquared state := by
  rw [coordinate_failure_norm_decompress_list_of_outside
    input output otherInputs (decompressAt input state) outside]
  exact known_at_decompress_failure_le input output state known

/-- Failure of a list of retained claims is the union of their literal
one-cell failure projectors.  This is a squared-mass union bound on one actual
CMS state, not an amplitude triangle inequality. -/
theorem claim_failure_norm_le_sum_coordinate_failures
    (claims : List (Input × Output))
    (state : State Input Output Phase Workspace) :
    normSquared (claimFailureProjection claims state) ≤
      ∑ claim ∈ claims.toFinset,
        normSquared
          (coordinateFailureProjection claim.1 claim.2 state) := by
  unfold normSquared claimFailureProjection databaseEventProjection
  simp_rw [coordinateFailureProjection,
    databaseEventProjection]
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  by_cases allClaims : ClaimsDatabaseEvent claims basis.database
  · simp [allClaims]
    apply Finset.sum_nonneg
    intro selected _
    exact Complex.normSq_nonneg _
  · have missing : ∃ claim, claim ∈ claims ∧
          basis.database claim.1 ≠ some claim.2 := by
      by_contra noMissing
      apply allClaims
      intro claim member
      by_contra different
      exact noMissing ⟨claim, member, different⟩
    obtain ⟨claim, member, different⟩ := missing
    have counted :
        Complex.normSq (state basis) ≤
          ∑ selected ∈ claims.toFinset,
            Complex.normSq
              (if basis.database selected.1 ≠ some selected.2 then
                state basis else 0) := by
      calc
        Complex.normSq (state basis) ≤
            Complex.normSq
              (if basis.database claim.1 ≠ some claim.2 then
                state basis else 0) := by simp [different]
        _ ≤ ∑ selected ∈ claims.toFinset,
              Complex.normSq
                (if basis.database selected.1 ≠ some selected.2 then
                  state basis else 0) := by
          exact Finset.single_le_sum
            (fun (selected : Input × Output) _ => Complex.normSq_nonneg
              (if basis.database selected.1 ≠ some selected.2 then
                state basis else 0))
            (by simpa using member)
    rw [if_pos allClaims]
    calc
      Complex.normSq (state basis) ≤
          ∑ selected ∈ claims.toFinset,
            Complex.normSq
              (if basis.database selected.1 ≠ some selected.2 then
                state basis else 0) := counted
      _ = _ := by
        apply Finset.sum_congr rfl
        intro selected _
        by_cases records : basis.database selected.1 ≠ some selected.2 <;>
          simp [records]

/-- Actual multi-cell terminal claim retention on `CmsCompressedOracle.State`.
The factorization premise is purely the deduplicated selected-role schedule:
for each claimed key, the final partial decompression is that key's concrete
`decompressAt` plus only different keys.  The probabilistic endpoint is
derived here from the one-cell kernel and the diagonal union bound. -/
theorem known_claims_partial_decompress_failure_le
    (claims : List (Input × Output))
    (knownState finalState : State Input Output Phase Workspace)
    (known : ∀ claim ∈ claims,
      KnownAt claim.1 claim.2 knownState)
    (factorization : ∀ claim ∈ claims,
      ∃ otherInputs : List Input,
        claim.1 ∉ otherInputs ∧
          finalState =
            decompressList otherInputs
              (decompressAt claim.1 knownState)) :
    normSquared (claimFailureProjection claims finalState) ≤
      ((2 * claims.toFinset.card : Nat) : ℝ) /
          Fintype.card Output * normSquared knownState := by
  calc
    normSquared (claimFailureProjection claims finalState) ≤
        ∑ claim ∈ claims.toFinset,
          normSquared
            (coordinateFailureProjection claim.1 claim.2 finalState) :=
      claim_failure_norm_le_sum_coordinate_failures claims finalState
    _ ≤ ∑ claim ∈ claims.toFinset,
          ((2 : ℝ) / Fintype.card Output) *
            normSquared knownState := by
      apply Finset.sum_le_sum
      intro claim member
      have listMember : claim ∈ claims := by simpa using member
      obtain ⟨otherInputs, outside, finalEq⟩ :=
        factorization claim listMember
      rw [finalEq]
      exact known_at_partial_decompress_failure_le
        claim.1 claim.2 otherInputs knownState outside
          (known claim listMember)
    _ = ((2 * claims.toFinset.card : Nat) : ℝ) /
          Fintype.card Output * normSquared knownState := by
      rw [Finset.sum_const, nsmul_eq_mul]
      push_cast
      ring

/-- A member of a duplicate-free schedule can be moved to the head while the
remaining schedule contains no copy of that key. -/
theorem nodup_perm_selected_cons
    (selected : Input) (inputs : List Input)
    (member : selected ∈ inputs) (nodup : inputs.Nodup) :
    ∃ otherInputs : List Input,
      selected ∉ otherInputs ∧ inputs.Perm (selected :: otherInputs) := by
  induction inputs with
  | nil => simp at member
  | cons head tail inductionHypothesis =>
      have headFresh : head ∉ tail := (List.nodup_cons.mp nodup).1
      have tailNodup : tail.Nodup := nodup.tail
      by_cases same : head = selected
      · subst head
        exact ⟨tail, headFresh, List.Perm.refl _⟩
      · have selectedInTail : selected ∈ tail := by
          rcases List.mem_cons.mp member with atHead | inTail
          · exact False.elim (same atHead.symm)
          · exact inTail
        obtain ⟨otherInputs, selectedFresh, permutation⟩ :=
          inductionHypothesis selectedInTail tailNodup
        refine ⟨head :: otherInputs, ?_, ?_⟩
        · simp only [List.mem_cons, not_or]
          exact ⟨fun equal => same equal.symm, selectedFresh⟩
        · exact (permutation.cons head).trans
            (List.Perm.swap selected head otherInputs)

/-- Mechanical selected-key factorization of a duplicate-free decompression
schedule; no per-claim factorization assumption remains. -/
theorem nodup_decompress_list_selected_factorization
    (selected : Input) (inputs : List Input)
    (state : State Input Output Phase Workspace)
    (member : selected ∈ inputs) (nodup : inputs.Nodup) :
    ∃ otherInputs : List Input,
      selected ∉ otherInputs ∧
        decompressList inputs state =
          decompressList otherInputs (decompressAt selected state) := by
  obtain ⟨otherInputs, outside, permutation⟩ :=
    nodup_perm_selected_cons selected inputs member nodup
  refine ⟨otherInputs, outside, ?_⟩
  rw [decompress_list_perm permutation, decompress_list_cons]
  exact decompress_at_decompress_list_commutes selected otherInputs state

/-- Workspace-dependent claim failure for the actual retained read lists.
Different classical branches may contain different keys and full-vector
answers. -/
def workspaceClaimFailureProjection
    (claimsFor : Workspace → List (Input × Output))
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  workspaceEventProjection (fun workspace database =>
    ¬ClaimsDatabaseEvent (claimsFor workspace) database) state

/-- Terminal retention on all orthogonal workspace branches at once.  Each
branch is kept with its original squared norm; the measured-X result can be a
component of `Workspace`.  Hence there is no normalization or postselection
of branch-dependent claim lists. -/
theorem workspace_known_claims_partial_decompress_failure_le
    (claimsFor : Workspace → List (Input × Output))
    (cap : Nat)
    (knownState finalState : State Input Output Phase Workspace)
    (bounded : ∀ workspace,
      (claimsFor workspace).toFinset.card ≤ cap)
    (known : ∀ workspace claim, claim ∈ claimsFor workspace →
      KnownAt claim.1 claim.2 (workspaceSlice workspace knownState))
    (factorization : ∀ workspace claim,
      claim ∈ claimsFor workspace →
        ∃ otherInputs : List Input,
          claim.1 ∉ otherInputs ∧
            workspaceSlice workspace finalState =
              decompressList otherInputs
                (decompressAt claim.1
                  (workspaceSlice workspace knownState))) :
    normSquared
        (workspaceClaimFailureProjection claimsFor finalState) ≤
      ((2 * cap : Nat) : ℝ) / Fintype.card Output *
        normSquared knownState := by
  rw [show
      normSquared (workspaceClaimFailureProjection claimsFor finalState) =
        ∑ workspace : Workspace,
          normSquared
            (claimFailureProjection (claimsFor workspace)
              (workspaceSlice workspace finalState)) by
    unfold workspaceClaimFailureProjection claimFailureProjection
    exact workspace_event_norm_squared_eq_sum_slices
      (fun workspace database =>
        ¬ClaimsDatabaseEvent (claimsFor workspace) database)
      finalState]
  calc
    (∑ workspace : Workspace,
        normSquared
          (claimFailureProjection (claimsFor workspace)
            (workspaceSlice workspace finalState))) ≤
      ∑ workspace : Workspace,
        (((2 * (claimsFor workspace).toFinset.card : Nat) : ℝ) /
          Fintype.card Output) *
            normSquared (workspaceSlice workspace knownState) := by
      apply Finset.sum_le_sum
      intro workspace _
      exact known_claims_partial_decompress_failure_le
        (claimsFor workspace)
        (workspaceSlice workspace knownState)
        (workspaceSlice workspace finalState)
        (known workspace)
        (factorization workspace)
    _ ≤ ∑ workspace : Workspace,
        (((2 * cap : Nat) : ℝ) / Fintype.card Output) *
          normSquared (workspaceSlice workspace knownState) := by
      apply Finset.sum_le_sum
      intro workspace _
      apply mul_le_mul_of_nonneg_right
      · apply div_le_div_of_nonneg_right
        · exact_mod_cast Nat.mul_le_mul_left 2 (bounded workspace)
        · positivity
      · unfold normSquared
        exact Finset.sum_nonneg fun basis _ =>
          Complex.normSq_nonneg
            (workspaceSlice workspace knownState basis)
    _ = ((2 * cap : Nat) : ℝ) / Fintype.card Output *
          normSquared knownState := by
      rw [← Finset.mul_sum, sum_workspace_slice_norm_squared]

/-- The same all-branch theorem with factorization derived from one actual
duplicate-free decompression schedule per workspace branch. -/
theorem workspace_known_claims_schedule_failure_le
    (claimsFor : Workspace → List (Input × Output))
    (scheduleFor : Workspace → List Input)
    (cap : Nat)
    (knownState finalState : State Input Output Phase Workspace)
    (bounded : ∀ workspace,
      (claimsFor workspace).toFinset.card ≤ cap)
    (scheduleNodup : ∀ workspace, (scheduleFor workspace).Nodup)
    (claimScheduled : ∀ workspace claim,
      claim ∈ claimsFor workspace → claim.1 ∈ scheduleFor workspace)
    (known : ∀ workspace claim, claim ∈ claimsFor workspace →
      KnownAt claim.1 claim.2 (workspaceSlice workspace knownState))
    (finalSlice : ∀ workspace,
      workspaceSlice workspace finalState =
        decompressList (scheduleFor workspace)
          (workspaceSlice workspace knownState)) :
    normSquared
        (workspaceClaimFailureProjection claimsFor finalState) ≤
      ((2 * cap : Nat) : ℝ) / Fintype.card Output *
        normSquared knownState := by
  apply workspace_known_claims_partial_decompress_failure_le
    claimsFor cap knownState finalState bounded known
  intro workspace claim member
  obtain ⟨otherInputs, outside, factor⟩ :=
    nodup_decompress_list_selected_factorization
      claim.1 (scheduleFor workspace)
      (workspaceSlice workspace knownState)
      (claimScheduled workspace claim member)
      (scheduleNodup workspace)
  exact ⟨otherInputs, outside, by rw [finalSlice workspace, factor]⟩

theorem workspace_known_claims_schedule_failure_le_of_subnormalized
    (claimsFor : Workspace → List (Input × Output))
    (scheduleFor : Workspace → List Input)
    (cap : Nat)
    (knownState finalState : State Input Output Phase Workspace)
    (bounded : ∀ workspace,
      (claimsFor workspace).toFinset.card ≤ cap)
    (scheduleNodup : ∀ workspace, (scheduleFor workspace).Nodup)
    (claimScheduled : ∀ workspace claim,
      claim ∈ claimsFor workspace → claim.1 ∈ scheduleFor workspace)
    (known : ∀ workspace claim, claim ∈ claimsFor workspace →
      KnownAt claim.1 claim.2 (workspaceSlice workspace knownState))
    (finalSlice : ∀ workspace,
      workspaceSlice workspace finalState =
        decompressList (scheduleFor workspace)
          (workspaceSlice workspace knownState))
    (subnormalized : normSquared knownState ≤ 1) :
    normSquared
        (workspaceClaimFailureProjection claimsFor finalState) ≤
      ((2 * cap : Nat) : ℝ) / Fintype.card Output := by
  have main := workspace_known_claims_schedule_failure_le
    claimsFor scheduleFor cap knownState finalState bounded scheduleNodup
    claimScheduled known finalSlice
  exact main.trans (by
    have nonnegative :
        0 ≤ ((2 * cap : Nat) : ℝ) / Fintype.card Output := by positivity
    simpa using mul_le_mul_of_nonneg_left subnormalized nonnegative)

/-- If the workspace-computed failed-role event can occur only on a bad
database or when a retained claim failed, its mass is bounded by the sum of
those two diagonal masses.  No triangle inequality or square-root bridge is
used. -/
theorem workspace_failure_le_bad_add_claim_failure
    (failed : Workspace → Prop)
    (bad : Database Input Output → Prop)
    (claims : List (Input × Output))
    (state : State Input Output Phase Workspace)
    (included : ∀ workspace database, failed workspace →
      bad database ∨ ¬ClaimsDatabaseEvent claims database) :
    normSquared (workspaceOnlyProjection failed state) ≤
      normSquared (databaseEventProjection bad state) +
        normSquared (claimFailureProjection claims state) := by
  unfold normSquared workspaceOnlyProjection workspaceEventProjection
  unfold claimFailureProjection databaseEventProjection
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro basis _
  by_cases failedHere : failed basis.workspace
  · rcases included basis.workspace basis.database failedHere with
      badHere | claimFailed
    · simp [failedHere, badHere, Complex.normSq_nonneg]
    · simp [failedHere, claimFailed, Complex.normSq_nonneg]
  · simp only [if_neg failedHere, Complex.normSq_zero]
    exact add_nonneg (Complex.normSq_nonneg _) (Complex.normSq_nonneg _)

/-- Workspace-dependent version used by the extractor: both the failed-role
predicate and the retained claim list are computed from the same classical
branch. -/
theorem workspace_failure_le_bad_add_workspace_claim_failure
    (failed : Workspace → Prop)
    (bad : Database Input Output → Prop)
    (claimsFor : Workspace → List (Input × Output))
    (state : State Input Output Phase Workspace)
    (included : ∀ workspace database, failed workspace →
      bad database ∨
        ¬ClaimsDatabaseEvent (claimsFor workspace) database) :
    normSquared (workspaceOnlyProjection failed state) ≤
      normSquared (databaseEventProjection bad state) +
        normSquared (workspaceClaimFailureProjection claimsFor state) := by
  unfold normSquared workspaceOnlyProjection workspaceEventProjection
  unfold workspaceClaimFailureProjection databaseEventProjection
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro basis _
  by_cases failedHere : failed basis.workspace
  · rcases included basis.workspace basis.database failedHere with
      badHere | claimFailed
    · simp [failedHere, badHere, Complex.normSq_nonneg]
    · simp only [if_pos failedHere, workspaceEventProjection,
        if_pos claimFailed]
      exact le_add_of_nonneg_left (Complex.normSq_nonneg _)
  · simp only [if_neg failedHere, Complex.normSq_zero,
      workspaceEventProjection]
    exact add_nonneg (Complex.normSq_nonneg _) (Complex.normSq_nonneg _)

/-- Fully branch-dependent additive decomposition.  The bad predicate may
depend on the marked set, measured X result, and all earlier tables retained
in classical workspace. -/
theorem workspace_failure_le_workspace_bad_add_claim_failure
    (failed : Workspace → Prop)
    (bad : Workspace → Database Input Output → Prop)
    (claimsFor : Workspace → List (Input × Output))
    (state : State Input Output Phase Workspace)
    (included : ∀ workspace database, failed workspace →
      bad workspace database ∨
        ¬ClaimsDatabaseEvent (claimsFor workspace) database) :
    normSquared (workspaceOnlyProjection failed state) ≤
      normSquared (workspaceEventProjection bad state) +
        normSquared (workspaceClaimFailureProjection claimsFor state) := by
  unfold normSquared workspaceOnlyProjection workspaceEventProjection
  unfold workspaceClaimFailureProjection
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro basis _
  by_cases failedHere : failed basis.workspace
  · rcases included basis.workspace basis.database failedHere with
      badHere | claimFailed
    · simp [failedHere, badHere, Complex.normSq_nonneg]
    · simp only [if_pos failedHere, workspaceEventProjection,
        if_pos claimFailed]
      exact le_add_of_nonneg_left (Complex.normSq_nonneg _)
  · simp only [if_neg failedHere, Complex.normSq_zero,
      workspaceEventProjection]
    exact add_nonneg (Complex.normSq_nonneg _) (Complex.normSq_nonneg _)

/-! ## Concrete terminal fibers including measured X -/

/-- `XRegister` is the private classical result of the unique X measurement.
It is deliberately a coordinate of `Rest`: terminal retention is summed over
it, not conditioned or normalized on an X outcome. -/
abbrev PartialReadoutRest
    (Workspace XRegister Purification : Type*) :=
  Workspace × XRegister × Purification

/-- Literal retained mass after applying the implemented selected-coordinate
CMS kernel to the known full-vector tuple on every actual rest coordinate.
This is the state-coordinate object used at terminal readout; it is not an
assumed probability endpoint. -/
def literalRetainedRoleMass
    {XRegister Purification : Type*}
    [Fintype XRegister] [DecidableEq XRegister]
    [Fintype Purification] [DecidableEq Purification]
    (arity : PartialReadoutRest Workspace XRegister Purification → Nat)
    (target : (rest : PartialReadoutRest Workspace XRegister Purification) →
      Fin (arity rest) → Output)
    (coefficient :
      PartialReadoutRest Workspace XRegister Purification → ℂ) : ℝ :=
  ∑ rest : PartialReadoutRest Workspace XRegister Purification,
    Complex.normSq
      (∑ source : Fin (arity rest) → Output,
        knownTupleCoefficient (target rest) (coefficient rest) source *
          selectedDecompressionKernel (target rest) source)

/-- Literal failure mass is total fiber mass minus the retained tuple outcome
of the concrete selected-coordinate kernel.  The total term is justified by
unitarity of the CMS decompression; no branch is divided by its weight. -/
def literalTerminalRoleFailureMass
    {XRegister Purification : Type*}
    [Fintype XRegister] [DecidableEq XRegister]
    [Fintype Purification] [DecidableEq Purification]
    (arity : PartialReadoutRest Workspace XRegister Purification → Nat)
    (target : (rest : PartialReadoutRest Workspace XRegister Purification) →
      Fin (arity rest) → Output)
    (coefficient :
      PartialReadoutRest Workspace XRegister Purification → ℂ) : ℝ :=
  restNormSquared coefficient -
    literalRetainedRoleMass arity target coefficient

/-- The actual coordinate calculation reduces to the `terminalFailureMass`
bounded in `SmzaRp05TerminalKnownClaims`.  The equality follows from the
literal implemented kernel, via
`known_tuple_selected_kernel_amplitude`; it is not supplied as a premise. -/
theorem literal_terminal_role_failure_eq
    {XRegister Purification : Type*}
    [Fintype XRegister] [DecidableEq XRegister]
    [Fintype Purification] [DecidableEq Purification]
    (arity : PartialReadoutRest Workspace XRegister Purification → Nat)
    (target : (rest : PartialReadoutRest Workspace XRegister Purification) →
      Fin (arity rest) → Output)
    (coefficient :
      PartialReadoutRest Workspace XRegister Purification → ℂ) :
    literalTerminalRoleFailureMass arity target coefficient =
      terminalFailureMass (Output := Output) arity coefficient := by
  rw [terminal_failure_eq_total_sub_retained arity target coefficient]
  unfold literalTerminalRoleFailureMass literalRetainedRoleMass
  congr 1
  unfold knownTupleRetainedMass
  apply Finset.sum_congr rfl
  intro rest _
  rw [known_tuple_selected_kernel_amplitude]
  rw [known_tuple_selected_decompression_amplitude]

/-- Direct application of the exact recorded-tuple kernel theorem to the
actual partial-readout rest coordinates.  `coefficient` may be arbitrarily
entangled across workspace, measured X, and purification coordinates. -/
theorem terminal_role_claim_failure_le
    {XRegister Purification : Type*}
    [Fintype XRegister] [DecidableEq XRegister]
    [Fintype Purification] [DecidableEq Purification]
    (arity : PartialReadoutRest Workspace XRegister Purification → Nat)
    (coefficient :
      PartialReadoutRest Workspace XRegister Purification → ℂ)
    (cap : Nat)
    (bounded : ∀ rest, arity rest ≤ cap) :
    terminalFailureMass (Output := Output) arity coefficient ≤
      ((2 * cap : Nat) : ℝ) / Fintype.card Output *
        restNormSquared coefficient := by
  exact terminal_known_claims_failure_le arity coefficient cap bounded

/-- The bound stated directly for the literal concrete-kernel failure mass. -/
theorem literal_terminal_role_claim_failure_le
    {XRegister Purification : Type*}
    [Fintype XRegister] [DecidableEq XRegister]
    [Fintype Purification] [DecidableEq Purification]
    (arity : PartialReadoutRest Workspace XRegister Purification → Nat)
    (target : (rest : PartialReadoutRest Workspace XRegister Purification) →
      Fin (arity rest) → Output)
    (coefficient :
      PartialReadoutRest Workspace XRegister Purification → ℂ)
    (cap : Nat)
    (bounded : ∀ rest, arity rest ≤ cap) :
    literalTerminalRoleFailureMass arity target coefficient ≤
      ((2 * cap : Nat) : ℝ) / Fintype.card Output *
        restNormSquared coefficient := by
  rw [literal_terminal_role_failure_eq]
  exact terminal_known_claims_failure_le arity coefficient cap bounded

/-- Subnormalized form used after public acceptance.  Since the measured-X
coordinate remains in the unnormalized rest sum, this introduces no
postselection denominator. -/
theorem terminal_role_claim_failure_le_of_subnormalized
    {XRegister Purification : Type*}
    [Fintype XRegister] [DecidableEq XRegister]
    [Fintype Purification] [DecidableEq Purification]
    (arity : PartialReadoutRest Workspace XRegister Purification → Nat)
    (coefficient :
      PartialReadoutRest Workspace XRegister Purification → ℂ)
    (cap : Nat)
    (bounded : ∀ rest, arity rest ≤ cap)
    (subnormalized : restNormSquared coefficient ≤ 1) :
    terminalFailureMass (Output := Output) arity coefficient ≤
      ((2 * cap : Nat) : ℝ) / Fintype.card Output := by
  exact terminal_known_claims_failure_le_of_subnormalized
    arity coefficient cap bounded subnormalized

/-!
For the RP05 instantiation, `cap = C_r`.  Combining
`workspace_failure_le_bad_add_claim_failure` with the final theorem gives

`Pr[E_r] ≤ Pr[DynamicBad_r] + 2*C_r/|Y|`.

The four-role ledger supplies `Σ_r C_r + C_X ≤ T`; this module intentionally
does not assume that ledger or the query-suffix/deduplication facts.
-/

end
end HegemonCrypto.SmallWood.SmzaRp05PartialReadout
