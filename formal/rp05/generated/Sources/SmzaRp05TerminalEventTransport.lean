import SmzaRp05SequentialReadCharge

/-!
# Final RP05 database-event transport

The current-role event is database dependent.  We do not commute it through
recompression.  Instead each successful physical-read branch is compared with
the same branch after decompressing exactly the recorded claim keys.  The
event below may inspect arbitrary other database cells, but it must be
intersected with successful recorded claims so that the existing finite CMS
event-distance theorem applies.  Claim failure is charged separately.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05TerminalEventTransport

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.SmzaRp05PartialReadout
open HegemonCrypto.SmallWood.SmzaRp05SuffixReadout
open HegemonCrypto.SmallWood.SmzaRp05PhysicalTerminalRead
open HegemonCrypto.SmallWood.SmzaRp05SequentialReadCharge
open HegemonCrypto.SmallWood.SmzaRp05AdaptiveFilteredCollision

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output Phase Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

/-- On a physically support-bounded state the adaptive cap does not alter
the workspace-selected event.  For the vector read branches the premise is
supplied by `charged_read_trace_bounded_add_length`, not by a caller's
projector-closeness assumption. -/
theorem adaptive_project_eq_workspace_event_of_bounded
    (event : Work → Database Key Output → Prop)
    (cap : Nat) (state : State Key Output Phase Work)
    (bounded : BoundedState cap state) :
    adaptiveProject event cap state = workspaceEventProjection event state := by
  funext basis
  by_cases within : size basis.database ≤ cap
  · simp [adaptiveProject, workspaceEventProjection, within]
  · have zero := bounded_state_apply_eq_zero_of_lt bounded basis
      (Nat.lt_of_not_ge within)
    simp [adaptiveProject, workspaceEventProjection, within, zero]

/-- A selected output projector commutes with reflections at other oracle
keys.  This generic form supports the actual vector-output CMS state and
does not use the digest-specialized response interpreter. -/
theorem generic_coordinate_projection_decompress_at_of_ne
    (selected : Key) (answer : Output) (changed : Key)
    (state : State Key Output Phase Work)
    (different : selected ≠ changed) :
    coordinateEventProjection selected answer (decompressAt changed state) =
      decompressAt changed
        (coordinateEventProjection selected answer state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold coordinateEventProjection
  by_cases accepted : target.database selected = some answer
  · rw [if_pos accepted, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro source _
    have sourceAccepted :
        setDatabaseCoordinate target.database changed source selected =
          some answer := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_pos sourceAccepted]
  · rw [if_neg accepted]
    symm
    apply Finset.sum_eq_zero
    intro source _
    have sourceRejected :
        setDatabaseCoordinate target.database changed source selected ≠
          some answer := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_neg sourceRejected]
    simp

theorem generic_coordinate_projection_decompress_list_of_outside
    (selected : Key) (answer : Output) (inputs : List Key)
    (state : State Key Output Phase Work)
    (outside : ∀ changed ∈ inputs, selected ≠ changed) :
    coordinateEventProjection selected answer (decompressList inputs state) =
      decompressList inputs
        (coordinateEventProjection selected answer state) := by
  induction inputs with
  | nil => rfl
  | cons changed remaining ih =>
      have changedOutside : selected ≠ changed := outside changed (by simp)
      have remainingOutside : ∀ input ∈ remaining, selected ≠ input := by
        intro input member
        exact outside input (by simp [member])
      simp only [decompress_list_cons]
      rw [generic_coordinate_projection_decompress_at_of_ne
        selected answer changed _ changedOutside]
      rw [ih remainingOutside]

theorem workspace_slice_coordinate_projection
    (selected : Work) (key : Key) (answer : Output)
    (state : State Key Output Phase Work) :
    workspaceSlice selected (coordinateEventProjection key answer state) =
      coordinateEventProjection key answer (workspaceSlice selected state) := by
  funext basis
  by_cases same : basis.workspace = selected <;>
    by_cases recorded : basis.database key = some answer <;>
    simp [workspaceSlice, coordinateEventProjection, same, recorded]

theorem workspace_slice_physical_read_branch
    (selected : Work) (key : Key) (answer : Output)
    (state : State Key Output Phase Work) :
    workspaceSlice selected (physicalReadBranch key answer state) =
      physicalReadBranch key answer (workspaceSlice selected state) := by
  unfold physicalReadBranch
  rw [workspace_slice_global_decompress,
    workspace_slice_coordinate_projection,
    workspace_slice_global_decompress]

theorem workspace_slice_physical_read_trace
    (selected : Work) (keys : List Key)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work) :
    workspaceSlice selected (physicalReadTrace keys answers state) =
      physicalReadTrace keys answers (workspaceSlice selected state) := by
  induction keys generalizing state with
  | nil => rfl
  | cons key keys ih =>
      rcases answers with ⟨answer, answers⟩
      simp only [physicalReadTrace]
      rw [ih, workspace_slice_physical_read_branch]

theorem standard_total_workspace_slice
    (selected : Work) (keys : List Key) (state : State Key Output Phase Work)
    (total : TotalOn keys (globalDecompress state)) :
    TotalOn keys (globalDecompress (workspaceSlice selected state)) := by
  intro key member basis absent
  rw [← workspace_slice_global_decompress]
  unfold workspaceSlice
  by_cases same : basis.workspace = selected
  · simp [same, total key member basis absent]
  · simp [same]

theorem branch_claim_keys
    (keys : List Key)
    (answers : ReadAnswers (Input := Key) Output keys) :
    (branchClaims keys answers).map Prod.fst = keys := by
  induction keys with
  | nil => rfl
  | cons key keys inductionHypothesis =>
      rcases answers with ⟨answer, answers⟩
      simp [branchClaims, inductionHypothesis answers]

/-- The full standard view factors into reflections at unmeasured keys and
the selected partial-standard view.  Both are concrete CMS decompressions. -/
theorem full_standard_eq_outside_selected
    (claims : List (Key × Output))
    (distinct : (claims.map Prod.fst).Nodup)
    (state : State Key Output Phase Work) :
    globalDecompress state =
      decompressList (outsideClaimInputs claims)
        (decompressList (claims.map Prod.fst) state) := by
  have permutation := outside_append_claim_inputs_perm_univ claims distinct
  calc
    globalDecompress state =
        decompressList
          (outsideClaimInputs claims ++ claims.map Prod.fst) state := by
      unfold globalDecompress
      exact (decompress_list_perm permutation state).symm
    _ = _ := decompress_list_append _ _ _

/-- Partial decompression of the actual compressed physical-read branch has
every recorded answer as a known database cell.  This is derived from the
honest standard measurement; no compressed-slot `TotalOn` premise appears. -/
theorem selected_physical_branch_claim_known
    (keys : List Key) (nodup : keys.Nodup)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work)
    (claim : Key × Output) (member : claim ∈ branchClaims keys answers) :
    KnownAt claim.1 claim.2
      (decompressList keys (physicalReadTrace keys answers state)) := by
  let claims := branchClaims keys answers
  let compressed := physicalReadTrace keys answers state
  let selected := decompressList keys compressed
  let standard := globalDecompress compressed
  let outside := outsideClaimInputs claims
  have distinct : (claims.map Prod.fst).Nodup := by
    simpa [claims, branch_claim_keys keys answers] using nodup
  have standardEq : standard = decompressList outside selected := by
    simpa [standard, selected, outside, claims,
      branch_claim_keys keys answers] using
      (full_standard_eq_outside_selected claims distinct compressed)
  have selectedEq : selected = decompressList outside standard := by
    calc
      selected = decompressList outside (decompressList outside selected) :=
        (decompress_list_involutive outside selected).symm
      _ = decompressList outside standard := by rw [← standardEq]
  have knownStandard : KnownAt claim.1 claim.2 standard := by
    exact physical_read_trace_claim_known keys nodup answers state claim member
  have outsideDisjoint :
      ∀ changed ∈ outside, claim.1 ≠ changed := by
    intro changed changedMember same
    have unclaimed := outside_claim_inputs_are_unclaimed claims
      changed changedMember
    have claimed : claim.1 ∈ claims.map Prod.fst := by
      exact List.mem_map.mpr ⟨claim, member, rfl⟩
    exact unclaimed (by simpa [← same] using claimed)
  change KnownAt claim.1 claim.2 selected
  rw [selectedEq]
  unfold KnownAt
  rw [generic_coordinate_projection_decompress_list_of_outside
    claim.1 claim.2 outside standard outsideDisjoint]
  rw [knownStandard]

theorem selected_physical_branch_claim_total
    (keys : List Key) (nodup : keys.Nodup)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work)
    (claim : Key × Output) (member : claim ∈ branchClaims keys answers) :
    TotalAt claim.1
      (decompressList keys (physicalReadTrace keys answers state)) := by
  intro basis absent
  have known := selected_physical_branch_claim_known
    keys nodup answers state claim member
  have basisKnown := congrFun known basis
  unfold KnownAt coordinateEventProjection at basisKnown
  have notRecorded : basis.database claim.1 ≠ some claim.2 := by
    rw [absent]
    simp
  simpa [notRecorded] using basisKnown.symm

/-- Final mass of any database event *on successful recorded claims* is
bounded by its mass on the actual compressed read branch plus the explicit
CMS event-distance term.  Unlike a false commute lemma, this remains valid
when decompression changes every database-dependent role predicate. -/
theorem selected_event_transport_amplitude
    (keys : List Key) (nodup : keys.Nodup)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work)
    (event : Database Key Output → Prop)
    (records : ∀ claim ∈ branchClaims keys answers,
      ∀ database, event database →
        database claim.1 = some claim.2) :
    let compressed := physicalReadTrace keys answers state
    let selected := decompressList keys compressed
    Real.sqrt
        (normSquared (databaseEventProjection event selected)) ≤
      Real.sqrt
        (normSquared (databaseEventProjection event compressed)) +
      keys.length * Real.sqrt
        ((1 / (Fintype.card Output : ℝ)) * normSquared selected) := by
  dsimp only
  let claims := branchClaims keys answers
  let compressed := physicalReadTrace keys answers state
  let selected := decompressList keys compressed
  have distinct : (claims.map Prod.fst).Nodup := by
    simpa [claims, branch_claim_keys keys answers] using nodup
  have total : ∀ claim ∈ claims, TotalAt claim.1 selected := by
    intro claim member
    exact selected_physical_branch_claim_total
      keys nodup answers state claim member
  have bound := event_probability_decompression_amplitude_le
    event claims selected distinct records total
  have recompressed : decompressList (claims.map Prod.fst) selected =
      compressed := by
    rw [branch_claim_keys keys answers]
    exact decompress_list_involutive keys compressed
  simpa [claims, physical_branch_claims_length keys answers,
    recompressed] using bound

/-- The useful specialization for final-role events.  No property of the
role predicate is assumed: successful recorded claims themselves provide the
`eventRecords` condition required by the CMS distance theorem. -/
theorem selected_event_with_claims_transport_amplitude
    (keys : List Key) (nodup : keys.Nodup)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work)
    (roleEvent : Database Key Output → Prop) :
    let claims := branchClaims keys answers
    let event : Database Key Output → Prop :=
      fun database => roleEvent database ∧ ClaimsDatabaseEvent claims database
    let compressed := physicalReadTrace keys answers state
    let selected := decompressList keys compressed
    Real.sqrt
        (normSquared (databaseEventProjection event selected)) ≤
      Real.sqrt
        (normSquared (databaseEventProjection event compressed)) +
      keys.length * Real.sqrt
        ((1 / (Fintype.card Output : ℝ)) * normSquared selected) := by
  dsimp only
  apply selected_event_transport_amplitude keys nodup answers state
  intro claim member database accepted
  exact accepted.2 claim member

/-- Squared-mass form.  The transport cost is `2*k^2/|Y|` times this
branch's norm; the security ledger reserves the looser `4*k^2/|Y|` term. -/
theorem selected_event_with_claims_transport_mass
    (keys : List Key) (nodup : keys.Nodup)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work)
    (roleEvent : Database Key Output → Prop) :
    let claims := branchClaims keys answers
    let event : Database Key Output → Prop :=
      fun database => roleEvent database ∧ ClaimsDatabaseEvent claims database
    let compressed := physicalReadTrace keys answers state
    let selected := decompressList keys compressed
    normSquared (databaseEventProjection event selected) ≤
      2 * normSquared (databaseEventProjection event compressed) +
        (2 * (keys.length : ℝ)^2 / Fintype.card Output) *
          normSquared compressed := by
  dsimp only
  let claims := branchClaims keys answers
  let event : Database Key Output → Prop :=
    fun database => roleEvent database ∧ ClaimsDatabaseEvent claims database
  let compressed := physicalReadTrace keys answers state
  let selected := decompressList keys compressed
  let finalMass := normSquared (databaseEventProjection event selected)
  let priorMass := normSquared (databaseEventProjection event compressed)
  let branchMass := normSquared compressed
  let cost := (1 / (Fintype.card Output : ℝ)) * normSquared selected
  have amplitude : Real.sqrt finalMass ≤
      Real.sqrt priorMass + keys.length * Real.sqrt cost := by
    exact selected_event_with_claims_transport_amplitude
      keys nodup answers state roleEvent
  have finalNonnegative : 0 ≤ finalMass := by
    unfold finalMass normSquared
    exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  have priorNonnegative : 0 ≤ priorMass := by
    unfold priorMass normSquared
    exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  have costNonnegative : 0 ≤ cost := by
    unfold cost
    have cardPos : 0 < (Fintype.card Output : ℝ) := by
      exact_mod_cast Fintype.card_pos
    apply mul_nonneg
    · exact div_nonneg (by norm_num) (le_of_lt cardPos)
    · unfold normSquared
      exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  have normEq : normSquared selected = branchMass := by
    exact decompress_list_preserves_norm_squared keys compressed
  have nonnegativeSum :
      0 ≤ Real.sqrt priorMass + keys.length * Real.sqrt cost := by
    positivity
  have squareOrder :
      (Real.sqrt finalMass)^2 ≤
        (Real.sqrt priorMass + keys.length * Real.sqrt cost)^2 := by
    nlinarith [mul_nonneg (sub_nonneg.mpr amplitude)
      (add_nonneg nonnegativeSum (Real.sqrt_nonneg finalMass))]
  have squareOrder' : finalMass ≤
      (Real.sqrt priorMass + keys.length * Real.sqrt cost)^2 := by
    simpa only [Real.sq_sqrt finalNonnegative] using squareOrder
  have priorRootSq : (Real.sqrt priorMass)^2 = priorMass :=
    Real.sq_sqrt priorNonnegative
  have costRootSq : (Real.sqrt cost)^2 = cost :=
    Real.sq_sqrt costNonnegative
  have split :
      (Real.sqrt priorMass + keys.length * Real.sqrt cost)^2 ≤
        2 * priorMass + 2 * (keys.length : ℝ)^2 * cost := by
    nlinarith [sq_nonneg
      (Real.sqrt priorMass - keys.length * Real.sqrt cost)]
  have costEq : cost = branchMass / Fintype.card Output := by
    simp [cost, branchMass, normEq, div_eq_mul_inv, mul_comm]
  calc
    finalMass ≤ 2 * priorMass + 2 * (keys.length : ℝ)^2 * cost :=
      squareOrder'.trans split
    _ = 2 * priorMass +
        (2 * (keys.length : ℝ)^2 / Fintype.card Output) *
          branchMass := by rw [costEq]; ring

/-- Summed transport over every actual physical-read answer branch.  The
branch-dependent claim-success conjunction is charged once, with no outcome
count multiplying the role event or the squared-distance term. -/
theorem sum_selected_event_with_claims_transport_mass
    (keys : List Key) (nodup : keys.Nodup)
    (state : State Key Output Phase Work)
    (total : TotalOn keys (globalDecompress state))
    (roleEvent : Database Key Output → Prop) :
    (∑ answers : ReadAnswers (Input := Key) Output keys,
      let claims := branchClaims keys answers
      let event : Database Key Output → Prop :=
        fun database => roleEvent database ∧ ClaimsDatabaseEvent claims database
      normSquared
        (databaseEventProjection event
          (decompressList keys (physicalReadTrace keys answers state)))) ≤
      2 * (∑ answers : ReadAnswers (Input := Key) Output keys,
        let claims := branchClaims keys answers
        let event : Database Key Output → Prop :=
          fun database => roleEvent database ∧ ClaimsDatabaseEvent claims database
        normSquared
          (databaseEventProjection event
            (physicalReadTrace keys answers state))) +
      (2 * (keys.length : ℝ)^2 / Fintype.card Output) *
        normSquared state := by
  calc
    _ ≤ ∑ answers : ReadAnswers (Input := Key) Output keys,
        (2 * normSquared
          (databaseEventProjection
            (fun database => roleEvent database ∧
              ClaimsDatabaseEvent (branchClaims keys answers) database)
            (physicalReadTrace keys answers state)) +
          (2 * (keys.length : ℝ)^2 / Fintype.card Output) *
            normSquared (physicalReadTrace keys answers state)) := by
      apply Finset.sum_le_sum
      intro answers _
      exact selected_event_with_claims_transport_mass
        keys nodup answers state roleEvent
    _ = 2 * (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (databaseEventProjection
            (fun database => roleEvent database ∧
              ClaimsDatabaseEvent (branchClaims keys answers) database)
            (physicalReadTrace keys answers state))) +
          (2 * (keys.length : ℝ)^2 / Fintype.card Output) *
            normSquared state := by
      rw [Finset.sum_add_distrib, ← Finset.mul_sum, ← Finset.mul_sum,
        sum_physical_read_trace_norm_squared_of_total_on keys state total]

/-- Workspace-selected version for the actual accepted transcript.  Each
workspace slice fixes its role predicate, while the read trace remains the
same physical branch.  Slices and answer branches are both summed exactly
once. -/
theorem sum_workspace_event_with_claims_transport_mass
    (keys : List Key) (nodup : keys.Nodup)
    (state : State Key Output Phase Work)
    (total : TotalOn keys (globalDecompress state))
    (roleEvent : Work → Database Key Output → Prop) :
    (∑ answers : ReadAnswers (Input := Key) Output keys,
      normSquared
        (workspaceEventProjection
          (fun work database => roleEvent work database ∧
            ClaimsDatabaseEvent (branchClaims keys answers) database)
          (decompressList keys (physicalReadTrace keys answers state)))) ≤
      2 * (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection
            (fun work database => roleEvent work database ∧
              ClaimsDatabaseEvent (branchClaims keys answers) database)
            (physicalReadTrace keys answers state))) +
      (2 * (keys.length : ℝ)^2 / Fintype.card Output) *
        normSquared state := by
  have branchBound (work : Work) :=
    sum_selected_event_with_claims_transport_mass keys nodup
      (workspaceSlice work state)
      (standard_total_workspace_slice work keys state total)
      (roleEvent work)
  have leftEq :
      (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection
            (fun work database => roleEvent work database ∧
              ClaimsDatabaseEvent (branchClaims keys answers) database)
            (decompressList keys (physicalReadTrace keys answers state)))) =
        ∑ work : Work,
          ∑ answers : ReadAnswers (Input := Key) Output keys,
            normSquared
              (databaseEventProjection
                (fun database => roleEvent work database ∧
                  ClaimsDatabaseEvent (branchClaims keys answers) database)
                (decompressList keys
                  (physicalReadTrace keys answers
                    (workspaceSlice work state)))) := by
    simp_rw [workspace_event_norm_squared_eq_sum_slices,
      workspace_slice_decompress_list, workspace_slice_physical_read_trace]
    rw [Finset.sum_comm]
  have rightEq :
      (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection
            (fun work database => roleEvent work database ∧
              ClaimsDatabaseEvent (branchClaims keys answers) database)
            (physicalReadTrace keys answers state))) =
        ∑ work : Work,
          ∑ answers : ReadAnswers (Input := Key) Output keys,
            normSquared
              (databaseEventProjection
                (fun database => roleEvent work database ∧
                  ClaimsDatabaseEvent (branchClaims keys answers) database)
                (physicalReadTrace keys answers
                  (workspaceSlice work state))) := by
    simp_rw [workspace_event_norm_squared_eq_sum_slices,
      workspace_slice_physical_read_trace]
    rw [Finset.sum_comm]
  rw [leftEq, rightEq]
  calc
    _ ≤ ∑ work : Work,
        (2 * (∑ answers : ReadAnswers (Input := Key) Output keys,
          normSquared
            (databaseEventProjection
              (fun database => roleEvent work database ∧
                ClaimsDatabaseEvent (branchClaims keys answers) database)
              (physicalReadTrace keys answers
                (workspaceSlice work state)))) +
          (2 * (keys.length : ℝ)^2 / Fintype.card Output) *
            normSquared (workspaceSlice work state)) := by
      apply Finset.sum_le_sum
      intro work _
      exact branchBound work
    _ = 2 * (∑ work : Work,
          ∑ answers : ReadAnswers (Input := Key) Output keys,
            normSquared
              (databaseEventProjection
                (fun database => roleEvent work database ∧
                  ClaimsDatabaseEvent (branchClaims keys answers) database)
                (physicalReadTrace keys answers
                  (workspaceSlice work state)))) +
          (2 * (keys.length : ℝ)^2 / Fintype.card Output) *
            normSquared state := by
      rw [Finset.sum_add_distrib, ← Finset.mul_sum, ← Finset.mul_sum,
        sum_workspace_slice_norm_squared]

/-- A role event splits into successful recorded claims and the literal
claim-failure branch; no assumption about its database stability is used. -/
theorem role_event_mass_le_claim_success_add_failure
    (roleEvent : Work → Database Key Output → Prop)
    (claims : List (Key × Output))
    (state : State Key Output Phase Work) :
    normSquared (workspaceEventProjection roleEvent state) ≤
      normSquared
        (workspaceEventProjection
          (fun work database => roleEvent work database ∧
            ClaimsDatabaseEvent claims database) state) +
      normSquared (claimFailureProjection claims state) := by
  unfold normSquared workspaceEventProjection claimFailureProjection
    databaseEventProjection
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro basis _
  by_cases role : roleEvent basis.workspace basis.database <;>
    by_cases claimsRead : ClaimsDatabaseEvent claims basis.database <;>
    simp [role, claimsRead, Complex.normSq_nonneg]

theorem role_with_claims_mass_le_role_mass
    (roleEvent : Work → Database Key Output → Prop)
    (claims : List (Key × Output))
    (state : State Key Output Phase Work) :
    normSquared
        (workspaceEventProjection
          (fun work database => roleEvent work database ∧
            ClaimsDatabaseEvent claims database) state) ≤
      normSquared (workspaceEventProjection roleEvent state) := by
  unfold normSquared workspaceEventProjection
  apply Finset.sum_le_sum
  intro basis _
  by_cases role : roleEvent basis.workspace basis.database <;>
    by_cases claimsRead : ClaimsDatabaseEvent claims basis.database <;>
    simp [role, claimsRead, Complex.normSq_nonneg]

/-- Final arbitrary workspace/database role-event transport for all physical
read branches.  The role event is evaluated on the actual post-read compressed
state; the final measurement may change it, and that change is paid for by
the explicit `2*k^2/|Y|` term plus `2*k/|Y|` claim retention. -/
theorem sum_final_role_event_mass_le_physical_pre_event
    (keys : List Key) (nodup : keys.Nodup)
    (state : State Key Output Phase Work)
    (total : TotalOn keys (globalDecompress state))
    (roleEvent : Work → Database Key Output → Prop) :
    (∑ answers : ReadAnswers (Input := Key) Output keys,
      normSquared
        (workspaceEventProjection roleEvent
          (decompressList keys (physicalReadTrace keys answers state)))) ≤
      2 * (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection roleEvent
            (physicalReadTrace keys answers state))) +
      ((2 * (keys.length : ℝ)^2 + 2 * keys.length) /
          Fintype.card Output) * normSquared state := by
  let success answers : Work → Database Key Output → Prop :=
    fun work database => roleEvent work database ∧
      ClaimsDatabaseEvent (branchClaims keys answers) database
  have successTransport := sum_workspace_event_with_claims_transport_mass
    keys nodup state total roleEvent
  have finalSplit :
      (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection roleEvent
            (decompressList keys (physicalReadTrace keys answers state)))) ≤
      (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection (success answers)
            (decompressList keys (physicalReadTrace keys answers state)))) +
      (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (claimFailureProjection (branchClaims keys answers)
            (decompressList keys (physicalReadTrace keys answers state)))) := by
    rw [← Finset.sum_add_distrib]
    apply Finset.sum_le_sum
    intro answers _
    exact role_event_mass_le_claim_success_add_failure
      roleEvent (branchClaims keys answers) _
  have priorSubset :
      (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection (success answers)
            (physicalReadTrace keys answers state))) ≤
      ∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection roleEvent
            (physicalReadTrace keys answers state)) := by
    apply Finset.sum_le_sum
    intro answers _
    exact role_with_claims_mass_le_role_mass
      roleEvent (branchClaims keys answers) _
  have selectedClaimLoss :
      (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (claimFailureProjection (branchClaims keys answers)
            (decompressList keys (physicalReadTrace keys answers state)))) ≤
      ((2 * keys.length : Nat) : ℝ) / Fintype.card Output *
        normSquared state := by
    -- The selected partial-standard view is known at all recorded keys;
    -- applying `known_claims_partial_decompress_failure_le` in the reverse
    -- direction would bound failure on the compressed state instead.  Here
    -- the selected view has zero claim failure, exactly.
    have zeroFailure (answers : ReadAnswers (Input := Key) Output keys) :
        claimFailureProjection (branchClaims keys answers)
          (decompressList keys (physicalReadTrace keys answers state)) = 0 := by
      funext basis
      by_cases failed : ¬ ClaimsDatabaseEvent
          (branchClaims keys answers) basis.database
      · have noAmplitude :
            decompressList keys (physicalReadTrace keys answers state) basis = 0 := by
          by_contra nonzero
          apply failed
          intro claim member
          have known := selected_physical_branch_claim_known
            keys nodup answers state claim member
          have atBasis := congrFun known basis
          unfold KnownAt coordinateEventProjection at atBasis
          by_cases recorded : basis.database claim.1 = some claim.2
          · exact recorded
          · have vanish :
                decompressList keys
                  (physicalReadTrace keys answers state) basis = 0 := by
              simpa [recorded] using atBasis.symm
            exact (nonzero vanish).elim
        simp [claimFailureProjection, databaseEventProjection, failed,
          noAmplitude]
      · simp [claimFailureProjection, databaseEventProjection, failed]
    have normNonnegative : 0 ≤ normSquared state := by
      unfold normSquared
      exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
    simpa [zeroFailure, normSquared] using
      (mul_nonneg
        (show 0 ≤ ((2 * keys.length : Nat) : ℝ) /
          Fintype.card Output by positivity)
        normNonnegative)
  calc
    _ ≤ (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection (success answers)
            (decompressList keys (physicalReadTrace keys answers state)))) +
        (∑ answers : ReadAnswers (Input := Key) Output keys,
          normSquared
            (claimFailureProjection (branchClaims keys answers)
              (decompressList keys (physicalReadTrace keys answers state)))) :=
      finalSplit
    _ ≤ 2 * (∑ answers : ReadAnswers (Input := Key) Output keys,
        normSquared
          (workspaceEventProjection roleEvent
            (physicalReadTrace keys answers state))) +
        ((2 * (keys.length : ℝ)^2 + 2 * keys.length) /
          Fintype.card Output) * normSquared state := by
      have priorDouble := mul_le_mul_of_nonneg_left priorSubset
        (show (0 : ℝ) ≤ 2 by norm_num)
      have transport :
          (∑ answers : ReadAnswers (Input := Key) Output keys,
            normSquared (workspaceEventProjection (success answers)
              (decompressList keys (physicalReadTrace keys answers state)))) ≤
          2 * (∑ answers : ReadAnswers (Input := Key) Output keys,
            normSquared (workspaceEventProjection roleEvent
              (physicalReadTrace keys answers state))) +
          2 * (keys.length : ℝ)^2 / Fintype.card Output *
            normSquared state := by
        nlinarith [successTransport, priorDouble]
      have := add_le_add transport selectedClaimLoss
      push_cast at this ⊢
      convert this using 1
      all_goals first | rfl | ring

end
end HegemonCrypto.SmallWood.SmzaRp05TerminalEventTransport
