import HegemonCrypto.CmsOracleDatabaseBridge
import HegemonCrypto.CmsLifting

/-!
# Adaptive claim bridge for the CMS compressed oracle

The fixed-claim oracle/database bridge is not enough for Fiat--Shamir extraction: the adversary's
final transcript determines which oracle claims certify acceptance.  This module partitions the
finite state by the adversary workspace, proves that concrete decompression preserves those
orthogonal slices, and then recombines their exact squared norms.

No cryptographic assumption appears here.  The only requirements are finite registers and the
concrete CMS decompression operator proved in `CmsOracleDatabaseBridge`.
-/

namespace HegemonCrypto.CmsAdaptiveClaimBridge

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsLifting

noncomputable section

set_option linter.unusedSectionVars false

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Orthogonal projection onto one adversary-workspace basis value. -/
def workspaceSlice
    (selected : Workspace)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun basis => if basis.workspace = selected then state basis else 0

/-- One-coordinate decompression cannot mix adversary-workspace slices. -/
theorem workspace_slice_decompress_at
    (selected : Workspace)
    (oracleInput : Input)
    (state : State Input Output Phase Workspace) :
    workspaceSlice selected (decompressAt oracleInput state) =
      decompressAt oracleInput (workspaceSlice selected state) := by
  funext target
  change
    (if target.workspace = selected then
      decompressAt oracleInput state target else 0) =
      decompressAt oracleInput (workspaceSlice selected state) target
  rw [decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel]
  by_cases sameWorkspace : target.workspace = selected
  · simp [workspaceSlice, sameWorkspace]
  · simp [workspaceSlice, sameWorkspace]

/-- A finite product of decompressions preserves every workspace slice. -/
theorem workspace_slice_decompress_list
    (selected : Workspace)
    (inputs : List Input)
    (state : State Input Output Phase Workspace) :
    workspaceSlice selected (decompressList inputs state) =
      decompressList inputs (workspaceSlice selected state) := by
  induction inputs with
  | nil =>
      rfl
  | cons input remaining inductionHypothesis =>
      rw [decompress_list_cons, decompress_list_cons,
        workspace_slice_decompress_at, inductionHypothesis]

/-- Full finite-domain decompression preserves every workspace slice. -/
theorem workspace_slice_global_decompress
    (selected : Workspace)
    (state : State Input Output Phase Workspace) :
    workspaceSlice selected (globalDecompress state) =
      globalDecompress (workspaceSlice selected state) := by
  exact workspace_slice_decompress_list selected
    (Finset.univ : Finset Input).toList state

/-- Restrict an oracle-indexed register family to one workspace basis value. -/
def workspaceSliceFamily
    (selected : Workspace)
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)) :
    OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace) :=
  fun oracle registers =>
    if registers.2.2 = selected then family oracle registers else 0

/-- Purifying total oracles commutes with workspace slicing. -/
theorem workspace_slice_total_oracle_family_state
    (selected : Workspace)
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)) :
    workspaceSlice selected (totalOracleFamilyState family) =
      totalOracleFamilyState (workspaceSliceFamily selected family) := by
  funext basis
  unfold workspaceSlice totalOracleFamilyState workspaceSliceFamily basisRegisters
  by_cases sameWorkspace : basis.workspace = selected
  · simp [sameWorkspace]
  · simp [sameWorkspace]

/-- Workspace slices are orthogonal and account for the complete state norm exactly. -/
theorem sum_workspace_slice_norm_squared
    (state : State Input Output Phase Workspace) :
    (∑ selected : Workspace, normSquared (workspaceSlice selected state)) =
      normSquared state := by
  classical
  unfold normSquared workspaceSlice
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro basis _
  rw [Finset.sum_eq_single basis.workspace]
  · simp
  · intro selected _ different
    simp [Ne.symm different]
  · simp

/-- Projection onto a database event selected by the final adversary workspace. -/
noncomputable def workspaceEventProjection
    (event : Workspace -> Database Input Output -> Prop)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace := by
  classical
  exact fun basis =>
    if event basis.workspace basis.database then state basis else 0

/--
The norm of a workspace-selected event is the exact sum of the corresponding fixed-event norms on
orthogonal workspace slices.
-/
theorem workspace_event_norm_squared_eq_sum_slices
    (event : Workspace -> Database Input Output -> Prop)
    (state : State Input Output Phase Workspace) :
    normSquared (workspaceEventProjection event state) =
      ∑ selected : Workspace,
        normSquared
          (databaseEventProjection (event selected)
            (workspaceSlice selected state)) := by
  classical
  unfold normSquared workspaceEventProjection databaseEventProjection workspaceSlice
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro basis _
  rw [Finset.sum_eq_single basis.workspace]
  · by_cases accepted : event basis.workspace basis.database <;>
      simp [accepted]
  · intro selected _ different
    simp [Ne.symm different]
  · simp

/--
A workspace-selected event included in a database property cannot carry more squared norm than
the corresponding bounded property projection.
-/
theorem workspace_event_norm_squared_le_project
    (event : Workspace -> Database Input Output -> Prop)
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (included :
      ∀ workspace database, event workspace database -> property database)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (bounded : BoundedState queryBound state) :
    normSquared (workspaceEventProjection event state) <=
      normSquared (project property queryBound state) := by
  classical
  unfold normSquared workspaceEventProjection project
  apply Finset.sum_le_sum
  intro basis _
  by_cases selected : event basis.workspace basis.database
  · have propertyMembership : property basis.database :=
      included basis.workspace basis.database selected
    by_cases within : size basis.database <= queryBound
    · simp [selected, propertyMembership, within]
    · have above : queryBound < size basis.database :=
        Nat.lt_of_not_ge within
      have stateZero :=
        bounded_state_apply_eq_zero_of_lt bounded basis above
      simp [selected, propertyMembership, within, stateZero]
  · simp [selected, Complex.normSq_nonneg]

/-- Database event asserting the exact claim list selected by one final workspace. -/
def AdaptiveClaimsEvent
    (enabled : Workspace -> Prop)
    (claims : Workspace -> List (Input × Output))
    (workspace : Workspace)
    (database : Database Input Output) : Prop :=
  enabled workspace ∧ ClaimsDatabaseEvent (claims workspace) database

/--
Adaptive finite oracle-to-database bridge.

The final adversary workspace may choose a different duplicate-free claim list on every branch.
The bridge loss depends only on `maxClaims`, because workspace branches are orthogonal and are
combined by their exact squared norms.
-/
theorem adaptive_claims_amplitude_bridge
    (compressedState : State Input Output Phase Workspace)
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (simulation :
      globalDecompress compressedState = totalOracleFamilyState family)
    (enabled : Workspace -> Prop)
    (claims : Workspace -> List (Input × Output))
    (distinctInputs : ∀ workspace, ((claims workspace).map Prod.fst).Nodup)
    (maxClaims : Nat)
    (claimBound : ∀ workspace, (claims workspace).length ≤ maxClaims) :
    Real.sqrt
        (normSquared
          (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
            (totalOracleFamilyState family))) ≤
      Real.sqrt
          (normSquared
            (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
              compressedState)) +
        Real.sqrt
          ((maxClaims : ℝ) ^ 2 *
            ((1 / (Fintype.card Output : ℝ)) *
              normSquared compressedState)) := by
  let event := AdaptiveClaimsEvent enabled claims
  let standardState := totalOracleFamilyState family
  let idealProbability := fun workspace =>
    normSquared
      (databaseEventProjection (event workspace)
        (workspaceSlice workspace standardState))
  let databaseProbability := fun workspace =>
    normSquared
      (databaseEventProjection (event workspace)
        (workspaceSlice workspace compressedState))
  let sliceNorm := fun workspace =>
    normSquared (workspaceSlice workspace compressedState)
  let idealAmplitude := fun workspace => Real.sqrt (idealProbability workspace)
  let databaseAmplitude := fun workspace => Real.sqrt (databaseProbability workspace)
  let bridgeAmplitude := fun workspace =>
    (maxClaims : ℝ) *
      Real.sqrt ((1 / (Fintype.card Output : ℝ)) * sliceNorm workspace)
  have sliceSimulation (workspace : Workspace) :
      globalDecompress (workspaceSlice workspace compressedState) =
        totalOracleFamilyState (workspaceSliceFamily workspace family) := by
    have sliced := congrArg (workspaceSlice workspace) simulation
    rw [workspace_slice_global_decompress,
      workspace_slice_total_oracle_family_state] at sliced
    exact sliced
  have perSlice (workspace : Workspace) :
      idealAmplitude workspace ≤
        databaseAmplitude workspace +
          (claims workspace).length *
            Real.sqrt
              ((1 / (Fintype.card Output : ℝ)) * sliceNorm workspace) := by
    by_cases active : enabled workspace
    · have fixed :=
        compressed_oracle_claims_amplitude_bridge_weighted
          (workspaceSlice workspace compressedState)
          (workspaceSliceFamily workspace family)
          (sliceSimulation workspace)
          (claims workspace)
          (distinctInputs workspace)
      have eventEq :
          event workspace = ClaimsDatabaseEvent (claims workspace) := by
        funext database
        simp [event, AdaptiveClaimsEvent, active]
      unfold idealAmplitude databaseAmplitude idealProbability
        databaseProbability sliceNorm standardState
      rw [eventEq, workspace_slice_total_oracle_family_state]
      exact fixed
    · have nonnegative :
          0 ≤
            (claims workspace).length *
              Real.sqrt
                ((1 / (Fintype.card Output : ℝ)) *
                  sliceNorm workspace) :=
        mul_nonneg (by positivity) (Real.sqrt_nonneg _)
      simpa [idealAmplitude, databaseAmplitude, idealProbability,
        databaseProbability, event, AdaptiveClaimsEvent, active,
        databaseEventProjection, normSquared] using nonnegative
  have perSliceMax (workspace : Workspace) :
      idealAmplitude workspace ≤
        databaseAmplitude workspace + bridgeAmplitude workspace := by
    apply (perSlice workspace).trans
    unfold bridgeAmplitude
    have lengthBound :
        ((claims workspace).length : ℝ) ≤ maxClaims := by
      exact_mod_cast claimBound workspace
    have termBound :=
      mul_le_mul_of_nonneg_right lengthBound (Real.sqrt_nonneg
        ((1 / (Fintype.card Output : ℝ)) * sliceNorm workspace))
    linarith
  have normSquaredNonnegative
      (state : State Input Output Phase Workspace) :
      0 ≤ normSquared state := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ =>
      Complex.normSq_nonneg (state basis)
  have idealProbabilityNonnegative (workspace : Workspace) :
      0 ≤ idealProbability workspace := by
    exact normSquaredNonnegative _
  have databaseProbabilityNonnegative (workspace : Workspace) :
      0 ≤ databaseProbability workspace := by
    exact normSquaredNonnegative _
  have sliceTermNonnegative (workspace : Workspace) :
      0 ≤
        (1 / (Fintype.card Output : ℝ)) * sliceNorm workspace := by
    exact mul_nonneg (by positivity) (normSquaredNonnegative _)
  have idealVectorBound :
      vectorNormSquared (fun workspace => (idealAmplitude workspace : ℂ)) ≤
        vectorNormSquared
          (fun workspace =>
            (databaseAmplitude workspace : ℂ) +
              (bridgeAmplitude workspace : ℂ)) := by
    unfold vectorNormSquared
    apply Finset.sum_le_sum
    intro workspace _
    have amplitudeNonnegative : 0 ≤ idealAmplitude workspace :=
      Real.sqrt_nonneg _
    have sumNonnegative :
        0 ≤ databaseAmplitude workspace + bridgeAmplitude workspace := by
      apply add_nonneg
      · exact Real.sqrt_nonneg _
      · unfold bridgeAmplitude
        positivity
    have squared :=
      mul_self_le_mul_self amplitudeNonnegative (perSliceMax workspace)
    change
      Complex.normSq (idealAmplitude workspace : ℂ) ≤
        Complex.normSq
          ((databaseAmplitude workspace : ℂ) +
            (bridgeAmplitude workspace : ℂ))
    rw [← Complex.ofReal_add, Complex.normSq_ofReal,
      Complex.normSq_ofReal]
    exact squared
  have idealVectorEq :
      vectorNormSquared (fun workspace => (idealAmplitude workspace : ℂ)) =
        normSquared
          (workspaceEventProjection event standardState) := by
    unfold vectorNormSquared idealAmplitude
    calc
      (∑ workspace : Workspace,
          Complex.normSq ((Real.sqrt (idealProbability workspace) : ℝ) : ℂ)) =
          ∑ workspace : Workspace, idealProbability workspace := by
        apply Finset.sum_congr rfl
        intro workspace _
        rw [Complex.normSq_ofReal,
          Real.mul_self_sqrt (idealProbabilityNonnegative workspace)]
      _ =
          normSquared
            (workspaceEventProjection event standardState) :=
        (workspace_event_norm_squared_eq_sum_slices event standardState).symm
  have databaseVectorEq :
      vectorNormSquared (fun workspace => (databaseAmplitude workspace : ℂ)) =
        normSquared
          (workspaceEventProjection event compressedState) := by
    unfold vectorNormSquared databaseAmplitude
    calc
      (∑ workspace : Workspace,
          Complex.normSq ((Real.sqrt (databaseProbability workspace) : ℝ) : ℂ)) =
          ∑ workspace : Workspace, databaseProbability workspace := by
        apply Finset.sum_congr rfl
        intro workspace _
        rw [Complex.normSq_ofReal,
          Real.mul_self_sqrt (databaseProbabilityNonnegative workspace)]
      _ =
          normSquared
            (workspaceEventProjection event compressedState) :=
        (workspace_event_norm_squared_eq_sum_slices event compressedState).symm
  have bridgeVectorEq :
      vectorNormSquared (fun workspace => (bridgeAmplitude workspace : ℂ)) =
        (maxClaims : ℝ) ^ 2 *
          ((1 / (Fintype.card Output : ℝ)) *
            normSquared compressedState) := by
    unfold vectorNormSquared bridgeAmplitude
    calc
      (∑ workspace : Workspace,
          Complex.normSq
            (((maxClaims : ℝ) *
              Real.sqrt
                ((1 / (Fintype.card Output : ℝ)) *
                  sliceNorm workspace) : ℝ) : ℂ)) =
          ∑ workspace : Workspace,
            (maxClaims : ℝ) ^ 2 *
              ((1 / (Fintype.card Output : ℝ)) *
                sliceNorm workspace) := by
        apply Finset.sum_congr rfl
        intro workspace _
        rw [Complex.normSq_ofReal]
        calc
          (maxClaims : ℝ) *
                Real.sqrt
                  ((1 / (Fintype.card Output : ℝ)) *
                    sliceNorm workspace) *
              ((maxClaims : ℝ) *
                Real.sqrt
                  ((1 / (Fintype.card Output : ℝ)) *
                    sliceNorm workspace)) =
              (maxClaims : ℝ) ^ 2 *
                (Real.sqrt
                  ((1 / (Fintype.card Output : ℝ)) *
                    sliceNorm workspace) *
                  Real.sqrt
                    ((1 / (Fintype.card Output : ℝ)) *
                      sliceNorm workspace)) := by
            ring
          _ =
              (maxClaims : ℝ) ^ 2 *
                ((1 / (Fintype.card Output : ℝ)) *
                  sliceNorm workspace) := by
            rw [Real.mul_self_sqrt (sliceTermNonnegative workspace)]
      _ =
          ((maxClaims : ℝ) ^ 2 *
            (1 / (Fintype.card Output : ℝ))) *
              ∑ workspace : Workspace, sliceNorm workspace := by
        rw [Finset.mul_sum]
        apply Finset.sum_congr rfl
        intro workspace _
        ring
      _ =
          (maxClaims : ℝ) ^ 2 *
            ((1 / (Fintype.card Output : ℝ)) *
              normSquared compressedState) := by
        rw [sum_workspace_slice_norm_squared]
        ring
  have sqrtVectorBound :
      Real.sqrt
          (vectorNormSquared
            (fun workspace => (idealAmplitude workspace : ℂ))) ≤
        Real.sqrt
          (vectorNormSquared
            (fun workspace =>
              (databaseAmplitude workspace : ℂ) +
                (bridgeAmplitude workspace : ℂ))) :=
    Real.sqrt_le_sqrt idealVectorBound
  have triangle :=
    sqrt_vector_norm_triangle
      (fun workspace => (databaseAmplitude workspace : ℂ))
      (fun workspace => (bridgeAmplitude workspace : ℂ))
  calc
    Real.sqrt
        (normSquared
          (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
            (totalOracleFamilyState family))) =
      Real.sqrt
        (vectorNormSquared
          (fun workspace => (idealAmplitude workspace : ℂ))) := by
      rw [idealVectorEq]
    _ ≤
      Real.sqrt
        (vectorNormSquared
          (fun workspace =>
            (databaseAmplitude workspace : ℂ) +
              (bridgeAmplitude workspace : ℂ))) :=
      sqrtVectorBound
    _ ≤
      Real.sqrt
          (vectorNormSquared
            (fun workspace => (databaseAmplitude workspace : ℂ))) +
        Real.sqrt
          (vectorNormSquared
            (fun workspace => (bridgeAmplitude workspace : ℂ))) :=
      triangle
    _ =
      Real.sqrt
          (normSquared
            (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
              compressedState)) +
        Real.sqrt
          ((maxClaims : ℝ) ^ 2 *
            ((1 / (Fintype.card Output : ℝ)) *
              normSquared compressedState)) := by
      rw [databaseVectorEq, bridgeVectorEq]

/--
Probability-form adaptive oracle/database transfer.

Once the compressed winning event is included in a bounded database property, this theorem
combines that database-game bound with the proved adaptive claim bridge.  It is the finite,
state-level form consumed by concrete BCS/QROM instantiations.
-/
theorem adaptive_claims_probability_le
    (compressedState : State Input Output Phase Workspace)
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (simulation :
      globalDecompress compressedState = totalOracleFamilyState family)
    (enabled : Workspace -> Prop)
    (claims : Workspace -> List (Input × Output))
    (distinctInputs : ∀ workspace, ((claims workspace).map Prod.fst).Nodup)
    (maxClaims : Nat)
    (claimBound : ∀ workspace, (claims workspace).length ≤ maxClaims)
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (eventIncluded :
      ∀ workspace database,
        AdaptiveClaimsEvent enabled claims workspace database ->
          property database)
    (queryBound : Nat)
    (bounded : BoundedState queryBound compressedState)
    (subnormalized : Subnormalized compressedState)
    (databaseGameLoss : ℝ)
    (databaseBound :
      normSquared (project property queryBound compressedState) <=
        databaseGameLoss) :
    normSquared
        (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
          (totalOracleFamilyState family)) <=
      oracleLoss databaseGameLoss
        ((maxClaims : ℝ) ^ 2 *
          (1 / (Fintype.card Output : ℝ))) := by
  let event := AdaptiveClaimsEvent enabled claims
  let bridgeLoss :=
    (maxClaims : ℝ) ^ 2 *
      (1 / (Fintype.card Output : ℝ))
  have compressedEventBound :
      normSquared
          (workspaceEventProjection event compressedState) <=
        databaseGameLoss := by
    exact
      (workspace_event_norm_squared_le_project
        event property eventIncluded queryBound compressedState bounded).trans
          databaseBound
  have bridge :=
    adaptive_claims_amplitude_bridge
      compressedState family simulation enabled claims distinctInputs
        maxClaims claimBound
  have compressedAmplitudeBound :
      Real.sqrt
          (normSquared
            (workspaceEventProjection event compressedState)) <=
        Real.sqrt databaseGameLoss :=
    Real.sqrt_le_sqrt compressedEventBound
  have bridgeCoefficientNonnegative :
      0 <=
        (maxClaims : ℝ) ^ 2 *
          (1 / (Fintype.card Output : ℝ)) := by
    positivity
  have bridgeInsideBound :
      (maxClaims : ℝ) ^ 2 *
          ((1 / (Fintype.card Output : ℝ)) *
            normSquared compressedState) <=
        bridgeLoss := by
    calc
      (maxClaims : ℝ) ^ 2 *
            ((1 / (Fintype.card Output : ℝ)) *
              normSquared compressedState) =
          ((maxClaims : ℝ) ^ 2 *
            (1 / (Fintype.card Output : ℝ))) *
              normSquared compressedState := by
        ring
      _ <=
          ((maxClaims : ℝ) ^ 2 *
            (1 / (Fintype.card Output : ℝ))) * 1 :=
        mul_le_mul_of_nonneg_left subnormalized
          bridgeCoefficientNonnegative
      _ = bridgeLoss := by
        simp [bridgeLoss]
  have bridgeAmplitudeBound :
      Real.sqrt
          ((maxClaims : ℝ) ^ 2 *
            ((1 / (Fintype.card Output : ℝ)) *
              normSquared compressedState)) <=
        Real.sqrt bridgeLoss :=
    Real.sqrt_le_sqrt bridgeInsideBound
  have amplitudeTransfer :
      Real.sqrt
          (normSquared
            (workspaceEventProjection event
              (totalOracleFamilyState family))) <=
        Real.sqrt databaseGameLoss + Real.sqrt bridgeLoss := by
    exact bridge.trans
      (add_le_add compressedAmplitudeBound bridgeAmplitudeBound)
  have idealNonnegative :
      0 <=
        normSquared
            (workspaceEventProjection event
              (totalOracleFamilyState family)) := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ =>
      Complex.normSq_nonneg
        (workspaceEventProjection event
          (totalOracleFamilyState family) basis)
  simpa [event, bridgeLoss] using
    oracle_to_database_transfer
      (normSquared
        (workspaceEventProjection event
          (totalOracleFamilyState family)))
      databaseGameLoss
      bridgeLoss
      idealNonnegative
      amplitudeTransfer

end

end HegemonCrypto.CmsAdaptiveClaimBridge
