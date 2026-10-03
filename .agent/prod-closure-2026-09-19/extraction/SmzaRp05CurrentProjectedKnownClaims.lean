import SmzaRp05CurrentKnownClaimsAmplitude
import SmzaRp05PhysicalReadSupport
import SmzaRp05TerminalEventTransport

/-! # Retained claims survive selectors invariant at their challenge keys

A selector may inspect workspace and any database coordinates other than the
retained challenge keys. The exact condition needed here is that the selector
be invariant under replacing a retained key's database coordinate. Factoring
global decompression through that key isolates the only decompression that
must commute with the selector; all other coordinates are handled by the
existing omitted-coordinate commutation lemma.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentProjectedKnownClaims

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05PhysicalAcceptedReplayLite (KnownAt)
open SmzaRp05CurrentKnownClaimsAmplitude
open SmzaRp05TerminalEventTransport

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

variable {Key Output Phase Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

/-- Workspace-event projection commutes with decompression at a key when
the event is invariant under every possible replacement of that database
coordinate. -/
theorem workspace_event_projection_decompress_at_of_invariant
    (event : Work → Database Key Output → Prop)
    (key : Key)
    (invariant : ∀ workspace database answer,
      event workspace (setDatabaseCoordinate database key answer) ↔
        event workspace database)
    (state : State Key Output Phase Work) :
    workspaceEventProjection event (decompressAt key state) =
      decompressAt key (workspaceEventProjection event state) := by
  funext target
  change (if event target.workspace target.database then
      decompressAt key state target else 0) =
    decompressAt key (fun basis =>
      if event basis.workspace basis.database then state basis else 0) target
  rw [decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel]
  by_cases selected : event target.workspace target.database
  · rw [if_pos selected]
    apply Finset.sum_congr rfl
    intro answer _
    have selectedAfter := (invariant target.workspace target.database answer).mpr selected
    simp [selectedAfter]
  · rw [if_neg selected]
    symm
    apply Finset.sum_eq_zero
    intro answer _
    have rejectedAfter :
        ¬ event target.workspace (setDatabaseCoordinate target.database key answer) := by
      intro acceptedAfter
      exact selected ((invariant target.workspace target.database answer).mp acceptedAfter)
    simp [rejectedAfter]

/-- The two basis-diagonal projectors commute: one selects a database
coordinate answer and the other selects a workspace/database event. -/
theorem coordinate_projection_workspace_event_projection
    (event : Work → Database Key Output → Prop)
    (key : Key) (answer : Output)
    (state : State Key Output Phase Work) :
    coordinateEventProjection key answer (workspaceEventProjection event state) =
      workspaceEventProjection event (coordinateEventProjection key answer state) := by
  funext basis
  by_cases recorded : basis.database key = some answer <;>
    simp [coordinateEventProjection, workspaceEventProjection, recorded]

/-- The generic selected-coordinate projector commutes with every
decompression except at that coordinate. -/
theorem coordinate_projection_decompress_except_generic
    (key : Key) (answer : Output)
    (state : State Key Output Phase Work) :
    coordinateEventProjection key answer (decompressExcept key state) =
      decompressExcept key (coordinateEventProjection key answer state) := by
  unfold decompressExcept
  apply generic_coordinate_projection_decompress_list_of_outside
  intro changed member
  have erased : changed ∈ (Finset.univ : Finset Key).erase key := by
    simpa using member
  exact fun same => (Finset.mem_erase.mp erased).1 same.symm

/-- A retained answer remains known after a workspace/database selector is
applied before global decompression, provided that selector does not inspect
or otherwise change when the retained key is updated. -/
theorem known_at_global_decompress_workspace_event_projection
    (event : Work → Database Key Output → Prop)
    (key : Key) (answer : Output)
    (state : State Key Output Phase Work)
    (invariant : ∀ workspace database replacement,
      event workspace (setDatabaseCoordinate database key replacement) ↔
        event workspace database)
    (known : KnownAt key answer (globalDecompress state)) :
    KnownAt key answer (globalDecompress (workspaceEventProjection event state)) := by
  have knownAtLocal : KnownAt key answer (decompressAt key state) := by
    have knownLast := known
    unfold KnownAt at knownLast ⊢
    rw [global_decompress_eq_selected_last key state] at knownLast
    rw [coordinate_projection_decompress_except_generic] at knownLast
    have cancelOthers := congrArg (decompressExcept key) knownLast
    simpa [decompressExcept, decompress_list_involutive] using cancelOthers
  change coordinateEventProjection key answer
      (globalDecompress (workspaceEventProjection event state)) =
    globalDecompress (workspaceEventProjection event state)
  rw [global_decompress_eq_selected_last key (workspaceEventProjection event state)]
  rw [← workspace_event_projection_decompress_at_of_invariant event key invariant state]
  rw [coordinate_projection_decompress_except_generic]
  rw [coordinate_projection_workspace_event_projection]
  rw [knownAtLocal]

/-- Every retained claim stays known in the selected state, so the existing
weighted-claim amplitude theorem applies directly to that same selected
state. No probability or normalization identity is added as a premise. -/
theorem projected_known_claims_weighted_amplitude_le
    (event : Work → Database Key Output → Prop)
    (state : State Key Output Phase Work)
    (claims : List (Key × Output))
    (distinct : (claims.map Prod.fst).Nodup)
    (known : ∀ claim ∈ claims,
      KnownAt claim.1 claim.2 (globalDecompress state))
    (invariant : ∀ claim ∈ claims, ∀ workspace database replacement,
      event workspace
          (setDatabaseCoordinate database claim.1 replacement) ↔
        event workspace database) :
    Real.sqrt (normSquared (workspaceEventProjection event state)) ≤
      Real.sqrt (normSquared
        (databaseEventProjection (ClaimsDatabaseEvent claims)
          (workspaceEventProjection event state))) +
      claims.length * Real.sqrt
        ((1 / (Fintype.card Output : ℝ)) *
          normSquared (workspaceEventProjection event state)) := by
  apply known_claims_weighted_amplitude_le
    (workspaceEventProjection event state) claims distinct
  intro claim member
  exact known_at_global_decompress_workspace_event_projection event
    claim.1 claim.2 state (invariant claim member) (known claim member)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentProjectedKnownClaims
