import SmzaRp05PhysicalReadSupport
import SmzaRp05ConditionedExecution

/-!
# Role-read totality survives the literal disjoint X copy

The compressed X database is measured before the final role-read schedule.
This does not preserve global standard-oracle totality. It does preserve
totality at every role coordinate, because the copy permutation depends
only on disjoint X cells. Only that local invariant is needed by a read.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05RoleReadTotality

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.SmallWood.V8Smz9CoherentVectorMerkle
open SmzaRp05PhysicalTerminalRead SmzaRp05SuffixReadout
open SmzaRp05ConditionedExecution

noncomputable section
set_option autoImplicit false

variable {Key Counter Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Work] [DecidableEq Work]

/-- Only the coordinates that will actually be read must remain total. -/
def StandardOn (keys : List Key)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work) : Prop :=
  ∀ key ∈ keys, TotalAt key (globalDecompress state)

theorem standard_at_iff_selected
    (key : Key)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work) :
    TotalAt key (globalDecompress state) ↔ TotalAt key (decompressAt key state) := by
  have omitted : key ∉ ((Finset.univ : Finset Key).erase key).toList := by simp
  constructor
  · intro total
    have twice := total_at_decompress_list_of_not_mem key
      ((Finset.univ : Finset Key).erase key).toList (globalDecompress state)
      omitted total
    rw [global_decompress_eq_selected_last key] at twice
    simpa only [decompressExcept,
      CmsOracleDatabaseBridge.decompress_list_involutive] using twice
  · intro total
    rw [global_decompress_eq_selected_last key]
    exact total_at_decompress_list_of_not_mem key
      ((Finset.univ : Finset Key).erase key).toList _ omitted total

/-- The literal X-view is unchanged by replacing a role coordinate. -/
theorem x_view_set_outside
    (keys : Finset Key) (key : Key) (outside : key ∉ keys)
    (database : Database Key (VectorOutput Counter))
    (answer : Option (VectorOutput Counter)) :
    xView keys (setDatabaseCoordinate database key answer) = xView keys database := by
  funext xkey
  exact set_database_coordinate_other database
    (input := key) (selected := xkey.val)
    (fun same => outside (same ▸ xkey.property)) answer

theorem decompress_at_x_copy_of_outside
    (keys : Finset Key) (key : Key) (outside : key ∉ keys)
    (update : (XKey keys → Option (VectorOutput Counter)) → Work ≃ Work)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work) :
    decompressAt key (xControlledWorkspaceUpdate keys update state) =
      xControlledWorkspaceUpdate keys update (decompressAt key state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold xControlledWorkspaceUpdate
  simp only [SmzaRp05AdaptiveKernelInstantiation.databaseControlledWorkspaceUpdate]
  simp_rw [x_view_set_outside keys key outside]
  rw [decompress_at_eq_sum_kernel]

/-- The actual copy transition preserves physical totality at a disjoint
role coordinate, without asserting totality at the measured X cells. -/
theorem standard_at_x_copy_of_outside
    (keys : Finset Key) (key : Key) (outside : key ∉ keys)
    (update : (XKey keys → Option (VectorOutput Counter)) → Work ≃ Work)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (total : TotalAt key (globalDecompress state)) :
    TotalAt key (globalDecompress (xControlledWorkspaceUpdate keys update state)) := by
  apply (standard_at_iff_selected key _).2
  rw [decompress_at_x_copy_of_outside keys key outside]
  have localTotal := (standard_at_iff_selected key state).1 total
  intro basis absent
  exact localTotal
    { input := basis.input
      phase := basis.phase
      workspace := (update (xView keys basis.database)).symm basis.workspace
      database := basis.database } absent

theorem standard_on_x_copy_of_disjoint
    (xkeys : Finset Key) (reads : List Key)
    (disjoint : ∀ key ∈ reads, key ∉ xkeys)
    (update : (XKey xkeys → Option (VectorOutput Counter)) → Work ≃ Work)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (total : StandardOn reads state) :
    StandardOn reads (xControlledWorkspaceUpdate xkeys update state) := by
  intro key member
  exact standard_at_x_copy_of_outside xkeys key (disjoint key member)
    update state (total key member)

/-- Role parsing discharges disjointness from the literal X-copy contract. -/
theorem parsed_role_standard_at_x_copy
    (xkeys : Finset Key) (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (unrecognized : ∀ key ∈ xkeys,
      SmzaChallengeStageTargets.parseStageQuery (keyBytes key) = none)
    (key : Key) (query : SmzaChallengeStageTargets.StageQuery)
    (parsed : SmzaChallengeStageTargets.parseStageQuery (keyBytes key) = some query)
    (update : (XKey xkeys → Option (VectorOutput Counter)) → Work ≃ Work)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (total : TotalAt key (globalDecompress state)) :
    TotalAt key (globalDecompress (xControlledWorkspaceUpdate xkeys update state)) := by
  apply standard_at_x_copy_of_outside xkeys key _ update state total
  intro member
  have incompatible := (unrecognized key member).symm.trans parsed
  cases incompatible

theorem standard_on_physical_read_branch
    (keys : List Key) (selected : Key) (answer : VectorOutput Counter)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (total : StandardOn keys state) :
    StandardOn keys (physicalReadBranch selected answer state) := by
  intro key member
  rw [physical_read_branch_standard_view]
  exact total_at_coordinate_event_projection key selected answer
    (globalDecompress state) (total key member)

theorem sum_physical_read_branch_norm_squared_of_total_at
    (key : Key)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (total : TotalAt key (globalDecompress state)) :
    (∑ answer : VectorOutput Counter,
      normSquared (physicalReadBranch key answer state)) = normSquared state := by
  calc
    _ = ∑ answer : VectorOutput Counter,
        normSquared (coordinateEventProjection key answer (globalDecompress state)) := by
      apply Finset.sum_congr rfl
      intro answer _
      exact decompress_list_preserves_norm_squared
        (Finset.univ : Finset Key).toList _
    _ = normSquared (globalDecompress state) :=
      sum_database_read_branch_norm_squared key (globalDecompress state) total
    _ = normSquared state :=
      decompress_list_preserves_norm_squared (Finset.univ : Finset Key).toList state

end
end HegemonCrypto.SmallWood.SmzaRp05RoleReadTotality
