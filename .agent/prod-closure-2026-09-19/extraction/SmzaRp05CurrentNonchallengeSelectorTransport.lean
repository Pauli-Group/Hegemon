import SmzaRp05ConditionedExecution
import SmzaRp05PartialReadout

/-! # Nonchallenge-record selector transport

A diagonal selector may inspect the classical workspace and the restriction
of the raw database to an arbitrary finite nonchallenge key set.  Decompressing
coordinates outside that set commutes with its projection exactly.  This is an
operator identity; it makes no probability or independence assertion.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentNonchallengeSelectorTransport

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRoleDomainConditioning
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution (XKey xView activeXView fixedOtherKeys
  otherRoleTransform active_x_view_restrict restrictActive)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

abbrev Output := VectorOutput Counter
abbrev Work := SmzaRp05CurrentAdaptiveExecution.Work
  (Counter := Counter) (BaseWork := BaseWork)
abbrev CmsState := State Key (Output (Counter := Counter))
  (Output (Counter := Counter)) (Work (Counter := Counter) (BaseWork := BaseWork))

/-- A selector depending only on the classical workspace and the database
view restricted to `keys`. -/
def nonchallengeSelectorProjection
    (keys : Finset Key)
    (select : (XKey keys → Option (Output (Counter := Counter))) →
      Work (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  workspaceEventProjection
    (fun work database => select (xView keys database) work) state

/-- Projection by an X-restricted selector commutes with one coordinate
decompression outside the selector's key set. -/
theorem nonchallenge_selector_projection_decompress_at
    (keys : Finset Key)
    (select : (XKey keys → Option (Output (Counter := Counter))) →
      Work (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (changed : Key) (state : CmsState (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (outside : changed ∉ keys) :
    nonchallengeSelectorProjection keys select (decompressAt changed state) =
      decompressAt changed (nonchallengeSelectorProjection keys select state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold nonchallengeSelectorProjection workspaceEventProjection
  by_cases accepted : select (xView keys target.database) target.workspace
  · rw [if_pos accepted, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro source _
    have viewEq : xView keys
        (setDatabaseCoordinate target.database changed source) =
        xView keys target.database := by
      funext key
      apply set_database_coordinate_other
      intro same
      apply outside
      simpa [same] using key.property
    simp [viewEq, accepted]
  · rw [if_neg accepted]
    symm
    apply Finset.sum_eq_zero
    intro source _
    have viewEq : xView keys
        (setDatabaseCoordinate target.database changed source) =
        xView keys target.database := by
      funext key
      apply set_database_coordinate_other
      intro same
      apply outside
      simpa [same] using key.property
    simp [viewEq, accepted]

/-- The same selector commutes with finite decompression over any list
disjoint from its nonchallenge keys. -/
theorem nonchallenge_selector_projection_decompress_list
    (keys : Finset Key)
    (select : (XKey keys → Option (Output (Counter := Counter))) →
      Work (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (inputs : List Key)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (outside : ∀ changed, changed ∈ inputs → changed ∉ keys) :
    nonchallengeSelectorProjection keys select (decompressList inputs state) =
      decompressList inputs (nonchallengeSelectorProjection keys select state) := by
  induction inputs with
  | nil => rfl
  | cons changed remaining ih =>
      have changedOutside : changed ∉ keys := outside changed (by simp)
      have remainingOutside : ∀ key, key ∈ remaining → key ∉ keys := by
        intro key member
        exact outside key (by simp [member])
      rw [decompress_list_cons, nonchallenge_selector_projection_decompress_at
        keys select changed _ changedOutside, ih remainingOutside,
        decompress_list_cons]

/-- Role conditioning decompresses only keys outside a nonchallenge set;
therefore every selector on that X restriction and workspace commutes with
the actual `otherRoleTransform`. -/
theorem nonchallenge_selector_projection_other_role_transform
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : Finset Key)
    (select : (XKey keys → Option (Output (Counter := Counter))) →
      Work (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (outside : ∀ key, key ∈ fixedOtherKeys ctx blockCap → key ∉ keys) :
    nonchallengeSelectorProjection keys select (otherRoleTransform ctx blockCap state) =
      otherRoleTransform ctx blockCap
        (nonchallengeSelectorProjection keys select state) := by
  unfold otherRoleTransform decompressFinset
  exact nonchallenge_selector_projection_decompress_list keys select
    (fixedOtherKeys ctx blockCap).toList state
    (fun key member => outside key (Finset.mem_toList.mp member))

/-- Active database views of nonchallenge keys agree with the original raw
database restriction after the checked active restriction map. -/
theorem active_nonchallenge_view_eq
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys,
      parseStageQuery (ctx.keyBytes key) = none)
    (database : Database Key (Output (Counter := Counter))) :
    activeXView ctx blockCap keys unrecognized
      (restrictActive ctx blockCap database) = xView keys database :=
  active_x_view_restrict ctx blockCap keys unrecognized database

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentNonchallengeSelectorTransport
