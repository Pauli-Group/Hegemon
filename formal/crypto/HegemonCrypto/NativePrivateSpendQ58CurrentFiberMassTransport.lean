import HegemonCrypto.NativePrivateSpendQ58CurrentActiveBranchClaims
import HegemonCrypto.NativePrivateSpendQ58CurrentTracePiopMass
import SmzaConditionedRoleOracleBound

/-! Finite current-role instantiation of the retained phase/table machinery.
`routingTag` only presents an arbitrary Boolean finite-key partition to the
retained generic routing/isometry/contraction proofs. It is NEVER an oracle
input, parser substitute or native challenge. Every actual key, oracle table,
label, raw vector decoder and counted bad event below uses literal current
COMPFF01 bytes. The routing predicate is proved equal to the current parser
predicate, and the same original query steps are preserved exactly.
The bounds start at actual empty CMS initialization. They do not set a later
cut's incoming event projection to zero. Acceptance inclusion and claim
recertification must be derived separately from the same branch.
SOURCE ONLY; no end-to-end security or gate qualification. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFiberMassTransport
open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsLifting HegemonCrypto.CmsFinitePhaseSystem
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes vectorPhaseSystem)
open V8Smz9RawCounterCompiler (digestCallCap)
open SmzaChallengeStageTargets (Role)
open SmzaDynamicDatabaseSoundness SmzaDynamicOracleExecution
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (RoleActive FixedTable)
end C
namespace G
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end G
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (RawInput RawDigest Trace)
end F
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel current_tracked_label_changes)
end P
namespace T
export NativePrivateSpendQ58CurrentTracePiopMass
  (matrixBad openingBad matrixLoss openingLoss current_trace_matrix_per_label
   current_trace_opening_per_label)
end T
namespace R
export SmzaRoleDomainConditioning
  (ActiveKey FixedOtherKey RoleActive ActiveRouteMemory roleTableSplit
   activeConditionedSteps activeRegisterEmbed active_initial_subnormalized
   active_conditioned_steps_length uniformTableRegisterEventMass
   uniform_full_table_mass_eq_fixed_average active_oracle_family_run_eq_full_embed)
end R
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

variable {Key Counter Work : Type}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
variable [Fintype Work] [DecidableEq Work]

private def otherRole : Role → Role
  | .decsMatrix => .decsSample
  | _ => .decsMatrix

private theorem other_role_different (selected : Role) : otherRole selected ≠ selected := by
  cases selected <;> decide

private theorem other_role_not_opening (selected : Role) : otherRole selected ≠ .piopOpening := by
  cases selected <;> decide

private def oneCap : Role → Nat := fun _ => 1

/-- A proof-internal route tag, not an input to the current oracle. -/
def routingTag (selected : Role) (keyBytes : Key → F.RawInput) (key : Key) : F.RawInput :=
  if C.RoleActive selected G.currentRoleCaps keyBytes key then [] else
    SmzaRp05ExecutableChallengeStage.counterInput
      (SmzaChallengeStageTargets.roleDomain (otherRole selected)) (fun _ => 0) 0

omit [Fintype Key] [DecidableEq Key] in
/-- Exact finite partition identity. Historical framing is only an internal
encoding of this already-defined predicate; all native bytes remain current. -/
theorem routing_predicate_is_literal_current
    (selected : Role) (keyBytes : Key → F.RawInput) (key : Key) :
    R.RoleActive selected oneCap (routingTag selected keyBytes) key ↔
      C.RoleActive selected G.currentRoleCaps keyBytes key := by
  have tagReceipt := SmzaRp05CertifiedReplaySchedule.ordinary_counter_roundtrip
    (otherRole selected) (other_role_not_opening selected) (fun _ => 0) ⟨0, by norm_num⟩
  have emptyReceipt : SmzaChallengeStageTargets.parseStageQuery [] = none := rfl
  by_cases active : C.RoleActive selected G.currentRoleCaps keyBytes key
  · simp [R.RoleActive, routingTag, active, emptyReceipt]
  · simp [R.RoleActive, routingTag, active, tagReceipt, oneCap, other_role_different selected]

abbrev Active (selected : Role) (keyBytes : Key → F.RawInput) :=
  R.ActiveKey selected oneCap (routingTag selected keyBytes)
abbrev Fixed (selected : Role) (keyBytes : Key → F.RawInput) :=
  R.FixedOtherKey selected oneCap (routingTag selected keyBytes)
abbrev FixedVectors (selected : Role) (keyBytes : Key → F.RawInput) :=
  Fixed selected keyBytes → VectorOutput Counter

def actualActiveEquiv (selected : Role) (keyBytes : Key → F.RawInput) :
    Active selected keyBytes ≃ { key : Key // C.RoleActive selected G.currentRoleCaps keyBytes key } where
  toFun key := ⟨key.val, (routing_predicate_is_literal_current selected keyBytes key.val).mp key.property⟩
  invFun key := ⟨key.val, (routing_predicate_is_literal_current selected keyBytes key.val).mpr key.property⟩
  left_inv key := by apply Subtype.ext; rfl
  right_inv key := by apply Subtype.ext; rfl

def actualFixedEquiv (selected : Role) (keyBytes : Key → F.RawInput) :
    Fixed selected keyBytes ≃ { key : Key // ¬C.RoleActive selected G.currentRoleCaps keyBytes key } where
  toFun key := ⟨key.val, fun active => key.property
    ((routing_predicate_is_literal_current selected keyBytes key.val).mpr active)⟩
  invFun key := ⟨key.val, fun active => key.property
    ((routing_predicate_is_literal_current selected keyBytes key.val).mp active)⟩
  left_inv key := by apply Subtype.ext; rfl
  right_inv key := by apply Subtype.ext; rfl

/-- The actual current fixed lookup receives the identical vector at the
identical full key. No primitive or profile equivalence is asserted. -/
def actualFixed (selected : Role) (keyBytes : Key → F.RawInput)
    (fixed : FixedVectors (Counter := Counter) selected keyBytes) :
    C.FixedTable (Counter := Counter) selected G.currentRoleCaps keyBytes :=
  fun key => fixed ((actualFixedEquiv selected keyBytes).symm key)

def activeBytes (selected : Role) (keyBytes : Key → F.RawInput) :
    Active selected keyBytes → F.RawInput := fun key => keyBytes key.val

abbrev OriginalSteps := List (DatabaseIndependentContraction
  (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
  (Workspace := Work))
abbrev OriginalRegisters := RegisterBasis
  (Input := Key) (Phase := VectorOutput Counter) (Workspace := Work) → ℂ

def fiberSteps (selected : Role) (keyBytes : Key → F.RawInput)
    (dummy : Active selected keyBytes) (fixed : FixedVectors (Counter := Counter) selected keyBytes)
    (steps : OriginalSteps (Key := Key) (Counter := Counter) (Work := Work)) :=
  R.activeConditionedSteps vectorPhaseSystem selected oneCap (routingTag selected keyBytes)
    dummy fixed steps

def fiberRegisters (selected : Role) (keyBytes : Key → F.RawInput)
    (dummy : Active selected keyBytes)
    (registers : OriginalRegisters (Key := Key) (Counter := Counter) (Work := Work)) :=
  R.activeRegisterEmbed vectorPhaseSystem selected oneCap (routingTag selected keyBytes) dummy registers

theorem current_fiber_steps_preserve_actual_query_count
    (selected : Role) (keyBytes : Key → F.RawInput) (dummy : Active selected keyBytes)
    (fixed : FixedVectors (Counter := Counter) selected keyBytes)
    (steps : OriginalSteps (Key := Key) (Counter := Counter) (Work := Work)) :
    (fiberSteps selected keyBytes dummy fixed steps).length = steps.length :=
  R.active_conditioned_steps_length vectorPhaseSystem selected oneCap
    (routingTag selected keyBytes) dummy fixed steps

theorem current_fiber_empty_initialization_is_subnormalized
    (selected : Role) (keyBytes : Key → F.RawInput) (dummy : Active selected keyBytes)
    (registers : OriginalRegisters (Key := Key) (Counter := Counter) (Work := Work))
    (normalized : Subnormalized (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :
    Subnormalized (partialRandomOracleState (Output := VectorOutput Counter) ∅
      (fiberRegisters selected keyBytes dummy registers)) :=
  R.active_initial_subnormalized vectorPhaseSystem selected oneCap
    (routingTag selected keyBytes) dummy registers normalized

/-- Literal current full oracle-family execution, factored through the exact
same current-selected-role partition and the SAME original private steps. -/
theorem current_original_run_is_same_fiber_run
    (selected : Role) (keyBytes : Key → F.RawInput) (dummy : Active selected keyBytes)
    (fixed : FixedVectors (Counter := Counter) selected keyBytes)
    (steps : OriginalSteps (Key := Key) (Counter := Counter) (Work := Work))
    (registers : OriginalRegisters (Key := Key) (Counter := Counter) (Work := Work))
    (active : Active selected keyBytes → VectorOutput Counter) :
    oracleFamilyRun vectorPhaseSystem (fiberSteps selected keyBytes dummy fixed steps)
      (fun _ => fiberRegisters selected keyBytes dummy registers) active =
    R.activeRegisterEmbed vectorPhaseSystem selected oneCap (routingTag selected keyBytes) dummy
      (oracleFamilyRun vectorPhaseSystem steps (fun _ => registers)
        ((R.roleTableSplit selected oneCap (routingTag selected keyBytes)).symm (active, fixed))) := by
  exact R.active_oracle_family_run_eq_full_embed vectorPhaseSystem selected oneCap
    (routingTag selected keyBytes) dummy fixed steps (fun _ => registers) active

omit [DecidableEq Work] in
/-- Exact weighted finite-table disintegration of an arbitrary event on the
unchanged original current-key run. No conditional independence is assumed. -/
theorem current_original_event_mass_is_same_fiber_average
    (selected : Role) (keyBytes : Key → F.RawInput)
    (steps : OriginalSteps (Key := Key) (Counter := Counter) (Work := Work))
    (registers : OriginalRegisters (Key := Key) (Counter := Counter) (Work := Work))
    (event : (Key → VectorOutput Counter) → RegisterBasis
      (Input := Key) (Phase := VectorOutput Counter) (Workspace := Work) → Prop) :
    R.uniformTableRegisterEventMass
      (oracleFamilyRun vectorPhaseSystem steps (fun _ => registers)) event =
      (∑ fixed : FixedVectors (Counter := Counter) selected keyBytes,
        R.uniformTableRegisterEventMass
          (fun active : Active selected keyBytes → VectorOutput Counter =>
            oracleFamilyRun vectorPhaseSystem steps (fun _ => registers)
              ((R.roleTableSplit selected oneCap (routingTag selected keyBytes)).symm (active, fixed)))
          (fun active register => event
            ((R.roleTableSplit selected oneCap (routingTag selected keyBytes)).symm (active, fixed)) register)) /
        Fintype.card (FixedVectors (Counter := Counter) selected keyBytes) := by
  exact R.uniform_full_table_mass_eq_fixed_average selected oneCap
    (routingTag selected keyBytes) _ event

def matrixEvent (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (fixed : FixedVectors (Counter := Counter) .piopMatrix keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (select : Fin (digestCallCap (5*1344594)) ↪ Counter)
    (trace : F.Trace) (key : Active .piopMatrix keyBytes) : VectorOutput Counter → Prop :=
  T.matrixBad relation keyBytes (actualFixed .piopMatrix keyBytes fixed) decode select trace key.val

def openingEvent (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (fixed : FixedVectors (Counter := Counter) .piopOpening keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (selectMatrix : Fin (digestCallCap (5*1344594)) ↪ Counter)
    (selectOpening : Fin (digestCallCap 6) ↪ Counter)
    (trace : F.Trace) (key : Active .piopOpening keyBytes) : VectorOutput Counter → Prop :=
  T.openingBad relation keyBytes (actualFixed .piopOpening keyBytes fixed) decode
    selectMatrix selectOpening trace key.val

private theorem matrixLoss_nonnegative : 0 ≤ T.matrixLoss := by
  delta T.matrixLoss
  exact pow_nonneg (div_nonneg zero_le_one (Nat.cast_nonneg _)) _

private theorem openingLoss_nonnegative : 0 ≤ T.openingLoss := by
  delta T.openingLoss
  exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)

/-- The current parser/frame insertion bound applies to the active current
literal bytes. Fixed advice enters only the candidate computation. -/
theorem current_matrix_fiber_instability
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (fixed : FixedVectors (Counter := Counter) .piopMatrix keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (select : Fin (digestCallCap (5*1344594)) ↪ Counter) (cap : Nat) :
    InstabilityBound (DynamicBad (P.currentLabel (activeBytes .piopMatrix keyBytes) counter 26)
      (matrixEvent relation keyBytes fixed decode select)) cap
      (((3*cap : Rat)/(2^512 : Rat)) + T.matrixLoss) := by
  apply dynamic_bad_instability _ _ cap T.matrixLoss ((3*cap : Rat)/(2^512 : Rat))
    matrixLoss_nonnegative (by positivity)
  · intro trace key
    delta matrixEvent
    with_reducible
      exact T.current_trace_matrix_per_label relation keyBytes
        (actualFixed .piopMatrix keyBytes fixed) decode select trace key.val
  · exact P.current_tracked_label_changes (activeBytes .piopMatrix keyBytes) counter 26 cap

theorem current_opening_fiber_instability
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (fixed : FixedVectors (Counter := Counter) .piopOpening keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (selectMatrix : Fin (digestCallCap (5*1344594)) ↪ Counter)
    (selectOpening : Fin (digestCallCap 6) ↪ Counter) (cap : Nat) :
    InstabilityBound (DynamicBad (P.currentLabel (activeBytes .piopOpening keyBytes) counter 27)
      (openingEvent relation keyBytes fixed decode selectMatrix selectOpening)) cap
      (((3*cap : Rat)/(2^512 : Rat)) + T.openingLoss) := by
  apply dynamic_bad_instability _ _ cap T.openingLoss ((3*cap : Rat)/(2^512 : Rat))
    openingLoss_nonnegative (by positivity)
  · intro trace key
    delta openingEvent
    with_reducible
      exact T.current_trace_opening_per_label relation keyBytes
        (actualFixed .piopOpening keyBytes fixed) decode selectMatrix selectOpening trace key.val
  · exact P.current_tracked_label_changes (activeBytes .piopOpening keyBytes) counter 27 cap

/-- Actual empty active CMS initialization, current matrix event, exact
original Q contractions including fixed phases. No later prefix is zeroed. -/
theorem current_initialized_matrix_fiber_event_mass
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (dummy : Active .piopMatrix keyBytes)
    (fixed : FixedVectors (Counter := Counter) .piopMatrix keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (select : Fin (digestCallCap (5*1344594)) ↪ Counter)
    (steps : OriginalSteps (Key := Key) (Counter := Counter) (Work := Work))
    (registers : OriginalRegisters (Key := Key) (Counter := Counter) (Work := Work))
    (normalized : Subnormalized (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :
    normSquared (project
      (DynamicBad (P.currentLabel (activeBytes .piopMatrix keyBytes) counter 26)
        (matrixEvent relation keyBytes fixed decode select)) steps.length
      (rawRun vectorPhaseSystem steps.length
        ((fiberSteps .piopMatrix keyBytes dummy fixed steps).map
          DatabaseIndependentContraction.toDatabaseBlindContraction)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅
          (fiberRegisters .piopMatrix keyBytes dummy registers)))) ≤
      databaseLoss steps.length
        ((((3*steps.length : Rat)/(2^512 : Rat)) + T.matrixLoss : Rat) : ℝ) := by
  let label := P.currentLabel (activeBytes .piopMatrix keyBytes) counter 26
  let bad := matrixEvent relation keyBytes fixed decode select
  let blind := (fiberSteps .piopMatrix keyBytes dummy fixed steps).map
    DatabaseIndependentContraction.toDatabaseBlindContraction
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅
    (fiberRegisters .piopMatrix keyBytes dummy registers)
  have length : blind.length = steps.length := by
    simp only [blind, List.length_map, current_fiber_steps_preserve_actual_query_count]
  have bound := implemented_raw_database_game_le_database_loss vectorPhaseSystem
    (DynamicBad label bad) steps.length blind initial
    (current_matrix_fiber_instability relation keyBytes counter fixed decode select steps.length).toReal
    (by omega) (partial_random_oracle_empty_bounded _)
    (current_fiber_empty_initialization_is_subnormalized .piopMatrix keyBytes dummy registers normalized)
    (initialized_dynamic_bad_zero label bad steps.length _)
  simpa only [label, bad, blind, initial, length] using bound

/-- The opening event retains the actual current domain and fixed current
matrix/response interpretation, including sampler rejection and exhaustion. -/
theorem current_initialized_opening_fiber_event_mass
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (keyBytes : Key → F.RawInput) (counter : Counter)
    (dummy : Active .piopOpening keyBytes)
    (fixed : FixedVectors (Counter := Counter) .piopOpening keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (selectMatrix : Fin (digestCallCap (5*1344594)) ↪ Counter)
    (selectOpening : Fin (digestCallCap 6) ↪ Counter)
    (steps : OriginalSteps (Key := Key) (Counter := Counter) (Work := Work))
    (registers : OriginalRegisters (Key := Key) (Counter := Counter) (Work := Work))
    (normalized : Subnormalized (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :
    normSquared (project
      (DynamicBad (P.currentLabel (activeBytes .piopOpening keyBytes) counter 27)
        (openingEvent relation keyBytes fixed decode selectMatrix selectOpening)) steps.length
      (rawRun vectorPhaseSystem steps.length
        ((fiberSteps .piopOpening keyBytes dummy fixed steps).map
          DatabaseIndependentContraction.toDatabaseBlindContraction)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅
          (fiberRegisters .piopOpening keyBytes dummy registers)))) ≤
      databaseLoss steps.length
        ((((3*steps.length : Rat)/(2^512 : Rat)) + T.openingLoss : Rat) : ℝ) := by
  let label := P.currentLabel (activeBytes .piopOpening keyBytes) counter 27
  let bad := openingEvent relation keyBytes fixed decode selectMatrix selectOpening
  let blind := (fiberSteps .piopOpening keyBytes dummy fixed steps).map
    DatabaseIndependentContraction.toDatabaseBlindContraction
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅
    (fiberRegisters .piopOpening keyBytes dummy registers)
  have length : blind.length = steps.length := by
    simp only [blind, List.length_map, current_fiber_steps_preserve_actual_query_count]
  have bound := implemented_raw_database_game_le_database_loss vectorPhaseSystem
    (DynamicBad label bad) steps.length blind initial
    (current_opening_fiber_instability relation keyBytes counter fixed decode
      selectMatrix selectOpening steps.length).toReal
    (by omega) (partial_random_oracle_empty_bounded _)
    (current_fiber_empty_initialization_is_subnormalized .piopOpening keyBytes dummy registers normalized)
    (initialized_dynamic_bad_zero label bad steps.length _)
  simpa only [label, bad, blind, initial, length] using bound

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFiberMassTransport

