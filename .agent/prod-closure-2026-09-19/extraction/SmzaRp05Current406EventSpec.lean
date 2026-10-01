import SmzaRp05ActualEventRecertification
import SmzaRp05CurrentMatrixPhysicalEventBound

/-!
# Checked current-406 event specification

Recertify the existing adaptive role context against the current-map event for
its selected role.  The DECS sample event uses the current 406-point source
label, the DECS matrix sibling uses its current universal-matrix event, and
the two PIOP events use current decoded-prefix labels.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05Current406EventSpec

open scoped Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05ActualEventRecertification
open SmzaRp05CurrentMatrixPhysicalEventBound
open SmzaRp05CurrentMatrixRoleEvent
open SmzaRp05CurrentSourceRoleEvent
open SmzaRp05CurrentPiopRoleEvents
open SmzaRp05CurrentUniversalMatrixLoss
open SmzaRp05CurrentRoleLabels
open SmzaRp05TracePrefixes
open SmzaRp04RoleBadCells
open SmzaRp04McaRoleCells
open SmzaRp04CompleteRawRoleCells
open SmzaRp05FilteredReadback
open SmzaRp05AdaptiveDynamicBad
open SmzaDynamicDatabaseSoundness
open SmzaRp05AdaptiveFilteredCollision
open SmzaChallengeStageTargets
open SmzaRp04RawMcaSampling
open SmzaRp04FourRoleLedger
open V8Smz9CoherentVectorMerkle
open SmzaRp05LeafNamespace

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

abbrev Output := VectorOutput Counter
abbrev RawInput := V8SmzaOracleParser.RawInput

local instance : DecidableEq RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

/-- Per-role instability loss for the exact current-406 event. The DECS
sample combines current small-support and LVCS loss; DECS matrix uses the
current universal matrix density rather than the legacy matrix loss. -/
def current406RoleLoss : Role → Rat
  | .decsMatrix => currentMatrixLoss
  | .piopMatrix => completeRoleLoss .piopMatrix
  | .piopOpening => completeRoleLoss .piopOpening
  | .decsSample => smallSupportLoss + roleLoss .decsSample

def current406Bound (role : Role) (cap : Nat) : ℝ :=
  (((6 * cap : Rat) / (2^512 : Rat) + current406RoleLoss role : Rat) : ℝ)

/-- Exact selected-role 406 event, retaining the context's own earlier-table
advice. This is extensionally the corresponding branch of the all-role
dispatcher `currentRoleEvent406For`. -/
def currentRoleEvent406Explicit
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter) :
    (role : Role) → AllEarlierTables model role → Nat → Nat →
      Finset (List Byte) → Database Key (Output (Counter := Counter)) → Prop
  | .decsMatrix, advice, outerFuel, innerFuel, authorized =>
      currentSourceMatrixRoleEvent406 model ns keyBytes counter routes
        advice outerFuel innerFuel authorized
  | .piopMatrix, advice, outerFuel, innerFuel, authorized =>
      currentPiopRoleEvent406 model ns keyBytes counter routes .matrix
        advice outerFuel innerFuel authorized
  | .piopOpening, advice, outerFuel, innerFuel, authorized =>
      currentPiopRoleEvent406 model ns keyBytes counter routes .opening
        advice outerFuel innerFuel authorized
  | .decsSample, advice, outerFuel, innerFuel, authorized =>
      currentSourceRoleEvent406 model ns keyBytes counter routes
        advice outerFuel innerFuel authorized

theorem current_role_event406_explicit_eq_dispatcher
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (advice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (role : Role)
    (authorized : Finset (List Byte)) :
    currentRoleEvent406Explicit model ns keyBytes counter routes role
      (advice role) outerFuel innerFuel authorized =
      currentRoleEvent406For model ns keyBytes counter routes advice
        outerFuel innerFuel authorized role := by
  cases role <;> rfl

def current406Base
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (authorized : Finset (List Byte)) :
    Database Key (Output (Counter := Counter)) → Prop :=
  currentRoleEvent406Explicit ctx.model ctx.leafNamespace ctx.keyBytes
    ctx.counter ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel authorized

private theorem current406Bound_nonnegative (role : Role) (cap : Nat) :
    0 ≤ current406Bound role cap := by
  cases role with
  | decsMatrix =>
      unfold current406Bound current406RoleLoss currentMatrixLoss
      positivity
  | piopMatrix =>
      unfold current406Bound current406RoleLoss
      exact_mod_cast add_nonneg (by positivity : (0 : Rat) ≤ (6 * cap : Rat) / 2^512)
        (complete_role_loss_nonnegative .piopMatrix)
  | piopOpening =>
      unfold current406Bound current406RoleLoss
      exact_mod_cast add_nonneg (by positivity : (0 : Rat) ≤ (6 * cap : Rat) / 2^512)
        (complete_role_loss_nonnegative .piopOpening)
  | decsSample =>
      unfold current406Bound current406RoleLoss
      exact_mod_cast add_nonneg (by positivity : (0 : Rat) ≤ (6 * cap : Rat) / 2^512)
        (source_only_role_loss_nonnegative .decsSample)

private theorem current_role_event406_instability
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (role : Role) (advice : AllEarlierTables model role)
    (outerFuel innerFuel cap : Nat) (authorized : Finset (List Byte)) :
    RealInstabilityBound
      (currentRoleEvent406Explicit model ns keyBytes counter routes role advice
        outerFuel innerFuel authorized)
      cap (current406Bound role cap) := by
  cases role with
  | decsMatrix =>
      simpa [currentRoleEvent406Explicit, current406Bound, current406RoleLoss,
        add_assoc] using
        (current_source_matrix_role_instability_406 model ns keyBytes counter routes
          advice outerFuel innerFuel cap authorized).toReal
  | piopMatrix =>
      simpa [currentRoleEvent406Explicit, current406Bound, current406RoleLoss,
        PiopRole.toRole] using
        (current_piop_role_instability406 model ns keyBytes counter routes .matrix
          advice outerFuel innerFuel authorized cap).toReal
  | piopOpening =>
      simpa [currentRoleEvent406Explicit, current406Bound, current406RoleLoss,
        PiopRole.toRole] using
        (current_piop_role_instability406 model ns keyBytes counter routes .opening
          advice outerFuel innerFuel authorized cap).toReal
  | decsSample =>
      simpa [currentRoleEvent406Explicit, current406Bound, current406RoleLoss,
        add_assoc] using
        (current_source_role_instability_406 model ns keyBytes counter routes
          advice outerFuel innerFuel cap authorized).toReal

private theorem current_role_event406_mark_mono
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (role : Role) (advice : AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    (statement : List Byte) (database : Database Key (Output (Counter := Counter)))
    (after : currentRoleEvent406Explicit model ns keyBytes counter routes role advice
      outerFuel innerFuel (insert statement authorized) database) :
    currentRoleEvent406Explicit model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized database := by
  cases role with
  | decsMatrix =>
      simpa [currentRoleEvent406Explicit, currentSourceMatrixRoleEvent406,
        currentMatrixRoleEvent406] using
        (role_event_mark_mono _ _ _ _ _ _ _ authorized statement database
          (by simpa [currentRoleEvent406Explicit, currentSourceMatrixRoleEvent406,
            currentMatrixRoleEvent406] using after))
  | piopMatrix =>
      simpa [currentRoleEvent406Explicit, currentPiopRoleEvent406, PiopRole.toRole] using
        (role_event_mark_mono _ _ _ _ _ _ _ authorized statement database
          (by simpa [currentRoleEvent406Explicit, currentPiopRoleEvent406,
            PiopRole.toRole] using after))
  | piopOpening =>
      simpa [currentRoleEvent406Explicit, currentPiopRoleEvent406, PiopRole.toRole] using
        (role_event_mark_mono _ _ _ _ _ _ _ authorized statement database
          (by simpa [currentRoleEvent406Explicit, currentPiopRoleEvent406,
            PiopRole.toRole] using after))
  | decsSample =>
      simpa [currentRoleEvent406Explicit, currentSourceRoleEvent406] using
        (role_event_mark_mono _ _ _ _ _ _ _ authorized statement database
          (by simpa [currentRoleEvent406Explicit, currentSourceRoleEvent406] using after))

private theorem current_role_event406_marked_write
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (role : Role) (advice : AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    (statement : List Byte) (marked : statement ∈ authorized) (key : Key)
    (parsed : globalLeafStatement ns (keyBytes key) = some statement)
    (left right : Database Key (Output (Counter := Counter)))
    (sameOutside : ∀ other, other ≠ key → left other = right other) :
    (currentRoleEvent406Explicit model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized left ↔
     currentRoleEvent406Explicit model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized right) := by
  have notSelected : ¬ InRoleDomain role (keyBytes key) :=
    SmzaRp05ChallengeRecordErasure.global_leaf_statement_not_in_role_domain
      ns (keyBytes key) statement parsed role
  cases role with
  | decsMatrix =>
      simpa [currentRoleEvent406Explicit, currentSourceMatrixRoleEvent406,
        currentMatrixRoleEvent406] using
        (role_event_iff_off_marked_key _ _ _ _ _
          (fun input => InRoleDomain .decsMatrix (keyBytes input)) _
          authorized statement marked key
          notSelected parsed left right sameOutside)
  | piopMatrix =>
      simpa [currentRoleEvent406Explicit, currentPiopRoleEvent406, PiopRole.toRole] using
        (role_event_iff_off_marked_key _ _ _ _ _
          (fun input => InRoleDomain .piopMatrix (keyBytes input)) _
          authorized statement marked key
          notSelected parsed left right sameOutside)
  | piopOpening =>
      simpa [currentRoleEvent406Explicit, currentPiopRoleEvent406, PiopRole.toRole] using
        (role_event_iff_off_marked_key _ _ _ _ _
          (fun input => InRoleDomain .piopOpening (keyBytes input)) _
          authorized statement marked key
          notSelected parsed left right sameOutside)
  | decsSample =>
      simpa [currentRoleEvent406Explicit, currentSourceRoleEvent406] using
        (role_event_iff_off_marked_key _ _ _ _ _
          (fun input => InRoleDomain .decsSample (keyBytes input)) _
          authorized statement marked key
          notSelected parsed left right sameOutside)

private theorem current_role_event406_empty_false
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (role : Role) (advice : AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte)) :
    ¬ currentRoleEvent406Explicit model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized
      (empty : Database Key (Output (Counter := Counter))) := by
  cases role with
  | decsMatrix =>
      unfold currentRoleEvent406Explicit currentSourceMatrixRoleEvent406
        currentMatrixRoleEvent406 roleEvent DynamicBad
      rintro ⟨key, output, recorded, _⟩
      simp at recorded
  | piopMatrix =>
      unfold currentRoleEvent406Explicit currentPiopRoleEvent406 roleEvent DynamicBad
      rintro ⟨key, output, recorded, _⟩
      simp at recorded
  | piopOpening =>
      unfold currentRoleEvent406Explicit currentPiopRoleEvent406 roleEvent DynamicBad
      rintro ⟨key, output, recorded, _⟩
      simp at recorded
  | decsSample =>
      unfold currentRoleEvent406Explicit currentSourceRoleEvent406 roleEvent DynamicBad
      rintro ⟨key, output, recorded, _⟩
      simp at recorded

/-- Certified dispatch for the context's selected current-406 role. -/
def current406EventSpec
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) : EventSpec ctx cap where
  base := current406Base ctx
  bound := current406Bound ctx.role cap
  bound_nonnegative := current406Bound_nonnegative ctx.role cap
  instability := by
    intro authorized
    exact current_role_event406_instability ctx.model ctx.leafNamespace
      ctx.keyBytes ctx.counter ctx.routes ctx.role ctx.advice
      ctx.outerFuel ctx.innerFuel cap authorized
  mark_mono := by
    intro authorized statement database after
    have after' : currentRoleEvent406Explicit ctx.model ctx.leafNamespace
        ctx.keyBytes ctx.counter ctx.routes ctx.role ctx.advice ctx.outerFuel
        ctx.innerFuel (insert statement authorized) database := by
      have eqInsert :
          @Insert.insert (List Byte) (Finset (List Byte))
            (@Finset.instInsert (List Byte) (fun a b => instDecidableEqList a b))
            statement authorized = insert statement authorized := by
        ext candidate
        simp only [Finset.mem_insert]
      change currentRoleEvent406Explicit ctx.model ctx.leafNamespace
          ctx.keyBytes ctx.counter ctx.routes ctx.role ctx.advice ctx.outerFuel
          ctx.innerFuel
          (@Insert.insert (List Byte) (Finset (List Byte))
            (@Finset.instInsert (List Byte) (fun a b => instDecidableEqList a b))
            statement authorized) database at after
      rw [eqInsert] at after
      exact after
    exact current_role_event406_mark_mono ctx.model ctx.leafNamespace
      ctx.keyBytes ctx.counter ctx.routes ctx.role ctx.advice
      ctx.outerFuel ctx.innerFuel authorized statement database after'
  marked_write := by
    intro authorized statement marked key parsed left right sameOutside
    exact current_role_event406_marked_write ctx.model ctx.leafNamespace
      ctx.keyBytes ctx.counter ctx.routes ctx.role ctx.advice
      ctx.outerFuel ctx.innerFuel authorized statement marked key parsed
      left right sameOutside
  empty_false := by
    intro authorized
    exact current_role_event406_empty_false ctx.model ctx.leafNamespace
      ctx.keyBytes ctx.counter ctx.routes ctx.role ctx.advice
      ctx.outerFuel ctx.innerFuel authorized

end
end HegemonCrypto.SmallWood.SmzaRp05Current406EventSpec
