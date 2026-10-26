import HegemonCrypto.NativePrivateSpendQ58CurrentRouteTransport
import HegemonCrypto.NativePrivateSpendQ58CurrentMatrixRawOrder
import HegemonCrypto.NativePrivateSpendQ58CurrentDecsDynamicMass
import HegemonCrypto.NativePrivateSpendQ58CurrentOpeningVectorInsertion
import HegemonCrypto.NativePrivateSpendQ58CurrentPointGeometry
import SmzaRp05ActualEventPhysicalMass

/-! Four literal current events on the unchanged physical prefix and adaptive
answer tree. The old Context below is retained operation metadata; routingTag
encodes only the proved current partition. Oracle inputs, source labels and
samplers use actual current bytes. EventSpec is constructed from current
counting and insertion theorems, never supplied by a caller. Every fixed-table
and answer-branch Born weight is retained, including zero incompatible fibers.
This event-mass theorem is not by itself accepted-invalid soundness: the
separate literal current classifier must insert the accepted branch into this
specific four-event union. SOURCE ONLY; kernel validation pending.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRoleEventPhysicalMass
open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaDynamicDatabaseSoundness
open SmzaChallengeStageTargets (Role)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun)
open SmzaRp05AdaptivePhysicalReadBound (ReadsAtMost ReadsWithinKeys physicalBranchesFintype)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution (FixedTable activeContext fixedFiberToActive otherRoleTransform activeMemoryEquiv)
open SmzaRp05ConditionedExecution (PhysicalProgramSkeleton CertifiedFor)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9RawCounterCompiler (digestCallCap)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter RawDigest keyBytes zero encode decode)
end G
namespace R
export NativePrivateSpendQ58CurrentFiberMassTransport
  (Active FixedVectors activeBytes matrixEvent openingEvent current_matrix_fiber_instability current_opening_fiber_instability)
end R
namespace RT
export NativePrivateSpendQ58CurrentRouteTransport (cap routeContext)
end RT
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel current_tracked_label_changes)
end P
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (Trace)
end F
namespace M
export NativePrivateSpendQ58CurrentMatrixRawOrder (vectorBad current_vector_event_density)
export NativePrivateSpendQ58CurrentMatrixDynamicMass (matrixLoss)
end M
namespace T
export NativePrivateSpendQ58CurrentTracePiopMass (matrixLoss openingLoss)
end T
namespace D
export NativePrivateSpendQ58CurrentDecsDynamicMass (fiberBad current_decs_sample_fiber_instability)
export NativePrivateSpendQ58CurrentDecsSampleDensity (Position loss)
end D
namespace MR
export NativePrivateSpendQ58CurrentClaimMatrixReadback (matrixSelect)
end MR
namespace OV
export NativePrivateSpendQ58CurrentOpeningVectorInsertion (openingSelect)
end OV
namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport (currentPoint)
end L
namespace C
export NativePrivateSpendQ58CurrentPublicOpening (Relation)
end C
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

variable {Result BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
variable (program : Program Result)

def matrixSelect : Fin (digestCallCap 700) ↪ G.Counter where
  toFun index := ⟨index.val, index.isLt.trans_le (by decide)⟩
  inj' := by intro left right equal; exact Fin.ext (congrArg (fun counter : G.Counter => counter.val) equal)

def stage : Role → Nat
  | .decsMatrix => 25
  | .decsSample => 28
  | .piopMatrix => 26
  | .piopOpening => 27

def localLoss : Role → Rat
  | .decsMatrix => M.matrixLoss
  | .decsSample => D.loss
  | .piopMatrix => T.matrixLoss
  | .piopOpening => T.openingLoss

def roleBad (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32)) :
    (role : Role) → R.FixedVectors (Counter := G.Counter) role (G.keyBytes program) →
      F.Trace → R.Active role (G.keyBytes program) → VectorOutput G.Counter → Prop
  | .decsMatrix, _, trace, key, vector =>
      M.vectorBad (R.activeBytes .decsMatrix (G.keyBytes program)) matrixSelect trace key vector
  | .decsSample, fixed, trace, key, vector =>
      D.fiberBad program fixed fallback nonce trace key vector
  | .piopMatrix, fixed, trace, key, vector =>
      R.matrixEvent relation (G.keyBytes program) fixed G.decode MR.matrixSelect trace key vector
  | .piopOpening, fixed, trace, key, vector =>
      R.openingEvent relation (G.keyBytes program) fixed G.decode MR.matrixSelect OV.openingSelect trace key vector

def roleEvent (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (role : Role) (fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program)) :=
  DynamicBad (P.currentLabel (R.activeBytes role (G.keyBytes program)) G.zero (stage role))
    (roleBad program relation fallback nonce role fixed)

private theorem decs_matrix_role_instability
    (injective : Function.Injective L.currentPoint) (budget : Nat) :
    InstabilityBound
      (DynamicBad (P.currentLabel (R.activeBytes .decsMatrix (G.keyBytes program)) G.zero 25)
        (M.vectorBad (R.activeBytes .decsMatrix (G.keyBytes program)) matrixSelect)) budget
      ((3*budget : Rat)/(2^512 : Rat)+M.matrixLoss) := by
  apply dynamic_bad_instability _ _ budget M.matrixLoss ((3*budget : Rat)/(2^512 : Rat))
    (by
      unfold M.matrixLoss
      exact div_nonneg (by norm_num) (Nat.cast_nonneg _))
    (by positivity)
  · intro trace key
    exact M.current_vector_event_density _ matrixSelect injective trace key
  · exact P.current_tracked_label_changes (R.activeBytes .decsMatrix (G.keyBytes program)) G.zero 25 budget

private theorem decs_sample_role_instability
    (fixed : R.FixedVectors (Counter := G.Counter) .decsSample (G.keyBytes program))
    (fallback : G.RawDigest) (nonce : Fin (2^32)) (budget : Nat)
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) :
    InstabilityBound
      (DynamicBad (P.currentLabel (R.activeBytes .decsSample (G.keyBytes program)) G.zero 28)
        (D.fiberBad program fixed fallback nonce)) budget
      ((3*budget : Rat)/(2^512 : Rat)+D.loss) := by
  exact D.current_decs_sample_fiber_instability program fixed fallback nonce budget sample point lookup

private theorem piop_matrix_role_instability
    (relation : C.Relation)
    (fixed : R.FixedVectors (Counter := G.Counter) .piopMatrix (G.keyBytes program))
    (budget : Nat) :
    InstabilityBound
      (DynamicBad (P.currentLabel (R.activeBytes .piopMatrix (G.keyBytes program)) G.zero 26)
        (R.matrixEvent relation (G.keyBytes program) fixed G.decode MR.matrixSelect)) budget
      ((3*budget : Rat)/(2^512 : Rat)+T.matrixLoss) := by
  exact R.current_matrix_fiber_instability relation (G.keyBytes program) G.zero fixed G.decode MR.matrixSelect budget

private theorem piop_opening_role_instability
    (relation : C.Relation)
    (fixed : R.FixedVectors (Counter := G.Counter) .piopOpening (G.keyBytes program))
    (budget : Nat) :
    InstabilityBound
      (DynamicBad (P.currentLabel (R.activeBytes .piopOpening (G.keyBytes program)) G.zero 27)
        (R.openingEvent relation (G.keyBytes program) fixed G.decode MR.matrixSelect OV.openingSelect)) budget
      ((3*budget : Rat)/(2^512 : Rat)+T.openingLoss) := by
  exact R.current_opening_fiber_instability relation (G.keyBytes program) G.zero fixed G.decode
    MR.matrixSelect OV.openingSelect budget

private theorem decs_matrix_canonical_role_instability
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (fixed : R.FixedVectors (Counter := G.Counter) .decsMatrix (G.keyBytes program))
    (injective : Function.Injective L.currentPoint) (budget : Nat) :
    InstabilityBound (roleEvent program relation fallback nonce .decsMatrix fixed) budget
      ((3*budget : Rat)/(2^512 : Rat)+localLoss .decsMatrix) := by
  exact decs_matrix_role_instability program injective budget

private theorem decs_sample_canonical_role_instability
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (fixed : R.FixedVectors (Counter := G.Counter) .decsSample (G.keyBytes program))
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) (budget : Nat) :
    InstabilityBound (roleEvent program relation fallback nonce .decsSample fixed) budget
      ((3*budget : Rat)/(2^512 : Rat)+localLoss .decsSample) := by
  exact decs_sample_role_instability program fixed fallback nonce budget sample point lookup

private theorem piop_matrix_role_bad_eq
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (fixed : R.FixedVectors (Counter := G.Counter) .piopMatrix (G.keyBytes program)) :
    roleBad program relation fallback nonce .piopMatrix fixed =
      R.matrixEvent relation (G.keyBytes program) fixed G.decode MR.matrixSelect := by
  funext trace key vector
  rfl

private theorem piop_matrix_role_event_eq
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (fixed : R.FixedVectors (Counter := G.Counter) .piopMatrix (G.keyBytes program)) :
    roleEvent program relation fallback nonce .piopMatrix fixed =
      DynamicBad (P.currentLabel (R.activeBytes .piopMatrix (G.keyBytes program)) G.zero 26)
        (R.matrixEvent relation (G.keyBytes program) fixed G.decode MR.matrixSelect) := by
  dsimp only [roleEvent, stage]
  exact congrArg
    (DynamicBad (P.currentLabel (R.activeBytes .piopMatrix (G.keyBytes program)) G.zero 26))
    (piop_matrix_role_bad_eq program relation fallback nonce fixed)

private theorem piop_matrix_local_loss_eq : localLoss .piopMatrix = T.matrixLoss := by
  rfl

private theorem property_loss_transport
    {EventProperty : Type*} (boundPredicate : EventProperty → Rat → Prop)
    {leftEvent rightEvent : EventProperty} {leftLoss rightLoss : Rat}
    (eventEq : leftEvent = rightEvent) (lossEq : leftLoss = rightLoss)
    (known : boundPredicate rightEvent rightLoss) :
    boundPredicate leftEvent leftLoss := by
  exact Eq.mpr
    ((congrArg (fun event => boundPredicate event leftLoss) eventEq).trans
      (congrArg (fun loss => boundPredicate rightEvent loss) lossEq)) known

private theorem piop_matrix_canonical_role_instability
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (fixed : R.FixedVectors (Counter := G.Counter) .piopMatrix (G.keyBytes program))
    (budget : Nat) :
    InstabilityBound (roleEvent program relation fallback nonce .piopMatrix fixed) budget
      ((3*budget : Rat)/(2^512 : Rat)+localLoss .piopMatrix) := by
  exact property_loss_transport
    (fun event loss => InstabilityBound event budget ((3*budget : Rat)/(2^512 : Rat)+loss))
    (piop_matrix_role_event_eq program relation fallback nonce fixed)
    piop_matrix_local_loss_eq
    (piop_matrix_role_instability program relation fixed budget)

private theorem piop_opening_role_bad_eq
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (fixed : R.FixedVectors (Counter := G.Counter) .piopOpening (G.keyBytes program)) :
    roleBad program relation fallback nonce .piopOpening fixed =
      R.openingEvent relation (G.keyBytes program) fixed G.decode MR.matrixSelect OV.openingSelect := by
  funext trace key vector
  rfl

private theorem piop_opening_role_event_eq
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (fixed : R.FixedVectors (Counter := G.Counter) .piopOpening (G.keyBytes program)) :
    roleEvent program relation fallback nonce .piopOpening fixed =
      DynamicBad (P.currentLabel (R.activeBytes .piopOpening (G.keyBytes program)) G.zero 27)
        (R.openingEvent relation (G.keyBytes program) fixed G.decode MR.matrixSelect OV.openingSelect) := by
  dsimp only [roleEvent, stage]
  exact congrArg
    (DynamicBad (P.currentLabel (R.activeBytes .piopOpening (G.keyBytes program)) G.zero 27))
    (piop_opening_role_bad_eq program relation fallback nonce fixed)

private theorem piop_opening_local_loss_eq : localLoss .piopOpening = T.openingLoss := by
  rfl

private theorem piop_opening_canonical_role_instability
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (fixed : R.FixedVectors (Counter := G.Counter) .piopOpening (G.keyBytes program))
    (budget : Nat) :
    InstabilityBound (roleEvent program relation fallback nonce .piopOpening fixed) budget
      ((3*budget : Rat)/(2^512 : Rat)+localLoss .piopOpening) := by
  exact property_loss_transport
    (fun event loss => InstabilityBound event budget ((3*budget : Rat)/(2^512 : Rat)+loss))
    (piop_opening_role_event_eq program relation fallback nonce fixed)
    piop_opening_local_loss_eq
    (piop_opening_role_instability program relation fixed budget)

private theorem role_eliminate {P : Role → Prop}
    (matrixCase : P .decsMatrix) (sampleCase : P .decsSample)
    (piopMatrixCase : P .piopMatrix) (piopOpeningCase : P .piopOpening)
    (role : Role) : P role := by
  cases role with
  | decsMatrix => exact matrixCase
  | decsSample => exact sampleCase
  | piopMatrix => exact piopMatrixCase
  | piopOpening => exact piopOpeningCase

theorem role_event_instability (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (role : Role) (fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (injective : Function.Injective L.currentPoint)
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) (budget : Nat) :
    InstabilityBound (roleEvent program relation fallback nonce role fixed) budget
      ((3*budget : Rat)/(2^512 : Rat)+localLoss role) := by
  exact role_eliminate
    (P := fun selected : Role =>
      ∀ fixed : R.FixedVectors (Counter := G.Counter) selected (G.keyBytes program),
        InstabilityBound (roleEvent program relation fallback nonce selected fixed) budget
          ((3*budget : Rat)/(2^512 : Rat)+localLoss selected))
    (fun selectedFixed =>
      decs_matrix_canonical_role_instability program relation fallback nonce selectedFixed injective budget)
    (fun selectedFixed =>
      decs_sample_canonical_role_instability program relation fallback nonce selectedFixed sample point lookup budget)
    (fun selectedFixed =>
      piop_matrix_canonical_role_instability program relation fallback nonce selectedFixed budget)
    (fun selectedFixed =>
      piop_opening_canonical_role_instability program relation fallback nonce selectedFixed budget)
    role fixed

private theorem route_is_not_leaf (ns : SmzaRp05LeafNamespace.Namespace)
    (role : Role) (key : G.Key program) :
    SmzaRp05FilteredReadback.globalLeafStatement ns
      (NativePrivateSpendQ58CurrentFiberMassTransport.routingTag role (G.keyBytes program) key) = none := by
  unfold NativePrivateSpendQ58CurrentFiberMassTransport.routingTag
  split
  · rfl
  · cases role <;> rfl

def contexts
    (metadata : Context (Key := G.Key program) (Counter := G.Counter) (BaseWork := BaseWork))
    (role : Role) := RT.routeContext metadata role (G.keyBytes program)

/-- Concrete current spec. Authorization is irrelevant in independent proof
mode. The internal partition tags cannot be canonical leaf write addresses. -/
def spec
    (metadata : Context (Key := G.Key program) (Counter := G.Counter) (BaseWork := BaseWork))
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (role : Role) (fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (injective : Function.Injective L.currentPoint)
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) (budget : Nat) :
    SmzaRp05ActualEventRecertification.EventSpec
      (activeContext (contexts program metadata role) RT.cap fixed) budget where
  base := fun _ => roleEvent program relation fallback nonce role fixed
  bound := (((3*budget : Rat)/(2^512 : Rat)+localLoss role : Rat) : ℝ)
  bound_nonnegative := by
    apply (Rat.cast_nonneg (K := ℝ)).mpr
    apply add_nonneg
    · exact div_nonneg (mul_nonneg (by norm_num) (Nat.cast_nonneg budget))
        (pow_nonneg (by norm_num) _)
    · cases role with
      | decsMatrix =>
          unfold localLoss M.matrixLoss
          exact div_nonneg (by norm_num) (Nat.cast_nonneg _)
      | decsSample =>
          unfold localLoss D.loss
          exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
      | piopMatrix =>
          unfold localLoss T.matrixLoss
          exact pow_nonneg (div_nonneg zero_le_one (Nat.cast_nonneg _)) _
      | piopOpening =>
          unfold localLoss T.openingLoss
          exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
  instability := fun _ =>
    (role_event_instability program relation fallback nonce role fixed injective sample point lookup budget).toReal
  mark_mono := fun _ _ _ event => event
  marked_write := by
    intro _ statement _ key parsed _ _ _
    have absent := route_is_not_leaf program metadata.leafNamespace role key.val
    change SmzaRp05FilteredReadback.globalLeafStatement metadata.leafNamespace
      (NativePrivateSpendQ58CurrentFiberMassTransport.routingTag role (G.keyBytes program) key.val) = some statement at parsed
    rw [absent] at parsed
    cases parsed
  empty_false := by
    intro _
    unfold roleEvent DynamicBad
    rintro ⟨key, vector, recorded, _⟩
    simp at recorded

/-- Actual initialized physical prefix plus the same adaptive current read
tree. Prefix certification is the retained typed operation class; no event
specification, instability, probability or transport equality is a premise. -/
theorem current_role_initialized_weighted_physical_mass
    (metadata : Context (Key := G.Key program) (Counter := G.Counter) (BaseWork := BaseWork))
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (role : Role) (dummy : R.Active role (G.keyBytes program))
    (injective : Function.Injective L.currentPoint)
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point)
    {budget finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := G.Key program) (Counter := G.Counter)
      (BaseWork := BaseWork) budget 0 finish queries}
    (certified : CertifiedFor (contexts program metadata) skeleton)
    (registers : RegisterBasis (Input := G.Key program) (Phase := VectorOutput G.Counter)
      (Workspace := Work (Counter := G.Counter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat) (readClass : ReadsAtMost G.decode depth program)
    (keys : List (G.Key program)) (keysWithin : ReadsWithinKeys (G.encode program) G.decode keys program)
    (supportWithin : finish+depth≤budget) (queriesWithin : queries+depth≤budget)
    (total : SmzaRp05RoleReadTotality.StandardOn keys
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers))) :
    (letI := physicalBranchesFintype G.decode program
      ∑ fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program),
        ∑ branch : Branches G.decode program,
          normSquared (workspaceEventProjection
            (fun _ database => roleEvent program relation fallback nonce role fixed database)
            (fixedFiberToActive (contexts program metadata role) RT.cap dummy fixed
              (otherRoleTransform (contexts program metadata role) RT.cap
                (physicalRun (G.encode program) G.decode program branch
                  (PhysicalProgramSkeleton.run skeleton
                    (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers))))))) ≤
      (6*(budget : ℝ)^2*(((3*budget : Rat)/(2^512 : Rat)+localLoss role : Rat) : ℝ)) *
        normSquared (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers) := by
  exact SmzaRp05ActualEventPhysicalMass.sum_physical_fiber_event_mass_le_certified_prefix
    certified role RT.cap dummy
    (fun fixed => spec program metadata relation fallback nonce role fixed injective sample point lookup budget)
    _ (fun _ => rfl) registers depth (G.encode program) G.decode program readClass keys keysWithin
    supportWithin queriesWithin total

/-- Sum of the FOUR literal current phase projections on the same initialized
physical tree. Each role uses its own actual fixed-table decomposition; every
answer branch and its original norm weight remains in the left side. -/
theorem current_four_roles_initialized_weighted_physical_mass
    (metadata : Context (Key := G.Key program) (Counter := G.Counter) (BaseWork := BaseWork))
    (relation : C.Relation) (fallback : G.RawDigest) (nonce : Fin (2^32))
    (dummy : (role : Role) → R.Active role (G.keyBytes program))
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point)
    {budget finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := G.Key program) (Counter := G.Counter)
      (BaseWork := BaseWork) budget 0 finish queries}
    (certified : CertifiedFor (contexts program metadata) skeleton)
    (registers : RegisterBasis (Input := G.Key program) (Phase := VectorOutput G.Counter)
      (Workspace := Work (Counter := G.Counter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat) (readClass : ReadsAtMost G.decode depth program)
    (keys : List (G.Key program)) (keysWithin : ReadsWithinKeys (G.encode program) G.decode keys program)
    (supportWithin : finish+depth≤budget) (queriesWithin : queries+depth≤budget)
    (total : SmzaRp05RoleReadTotality.StandardOn keys
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers))) :
    (letI := physicalBranchesFintype G.decode program
      ∑ role : Role,
        ∑ fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program),
          ∑ branch : Branches G.decode program,
            normSquared (workspaceEventProjection
              (fun _ database => roleEvent program relation fallback nonce role fixed database)
              (fixedFiberToActive (contexts program metadata role) RT.cap (dummy role) fixed
                (otherRoleTransform (contexts program metadata role) RT.cap
                  (physicalRun (G.encode program) G.decode program branch
                    (PhysicalProgramSkeleton.run skeleton
                      (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers))))))) ≤
      (6*(budget : ℝ)^2 *
        (∑ role : Role, (((3*budget : Rat)/(2^512 : Rat)+localLoss role : Rat) : ℝ))) *
        normSquared (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers) := by
  letI := physicalBranchesFintype G.decode program
  have injective : Function.Injective L.currentPoint :=
    NativePrivateSpendQ58CurrentPointGeometry.current_point_injective_from_one_success sample point lookup
  calc
    _ ≤ ∑ role : Role,
        (6*(budget : ℝ)^2*(((3*budget : Rat)/(2^512 : Rat)+localLoss role : Rat) : ℝ)) *
          normSquared (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers) := by
      apply Finset.sum_le_sum
      intro role _
      exact current_role_initialized_weighted_physical_mass program metadata relation fallback nonce
        role (dummy role) injective sample point lookup certified registers depth readClass keys keysWithin
        supportWithin queriesWithin total
    _ = _ := by rw [← Finset.sum_mul, ← Finset.mul_sum]

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRoleEventPhysicalMass
