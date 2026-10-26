import HegemonCrypto.NativePrivateSpendQ58CurrentCausalSourceJoin
import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceArithmeticCollision

/-! The initialized physical mass of the four deterministic CURRENT global
causal predicates, on an arbitrary one global adaptive Program. Retained
PR205 typed physical-prefix and read-tree operators are reused. Every role
uses the same original global budget and original branch Born weight. There
is no invocation union, selected-stage premise or logical observer execution.
This proves event mass only; accepted-history failure SUPPORT must be derived
separately from the actual same-source global branch. SOURCE ONLY. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalCausalMass
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
namespace N
export NativePrivateSpendQ58CurrentRoleEventPhysicalMass (stage localLoss contexts)
end N
namespace CS
export NativePrivateSpendQ58CurrentCausalSourceJoin (SourceTemplate causalBad current_native_causal_instability)
end CS
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

variable {Result BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
variable (program : Program Result)

/-- Four fixed global causal predicates. The immutable native CSR template,
parsed trace and actual fixed-other-role oracle determine every parameter.
There is no invocation index, active-database-dependent selector or event
transport certificate in this predicate. -/
def event (template : CS.SourceTemplate) (fallback : G.RawDigest)
    (role : Role) (fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program)) :=
  DynamicBad (P.currentLabel (R.activeBytes role (G.keyBytes program)) G.zero (N.stage role))
    (CS.causalBad program template fallback role fixed)

private theorem route_is_not_leaf (ns : SmzaRp05LeafNamespace.Namespace)
    (role : Role) (key : G.Key program) :
    SmzaRp05FilteredReadback.globalLeafStatement ns
      (NativePrivateSpendQ58CurrentFiberMassTransport.routingTag role (G.keyBytes program) key) = none := by
  unfold NativePrivateSpendQ58CurrentFiberMassTransport.routingTag
  split
  · rfl
  · cases role <;> rfl

/-- Concrete current spec. Authorization is irrelevant in independent proof
mode. The internal partition tags cannot be canonical leaf write addresses. -/
def spec
    (metadata : Context (Key := G.Key program) (Counter := G.Counter) (BaseWork := BaseWork))
    (template : CS.SourceTemplate) (fallback : G.RawDigest)
    (role : Role) (fixed : R.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (injective : Function.Injective L.currentPoint)
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) (budget : Nat) :
    SmzaRp05ActualEventRecertification.EventSpec
      (activeContext (N.contexts program metadata role) RT.cap fixed) budget where
  base := fun _ => event program template fallback role fixed
  bound := (((3*budget : Rat)/(2^512 : Rat)+N.localLoss role : Rat) : ℝ)
  bound_nonnegative := by
    cases role <;>
      dsimp [N.localLoss, M.matrixLoss, D.loss, T.matrixLoss, T.openingLoss] <;> positivity
  instability := fun _ =>
    (CS.current_native_causal_instability program template fallback role fixed injective sample point lookup budget).toReal
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
    unfold event DynamicBad
    rintro ⟨key, vector, recorded, _⟩
    simp at recorded

/-- Actual initialized physical prefix plus the same adaptive current read
tree. Prefix certification is the retained typed operation class; no event
specification, instability, probability or transport equality is a premise. -/
theorem current_global_role_causal_initialized_mass
    (metadata : Context (Key := G.Key program) (Counter := G.Counter) (BaseWork := BaseWork))
    (template : CS.SourceTemplate) (fallback : G.RawDigest)
    (role : Role) (dummy : R.Active role (G.keyBytes program))
    (injective : Function.Injective L.currentPoint)
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point)
    {budget finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := G.Key program) (Counter := G.Counter)
      (BaseWork := BaseWork) budget 0 finish queries}
    (certified : CertifiedFor (N.contexts program metadata) skeleton)
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
            (fun _memory database => event program template fallback role fixed database)
            (fixedFiberToActive (N.contexts program metadata role) RT.cap dummy fixed
              (otherRoleTransform (N.contexts program metadata role) RT.cap
                (physicalRun (G.encode program) G.decode program branch
                  (PhysicalProgramSkeleton.run skeleton
                    (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers))))))) ≤
      (6*(budget : ℝ)^2*(((3*budget : Rat)/(2^512 : Rat)+N.localLoss role : Rat) : ℝ)) *
        normSquared (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers) := by
  exact SmzaRp05ActualEventPhysicalMass.sum_physical_fiber_event_mass_le_certified_prefix
    certified role RT.cap dummy
    (fun fixed => spec program metadata template fallback role fixed injective sample point lookup budget)
    _ (fun _ => rfl) registers depth (G.encode program) G.decode program readClass keys keysWithin
    supportWithin queriesWithin total

/-- Sum of the FOUR literal current phase projections on the same initialized
physical tree. Each role uses its own actual fixed-table decomposition; every
answer branch and its original norm weight remains in the left side. -/
theorem current_global_four_role_causal_initialized_mass
    (metadata : Context (Key := G.Key program) (Counter := G.Counter) (BaseWork := BaseWork))
    (template : CS.SourceTemplate) (fallback : G.RawDigest)
    (dummy : (role : Role) → R.Active role (G.keyBytes program))
    (sample : D.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point)
    {budget finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := G.Key program) (Counter := G.Counter)
      (BaseWork := BaseWork) budget 0 finish queries}
    (certified : CertifiedFor (N.contexts program metadata) skeleton)
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
              (fun _ database => event program template fallback role fixed database)
              (fixedFiberToActive (N.contexts program metadata role) RT.cap (dummy role) fixed
                (otherRoleTransform (N.contexts program metadata role) RT.cap
                  (physicalRun (G.encode program) G.decode program branch
                    (PhysicalProgramSkeleton.run skeleton
                      (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers))))))) ≤
      (6*(budget : ℝ)^2 *
        (∑ role : Role, (((3*budget : Rat)/(2^512 : Rat)+N.localLoss role : Rat) : ℝ))) *
        normSquared (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers) := by
  letI := physicalBranchesFintype G.decode program
  have injective : Function.Injective L.currentPoint :=
    NativePrivateSpendQ58CurrentPointGeometry.current_point_injective_from_one_success sample point lookup
  calc
    _ ≤ ∑ role : Role,
        (6*(budget : ℝ)^2*(((3*budget : Rat)/(2^512 : Rat)+N.localLoss role : Rat) : ℝ)) *
          normSquared (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers) := by
      apply Finset.sum_le_sum
      intro role _
      exact current_global_role_causal_initialized_mass program metadata template fallback
        role (dummy role) injective sample point lookup certified registers depth readClass keys keysWithin
        supportWithin queriesWithin total
    _ = _ := by rw [Finset.mul_sum, Finset.sum_mul]

/-- Exact current global coefficient. The four role losses are paid once
under the lifetime Q account; the retained collision and missing-raw-claim
coefficients remain separate. This arithmetic does not assert that a new
history failure selector has already been transported into these events. -/
theorem current_global_causal_coefficient_with_collision_and_cut_below_128
    (counter : G.Counter) (q : Nat) (budget : q ≤ 3*2^64) :
    6*(q:ℝ)^2*(∑ role : Role,
        (((3*q:Rat)/(2^512:Rat)+N.localLoss role:Rat):ℝ)) +
      16*(q:ℝ)^3/2^512 + 20*q/Fintype.card (VectorOutput G.Counter) <
        (2:ℝ)^(-128:ℤ) := by
  have count : Fintype.card Role = 4 := by decide
  have sumLoss : (∑ role : Role,
        (((3*q:Rat)/(2^512:Rat)+N.localLoss role:Rat):ℝ)) =
      12*(q:ℝ)/2^512 +
        (NativePrivateSpendQ58CurrentAcceptedSourceArithmetic.totalLoss:ℝ) := by
    simp only [Rat.cast_add,Rat.cast_div,Rat.cast_mul,Rat.cast_natCast,Rat.cast_pow,Rat.cast_ofNat,
      Finset.sum_add_distrib,Finset.sum_const,Finset.card_univ,count,nsmul_eq_mul,
      NativePrivateSpendQ58CurrentAcceptedSourceArithmetic.totalLoss,Rat.cast_sum]
    generalize (2 : ℝ)^512 = denominator
    ring
  rw [sumLoss]
  have numerical :=
    NativePrivateSpendQ58CurrentAcceptedSourceArithmeticCollision.accepted_arithmetic_with_collision_below_128
      counter q budget
  convert numerical using 1; (generalize (2 : ℝ)^512 = denominator; ring)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalCausalMass
