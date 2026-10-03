import SmzaRp05ActiveZeroTransport

/-! # Structural compiler for the certified common physical prefix

The fixed table supplies only private phases. Every charged opcode remains
one sparse CMS query; all other opcodes retain their original charge and
support indices. The compiler consumes the local certificates of the common
syntax, never an execution equality or probability certificate.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CertifiedFiberCompiler

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CanonicalBytes
open SmzaRp05AdaptiveFilteredCollision
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05ConditionedEventJoin SmzaRp05ActiveFiberQuery
open SmzaRp05AdaptiveKernelInstantiation SmzaRp05ActiveZeroTransport
open SmzaRp05HomogeneousFiberSum V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

/-- A nonzero routed kernel entry comes from the literal original kernel. -/
theorem routed_kernel_nonzero
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork)))
    (source target : RegisterBasis
      (Input := ActiveKey ctx.role blockCap ctx.keyBytes)
      (Phase := VectorOutput Counter) (Workspace := RoutedWork Key Counter BaseWork))
    (nonzero : (routedPrivateContraction ctx blockCap dummy step).kernel source target ≠ 0) :
    step.kernel
      (source.2.2.2.queryInput, source.2.2.2.queryPhase,
        (source.2.2.1, source.2.2.2.base))
      (target.2.2.2.queryInput, target.2.2.2.queryPhase,
        (target.2.2.1, target.2.2.2.base)) ≠ 0 := by
  simp only [routedPrivateContraction, reindexWorkspaceContraction,
    transportContraction, transportedKernel, registerWorkspaceEquiv,
    activeMemoryEquiv] at nonzero
  split at nonzero
  · exact nonzero
  · exact False.elim (nonzero rfl)

def privateOpcode
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap budget : Nat) (within : budget ≤ cap)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork)))
    (authorization : ∀ source target, step.kernel source target ≠ 0 →
      ctx.authorizedOf source.2.2.2 = ctx.authorizedOf target.2.2.2) :
    Opcode ctx cap budget budget 0 :=
  .privateKernel budget within (databaseIndependentTransition step)
    (by
      intro source target nonzero
      have same : source.database = target.database := by
        by_contra different
        simp [databaseIndependentTransition, different] at nonzero
      have entry : step.kernel (basisRegisters source) (basisRegisters target) ≠ 0 := by
        simpa [databaseIndependentTransition, same] using nonzero
      exact ⟨authorization _ _ entry, same⟩)
    (by intro state; rw [kernel_apply_database_independent_transition]; exact step.contractive state)
    (database_independent_transition_bounded step budget)

def markOpcode
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap budget : Nat) (within : budget ≤ cap)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork)))
    (authorization : ∀ source target, step.kernel source target ≠ 0 →
      ∃ statement, ctx.authorizedOf target.2.2.2 =
        Insert.insert statement (ctx.authorizedOf source.2.2.2)) :
    Opcode ctx cap budget budget 0 :=
  .mark budget within (databaseIndependentTransition step)
    (by
      intro source target nonzero
      have same : source.database = target.database := by
        by_contra different
        simp [databaseIndependentTransition, different] at nonzero
      have entry : step.kernel (basisRegisters source) (basisRegisters target) ≠ 0 := by
        simpa [databaseIndependentTransition, same] using nonzero
      obtain ⟨statement, marked⟩ := authorization _ _ entry
      exact ⟨statement, marked, same.symm⟩)
    (by intro state; rw [kernel_apply_database_independent_transition]; exact step.contractive state)
    (database_independent_transition_bounded step budget)

def routedWorkUpdate
    (update : SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork) ≃
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork)) :
    RoutedWork Key Counter BaseWork ≃ RoutedWork Key Counter BaseWork where
  toFun work := ((update (work.1, work.2.base)).1,
    ⟨work.2.queryInput, work.2.queryPhase, (update (work.1, work.2.base)).2⟩)
  invFun work := ((update.symm (work.1, work.2.base)).1,
    ⟨work.2.queryInput, work.2.queryPhase, (update.symm (work.1, work.2.base)).2⟩)
  left_inv work := by rcases work with ⟨retained, input, phase, base⟩; simp
  right_inv work := by rcases work with ⟨retained, input, phase, base⟩; simp

def consZero
    {ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    {cap start middle finish queries : Nat}
    (first : Opcode ctx cap start middle 0)
    (remaining : ActualProgram ctx cap middle finish queries) :
    ActualProgram ctx cap start finish queries :=
  CertifiedPhysicalProgram.transportActual (Nat.zero_add queries)
    (.cons first remaining)

/-- Every constructor is mapped structurally, including the retained answer
slot. The type records exact preservation of support and query counts. -/
def compilePrefix
    {contexts : Role → Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    {cap start finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap start finish queries}
    (certified : CertifiedFor contexts skeleton)
    (role : Role) (blockCap : Role → Nat)
    (dummy : ActiveKey (contexts role).role blockCap (contexts role).keyBytes)
    (fixed : FixedTable (contexts role) blockCap) :
    ActualProgram (activeContext (contexts role) blockCap fixed) cap start finish queries :=
  match certified with
  | .nil budget => .nil budget
  | .query occupied room remaining =>
      .cons (.query occupied room)
        (consZero (privateOpcode (activeContext (contexts role) blockCap fixed)
          cap (occupied + 1) (by omega)
          (routedPrivateContraction (contexts role) blockCap dummy
            (fixedOtherPhaseContraction vectorPhaseSystem (contexts role).role blockCap
              (contexts role).keyBytes fixed))
          (by
            intro source target nonzero
            have entry := routed_kernel_nonzero (contexts role) blockCap dummy _ source target nonzero
            simp only [fixedOtherPhaseContraction, fixedOtherPhaseKernel] at entry
            split at entry
            · rename_i same
              exact congrArg (fun registers => (contexts role).authorizedOf registers.2.2.2) same
            · exact False.elim (entry rfl)))
          (compilePrefix remaining role blockCap dummy fixed))
  | .privateGate budget within step authorization remaining =>
      consZero (privateOpcode (activeContext (contexts role) blockCap fixed) cap budget within
        (routedPrivateContraction (contexts role) blockCap dummy step)
        (by
          intro source target nonzero
          exact authorization role _ _
            (routed_kernel_nonzero (contexts role) blockCap dummy step source target nonzero)))
        (compilePrefix remaining role blockCap dummy fixed)
  | .markGate budget within step authorization remaining =>
      consZero (markOpcode (activeContext (contexts role) blockCap fixed) cap budget within
        (routedPrivateContraction (contexts role) blockCap dummy step)
        (by
          intro source target nonzero
          exact authorization role _ _
            (routed_kernel_nonzero (contexts role) blockCap dummy step source target nonzero)))
        (compilePrefix remaining role blockCap dummy fixed)
  | .retainedLeafWrite occupied room key statement fresh marked parsed remaining =>
      consZero (.retainedWrite occupied room
        ⟨key, canonical_leaf_is_active (contexts role) blockCap key statement (parsed role)⟩
        statement (fun work => marked role work.base) (parsed role) fresh)
        (compilePrefix remaining role blockCap dummy fixed)
  | .copyX budget within keys update unrecognized authorization remaining =>
      consZero (.copy budget within
        (fun database => routedWorkUpdate
          (update (activeXView (contexts role) blockCap keys (unrecognized role) database)))
        (by
          intro database workspace
          exact authorization role _ (workspace.1, workspace.2.base)))
        (compilePrefix remaining role blockCap dummy fixed)

end
end HegemonCrypto.SmallWood.SmzaRp05CertifiedFiberCompiler
