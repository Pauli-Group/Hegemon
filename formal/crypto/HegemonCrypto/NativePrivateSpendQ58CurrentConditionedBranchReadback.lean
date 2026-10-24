import HegemonCrypto.NativePrivateSpendQ58CurrentSameDatabaseEventJoin
import HegemonCrypto.NativePrivateSpendQ58ActiveProgramTransport
import SmzaRp05CurrentPhysicalBranchClaims

/-! Literal current branch transport to the retained physical claim bound.
The erased Program consumes every inactive answer from this SAME fixed table;
its active calls and answers are unchanged. The branch and its claims are
constructed, rather than postulated. The physical run equality uses the
already-retained sparse same-fiber transport. No raw parser/profile is changed.
SOURCE ONLY; kernel validation and final event-density composition are pending.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentConditionedBranchReadback
open scoped Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaChallengeStageTargets (Role)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter RawInput RawDigest encode decode)
end G
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims (live activeClaims fixedCompatible)
end AC
namespace A
export NativePrivateSpendQ58ActiveEventProjection
  (ActiveKey FixedTable FullState SparseState restrictFiber fixed_fiber_isometry)
end A
namespace PT
export NativePrivateSpendQ58PartitionTransport (conditioned projectFiber)
end PT
namespace AP
export NativePrivateSpendQ58ActiveProgramTransport (sparseRun physical_run_to_sparse_same_fiber)
end AP
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
variable {RootResult Result Work : Type}

/-- Constant native root encoding is retained throughout each continuation. -/
def Compatible (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps))
    (program : Program Result) (branch : Branches G.decode program) : Prop :=
  ∀ call ∈ answerLog G.decode program branch,
    ∀ inactive : ¬AC.live root selected caps (G.encode root call.1),
      fixed ⟨G.encode root call.1, inactive⟩ = call.2

private theorem compatible_tail
    (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps))
    (raw : G.RawInput) (next : G.RawDigest → Program Result)
    (answer : VectorOutput G.Counter) (branch : Branches G.decode (next (G.decode raw answer)))
    (compatible : Compatible root selected caps fixed (.read raw next) ⟨answer, branch⟩) :
    Compatible root selected caps fixed (next (G.decode raw answer)) branch := by
  intro call recorded inactive
  exact compatible call (List.mem_cons_of_mem _ recorded) inactive

/-- Fixed reads are executed classically from the same table; live reads
remain the literal native raw calls. This is an execution adapter only. -/
def eraseProgram (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps)) :
    Program Result → Program Result
  | .done result => .done result
  | .read raw next =>
      if active : AC.live root selected caps (G.encode root raw) then
        .read raw (fun digest => eraseProgram root selected caps fixed (next digest))
      else eraseProgram root selected caps fixed
        (next (G.decode raw (fixed ⟨G.encode root raw, active⟩)))

def activeEncode (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (dummy : A.ActiveKey (AC.live root selected caps)) (raw : G.RawInput) :
    A.ActiveKey (AC.live root selected caps) :=
  if active : AC.live root selected caps (G.encode root raw) then ⟨G.encode root raw, active⟩
  else dummy

/-- The actual branch is transformed only after its inactive answers have
been proved equal to this fiber's table. No candidate/acceptance is involved. -/
def eraseBranch (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps)) :
    (program : Program Result) → (branch : Branches G.decode program) →
      Compatible root selected caps fixed program branch →
      Branches G.decode (eraseProgram root selected caps fixed program)
  | .done _, _, _ => PUnit.unit
  | .read raw next, ⟨answer, branch⟩, compatible => by
      have tail := compatible_tail root selected caps fixed raw next answer branch compatible
      by_cases active : AC.live root selected caps (G.encode root raw)
      · change Branches G.decode
          (if h : AC.live root selected caps (G.encode root raw) then
            .read raw (fun digest => eraseProgram root selected caps fixed (next digest))
          else eraseProgram root selected caps fixed
            (next (G.decode raw (fixed ⟨G.encode root raw, h⟩))))
        rw [dif_pos active]
        exact ⟨answer, eraseBranch root selected caps fixed (next (G.decode raw answer)) branch tail⟩
      · have head := compatible (raw, answer) (List.mem_cons_self) active
        simpa only [eraseProgram, dif_neg active, head] using
          eraseBranch root selected caps fixed (next (G.decode raw answer)) branch tail

def filteredClaims (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (program : Program Result) (branch : Branches G.decode program) :
    List (A.ActiveKey (AC.live root selected caps) × VectorOutput G.Counter) :=
  ((answerLog G.decode program branch).map (fun call => (G.encode root call.1, call.2))).filterMap
    fun claim => if active : AC.live root selected caps claim.1 then some (⟨claim.1, active⟩, claim.2)
      else none

private theorem consume_program_cast {Value : Type}
    (consume : (program : Program Result) → Branches G.decode program → Value)
    {left right : Program Result} (same : left = right)
    (typeEq : Branches G.decode right = Branches G.decode left)
    (branch : Branches G.decode right) :
    consume left (cast typeEq branch) = consume right branch := by
  cases same
  rfl

/-- Repeated addresses are retained here; the existing exact-pair claim
bound performs deduplication after consistency is derived from physical support. -/
theorem erased_branch_claims_are_actual_active_claims
    (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (dummy : A.ActiveKey (AC.live root selected caps))
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps))
    (program : Program Result) (branch : Branches G.decode program)
    (compatible : Compatible root selected caps fixed program branch) :
    branchClaims
      (branchKeys (activeEncode root selected caps dummy) G.decode
        (eraseProgram root selected caps fixed program)
        (eraseBranch root selected caps fixed program branch compatible))
      (branchAnswers (activeEncode root selected caps dummy) G.decode
        (eraseProgram root selected caps fixed program)
        (eraseBranch root selected caps fixed program branch compatible)) =
      filteredClaims root selected caps program branch := by
  induction program with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      have tail := compatible_tail root selected caps fixed raw next answer branch compatible
      by_cases active : AC.live root selected caps (G.encode root raw)
      · simpa [branch_claims_eq_answer_log, eraseProgram, eraseBranch, active,
          consume_program_cast, activeEncode, filteredClaims, answerLog,
          List.map_cons, List.filterMap_cons] using
          congrArg (List.cons (⟨G.encode root raw, active⟩, answer))
            (ih (G.decode raw answer) branch tail)
      · have head := compatible (raw, answer) (List.mem_cons_self) active
        simpa [branch_claims_eq_answer_log, eraseProgram, eraseBranch, active,
          consume_program_cast, head, filteredClaims, answerLog,
          List.map_cons, List.filterMap_cons] using
          ih (G.decode raw answer) branch tail

theorem filtered_claims_at_native_root
    (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (branch : Branches G.decode root) :
    filteredClaims root selected caps root branch = AC.activeClaims root selected caps branch := by
  simp only [filteredClaims, AC.activeClaims,
    NativePrivateSpendQ58CurrentClaimReplay.fullClaims, branch_claims_eq_answer_log]

theorem compatible_at_native_root
    (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps))
    (branch : Branches G.decode root) :
    Compatible root selected caps fixed root branch ↔ AC.fixedCompatible root selected caps fixed branch :=
  Iff.rfl

private theorem physical_run_program_cast
    [Fintype Work] [DecidableEq Work]
    (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (dummy : A.ActiveKey (AC.live root selected caps))
    {left right : Program Result} (same : left = right)
    (typeEq : Branches G.decode right = Branches G.decode left)
    (branch : Branches G.decode right)
    (state : A.SparseState (Counter := G.Counter) (Work := Work) (AC.live root selected caps)) :
    physicalRun (activeEncode root selected caps dummy) G.decode left (cast typeEq branch) state =
      physicalRun (activeEncode root selected caps dummy) G.decode right branch state := by
  cases same
  rfl

/-- The already-retained sparse physical run equals the physical Program of
exactly these actual active calls. No standard/conditioned same-basis claim. -/
theorem sparse_run_is_erased_actual_branch
    [Fintype Work] [DecidableEq Work]
    (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (dummy : A.ActiveKey (AC.live root selected caps))
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps))
    (program : Program Result) (branch : Branches G.decode program)
    (compatible : Compatible root selected caps fixed program branch)
    (state : A.SparseState (Counter := G.Counter) (Work := Work) (AC.live root selected caps)) :
    AP.sparseRun (AC.live root selected caps) fixed (G.encode root) G.decode program branch state =
      physicalRun (activeEncode root selected caps dummy) G.decode
        (eraseProgram root selected caps fixed program)
        (eraseBranch root selected caps fixed program branch compatible) state := by
  induction program generalizing state with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      have tail := compatible_tail root selected caps fixed raw next answer branch compatible
      by_cases active : AC.live root selected caps (G.encode root raw)
      · have programEq : eraseProgram root selected caps fixed (.read raw next) =
            .read raw (fun digest => eraseProgram root selected caps fixed (next digest)) := by
          simp only [eraseProgram, dif_pos active]
        have runEq :
            physicalRun (activeEncode root selected caps dummy) G.decode
              (eraseProgram root selected caps fixed (.read raw next))
              (eraseBranch root selected caps fixed (.read raw next) ⟨answer, branch⟩ compatible) state =
            physicalRun (activeEncode root selected caps dummy) G.decode
              (.read raw (fun digest => eraseProgram root selected caps fixed (next digest)))
              ⟨answer, eraseBranch root selected caps fixed (next (G.decode raw answer)) branch tail⟩ state := by
          simpa only [eraseProgram, eraseBranch, dif_pos active, eq_mpr_eq_cast, id_eq] using
            physical_run_program_cast root selected caps dummy programEq
              (congrArg (Branches G.decode) programEq.symm)
              ⟨answer, eraseBranch root selected caps fixed (next (G.decode raw answer)) branch tail⟩ state
        rw [runEq]
        simpa [AP.sparseRun, active, physicalRun, activeEncode,
          SmzaRp05PhysicalAcceptedReplayBridge.physical_read_step_eq_branch] using
          ih (G.decode raw answer) branch tail
            (SmzaRp05PhysicalTerminalRead.physicalReadBranch ⟨G.encode root raw, active⟩ answer state)
      · have head := compatible (raw, answer) (List.mem_cons_self) active
        have programEq : eraseProgram root selected caps fixed (.read raw next) =
            eraseProgram root selected caps fixed (next (G.decode raw answer)) := by
          simp only [eraseProgram, dif_neg active, head]
        have runEq :
            physicalRun (activeEncode root selected caps dummy) G.decode
              (eraseProgram root selected caps fixed (.read raw next))
              (eraseBranch root selected caps fixed (.read raw next) ⟨answer, branch⟩ compatible) state =
            physicalRun (activeEncode root selected caps dummy) G.decode
              (eraseProgram root selected caps fixed (next (G.decode raw answer)))
              (eraseBranch root selected caps fixed (next (G.decode raw answer)) branch tail) state := by
          simpa only [eraseBranch, dif_neg active, head, eq_mpr_eq_cast] using
            physical_run_program_cast root selected caps dummy programEq
              (congrArg (Branches G.decode) programEq.symm)
              (eraseBranch root selected caps fixed (next (G.decode raw answer)) branch tail) state
        rw [runEq]
        simpa [AP.sparseRun, active, head] using ih (G.decode raw answer) branch tail state

private theorem project_conditioned
    [Fintype Work] [DecidableEq Work]
    (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps))
    (state : A.FullState (Key := G.Key root) (Counter := G.Counter) (Work := Work)) :
    PT.projectFiber (AC.live root selected caps) fixed
      (PT.conditioned (AC.live root selected caps) fixed state) =
      PT.conditioned (AC.live root selected caps) fixed state := by
  funext basis
  simp only [PT.conditioned, PT.projectFiber]
  split <;> rfl

/-- Exact terminal branch norm, without renormalizing a conditioned state. -/
theorem current_same_fiber_branch_norm
    [Fintype Work] [DecidableEq Work]
    (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (dummy : A.ActiveKey (AC.live root selected caps))
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps))
    (branch : Branches G.decode root)
    (compatible : AC.fixedCompatible root selected caps fixed branch)
    (state : A.FullState (Key := G.Key root) (Counter := G.Counter) (Work := Work)) :
    normSquared (PT.conditioned (AC.live root selected caps) fixed
      (physicalRun (G.encode root) G.decode root branch state)) =
      normSquared (physicalRun (activeEncode root selected caps dummy) G.decode
        (eraseProgram root selected caps fixed root)
        (eraseBranch root selected caps fixed root branch compatible)
        (A.restrictFiber (AC.live root selected caps) dummy fixed
          (PT.conditioned (AC.live root selected caps) fixed state))) := by
  rw [← sparse_run_is_erased_actual_branch root selected caps dummy fixed root branch compatible]
  rw [← AP.physical_run_to_sparse_same_fiber]
  rw [A.fixed_fiber_isometry, project_conditioned]

/-- Fixed compatibility is an actual support consequence. Incompatible
answer branches have zero conditioned amplitude at every basis. -/
theorem current_incompatible_conditioned_branch_is_zero
    [Fintype Work] [DecidableEq Work]
    (root : Program RootResult) (selected : Role) (caps : Role → Nat)
    (fixed : A.FixedTable (Counter := G.Counter) (AC.live root selected caps))
    (branch : Branches G.decode root)
    (incompatible : ¬AC.fixedCompatible root selected caps fixed branch)
    (state : A.FullState (Key := G.Key root) (Counter := G.Counter) (Work := Work)) :
    PT.conditioned (AC.live root selected caps) fixed
      (physicalRun (G.encode root) G.decode root branch state) = 0 := by
  funext basis
  by_contra nonzero
  exact incompatible
    (NativePrivateSpendQ58CurrentActiveBranchClaims.current_nonzero_conditioned_branch_is_fixed_compatible
      root selected caps fixed branch state basis nonzero)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentConditionedBranchReadback
