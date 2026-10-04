import HegemonCrypto.CmsLocalOperator
import Mathlib.Analysis.Complex.Basic
import Mathlib.Analysis.Real.Sqrt

/-!
# Finite compressed phase-oracle kernel

This file defines the exact three-case compressed phase oracle from Chiesa, Manohar, and
Spooner, Lemma 3.2 (full version dated 2020-01-14). The database is the finite recorded map
from `FiniteOracleDatabase`; no classical query log is substituted for a quantum query.

The operator is represented by its finite computational-basis kernel.  This keeps the definition
independent of a particular Hilbert-space library while still giving an exact complex-linear
state transformation.  The separate local-operator proof applies finite Cauchy--Schwarz to this
kernel.
-/

namespace HegemonCrypto.CmsCompressedOracle

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase

noncomputable section

/--
A finite Fourier phase register for the oracle output group.

`zeroPhase` is the trivial character.  Every other phase is nontrivial.  The active SHA-512
instantiation uses the standard perfect character pairing of fixed-width bit vectors; that
algebraic instantiation is proved separately and is not a cryptographic assumption.
-/
structure PhaseSystem (Output Phase : Type*) [AddCommGroup Output] where
  character : Phase -> AddChar Output ℂ
  zeroPhase : Phase
  character_zero : character zeroPhase = 0
  character_nonzero : ∀ phase, phase ≠ zeroPhase -> character phase ≠ 0

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Computational basis of the compressed-oracle simulation. -/
structure Basis (Input Output Phase Workspace : Type*) where
  input : Input
  phase : Phase
  workspace : Workspace
  database : Database Input Output

def basisEquiv :
    (Input × Phase × Workspace × Database Input Output) ≃
      Basis Input Output Phase Workspace where
  toFun basis :=
    { input := basis.1
      phase := basis.2.1
      workspace := basis.2.2.1
      database := basis.2.2.2 }
  invFun basis :=
    (basis.input, basis.phase, basis.workspace, basis.database)
  left_inv basis := by cases basis; rfl
  right_inv basis := by cases basis; rfl

noncomputable instance : DecidableEq (Basis Input Output Phase Workspace) :=
  Classical.decEq _

noncomputable instance : Fintype (Basis Input Output Phase Workspace) :=
  Fintype.ofEquiv
    (Input × Phase × Workspace × Database Input Output)
    (basisEquiv (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))

abbrev State (Input Output Phase Workspace : Type*) :=
  Basis Input Output Phase Workspace -> ℂ

/-- One computational-basis ket. -/
def basisState
    (basis : Basis Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun candidate => if candidate = basis then 1 else 0

/-- Squared Hilbert norm of a finite compressed-oracle state. -/
def normSquared
    (state : State Input Output Phase Workspace) : ℝ :=
  ∑ basis, Complex.normSq (state basis)

/-- The phase contributed by a recorded answer; an absent entry contributes one. -/
def recordedPhase
    (system : PhaseSystem Output Phase)
    (phase : Phase)
    (database : Database Input Output)
    (input : Input) : ℂ :=
  match database input with
  | none => 1
  | some output => system.character phase output

/-- `1 / sqrt |Y|`, embedded into the complex amplitudes. -/
def inverseSqrtOutputCard : ℂ :=
  ((Real.sqrt (Fintype.card Output : ℝ) : ℝ) : ℂ)⁻¹

/-- `1 / |Y|`, embedded into the complex amplitudes. -/
def inverseOutputCard : ℂ :=
  (((Fintype.card Output : ℝ) : ℝ) : ℂ)⁻¹

/--
Database-register matrix element of the exact CMS compressed phase oracle.

The three branches are:

* a diagonal phase when the database is full or the phase register is zero;
* the uniform Fourier insertion state for a fresh input;
* the recorded-entry formula containing the retained, erased, and replacement terms.

Indicators are added rather than made mutually exclusive because the kets in the published
formula can coincide (notably reinserting the recorded output restores the original database).
-/
def databaseKernel
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phase : Phase)
    (source target : Database Input Output) : ℂ :=
  if size source = queryBound ∨ phase = system.zeroPhase then
    if target = source then recordedPhase system phase source input else 0
  else
    match source input with
    | none =>
        ∑ output : Output,
          if target = insert source input output then
            inverseSqrtOutputCard (Output := Output) * system.character phase output
          else 0
    | some recordedOutput =>
        (if target = source then system.character phase recordedOutput else 0) +
        (if target = erase source input then
          system.character phase recordedOutput * inverseSqrtOutputCard (Output := Output)
        else 0) +
        ∑ output : Output,
          if target = insert (erase source input) input output then
            inverseOutputCard (Output := Output) *
              (1 - system.character phase output -
                system.character phase recordedOutput)
          else 0

/-- Full basis kernel; the query does not change input, phase, or private workspace registers. -/
def kernel
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (source target : Basis Input Output Phase Workspace) : ℂ :=
  if target.input = source.input ∧
      target.phase = source.phase ∧
      target.workspace = source.workspace then
    databaseKernel system queryBound source.input source.phase
      source.database target.database
  else 0

/-- Complex-linear extension of the compressed-oracle basis kernel. -/
def queryState
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun target => ∑ source, state source * kernel system queryBound source target

/-- Applying the operator to a basis ket exposes exactly one column of the kernel. -/
theorem query_basis_state
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (source target : Basis Input Output Phase Workspace) :
    queryState system queryBound (basisState source) target =
      kernel system queryBound source target := by
  classical
  unfold queryState basisState
  rw [Finset.sum_eq_single source]
  · simp
  · intro candidate _ different
    simp [different]
  · simp

/-- The operator is additive on finite states. -/
theorem query_state_add
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (left right : State Input Output Phase Workspace) :
    queryState system queryBound (fun basis => left basis + right basis) =
      fun basis =>
        queryState system queryBound left basis +
          queryState system queryBound right basis := by
  funext target
  unfold queryState
  simp_rw [add_mul, Finset.sum_add_distrib]

/-- The operator commutes with complex scalar multiplication. -/
theorem query_state_smul
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (scalar : ℂ)
    (state : State Input Output Phase Workspace) :
    queryState system queryBound (fun basis => scalar * state basis) =
      fun basis => scalar * queryState system queryBound state basis := by
  funext target
  unfold queryState
  simp_rw [mul_assoc, Finset.mul_sum]

omit [Fintype Phase] in
/-- Exact capped/trivial-phase branch of CMS Lemma 3.2. -/
theorem database_kernel_of_capped_or_zero
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phase : Phase)
    (source target : Database Input Output)
    (cappedOrZero : size source = queryBound ∨ phase = system.zeroPhase) :
    databaseKernel system queryBound input phase source target =
      if target = source then recordedPhase system phase source input else 0 := by
  simp [databaseKernel, cappedOrZero]

omit [Fintype Phase] in
/-- Exact fresh-input branch of CMS Lemma 3.2. -/
theorem database_kernel_of_absent
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phase : Phase)
    (source target : Database Input Output)
    (notCapped : size source ≠ queryBound)
    (nonzeroPhase : phase ≠ system.zeroPhase)
    (absent : source input = none) :
    databaseKernel system queryBound input phase source target =
      ∑ output : Output,
        if target = insert source input output then
          inverseSqrtOutputCard (Output := Output) * system.character phase output
        else 0 := by
  simp [databaseKernel, notCapped, nonzeroPhase, absent]

omit [Fintype Phase] in
/-- Exact recorded-input branch of CMS Lemma 3.2. -/
theorem database_kernel_of_recorded
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phase : Phase)
    (source target : Database Input Output)
    (recordedOutput : Output)
    (notCapped : size source ≠ queryBound)
    (nonzeroPhase : phase ≠ system.zeroPhase)
    (recorded : source input = some recordedOutput) :
    databaseKernel system queryBound input phase source target =
      (if target = source then system.character phase recordedOutput else 0) +
      (if target = erase source input then
        system.character phase recordedOutput * inverseSqrtOutputCard (Output := Output)
      else 0) +
      ∑ output : Output,
        if target = insert (erase source input) input output then
          inverseOutputCard (Output := Output) *
            (1 - system.character phase output -
              system.character phase recordedOutput)
        else 0 := by
  simp [databaseKernel, notCapped, nonzeroPhase, recorded]

/-- Projection onto bounded databases satisfying a property. -/
def project
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun basis =>
    if size basis.database <= queryBound ∧ property basis.database then
      state basis
    else 0

omit [DecidableEq Output] [AddCommGroup Output] [DecidableEq Phase]
    [DecidableEq Workspace] in
/-- Orthogonal coordinate projection cannot increase finite squared norm. -/
theorem project_norm_squared_le
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    normSquared (project property queryBound state) <= normSquared state := by
  classical
  unfold normSquared project
  apply Finset.sum_le_sum
  intro basis _
  split_ifs
  · exact le_rfl
  · simpa using Complex.normSq_nonneg (state basis)

omit [DecidableEq Input] [Fintype Output] [DecidableEq Output]
    [AddCommGroup Output] [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace] in
/-- Projection is idempotent. -/
theorem project_project
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    project property queryBound (project property queryBound state) =
      project property queryBound state := by
  funext basis
  by_cases accepted :
      size basis.database <= queryBound ∧ property basis.database
  · simp [project, accepted]
  · simp [project, accepted]

end

end HegemonCrypto.CmsCompressedOracle
