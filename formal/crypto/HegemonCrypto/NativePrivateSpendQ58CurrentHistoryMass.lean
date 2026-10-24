import HegemonCrypto.NativePrivateSpendQ58CurrentCompletePublicJoin
import HegemonCrypto.SmallWoodV8Smz9RunHomogeneity
import Q38Rp05PhaseStoppingBound
import Q38CmsAdaptiveWholeViewApplication

/-! Current SMZD request comparison on arbitrary reached mass. The already
checked normalized Source143 theorem is instantiated, never reimplemented.
Zero branches and all instrument outcomes retain their actual Born weights. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentHistoryMass
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsQuerySequence
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9MixedMaskCompiler V8Smz9RunHomogeneity V8Smz9MeasuredRunContinuity
open NativePrivateSpendQ58CurrentLeafInput NativePrivateSpendQ58CurrentChronologicalRequest
open NativePrivateSpendQ58CurrentInitializedPublic NativePrivateSpendQ58CurrentOriginalRequest
open NativePrivateSpendQ58CurrentCompletePublicJoin
open Q38WholeViewCmsSemantics Q38CmsAdaptiveWholeViewApplication
open Q38CmsAdaptiveWholeViewBound Q38CmsPhaseDecodeIsometry
open scoped Classical BigOperators ENNReal
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev CurrentInput (bound : Nat) := CurrentFullRawInput bound
abbrev Context := Option ((NativePrivateSpendQ58CurrentCosetSelector.Index → DigestRegister) × CommitPrefix)
variable {bound : Nat} {Work : Type} [Fintype Work]

/-- Validity is the existing privacy relation premise, not accepted-invalid
soundness. Every private value is confined to the real request constructor. -/
structure RequestData (bound : Nat) where
  largeEnough : 1264811 ≤ bound
  relation : PublicRelation
  values : NativePrivateSpendQ58CurrentRowBoundary.CurrentValues
  valid : NativePrivateSpendQ58CurrentPublicOpening.Satisfies relation values
  statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte
  salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte
  binding : Fin 77 → Goldilocks

def sourceRequest (data : RequestData bound)
    (next : Context → Except String PublicResult → MixedProgram (CurrentInput bound) Work) :=
  originalRequest data.largeEnough data.relation data.values data.statement data.salt data.binding next

def publicRequest (data : RequestData bound)
    (next : Context → Except String PublicResult → MixedProgram (CurrentInput bound) Work) :=
  completePublicSimulator data.largeEnough data.relation data.statement data.salt data.binding next

def erasureLoss (queries : Nat) : ℝ := 4 * (queries : ℝ) / (2 ^ 256 : ℝ)

theorem erasure_loss_nonnegative (queries : Nat) : 0 ≤ erasureLoss queries := by
  unfold erasureLoss
  positivity

/-- This lift explicitly handles state=0 and normalizes only a mathematical
comparison vector. Neither executed branch is normalized or postselected. -/
theorem current_request_bound_mass (data : RequestData bound)
    (next : Context → Except String PublicResult → MixedProgram (CurrentInput bound) Work)
    (old : CurrentInput bound → DigestRegister)
    (state : V8Smz9HonestWholeViewGames.GameState (Input := CurrentInput bound) (Work := Work))
    (queries : Nat) (callerQueries : ∀ context outcome,
      V8Smz9HonestWholeViewGames.queryCount (compile (next context outcome) []) ≤ queries) :
    |V8Smz9MixedMaskCompiler.run true (sourceRequest data next) old state -
      V8Smz9MixedMaskCompiler.run true (publicRequest data next) old state| ≤
      erasureLoss queries * ‖state‖ ^ 2 := by
  apply normalized_comparison_lifts_to_all_states
    (fun reached => V8Smz9MixedMaskCompiler.run true (sourceRequest data next) old reached)
    (fun reached => V8Smz9MixedMaskCompiler.run true (publicRequest data next) old reached)
    (mixed_run_quadratically_homogeneous true (sourceRequest data next) old)
    (mixed_run_quadratically_homogeneous true (publicRequest data next) old)
    (erasureLoss queries)
  intro reached normalized
  exact protected_source_complete_public_bound data.largeEnough data.relation data.values
    data.valid data.statement data.salt data.binding next old reached normalized queries callerQueries

section Physical
variable [DecidableEq Work]

theorem current_request_bound_family (data : RequestData bound)
    (next : Context → Except String PublicResult → MixedProgram (CurrentInput bound) Work)
    (family : OracleRegisterFamily (Input := CurrentInput bound) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (queries : Nat) (callerQueries : ∀ context outcome,
      V8Smz9HonestWholeViewGames.queryCount (compile (next context outcome) []) ≤ queries) :
    |uniformAverage (fun old : CurrentInput bound → DigestRegister =>
        V8Smz9MixedMaskCompiler.run true (sourceRequest data next) old (familyGameState family old)) -
      uniformAverage (fun old : CurrentInput bound → DigestRegister =>
        V8Smz9MixedMaskCompiler.run true (publicRequest data next) old (familyGameState family old))| ≤
      erasureLoss queries * normSquared (totalOracleFamilyState family) := by
  apply (average_difference_abs_le _ _).trans
  calc
    _ ≤ uniformAverage (fun old : CurrentInput bound → DigestRegister =>
        erasureLoss queries * ‖familyGameState family old‖ ^ 2) :=
      average_mono _ _ (fun old => current_request_bound_mass data next old
        (familyGameState family old) queries callerQueries)
    _ = _ := by rw [average_mul_left, ← total_oracle_family_norm_squared]

/-- Generic oracle-family adequacy from PR205, instantiated at the current raw
input type. No new oracle is drawn after the branch has been reached. -/
theorem compiled_family_execution (program : MixedProgram (CurrentInput bound) Work)
    (family : OracleRegisterFamily (Input := CurrentInput bound) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    phaseRun true (compile program []) (phaseEncode (totalOracleFamilyState family)) =
      uniformAverage (fun old : CurrentInput bound → DigestRegister =>
        V8Smz9MixedMaskCompiler.run true program old (familyGameState family old)) := by
  rw [phase_run_eq_database_run, phase_decode_encode, databaseRun_totalOracleFamilyState]
  apply congrArg uniformAverage
  funext old
  rw [databaseRun_oracleState, compile_executes, effective_empty]

/-- The reached CMS state is canonically decomposed on total-table support.
This is a representation invariant, not the desired privacy inequality. -/
theorem current_request_bound_phase (data : RequestData bound)
    (next : Context → Except String PublicResult → MixedProgram (CurrentInput bound) Work)
    (queries : Nat) (callerQueries : ∀ context outcome,
      V8Smz9HonestWholeViewGames.queryCount (compile (next context outcome) []) ≤ queries)
    (reached : ResponseCmsState (CurrentInput bound) Work)
    (supported : TotalDatabaseSupport (phaseDecode reached)) :
    |phaseRun true (compile (sourceRequest data next) []) reached -
      phaseRun true (compile (publicRequest data next) []) reached| ≤
      erasureLoss queries * normSquared reached := by
  let family := canonicalTotalFamily (phaseDecode reached)
  have same : phaseEncode (totalOracleFamilyState family) = reached := by
    rw [total_oracle_family_canonical_eq (phaseDecode reached) supported, phase_encode_decode]
  have familyMass : normSquared (totalOracleFamilyState family) = normSquared reached := by
    rw [total_oracle_family_canonical_eq (phaseDecode reached) supported, phase_decode_norm_squared]
  have bounded := current_request_bound_family data next family queries callerQueries
  rw [← compiled_family_execution, ← compiled_family_execution, same, familyMass] at bounded
  exact bounded

/-- The pending request and its complete future program are ordinary syntax.
The query field describes the same disclosed adversary class used by Source143. -/
structure Pivot (bound : Nat) (Work : Type) [Fintype Work] (queries : Nat) where
  data : RequestData bound
  next : Context → Except String PublicResult → MixedProgram (CurrentInput bound) Work
  callerQueries : ∀ context outcome,
    V8Smz9HonestWholeViewGames.queryCount (compile (next context outcome) []) ≤ queries

/-- Exact PR205 stopping-tree lift with the current request pivot proved above.
Both phase executions start from the same reached state and same original
oracle family; no local or adjacent-hybrid inequality is a hypothesis. -/
theorem current_stopped_request_bound (queries : Nat)
    (stopped : Q38Rp05StoppedMass.Prefix (CurrentInput bound) Work (Pivot bound Work queries))
    (reached : ResponseCmsState (CurrentInput bound) Work)
    (supported : TotalDatabaseSupport (phaseDecode reached)) :
    |phaseRun true (Q38Rp05StoppedSupport.closePrefix stopped
        (fun job => compile (sourceRequest job.data job.next) [])) reached -
      phaseRun true (Q38Rp05StoppedSupport.closePrefix stopped
        (fun job => compile (publicRequest job.data job.next) [])) reached| ≤
      erasureLoss queries * normSquared reached := by
  rw [Q38Rp05StoppedSupport.closed_difference_eq_pivot_fold]
  apply Q38Rp05PhaseStoppingBound.phase_gap_bound stopped _ (erasureLoss queries)
    (erasure_loss_nonnegative queries) 0 reached
  have transport (tree : Q38Rp05StoppedMass.Prefix (CurrentInput bound) Work (Pivot bound Work queries))
      (spent : Nat) (state : ResponseCmsState (CurrentInput bound) Work)
      (totals : Q38Rp05StoppedSupport.AtPivots
        (fun _ _ state => TotalDatabaseSupport (phaseDecode state)) tree spent state) :
      Q38Rp05StoppedSupport.AtPivots (fun job _ state =>
        |phaseRun true (compile (sourceRequest job.data job.next) []) state -
          phaseRun true (compile (publicRequest job.data job.next) []) state| ≤
        erasureLoss queries * normSquared state) tree spent state := by
    induction tree generalizing spent state with
    | finish event => trivial
    | pivot job => exact current_request_bound_phase job.data job.next queries job.callerQueries state totals
    | gate operation next ih => exact ih spent _ totals
    | quantumQuery next ih => exact ih (spent + 1) _ totals
    | honestRead input next ih => exact fun answer => ih answer (spent + 1) _ (totals answer)
    | instrument operation next ih => exact fun outcome => ih outcome spent _ (totals outcome)
    | random source next ih => exact fun coins => ih coins spent state (totals coins)
  exact transport stopped 0 reached
    (Q38Rp05StoppedSupport.total_support_at_every_pivot stopped 0 reached supported)

end Physical
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentHistoryMass
