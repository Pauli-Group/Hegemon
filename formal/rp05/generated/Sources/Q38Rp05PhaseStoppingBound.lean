import Q38Rp05StoppedSupport
import Q38CmsAdaptiveWholeViewBound
import Q38CmsPhaseDecodeIsometry

/-! Homogeneous physical stopping-tree lifting. -/
namespace HegemonCrypto.SmallWood.Q38Rp05PhaseStoppingBound

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.Q38Rp05StoppedMass
open HegemonCrypto.SmallWood.Q38Rp05StoppedSupport
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 1000000
set_option maxRecDepth 10000
universe u
variable {Input Work : Type} {Job : Type u}
variable [Fintype Input] [DecidableEq Input] [Fintype Work] [DecidableEq Work]

theorem born_univ (state : GameState (Input := Input) (Work := Work)) :
    born Finset.univ state = ‖state‖ ^ 2 := by
  have projection : eventProjection Finset.univ state = state := by
    ext basis
    simp [eventProjection]
  simp only [born, projection]

theorem database_mass_slices (state : ResponseCmsState Input Work) :
    normSquared state = ∑ database, ‖databaseSlice state database‖ ^ 2 := by
  rw [← database_born_univ_eq_norm_squared]
  simp only [databaseBorn, born_univ]

theorem phase_gate_mass (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) :
    normSquared (phaseGate operation state) = normSquared state := by
  rw [← phase_decode_norm_squared (phaseGate operation state), phase_decode_gate]
  rw [database_mass_slices]
  simp only [database_slice_liftGate, operation.norm_map]
  rw [← database_mass_slices, phase_decode_norm_squared]

theorem phase_query_mass (state : ResponseCmsState Input Work) :
    normSquared (phaseResponseQuery state) = normSquared state := by
  have slice (database : Database Input DigestRegister) :
      databaseSlice (databaseResponseQuery (phaseDecode state)) database =
        query (fun input => (database input).getD 0) (databaseSlice (phaseDecode state) database) := by
    ext basis
    cases answer : database basis.1 <;>
      simp [databaseSlice, databaseResponseQuery, query_apply, answer]
  rw [← phase_decode_norm_squared (phaseResponseQuery state), phase_decode_response_query]
  rw [database_mass_slices]
  simp_rw [slice, (query _).norm_map]
  rw [← database_mass_slices, phase_decode_norm_squared]

theorem phase_instrument_mass {count : Nat} (operation : Instrument Input Work count)
    (state : ResponseCmsState Input Work) :
    (∑ outcome, normSquared (phaseInstrumentBranch operation outcome state)) = normSquared state := by
  calc
    _ = ∑ outcome, ∑ database,
        ‖operation.branch outcome (databaseSlice (phaseDecode state) database)‖ ^ 2 := by
      apply Finset.sum_congr rfl
      intro outcome _
      rw [← phase_decode_norm_squared (phaseInstrumentBranch operation outcome state),
        phase_decode_instrument_branch, database_mass_slices]
      simp only [database_slice_liftInstrumentBranch]
    _ = ∑ database, ∑ outcome,
        ‖operation.branch outcome (databaseSlice (phaseDecode state) database)‖ ^ 2 :=
      Finset.sum_comm
    _ = ∑ database, ‖databaseSlice (phaseDecode state) database‖ ^ 2 := by
      apply Finset.sum_congr rfl
      intro database _
      exact operation.complete _
    _ = normSquared (phaseDecode state) := (database_mass_slices _).symm
    _ = normSquared state := phase_decode_norm_squared state

/-- On total support equality holds; the inequality below also covers partial
database states and is sufficient for the stopping bound. -/
theorem phase_read_mass_le (input : Input) (state : ResponseCmsState Input Work) :
    (∑ answer, normSquared (phaseReadBranch input answer state)) ≤ normSquared state := by
  simp_rw [← phase_decode_norm_squared (phaseReadBranch input _ state), phase_decode_read_branch]
  rw [← phase_decode_norm_squared state]
  unfold normSquared databaseReadBranch coordinateEventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  cases basis.database input with
  | none => simp [Complex.normSq_nonneg]
  | some value =>
      simp only [Option.some.injEq]
      rw [Finset.sum_eq_single value]
      · simp only [ite_true]
        exact le_rfl
      · intro other _ different
        simp only [if_neg (Ne.symm different), Complex.normSq_zero]
      · intro absent
        exact (absent (Finset.mem_univ _)).elim

/-- A localBound bound is charged only at reached pivots and multiplied by actual
incoming mass. This generic lifting lemma is instantiated with the derived
current-request bound; it is not itself the privacy endpoint. -/
theorem phase_gap_bound (stopped : Prefix Input Work Job)
    (gap : Job → ResponseCmsState Input Work → ℝ) (loss : ℝ) (nonnegative : 0 ≤ loss)
    (spent : Nat) (state : ResponseCmsState Input Work)
    (localBound : AtPivots (fun job _ reached => |gap job reached| ≤ loss * normSquared reached)
      stopped spent state) :
    |phaseGap stopped gap state| ≤ loss * normSquared state := by
  induction stopped generalizing spent state with
  | finish event =>
      simp only [phaseGap, abs_zero]
      exact mul_nonneg nonnegative (Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _)
  | pivot job => exact localBound
  | gate operation next ih =>
      simpa only [phaseGap, phase_gate_mass] using ih spent _ localBound
  | quantumQuery next ih =>
      simpa only [phaseGap, phase_query_mass] using ih (spent + 1) _ localBound
  | honestRead input next ih =>
      change |∑ answer, _| ≤ _
      apply (Finset.abs_sum_le_sum_abs _ _).trans
      calc
        _ ≤ ∑ answer, loss * normSquared (phaseReadBranch input answer state) :=
          Finset.sum_le_sum fun answer _ => ih answer (spent + 1) _ (localBound answer)
        _ = loss * ∑ answer, normSquared (phaseReadBranch input answer state) :=
          (Finset.mul_sum _ _ _).symm
        _ ≤ _ := mul_le_mul_of_nonneg_left (phase_read_mass_le input state) nonnegative
  | instrument operation next ih =>
      change |∑ outcome, _| ≤ _
      apply (Finset.abs_sum_le_sum_abs _ _).trans
      calc
        _ ≤ ∑ outcome, loss * normSquared (phaseInstrumentBranch operation outcome state) :=
          Finset.sum_le_sum fun outcome _ => ih outcome spent _ (localBound outcome)
        _ = _ := by rw [← Finset.mul_sum, phase_instrument_mass]
  | random source next ih =>
      change |uniformAverage _| ≤ _
      unfold uniformAverage
      apply (Finset.abs_sum_le_sum_abs _ _).trans
      calc
        _ ≤ ∑ coins : source.Coins,
            (uniformFintypePMF source.Coins coins).toReal * (loss * normSquared state) := by
          apply Finset.sum_le_sum
          intro coins _
          rw [abs_mul, abs_of_nonneg ENNReal.toReal_nonneg]
          exact mul_le_mul_of_nonneg_left (ih coins spent state (localBound coins)) ENNReal.toReal_nonneg
        _ = _ := uniform_average_const _

end
end HegemonCrypto.SmallWood.Q38Rp05PhaseStoppingBound
