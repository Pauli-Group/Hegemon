import Q38WholeViewCmsSemantics

/-! Generic stopping-tree mass ledger, separated from the current request
compiler without changing definitions or theorem statements. -/
namespace HegemonCrypto.SmallWood.Q38Rp05StoppedMass

open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 1000000
set_option maxRecDepth 10000
universe u
variable {Input Work : Type} {Job : Type u} [Fintype Input] [DecidableEq Input]
variable [Fintype Work]

abbrev Family (Input Work : Type) [Fintype Input] [Fintype Work] :=
  (Input → DigestRegister) → GameState (Input := Input) (Work := Work)

def mass (family : Family Input Work) : ℝ :=
  uniformAverage fun oracle => ‖family oracle‖ ^ 2

def readFamily (input : Input) (answer : DigestRegister)
    (family : Family Input Work) : Family Input Work :=
  fun oracle => if oracle input = answer then family oracle else 0

theorem mass_nonnegative (family : Family Input Work) : 0 ≤ mass family := by
  unfold mass uniformAverage
  exact Finset.sum_nonneg fun _ _ => mul_nonneg ENNReal.toReal_nonneg (sq_nonneg _)

theorem read_mass_complete (input : Input) (family : Family Input Work) :
    (∑ answer : DigestRegister, mass (readFamily input answer family)) = mass family := by
  unfold mass uniformAverage
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro oracle _
  rw [← Finset.mul_sum]
  apply congrArg (fun value : ℝ =>
    (uniformFintypePMF (Input → DigestRegister) oracle).toReal * value)
  rw [Finset.sum_eq_single (oracle input)]
  · simp only [readFamily, ite_true]
  · intro answer _ different
    simp only [readFamily, if_neg (Ne.symm different), norm_zero, zero_pow (by decide : 2 ≠ 0)]
  · intro absent
    exact (absent (Finset.mem_univ _)).elim

theorem instrument_mass_complete {count : Nat}
    (operation : Instrument Input Work count) (family : Family Input Work) :
    (∑ outcome, mass (fun oracle => operation.branch outcome (family oracle))) =
      mass family := by
  unfold mass uniformAverage
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro oracle _
  rw [← Finset.mul_sum, operation.complete]

/-- This is the real-stopped syntax after false fresh inputs have been compiled
to sampled honest reads. Finish represents stopping without another request.
There is deliberately no write constructor before the reverse-hybrid pivot. -/
inductive Prefix (Input Work : Type) (Job : Type u) [Fintype Input] [Fintype Work] : Type (max 1 u) where
  | finish (event : Finset (QueryBasis Input DigestRegister Work)) : Prefix Input Work Job
  | pivot (job : Job) : Prefix Input Work Job
  | gate (operation : GameGate (Input := Input) (Work := Work))
      (next : Prefix Input Work Job) : Prefix Input Work Job
  | quantumQuery (next : Prefix Input Work Job) : Prefix Input Work Job
  | honestRead (input : Input) (next : DigestRegister → Prefix Input Work Job) :
      Prefix Input Work Job
  | instrument {count : Nat} (operation : Instrument Input Work count)
      (next : Fin count → Prefix Input Work Job) : Prefix Input Work Job
  | random (source : RandomSource) (next : source.Coins → Prefix Input Work Job) :
      Prefix Input Work Job

/-- Actual stopping tree, with each observed answer restricting the SAME
initial family. This expression never recomputes a selector on a new oracle. -/
def arrivalMass : Prefix Input Work Job → Family Input Work → ℝ
  | .finish _, _ => 0
  | .pivot _, family => mass family
  | .gate operation next, family =>
      arrivalMass next (fun oracle => operation (family oracle))
  | .quantumQuery next, family =>
      arrivalMass next (fun oracle => query oracle (family oracle))
  | .honestRead input next, family =>
      ∑ answer, arrivalMass (next answer) (readFamily input answer family)
  | .instrument operation next, family =>
      ∑ outcome, arrivalMass (next outcome)
        (fun oracle => operation.branch outcome (family oracle))
  | .random source next, family =>
      uniformAverage fun coins : source.Coins => arrivalMass (next coins) family

/-- Every stopping branch contributes its original subnormalized mass.
An early abort can only reduce total pivot mass. Neither the count of histories
nor an inverse success probability appears. -/
theorem stopped_mass_le (stopped : Prefix Input Work Job) (family : Family Input Work) :
    arrivalMass stopped family ≤ mass family := by
  induction stopped generalizing family with
  | finish event => exact mass_nonnegative family
  | pivot job => exact le_rfl
  | gate operation next ih =>
      simpa only [arrivalMass, mass, operation.norm_map] using
        ih (fun oracle => operation (family oracle))
  | quantumQuery next ih =>
      simpa only [arrivalMass, mass, (query _).norm_map] using
        ih (fun oracle => query oracle (family oracle))
  | honestRead input next ih =>
      calc
        _ ≤ ∑ answer, mass (readFamily input answer family) :=
          Finset.sum_le_sum fun answer _ => ih answer _
        _ = _ := read_mass_complete input family
  | instrument operation next ih =>
      calc
        _ ≤ ∑ outcome, mass (fun oracle => operation.branch outcome (family oracle)) :=
          Finset.sum_le_sum fun outcome _ => ih outcome _
        _ = _ := instrument_mass_complete operation family
  | random source next ih =>
      change uniformAverage _ ≤ _
      calc
        _ ≤ uniformAverage (fun _ : source.Coins => mass family) := by
          unfold uniformAverage
          exact Finset.sum_le_sum fun coins _ =>
            mul_le_mul_of_nonneg_left (ih coins family) ENNReal.toReal_nonneg
        _ = _ := uniform_average_const _

end
end HegemonCrypto.SmallWood.Q38Rp05StoppedMass
