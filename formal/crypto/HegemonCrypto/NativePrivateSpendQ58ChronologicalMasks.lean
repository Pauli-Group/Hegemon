import HegemonCrypto.NativePrivateSpendQ58LvcsJoint

/-!
A sequential ideal-field-coin transport, retaining witness and PCS coins.
No hypothesis says masks/tails remain independent after a DECS observation.
An explicit bijection proves the joint law before any coordinate is hidden.
Actual cryptographic oracle chronology and removal of retained witness/PCS
coins are NOT established by this component.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58ChronologicalMasks
open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

abbrev W := Fin 26203 → Fin 6 → Goldilocks
abbrev P := Fin 6 → Fin 10 → Goldilocks
/-- Degree74 nonlinear masks and132 nonconstant zero-sum linear coordinates. -/
abbrev Q := (Fin 5 → Fin 75 → Goldilocks) × (Fin 5 → Fin 132 → Goldilocks)
abbrev D := Fin 5 → Fin 13170 → Goldilocks
abbrev Gamma := Fin 5 → Fin 140 → Goldilocks
abbrev Heads := NativePrivateSpendQ58LvcsJoint.Heads
abbrev Tails := NativePrivateSpendQ58LvcsJoint.Tails
abbrev Earlier := NativePrivateSpendQ58LvcsJoint.Earlier
abbrev Later := NativePrivateSpendQ58LvcsJoint.Later
abbrev Targets := NativePrivateSpendQ58LvcsJoint.Targets
abbrev TailView := Earlier × Later
/-- Source role order: witness interpolation, PIOP masks, PCS, LVCS, DECS. -/
abbrev Coins := W × (Q × (P × (Tails × D)))
abbrev Base := W × (P × Tails)
abbrev Prefix := W × (P × (D × Q))
abbrev View := Prefix × TailView

/-- Literal full DECS response offset: interpolate the gamma-combined rotated
rows, then retain ALL13170 coefficients, as pcs_commit_transcript_words does. -/
def decsOffset (gamma : Gamma) (heads : Heads) (tails : Tails) : D :=
  fun polynomial coefficient =>
    (Lagrange.interpolate (Finset.univ : Finset (Fin 13170))
      (fun node => (node.val : Goldilocks))
      (fun node => ∑ row : Fin 140, gamma polynomial row *
        Fin.append (tails row) (heads row) node)).coeff coefficient.val

/-- Physical head construction and unmasked PIOP batching remain explicit
source functions. Their argument lists enforce the necessary dependency order. -/
structure Model where
  gamma : Gamma
  heads : W → P → Q → Heads
  piopUnmasked : W → D → Q

/-- May capture already-retained W/PCS and public response context. No current
LVCS tail is accessible except through the published Earlier argument. -/
structure Plan where
  points : Fin 6 → Goldilocks
  distinct : Function.Injective points
  fallback : Targets
  choose : Earlier → Option Targets

def totalChoose (plan : Plan) (early : Earlier) : Targets :=
  (plan.choose early).getD plan.fallback

abbrev Plans := W → P → D → Q → Plan

def maskForward (model : Model) (base : Base) (masks : Q × D) : D × Q :=
  let reply := decsOffset model.gamma (model.heads base.1 base.2.1 masks.1) base.2.2 + masks.2
  (reply, model.piopUnmasked base.1 reply + masks.1)

def maskInverse (model : Model) (base : Base) (output : D × Q) : Q × D :=
  let q := output.2 - model.piopUnmasked base.1 output.1
  (q, output.1 - decsOffset model.gamma (model.heads base.1 base.2.1 q) base.2.2)

theorem mask_inverse_forward (model : Model) (base : Base) (masks : Q × D) :
    maskInverse model base (maskForward model base masks) = masks := by
  simp [maskInverse, maskForward]

theorem mask_forward_inverse (model : Model) (base : Base) (output : D × Q) :
    maskForward model base (maskInverse model base output) = output := by
  have reply : decsOffset model.gamma
      (model.heads base.1 base.2.1 (output.2 - model.piopUnmasked base.1 output.1)) base.2.2 +
      (output.1 - decsOffset model.gamma
        (model.heads base.1 base.2.1 (output.2 - model.piopUnmasked base.1 output.1)) base.2.2) =
      output.1 := by abel
  simp only [maskForward, maskInverse, reply]
  congr 1
  abel

def maskEquiv (model : Model) (base : Base) : (Q × D) ≃ (D × Q) where
  toFun := maskForward model base
  invFun := maskInverse model base
  left_inv := mask_inverse_forward model base
  right_inv := mask_forward_inverse model base

/-- Retain every coin used to choose a fiber map, rather than silently
conditioning its distribution. -/
def fiberEquiv {A B C : Type*} (maps : A → B ≃ C) : (A × B) ≃ (A × C) where
  toFun value := (value.1, maps value.1 value.2)
  invFun value := (value.1, (maps value.1).symm value.2)
  left_inv value := by simp
  right_inv value := by simp

def roleOrder : Coins ≃ (Base × (Q × D)) where
  toFun coins := ((coins.1, coins.2.2.1, coins.2.2.2.1), (coins.2.1, coins.2.2.2.2))
  invFun value := (value.1.1, value.2.1, value.1.2.1, value.1.2.2, value.2.2)
  left_inv _ := rfl
  right_inv _ := rfl

def responseOrder : (Base × (D × Q)) ≃ (Prefix × Tails) where
  toFun value := ((value.1.1, value.1.2.1, value.2.1, value.2.2), value.1.2.2)
  invFun value := ((value.1.1, value.1.2.1, value.2), value.1.2.2)
  left_inv _ := rfl
  right_inv _ := rfl

/-- Recover Q BEFORE eliminating tails. This Q depends on W,D,T but no tail,
so the already-checked LVCS fiber inverse applies without a fresh-independence
premise after D was observed. -/
def tailEquiv (model : Model) (plans : Plans) (pre : Prefix) : Tails ≃ TailView :=
  let q := pre.2.2.2 - model.piopUnmasked pre.1 pre.2.2.1
  let heads := model.heads pre.1 pre.2.1 q
  let plan := plans pre.1 pre.2.1 pre.2.2.1 pre.2.2.2
  NativePrivateSpendQ58LvcsJoint.feedbackEquiv plan.points plan.distinct heads (totalChoose plan)

def sequentialEquiv (model : Model) (plans : Plans) : Coins ≃ View :=
  roleOrder.trans ((fiberEquiv (maskEquiv model)).trans
    (responseOrder.trans (fiberEquiv (tailEquiv model plans))))

/-- Concrete forward chronology: actual Q-dependent heads; full DECS reply;
D-dependent unmasked PIOP plus Q; same-tail LVCS feedback. -/
def sequentialOutput (model : Model) (plans : Plans) (coins : Coins) : View :=
  let w := coins.1
  let q := coins.2.1
  let p := coins.2.2.1
  let tails := coins.2.2.2.1
  let d := decsOffset model.gamma (model.heads w p q) tails + coins.2.2.2.2
  let t := model.piopUnmasked w d + q
  let plan := plans w p d t
  ((w, p, d, t),
    NativePrivateSpendQ58LvcsJoint.feedbackEquiv plan.points plan.distinct
      (model.heads w p q) (totalChoose plan) tails)

theorem sequential_equiv_matches (model : Model) (plans : Plans) (coins : Coins) :
    sequentialEquiv model plans coins = sequentialOutput model plans coins := by
  simp only [sequentialEquiv, roleOrder, fiberEquiv, maskEquiv, maskForward,
    responseOrder, tailEquiv, sequentialOutput, Equiv.trans_apply,
    Equiv.coe_fn_mk, add_sub_cancel_left]

/-- Complete joint law includes W and PCS coins. It proves, rather than
assumes, the needed remaining-tail distribution after the D/T change of variables. -/
theorem sequential_joint_uniform (model : Model) (plans : Plans) :
    pmfMap (uniformFintypePMF Coins) (sequentialOutput model plans) =
      uniformFintypePMF View := by
  have functions : sequentialOutput model plans = sequentialEquiv model plans := by
    funext coins
    exact (sequential_equiv_matches model plans coins).symm
  rw [functions]
  exact uniform_pmf_map_equiv (sequentialEquiv model plans)

/-- The old masks, leaf preimages and any other coin-dependent observation
are kept through the inverse. Nothing is erased by this change of variables. -/
theorem transport_arbitrary_continuation {Result : Type*}
    (model : Model) (plans : Plans) (observe : Coins → View → PMF Result) :
    ((uniformFintypePMF Coins).bind fun coins =>
      observe coins (sequentialEquiv model plans coins)) =
    ((uniformFintypePMF View).bind fun view =>
      observe ((sequentialEquiv model plans).symm view) view) := by
  let transport := sequentialEquiv model plans
  calc
    _ = (pmfMap (uniformFintypePMF Coins) transport).bind
        (fun view => observe (transport.symm view) view) := by
      simp only [pmfMap, PMF.bind_bind, Function.comp_def, PMF.pure_bind,
        Equiv.symm_apply_apply]
      rfl
    _ = _ := by rw [uniform_pmf_map_equiv transport]

/-- Finite instrument outcomes and arbitrary unnormalized state-valued
kernels remain in the sum. This does NOT make the instrument public-only. -/
theorem transport_instrument_kernel {Branch Value : Type*}
    [Fintype Branch] [AddCommMonoid Value]
    (models : Branch → Model) (plans : Branch → Plans)
    (kernel : Branch → Coins → View → Value) :
    (∑ coins, ∑ branch, kernel branch coins
      (sequentialEquiv (models branch) (plans branch) coins)) =
      ∑ view, ∑ branch, kernel branch
        ((sequentialEquiv (models branch) (plans branch)).symm view) view := by
  rw [Finset.sum_comm]
  calc
    _ = ∑ branch, ∑ view, kernel branch
        ((sequentialEquiv (models branch) (plans branch)).symm view) view := by
      apply Finset.sum_congr rfl
      intro branch _
      let e := sequentialEquiv (models branch) (plans branch)
      have reindex := e.sum_comp (fun view => kernel branch (e.symm view) view)
      simpa only [Equiv.symm_apply_apply] using reindex
    _ = _ := Finset.sum_comm

/-- DECS sampler failure retains its exact prefix-dependent event. The
fallback only totalizes the unused later coordinates on failed branches. -/
def abortObservation (plans : Plans) (view : View) : Prefix × (Earlier × Option Later) :=
  let pre := view.1
  let plan := plans pre.1 pre.2.1 pre.2.2.1 pre.2.2.2
  (pre, view.2.1, (plan.choose view.2.1).map fun _ => view.2.2)

theorem sequential_abort_law (model : Model) (plans : Plans) :
    pmfMap (uniformFintypePMF Coins)
        (abortObservation plans ∘ sequentialOutput model plans) =
      pmfMap (uniformFintypePMF View) (abortObservation plans) := by
  have law := congrArg (fun law => pmfMap law (abortObservation plans))
    (sequential_joint_uniform model plans)
  rw [pmfMap_comp] at law
  exact law

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58ChronologicalMasks
