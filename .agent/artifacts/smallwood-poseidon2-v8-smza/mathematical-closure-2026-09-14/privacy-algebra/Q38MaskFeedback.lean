import Q38JointSimulatorR2
import HegemonCrypto.SmallWoodV8Smz9EagerPrivacy

namespace HegemonCrypto.SmallWood.V8SmzaMaskFeedback
open V8Smz9EagerPrivacy V8SmzaMathPrivacy
open V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

abbrev MaskCoins (F : Type*) := PiopCoefficients F × Decs F
abbrev MaskOutputs (F : Type*) := Decs F × PiopCoefficients F

/-- Actual feedback order: Q fixes committed heads; M hides D; D selects the
    public PIOP challenges, whose unmasked output is then hidden by Q. -/
def forward {F : Type*} [Field F] (gamma : Gamma F)
    (heads : PiopCoefficients F → Heads F) (tails : Tails F)
    (piopUnmasked : Decs F → PiopCoefficients F) (coins : MaskCoins F) : MaskOutputs F :=
  let reply := response gamma (heads coins.1) tails coins.2
  (reply, piopUnmasked reply + coins.1)

def inverse {F : Type*} [Field F] (gamma : Gamma F)
    (heads : PiopCoefficients F → Heads F) (tails : Tails F)
    (piopUnmasked : Decs F → PiopCoefficients F) (outputs : MaskOutputs F) : MaskCoins F :=
  let q := outputs.2 - piopUnmasked outputs.1
  (q, outputs.1 - unmasked gamma (heads q) tails)

theorem inverse_after_forward {F : Type*} [Field F] (gamma : Gamma F)
    (heads : PiopCoefficients F → Heads F) (tails : Tails F)
    (piopUnmasked : Decs F → PiopCoefficients F) (coins : MaskCoins F) :
    inverse gamma heads tails piopUnmasked (forward gamma heads tails piopUnmasked coins) = coins := by
  simp only [inverse, forward, add_sub_cancel_left]
  change (coins.1, unmasked gamma (heads coins.1) tails + coins.2 -
    unmasked gamma (heads coins.1) tails) = coins
  rw [add_sub_cancel_left]

theorem forward_after_inverse {F : Type*} [Field F] (gamma : Gamma F)
    (heads : PiopCoefficients F → Heads F) (tails : Tails F)
    (piopUnmasked : Decs F → PiopCoefficients F) (outputs : MaskOutputs F) :
    forward gamma heads tails piopUnmasked (inverse gamma heads tails piopUnmasked outputs) = outputs := by
  have replyEq : response gamma (heads (outputs.2 - piopUnmasked outputs.1)) tails
      (outputs.1 - unmasked gamma (heads (outputs.2 - piopUnmasked outputs.1)) tails) = outputs.1 := by
    unfold response
    abel
  simp only [forward, inverse, replyEq]
  congr 1
  abel

def maskEquiv {F : Type*} [Field F] (gamma : Gamma F)
    (heads : PiopCoefficients F → Heads F) (tails : Tails F)
    (piopUnmasked : Decs F → PiopCoefficients F) : MaskCoins F ≃ MaskOutputs F where
  toFun := forward gamma heads tails piopUnmasked
  invFun := inverse gamma heads tails piopUnmasked
  left_inv := inverse_after_forward gamma heads tails piopUnmasked
  right_inv := forward_after_inverse gamma heads tails piopUnmasked

/-- Full2030 DECS coefficients and3105 PIOP coefficients are jointly uniform;
    Q-dependent committed heads and D-dependent PIOP challenges are retained. -/
theorem q38_decs_piop_joint_uniform {F : Type*} [Field F] [Fintype F]
    (gamma : Gamma F) (heads : PiopCoefficients F → Heads F) (tails : Tails F)
    (piopUnmasked : Decs F → PiopCoefficients F) :
    pmfMap (uniformFintypePMF (MaskCoins F)) (forward gamma heads tails piopUnmasked) =
      uniformFintypePMF (MaskOutputs F) :=
  uniform_pmf_map_equiv (maskEquiv gamma heads tails piopUnmasked)

/-- Arbitrary continuation retains the old masks through the constructive
    inverse. In particular witness-dependent leaf inputs are not erased. -/
theorem q38_mask_transport_retains_coins {F Output : Type*} [Field F] [Fintype F]
    (gamma : Gamma F) (heads : PiopCoefficients F → Heads F) (tails : Tails F)
    (piopUnmasked : Decs F → PiopCoefficients F)
    (observe : MaskCoins F → MaskOutputs F → PMF Output) :
    ((uniformFintypePMF (MaskCoins F)).bind fun coins =>
      observe coins (forward gamma heads tails piopUnmasked coins)) =
    ((uniformFintypePMF (MaskOutputs F)).bind fun outputs =>
      observe (inverse gamma heads tails piopUnmasked outputs) outputs) := by
  let transport := maskEquiv gamma heads tails piopUnmasked
  calc
    _ = (pmfMap (uniformFintypePMF (MaskCoins F)) transport).bind
        (fun outputs => observe (transport.symm outputs) outputs) := by
      simp only [pmfMap, PMF.bind_bind, Function.comp_def, PMF.pure_bind,
        Equiv.symm_apply_apply]
      rfl
    _ = _ := by rw [uniform_pmf_map_equiv transport]; rfl

end
end HegemonCrypto.SmallWood.V8SmzaMaskFeedback
