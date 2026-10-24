import HegemonCrypto.NativePrivateSpendQ58CurrentRowBoundary

/-! Opening points may be selected from the already public DECS/PIOP replies.
This closes the fixed-points restriction of the scalar/current-row transport.
The public request schedule and its error projection still need a concrete
source constructor; no arbitrary Model is promoted to a public simulator. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentResponseIndexedTransport

open NativePrivateSpendQ58CurrentRowBoundary
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

def responseIndexedEquiv {rows : Nat} (values : Values rows)
    (points : Response → Fin 6 → Goldilocks)
    (admissible : ∀ reply, Smz9WitnessInterpolationAdmissible (points reply))
    (nonzero : ∀ reply opening, points reply opening ≠ 0)
    (model : Model rows) (choose : Response → W rows → P → Earlier → Targets) :
    Coins rows ≃ View rows :=
  (maskStage model).trans
    (NativePrivateSpendQ58ChronologicalMasks.fiberEquiv fun reply =>
      remainingEquiv values (points reply) (admissible reply) (nonzero reply)
        model reply (choose reply))

/-- There is no post-DECS independence assumption: the response-dependent
fiber bijection follows the joint mask transport in the same coin space. -/
theorem response_indexed_joint_uniform {rows : Nat} (values : Values rows)
    (points : Response → Fin 6 → Goldilocks)
    (admissible : ∀ reply, Smz9WitnessInterpolationAdmissible (points reply))
    (nonzero : ∀ reply opening, points reply opening ≠ 0)
    (model : Model rows) (choose : Response → W rows → P → Earlier → Targets) :
    pmfMap (uniformFintypePMF (Coins rows))
      (responseIndexedEquiv values points admissible nonzero model choose) =
        uniformFintypePMF (View rows) :=
  V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv
    (responseIndexedEquiv values points admissible nonzero model choose)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentResponseIndexedTransport
