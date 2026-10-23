import HegemonCrypto.NativePrivateSpendQ58Compff01OpeningContinuation
import HegemonCrypto.NativePrivateSpendQ58Wpcs
import HegemonCrypto.NativePrivateSpendQ58Compff01ClosedLinearRecovery

/-! The row count is an index, not a new scalar algebra proof for every row.
The current head/tail continuation is imported from retained checked source.
This component constructs joint transport of ideal field coordinates. It does
not assert complete public simulation, a source refinement, or a QROM bound.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRowBoundary
open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open V8Smz9EagerPrivacy
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev W (rows : Nat) := Fin rows → Fin 6 → Goldilocks
abbrev Values (rows : Nat) := Fin rows → Fin 64 → Goldilocks
abbrev P := NativePrivateSpendQ58Wpcs.P
abbrev Q := NativePrivateSpendQ58ChronologicalMasks.Q
abbrev D := Fin 5 → Fin 13173 → Goldilocks
abbrev Gamma := Fin 5 → Fin 140 → Goldilocks
abbrev Heads := NativePrivateSpendQ58Compff01OpeningContinuation.Heads
abbrev Tails := NativePrivateSpendQ58Compff01OpeningContinuation.Tails
abbrev Earlier := NativePrivateSpendQ58Compff01OpeningContinuation.Earlier
abbrev Later := NativePrivateSpendQ58Compff01OpeningContinuation.Later
abbrev Targets := NativePrivateSpendQ58Compff01OpeningContinuation.Targets
abbrev TailView := Earlier × Later
abbrev Base (rows : Nat) := W rows × (P × Tails)
abbrev Coins (rows : Nat) := W rows × (Q × (P × (Tails × D)))
abbrev Response := D × Q
abbrev View (rows : Nat) := Response × ((W rows × P) × TailView)

/-- Reuse the six-coordinate scalar proof, then take its finite product. -/
def witnessEquiv {rows : Nat} (values : Values rows)
    (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points) : W rows ≃ W rows :=
  Equiv.piCongrRight fun row =>
    (NativePrivateSpendQ58Wpcs.witnessBlockEquiv points admissible).trans
      (Equiv.addLeft fun opening =>
        (sourceWitnessBasePolynomial (values row)).eval (points opening))

/-- All current 13173 DECS coordinates are retained, including 58 tail nodes. -/
def decsOffset (gamma : Gamma) (heads : Heads) (tails : Tails) : D :=
  fun polynomial coefficient =>
    (Lagrange.interpolate (Finset.univ : Finset (Fin 13173))
      (fun node => (node.val : Goldilocks))
      (fun node => ∑ row : Fin 140, gamma polynomial row *
        Fin.append (tails row) (heads row) node)).coeff coefficient.val

/-- Dependency order is explicit: heads use original PIOP masks and PCS coins;
the unmasked PIOP reply may depend on the already published DECS response. -/
structure Model (rows : Nat) where
  gamma : Gamma
  heads : W rows → P → Q → Heads
  piopUnmasked : W rows → D → Q

def maskForward {rows : Nat} (model : Model rows) (base : Base rows)
    (masks : Q × D) : Response :=
  let reply := decsOffset model.gamma (model.heads base.1 base.2.1 masks.1)
    base.2.2 + masks.2
  (reply, model.piopUnmasked base.1 reply + masks.1)

def maskInverse {rows : Nat} (model : Model rows) (base : Base rows)
    (output : Response) : Q × D :=
  let q := output.2 - model.piopUnmasked base.1 output.1
  (q, output.1 - decsOffset model.gamma (model.heads base.1 base.2.1 q) base.2.2)

theorem mask_inverse_forward {rows : Nat} (model : Model rows) (base : Base rows)
    (masks : Q × D) : maskInverse model base (maskForward model base masks) = masks := by
  simp [maskInverse, maskForward]

theorem mask_forward_inverse {rows : Nat} (model : Model rows) (base : Base rows)
    (output : Response) : maskForward model base (maskInverse model base output) = output := by
  have reply : decsOffset model.gamma
      (model.heads base.1 base.2.1 (output.2 - model.piopUnmasked base.1 output.1)) base.2.2 +
      (output.1 - decsOffset model.gamma
        (model.heads base.1 base.2.1 (output.2 - model.piopUnmasked base.1 output.1)) base.2.2) =
      output.1 := by abel
  simp only [maskForward, maskInverse, reply]
  congr 1
  abel

def maskEquiv {rows : Nat} (model : Model rows) (base : Base rows) :
    (Q × D) ≃ Response where
  toFun := maskForward model base
  invFun := maskInverse model base
  left_inv := mask_inverse_forward model base
  right_inv := mask_forward_inverse model base

def roleOrder (rows : Nat) : Coins rows ≃ (Base rows × (Q × D)) where
  toFun coins := ((coins.1, coins.2.2.1, coins.2.2.2.1), (coins.2.1, coins.2.2.2.2))
  invFun value := (value.1.1, value.2.1, value.1.2.1, value.1.2.2, value.2.2)
  left_inv _ := rfl
  right_inv _ := rfl

def responseFirst (rows : Nat) :
    (Base rows × Response) ≃ (Response × ((W rows × P) × Tails)) where
  toFun value := (value.2, ((value.1.1, value.1.2.1), value.1.2.2))
  invFun value := ((value.2.1.1, value.2.1.2, value.2.2), value.1)
  left_inv _ := rfl
  right_inv _ := rfl

def maskStage {rows : Nat} (model : Model rows) :
    Coins rows ≃ (Response × ((W rows × P) × Tails)) :=
  (roleOrder rows).trans
    ((NativePrivateSpendQ58ChronologicalMasks.fiberEquiv (maskEquiv model)).trans
      (responseFirst rows))

/-- Recover Q from W,D,T before transforming PCS coins. There is no premise
that masks remain independent after the public DECS response was observed. -/
def conditionedEquiv {rows : Nat} (values : Values rows)
    (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (nonzero : ∀ opening, points opening ≠ 0)
    (model : Model rows) (response : Response) : (W rows × P) ≃ (W rows × P) :=
  let ew := witnessEquiv values points admissible
  (Equiv.prodCongr ew (Equiv.refl P)).trans
    (NativePrivateSpendQ58ChronologicalMasks.fiberEquiv fun z =>
      NativePrivateSpendQ58Wpcs.partialEquiv points
        admissible.openingPointsInjective nonzero
        (response.2 - model.piopUnmasked (ew.symm z) response.1))

def remainingEquiv {rows : Nat} (values : Values rows)
    (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (nonzero : ∀ opening, points opening ≠ 0)
    (model : Model rows) (response : Response)
    (choose : W rows → P → Earlier → Targets) :
    ((W rows × P) × Tails) ≃ ((W rows × P) × TailView) :=
  let e := conditionedEquiv values points admissible nonzero model response
  (Equiv.prodCongr e (Equiv.refl Tails)).trans
    (NativePrivateSpendQ58ChronologicalMasks.fiberEquiv fun output =>
      let old := e.symm output
      NativePrivateSpendQ58Compff01OpeningContinuation.feedbackEquiv
        points admissible.openingPointsInjective
        (model.heads old.1 old.2 (response.2 - model.piopUnmasked old.1 response.1))
        (choose output.1 output.2))

def wholeEquiv {rows : Nat} (values : Values rows)
    (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (nonzero : ∀ opening, points opening ≠ 0)
    (model : Model rows) (choose : Response → W rows → P → Earlier → Targets) :
    Coins rows ≃ View rows :=
  (maskStage model).trans
    (NativePrivateSpendQ58ChronologicalMasks.fiberEquiv fun response =>
      remainingEquiv values points admissible nonzero model response (choose response))

theorem whole_joint_uniform {rows : Nat} (values : Values rows)
    (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (nonzero : ∀ opening, points opening ≠ 0)
    (model : Model rows) (choose : Response → W rows → P → Earlier → Targets) :
    pmfMap (uniformFintypePMF (Coins rows))
      (wholeEquiv values points admissible nonzero model choose) =
      uniformFintypePMF (View rows) :=
  uniform_pmf_map_equiv (wholeEquiv values points admissible nonzero model choose)

abbrev CurrentModel := Model 26210
abbrev CurrentValues := Values 26210
abbrev CurrentCoins := Coins 26210
abbrev CurrentView := View 26210

/-- Public linear-mask recovery already has an authentic checked Fin26210
specialization. Keep its genuine packing-sum validity premise visible. -/
abbrev current_linear_mask_recovery :=
  NativePrivateSpendQ58Compff01ClosedLinearRecovery.closed_linear_coins_recovered_from_opened_rows

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRowBoundary
