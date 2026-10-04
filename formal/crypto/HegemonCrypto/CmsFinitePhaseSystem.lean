import HegemonCrypto.CmsCompressedOracle
import Mathlib.Analysis.SpecialFunctions.Complex.Circle
import Mathlib.Topology.Instances.AddCircle.Real

/-!
# Complete cyclic Fourier phase system

The compressed-oracle kernel is written in a phase basis.  Modeling an unrestricted quantum
random-oracle query therefore requires the phase labels to enumerate every additive character of
the finite output group exactly once.  The active logical SmallWood output group is deliberately
the cyclic group on its finite cardinality.  This module supplies its explicit standard Fourier
pairing through `ZMod.stdAddChar`; no arbitrary character enumeration is chosen.
-/

namespace HegemonCrypto.CmsFinitePhaseSystem

open HegemonCrypto.CmsCompressedOracle
open Complex Function

noncomputable section

set_option linter.unusedSectionVars false

variable {Output : Type*}
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable {modulus : Nat} [NeZero modulus]

/-- A phase system is complete when phase labels are unique and span the output dimension. -/
structure CompletePhaseSystem
    (Output Phase : Type*)
    [AddCommGroup Output] [Fintype Output] [Fintype Phase] where
  system : PhaseSystem Output Phase
  characterInjective : Function.Injective system.character
  phaseDimension : Fintype.card Phase = Fintype.card Output

/-- The usual exponential character on the additive circle, without importing roots-of-unity
machinery that the finite compressed-oracle proof does not use. -/
noncomputable def circleCharacter {period : ℝ} :
    AddChar (AddCircle period) Circle where
  toFun := AddCircle.toCircle
  map_zero_eq_one' := AddCircle.toCircle_zero
  map_add_eq_mul' := AddCircle.toCircle_add

/-- Standard injective circle-valued character on `ZMod modulus`. -/
noncomputable def zmodCircleCharacter :
    AddChar (ZMod modulus) Circle :=
  circleCharacter.compAddMonoidHom ZMod.toAddCircle

/-- Standard complex-valued character on `ZMod modulus`. -/
noncomputable def zmodComplexCharacter :
    AddChar (ZMod modulus) ℂ :=
  Circle.coeHom.compAddChar zmodCircleCharacter

theorem zmod_circle_character_injective :
    Function.Injective
      (zmodCircleCharacter :
        ZMod modulus -> Circle) :=
  (AddCircle.injective_toCircle one_ne_zero).comp
    (ZMod.toAddCircle_injective modulus)

theorem zmod_complex_character_injective :
    Function.Injective
      (zmodComplexCharacter :
        ZMod modulus -> ℂ) :=
  Subtype.coe_injective.comp zmod_circle_character_injective

/--
The character indexed by `phase` is `x ↦ exp(2πi * phase * x / modulus)` after transporting the
output into `ZMod modulus`.
-/
noncomputable def cyclicCharacter
    (outputEquiv : Output ≃+ ZMod modulus)
    (phase : ZMod modulus) : AddChar Output ℂ :=
  (zmodComplexCharacter.mulShift phase).compAddMonoidHom
    outputEquiv.toAddMonoidHom

/--
The complete Fourier phase system on a finite cyclic additive output group.
-/
noncomputable def cyclicPhaseSystem
    (outputEquiv : Output ≃+ ZMod modulus) :
    PhaseSystem Output (ZMod modulus) where
  character := cyclicCharacter outputEquiv
  zeroPhase := 0
  character_zero := by
    ext output
    simp [cyclicCharacter]
  character_nonzero := by
    intro phase phaseNonzero characterTrivial
    have atOne :=
      DFunLike.congr_fun characterTrivial (outputEquiv.symm 1)
    have phaseValue :
        zmodComplexCharacter phase =
          zmodComplexCharacter (0 : ZMod modulus) := by
      simpa [cyclicCharacter] using atOne
    apply phaseNonzero
    exact zmod_complex_character_injective phaseValue

/-- Distinct phase labels produce distinct characters. -/
theorem cyclic_phase_system_character_injective
    (outputEquiv : Output ≃+ ZMod modulus) :
    Function.Injective (cyclicPhaseSystem outputEquiv).character := by
  intro left right sameCharacter
  have atOne :=
    DFunLike.congr_fun sameCharacter (outputEquiv.symm 1)
  apply zmod_complex_character_injective
  simpa [cyclicPhaseSystem, cyclicCharacter] using atOne

/-- The phase register and output register have exactly the same finite dimension. -/
theorem cyclic_phase_card_eq_output_card
    (outputEquiv : Output ≃+ ZMod modulus) :
    Fintype.card (ZMod modulus) = Fintype.card Output := by
  exact (Fintype.card_congr outputEquiv.toEquiv).symm

/-- The explicit cyclic construction is a complete phase system. -/
noncomputable def cyclicCompletePhaseSystem
    (outputEquiv : Output ≃+ ZMod modulus) :
    CompletePhaseSystem Output (ZMod modulus) where
  system := cyclicPhaseSystem outputEquiv
  characterInjective :=
    cyclic_phase_system_character_injective outputEquiv
  phaseDimension :=
    cyclic_phase_card_eq_output_card outputEquiv

end

end HegemonCrypto.CmsFinitePhaseSystem
