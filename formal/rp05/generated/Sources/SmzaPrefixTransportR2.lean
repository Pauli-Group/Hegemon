import HegemonCrypto.CmsCompressedOracleUnitary
import HegemonCrypto.SmallWoodV8Smz9HiddenLeafQrom

/-!
An exact reachable-fiber obstruction and a finite coherent-extraction transport
lemma. This file does NOT supply SMZA parser refinement, offline extraction,
or the adaptive Record/Split coupling. The transport premise is a local norm
commutator, not an assumed global extraction-success probability.
-/

namespace HegemonCrypto.SmallWood.SmzaPrefixTransportR2

noncomputable section

open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsKernelBounds
open V8Smz9HiddenLeafQrom

set_option exponentiation.threshold 1024

/-- Conditional compressed database fiber after observing a classical output h
at a fresh input: the decompression reflection applied to the recorded ket.
The identification with the standard-oracle output-basis measurement is not
claimed to be formalized by this definition. -/
def conditionalFiber (h : DigestRegister) : FiberState DigestRegister :=
  decompressFiber (fiberBasisKet (some h))

/-- The physical compressed representation need not contain the queried input,
even after an output has been observed. This is an exact coordinate mass. -/
theorem conditional_fiber_missing_mass (h : DigestRegister) :
    Complex.normSq (conditionalFiber h none) = 1 / (2 ^ 512 : ℝ) := by
  unfold conditionalFiber
  rw [decompress_recorded_ket_apply_none, normSq_inverseSqrtOutputCard]
  norm_num [DigestRegister, ZMod.card]

theorem conditional_fiber_missing_mass_positive (h : DigestRegister) :
    0 < Complex.normSq (conditionalFiber h none) := by
  rw [conditional_fiber_missing_mass]
  positivity

/-- Finite execution. Inter-query classical/quantum computation can be absorbed
into each step, provided it obeys the stated contraction and commutator facts. -/
def evolve {H : Type*} (step : ℕ → H → H) (initial : H) : ℕ → H
  | 0 => initial
  | n + 1 => step n (evolve step initial n)

section Transport

variable {H : Type*} [PseudoMetricSpace H]

/-- Move one fixed coherent extraction through a finite execution. The target
and answer registers must remain private: otherwise the supplied local
commutator is not justified by the compressed-oracle theorem. -/
theorem extraction_transport
    (step : ℕ → H → H) (extract : H → H) (initial : H)
    (epsilon : ℝ) (count : ℕ)
    (contractive : ∀ n < count, ∀ left right,
      dist (step n left) (step n right) ≤ dist left right)
    (localBound : ∀ n < count,
      dist (extract (step n (evolve step initial n)))
        (step n (extract (evolve step initial n))) ≤ epsilon) :
    dist (extract (evolve step initial count))
      (evolve step (extract initial) count) ≤ (count : ℝ) * epsilon := by
  have prefixBound : ∀ n ≤ count,
      dist (extract (evolve step initial n))
        (evolve step (extract initial) n) ≤ (n : ℝ) * epsilon := by
    intro n
    induction n with
    | zero => intro _; simp [evolve]
    | succ n ih =>
      intro hn
      have before : n < count := Nat.lt_of_lt_of_le (Nat.lt_succ_self n) hn
      have previous := ih (Nat.le_of_lt before)
      calc
        _ ≤ dist (extract (step n (evolve step initial n)))
              (step n (extract (evolve step initial n))) +
            dist (step n (extract (evolve step initial n)))
              (step n (evolve step (extract initial) n)) := dist_triangle _ _ _
        _ ≤ epsilon + dist (extract (evolve step initial n))
              (evolve step (extract initial) n) :=
          add_le_add (localBound n before) (contractive n before _ _)
        _ ≤ epsilon + (n : ℝ) * epsilon := add_le_add (le_refl epsilon) previous
        _ = ((n + 1 : ℕ) : ℝ) * epsilon := by push_cast; ring
  exact prefixBound count (Nat.le_refl count)

/-- Event amplitude is Lipschitz under a contractive event projector. Applying
this to the transport theorem yields sqrt(p_early) ≤ sqrt(p_late)+s*epsilon.
It does not assume that late extraction always succeeds. -/
theorem event_amplitude_transport
    (eventAmplitude : H → ℝ)
    (lipschitz : ∀ left right,
      eventAmplitude left ≤ eventAmplitude right + dist left right)
    (early late : H) (delta : ℝ) (transport : dist early late ≤ delta) :
    eventAmplitude early ≤ eventAmplitude late + delta :=
  (lipschitz early late).trans (add_le_add (le_refl _) transport)

end Transport

end
end HegemonCrypto.SmallWood.SmzaPrefixTransportR2
