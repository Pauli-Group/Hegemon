import Q38Rp05AdaptiveOpening
import Q38Rp05PostFinalCompiler

/-! Exact abort-aware RP05 opening bounds shared by the selected-opening
clients. Kept separate from the historical full adaptive trace analysis so
current privacy clients do not import that unrelated profile. -/
namespace HegemonCrypto.SmallWood.Q38Rp05FullAdaptiveComposition

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestFinalGame
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator (PublicCombinationHeads)
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid (Opened q38Unopened)
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy (Earlier)
open HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
open HegemonCrypto.SmallWood.V8SmzaSelectionFeedback (exposures)
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport (Rp05LeafInput)
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

local notation "Statement" =>
  HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

/- Exact declarations moved without changing their statements or proofs. -/
def rp05AbortAwareUnopened {points : Fin 6 → Goldilocks}
    (job : SelectionResult points) : Finset LeafIndex :=
  match job.targets with
  | none => Finset.univ
  | some targets => q38Unopened targets.val

/-- The concrete P8/P9 bound on the unnormalised state left by an earlier
measured execution. Zero-mass branches cost zero; no branch is divided by
its probability, and no oracle-indexed prior family is replaced. -/
theorem rp05_abort_aware_opening_bound_mass
    {Work : Type} [Fintype Work]
    (bound : Nat) (randomized : Bool) (largeEnough : 39162 ≤ bound)
    (points : Fin 6 → Goldilocks) (pointsDistinct : Function.Injective points)
    (digest : DigestRegister) (heads : PublicCombinationHeads Goldilocks)
    (early : Earlier Goldilocks) (pending : Bool)
    (program : (job : SelectionResult points) →
      (Opened (rp05AbortAwareUnopened job) → LeafTape) →
        Program (Rp05LeafInput ⊕ OtherRawInput bound) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : OtherRawInput bound → DigestRegister)
    (labels : LeafIndex → DigestRegister)
    (statement : Statement) (salt : SaltBytes)
    (data : LeafIndex → Fin 1176 → Byte)
    (queries : Nat) (bounded : ∀ job visible,
      queryCount (program job visible) ≤ queries)
    (state : GameState
      (Input := Rp05LeafInput ⊕ OtherRawInput bound) (Work := Work)) :
    |fullGame randomized
        (asSelection (selectIndices bound largeEnough points pointsDistinct
          digest heads early pending))
        rp05AbortAwareUnopened program old other labels statement salt data state -
      publicGame randomized
        (asSelection (selectIndices bound largeEnough points pointsDistinct
          digest heads early pending))
        rp05AbortAwareUnopened program old other labels statement salt data state| ≤
      (4 * ((exposures
        (asSelection (Other := OtherRawInput bound) (Work := Work)
          (selectIndices bound largeEnough points pointsDistinct
          digest heads early pending)) : ℝ) + queries) / (2 ^ 256 : ℝ)) *
        ‖state‖ ^ 2 := by
  apply adaptive_opening_bound_mass randomized
    (asSelection (selectIndices bound largeEnough points pointsDistinct
      digest heads early pending)) rp05AbortAwareUnopened
    (fun job => by
      cases h : job.targets with
      | none => exact ⟨defaultIndices 0, by simp [rp05AbortAwareUnopened, h]⟩
      | some targets =>
          simpa [rp05AbortAwareUnopened, h] using
            q38Anchor targets.val targets.property.1)
    program old other labels statement salt data queries bounded state

/-- Unit-state form of the exact unnormalized bound above. -/
theorem rp05_abort_aware_opening_bound
    {Work : Type} [Fintype Work]
    (bound : Nat) (randomized : Bool) (largeEnough : 39162 ≤ bound)
    (points : Fin 6 → Goldilocks) (pointsDistinct : Function.Injective points)
    (digest : DigestRegister) (heads : PublicCombinationHeads Goldilocks)
    (early : Earlier Goldilocks) (pending : Bool)
    (program : (job : SelectionResult points) →
      (Opened (rp05AbortAwareUnopened job) → LeafTape) →
        Program (Rp05LeafInput ⊕ OtherRawInput bound) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : OtherRawInput bound → DigestRegister)
    (labels : LeafIndex → DigestRegister)
    (statement : Statement) (salt : SaltBytes)
    (data : LeafIndex → Fin 1176 → Byte)
    (queries : Nat) (bounded : ∀ job visible,
      queryCount (program job visible) ≤ queries)
    (state : GameState
      (Input := Rp05LeafInput ⊕ OtherRawInput bound) (Work := Work))
    (normalized : ‖state‖ = 1) :
    |fullGame randomized
        (asSelection (selectIndices bound largeEnough points pointsDistinct
          digest heads early pending))
        rp05AbortAwareUnopened program old other labels statement salt data state -
      publicGame randomized
        (asSelection (selectIndices bound largeEnough points pointsDistinct
          digest heads early pending))
        rp05AbortAwareUnopened program old other labels statement salt data state| ≤
      4 * ((exposures
        (asSelection (Other := OtherRawInput bound) (Work := Work)
          (selectIndices bound largeEnough points pointsDistinct
          digest heads early pending)) : ℝ) + queries) / (2 ^ 256 : ℝ) := by
  apply adaptive_opening_bound randomized
    (asSelection (selectIndices bound largeEnough points pointsDistinct
      digest heads early pending)) rp05AbortAwareUnopened
    (fun job => by
      cases h : job.targets with
      | none => exact ⟨defaultIndices 0, by simp [rp05AbortAwareUnopened, h]⟩
      | some targets =>
          simpa [rp05AbortAwareUnopened, h] using
            q38Anchor targets.val targets.property.1)
    program old other labels statement salt data queries bounded state normalized

end
end HegemonCrypto.SmallWood.Q38Rp05FullAdaptiveComposition
