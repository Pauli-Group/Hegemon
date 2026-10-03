import HegemonCrypto.SmallWoodV8Smz9MeasuredAdjacentComposition

namespace HegemonCrypto.SmallWood.V8Smz9MeasuredSameOracleAdjacent

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9RuntimeRandomness V8Smz9JointAlgebraicLaw V8Smz9HonestHybrid
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame V8Smz9EagerPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9CurrentPublicContext
open V8Smz9ZeroKnowledge V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler
open V8Smz9PrivacyGameComposition V8Smz9RuntimeDistribution V8Smz9WholeViewObservation
open V8Smz9AdjacentComposition V8Smz9MeasuredTablePublic V8Smz9MeasuredAdjacentComposition
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Work : Type} [Fintype Work]

abbrev FullOracle (bound : Nat) := (LeafInput ⊕ OtherRawInput bound) → DigestRegister

/-- Future code/state only. Oracle fields cannot be supplied independently
of the one persistent table used by actual nonce and index interpretation. -/
structure MeasuredFuture (bound : Nat) where
  program : Program (LeafInput ⊕ OtherRawInput bound) Work
  initial : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work)
  normalized : ‖initial‖ = 1

def withPersistentOracle {bound : Nat} (oracle : FullOracle bound)
    (future : MeasuredFuture (Work := Work) bound) :
    MeasuredContinuation (Other := OtherRawInput bound) (Work := Work) where
  oldLeaf := fun input => oracle (Sum.inl input)
  other := fun input => oracle (Sum.inr input)
  program := future.program
  initial := future.initial
  normalized := future.normalized

abbrev SuccessfulFuture (bound : Nat) := (opening : ComputedOpening) →
  PiopCoefficients Goldilocks → (context : EagerContext opening.points) →
    OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context)) →
      MeasuredFuture (Work := Work) bound

/-- A fixed prior nonleaf programming event is part of the common baseline.
Current leaf overlays are still added separately by the source/reference games. -/
def fixedNonleafUpdate {bound : Nat} (oracle : FullOracle bound)
    (input : OtherRawInput bound) (answer : DigestRegister) : FullOracle bound :=
  Function.update oracle (Sum.inr input) answer

theorem fixed_nonleaf_update_preserves_leaf {bound : Nat} (oracle : FullOracle bound)
    (input : OtherRawInput bound) (answer : DigestRegister) (leaf : LeafInput) :
    fixedNonleafUpdate oracle input answer (Sum.inl leaf) = oracle (Sum.inl leaf) := by
  simp [fixedNonleafUpdate]

theorem fixed_nonleaf_update_other_projection {bound : Nat} (oracle : FullOracle bound)
    (input : OtherRawInput bound) (answer : DigestRegister) :
    (fun point => fixedNonleafUpdate oracle input answer (Sum.inr point)) =
      Function.update (fun point => oracle (Sum.inr point)) input answer := by
  funext point
  simp [fixedNonleafUpdate, Function.update]

def sameOraclePostFinalSource (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (batching : Fin 5 → Nat → Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : FullOracle bound) (aborted : MeasuredFuture (Work := Work) bound)
    (succeeded : SuccessfulFuture (Work := Work) bound) : ℝ :=
  measuredActualPostFinalSource randomized bound largeEnough statement batching gamma response transcript values
    salt labels digest pending (fun input => oracle (Sum.inr input))
    (withPersistentOracle oracle aborted)
    (fun opening transcript context visible => withPersistentOracle oracle (succeeded opening transcript context visible))

def sameOraclePostFinalPublic (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (batching : Fin 5 → Nat → Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : FullOracle bound) (aborted : MeasuredFuture (Work := Work) bound)
    (succeeded : SuccessfulFuture (Work := Work) bound) : ℝ :=
  measuredActualPostFinalPublic randomized bound largeEnough statement batching gamma response transcript
    salt labels digest pending (fun input => oracle (Sum.inr input))
    (withPersistentOracle oracle aborted)
    (fun opening transcript context visible => withPersistentOracle oracle (succeeded opening transcript context visible))

/-- Nonce/index reads and the full measured future share one actual baseline
by construction. No caller-supplied table equality or game distance is needed. -/
theorem same_oracle_post_final_source_to_public_bound
    (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : Fin 5 → Nat → Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : FullOracle bound) (aborted : MeasuredFuture (Work := Work) bound)
    (succeeded : SuccessfulFuture (Work := Work) bound)
    (queryBound : Nat) (abortBounded : queryCount aborted.program ≤ queryBound)
    (successBounded : ∀ opening context visible,
      queryCount (succeeded opening transcript context visible).program ≤ queryBound) :
    |sameOraclePostFinalSource randomized bound largeEnough statement batching gamma response transcript
        (packingValues witness) salt labels digest pending oracle aborted succeeded -
      sameOraclePostFinalPublic randomized bound largeEnough statement batching gamma response transcript
        salt labels digest pending oracle aborted succeeded| ≤ hiddenPatchLoss queryBound :=
  measured_actual_post_final_source_to_public_bound randomized bound largeEnough statement publicValues witness
    domain batching gamma response transcript salt labels digest pending (fun input => oracle (Sum.inr input))
    (withPersistentOracle oracle aborted)
    (fun opening transcript context visible => withPersistentOracle oracle (succeeded opening transcript context visible))
    queryBound abortBounded successBounded

/-- The baseline may contain the final nonleaf update at an address depending
on the sampled full transcript. Pointwise comparison uses the same H(T) for
all reads and futures; averaging T does not require a false H-independence premise. -/
theorem same_oracle_post_final_transcript_mixture_bound
    (randomized : Bool) (bound : Nat) (largeEnough : 37434 ≤ bound)
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : Fin 5 → Nat → Goldilocks) (gamma : DecsGamma Goldilocks)
    (response : DecsFullCoefficients Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (digest : DigestRegister) (pending : Bool)
    (oracle : PiopCoefficients Goldilocks → FullOracle bound)
    (aborted : PiopCoefficients Goldilocks → MeasuredFuture (Work := Work) bound)
    (succeeded : SuccessfulFuture (Work := Work) bound)
    (queryBound : Nat) (abortBounded : ∀ transcript, queryCount (aborted transcript).program ≤ queryBound)
    (successBounded : ∀ opening transcript context visible,
      queryCount (succeeded opening transcript context visible).program ≤ queryBound) :
    |uniformAverage (fun transcript =>
        sameOraclePostFinalSource randomized bound largeEnough statement batching gamma response transcript
          (packingValues witness) salt labels digest pending (oracle transcript) (aborted transcript) succeeded) -
      uniformAverage (fun transcript =>
        sameOraclePostFinalPublic randomized bound largeEnough statement batching gamma response transcript
          salt labels digest pending (oracle transcript) (aborted transcript) succeeded)| ≤ hiddenPatchLoss queryBound := by
  apply uniform_average_difference_le
  intro transcript
  exact same_oracle_post_final_source_to_public_bound randomized bound largeEnough statement publicValues witness
    domain batching gamma response transcript salt labels digest pending (oracle transcript) (aborted transcript)
    succeeded queryBound (abortBounded transcript) (fun opening => successBounded opening transcript)


end
end HegemonCrypto.SmallWood.V8Smz9MeasuredSameOracleAdjacent
