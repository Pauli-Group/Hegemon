import HegemonCrypto.SmallWoodV8Smz9MeasuredSourceHiddenPatch

namespace HegemonCrypto.SmallWood.V8Smz9MeasuredTablePublic

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9CurrentPublicContext
open V8Smz9HonestWholeViewGames V8Smz9MeasuredRunContinuity V8Smz9MeasuredSourceHiddenPatch
open V8Smz9PrivacyGameComposition V8Smz9EagerOracleGame V8Smz9EagerPrivacy
open V8Smz9ZeroKnowledge V8Smz9RuntimeFieldLayout
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Other Work : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]

/-- Actual measured continuation data on a fixed public-context/opened-tape
fiber. There is no hidden-tape argument, experiment probability or distance field. -/
structure MeasuredContinuation where
  oldLeaf : LeafInput → DigestRegister
  other : Other → DigestRegister
  program : Program (LeafInput ⊕ Other) Work
  initial : GameState (Input := LeafInput ⊕ Other) (Work := Work)
  normalized : ‖initial‖ = 1

def measuredFullTableAcceptance (randomized : Bool)
    (opened : Finset LeafIndex) (visible : OpenedTapes (Tape := LeafTape) opened)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (continuation : MeasuredContinuation (Other := Other) (Work := Work))
    (fullSuffix : LeafIndex → LeafSuffix) : ℝ :=
  uniformAverage fun padded : TapeTable =>
    V8Smz9HonestWholeViewGames.run randomized continuation.program
      (fullSourceOverlay continuation.oldLeaf continuation.other labels Finset.univ
        (fun _ => canonicalLeafHeader salt) fullSuffix
        (mergeTapes opened visible (splitTapes opened padded).2)) continuation.initial

def measuredPublicTableAcceptance (randomized : Bool)
    (points : Fin 6 → Goldilocks) (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (context : EagerContext points)
    (continuation : MeasuredContinuation (Other := Other) (Work := Work))
    (visible : OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context))) : ℝ :=
  V8Smz9HonestWholeViewGames.run randomized continuation.program
    (Sum.elim
      (publicOpenedOracle continuation.oldLeaf labels points selected salt context
        (mergeTapes (openedOrEmpty (contextSelection context)) visible (fun _ => 0)))
      continuation.other) continuation.initial

theorem source_opened_overlay_eq_public
    (points : Fin 6 → Goldilocks) (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (context : EagerContext points)
    (oldLeaf : LeafInput → DigestRegister) (fullSuffix : LeafIndex → LeafSuffix)
    (suffixMatches : ∀ index ∈ openedOrEmpty (contextSelection context),
      fullSuffix index = publicSuffix points selected context index) (tapes : TapeTable) :
    sourceOverlay oldLeaf labels (openedOrEmpty (contextSelection context))
      (fun _ => canonicalLeafHeader salt) fullSuffix tapes =
      publicOpenedOracle oldLeaf labels points selected salt context tapes := by
  have supportEquality : sourcePatchSupport (openedOrEmpty (contextSelection context))
      (fun _ => canonicalLeafHeader salt) fullSuffix tapes =
      sourcePatchSupport (openedOrEmpty (contextSelection context))
        (fun _ => canonicalLeafHeader salt) (publicSuffix points selected context) tapes := by
    apply Finset.image_congr
    intro index member
    dsimp only
    rw [suffixMatches index member]
  funext input
  simp only [sourceOverlay, supportEquality, public_suffix_support_is_exact, publicOpenedOracle]

/-- The full source oracle is compared with the literal public serializer's
opened-only table. The revealed suffix equality is a source-binding premise;
the current-program theorem below discharges it from packed acceptance. -/
theorem measured_completed_table_to_public_reference_bound
    (randomized : Bool) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister) (context : EagerContext points)
    (continuation : MeasuredContinuation (Other := Other) (Work := Work))
    (fullSuffix : LeafIndex → LeafSuffix)
    (suffixMatches : ∀ index ∈ openedOrEmpty (contextSelection context),
      fullSuffix index = publicSuffix points selected context index)
    (visible : OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context))) :
    |measuredFullTableAcceptance randomized (openedOrEmpty (contextSelection context)) visible
        salt labels continuation fullSuffix -
      measuredPublicTableAcceptance randomized points selected salt labels context continuation visible| ≤
      hiddenPatchLoss (queryCount continuation.program) := by
  let opened := openedOrEmpty (contextSelection context)
  let oldKept := sourceOverlay continuation.oldLeaf labels opened (fun _ => canonicalLeafHeader salt)
    fullSuffix (mergeTapes opened visible (fun _ => (0 : LeafTape)))
  have bound := full_source_overlay_measured_distance_le randomized continuation.program oldKept
    continuation.other labels (Finset.univ \ opened) (fun _ => canonicalLeafHeader salt) fullSuffix
    continuation.initial continuation.normalized
  have fullOracle (padded : TapeTable) :
      fullSourceOverlay oldKept continuation.other labels (Finset.univ \ opened)
        (fun _ => canonicalLeafHeader salt) fullSuffix padded =
      fullSourceOverlay continuation.oldLeaf continuation.other labels Finset.univ
        (fun _ => canonicalLeafHeader salt) fullSuffix
        (mergeTapes opened visible (splitTapes opened padded).2) := by
    unfold fullSourceOverlay
    change Sum.elim (sourceOverlay
      (sourceOverlay continuation.oldLeaf labels opened (fun _ => canonicalLeafHeader salt)
        fullSuffix (mergeTapes opened visible (fun _ => (0 : LeafTape))))
      labels (Finset.univ \ opened) (fun _ => canonicalLeafHeader salt) fullSuffix padded)
      continuation.other = _
    rw [full_overlay_from_opened_reference]
  simp_rw [fullOracle] at bound
  have publicOracle := source_opened_overlay_eq_public points selected salt labels context
    continuation.oldLeaf fullSuffix suffixMatches
    (mergeTapes opened visible (fun _ => (0 : LeafTape)))
  change oldKept = _ at publicOracle
  rw [publicOracle] at bound
  rw [current_hidden_patch_loss_closed_form]
  exact bound


end
end HegemonCrypto.SmallWood.V8Smz9MeasuredTablePublic
