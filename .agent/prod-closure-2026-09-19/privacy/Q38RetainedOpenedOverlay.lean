import Q38OpenedTapeConditioningR5

/-! The all-leaf randomized oracle retains its opened entries. Only unopened
entries are erased in this hop. The reference circuit and selected set can
depend on public labels and revealed tapes, but not on unopened tapes. This
does not silently condition a hidden-dependent selection into independence. -/
namespace HegemonCrypto.SmallWood.V8SmzaRetainedOpenedOverlay
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8SmzaLeafFrameHybrid
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 5000

theorem overlay_union {Output : Type*}
    (old : LeafInput → Output) (targets : LeafIndex → Output)
    (a b : Finset LeafIndex) (heads : LeafIndex → LeafHeader)
    (tails : LeafIndex → LeafSuffix) (tapes : LeafIndex → LeafTape) :
    sourceOverlay (sourceOverlay old targets a heads tails tapes)
      targets b heads tails tapes =
        sourceOverlay old targets (a ∪ b) heads tails tapes := by
  funext input
  unfold sourceOverlay sourcePatchSupport
  simp only [Finset.image_union, Finset.mem_union]
  by_cases ha : input ∈ a.image (fun i => sourceLeafInput (heads i) (tails i) i (tapes i))
  <;> by_cases hb : input ∈ b.image (fun i => sourceLeafInput (heads i) (tails i) i (tapes i))
  <;> simp [ha, hb]

theorem opened_support_retained (unopened : Finset LeafIndex)
    (known : LeafIndex → LeafTape) (fresh : Unopened unopened → LeafTape)
    (heads : LeafIndex → LeafHeader) (tails : LeafIndex → LeafSuffix) :
    sourcePatchSupport unopenedᶜ heads tails (completeTapes unopened known fresh) =
      sourcePatchSupport unopenedᶜ heads tails known := by
  apply Finset.image_congr
  intro i hi
  dsimp only
  rw [complete_preserves_opened unopened known fresh i (Finset.mem_compl.mp hi)]

/-- Reconstructed opened payloads suffice for the retained oracle, even if
the simulator uses unrelated payloads at every unopened index. This is the
deterministic interface consumed by the q38 row/mask reconstruction. -/
theorem opened_overlay_payload_congr {Output : Type*}
    (old : LeafInput → Output) (targets : LeafIndex → Output)
    (opened : Finset LeafIndex) (heads : LeafIndex → LeafHeader)
    (real simulated : LeafIndex → LeafSuffix) (tapes : LeafIndex → LeafTape)
    (same : ∀ i ∈ opened, real i = simulated i) :
    sourceOverlay old targets opened heads real tapes =
      sourceOverlay old targets opened heads simulated tapes := by
  have supports : sourcePatchSupport opened heads real tapes =
      sourcePatchSupport opened heads simulated tapes := by
    apply Finset.image_congr
    intro i hi
    dsimp only
    rw [same i hi]
  unfold sourceOverlay
  rw [supports]

theorem full_overlay_decomposition {Other Output : Type*}
    [Fintype Other] [DecidableEq Other]
    (old : LeafInput → Output) (other : Other → Output)
    (targets : LeafIndex → Output) (unopened : Finset LeafIndex)
    (known : LeafIndex → LeafTape) (fresh : Unopened unopened → LeafTape)
    (heads : LeafIndex → LeafHeader) (tails : LeafIndex → LeafSuffix) :
    fullSourceOverlay old other targets Finset.univ heads tails
        (completeTapes unopened known fresh) =
      fullSourceOverlay (sourceOverlay old targets unopenedᶜ heads tails known)
        other targets unopened heads tails (completeTapes unopened known fresh) := by
  have retained : sourceOverlay old targets unopenedᶜ heads tails
      (completeTapes unopened known fresh) =
        sourceOverlay old targets unopenedᶜ heads tails known := by
    unfold sourceOverlay
    rw [opened_support_retained]
  rw [← retained]
  unfold fullSourceOverlay
  have union : unopenedᶜ ∪ unopened = Finset.univ := by
    ext i
    by_cases member : i ∈ unopened <;> simp [member]
  rw [overlay_union, union]

/-- Born-event advantage of erasing unopened leaves, with the opened overlay
retained in the reference oracle. The adversary may mix all leaf/nonleaf query
inputs; the postprocessing and event may even depend on the fresh tape table.
No indistinguishability premise or external reprogramming theorem is used. -/
theorem erase_unopened_observation
    {Other Output Workspace : Type*}
    [Fintype Other] [DecidableEq Other]
    [Fintype Output] [AddGroup Output] [DecidableEq Output]
    [Fintype Workspace] [DecidableEq Workspace]
    (old : LeafInput → Output) (other : Other → Output)
    (targets : LeafIndex → Output) (unopened : Finset LeafIndex)
    (anchor : Unopened unopened) (known : LeafIndex → LeafTape)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte)
    (steps : ℕ → State (Input := LeafInput ⊕ Other) (Output := Output)
      (Workspace := Workspace) ≃ₗᵢ[ℂ]
      State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (initial : State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (queries : ℕ)
    (post : (Unopened unopened → LeafTape) →
      State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (event : (Unopened unopened → LeafTape) →
      Finset (QueryBasis (LeafInput ⊕ Other) Output Workspace)) :
    |(∑ fresh : Unopened unopened → LeafTape,
        born (event fresh) (post fresh
          (run (fullSourceOverlay old other targets Finset.univ (fun _ => header salt)
            (fun i => suffix (data i)) (completeTapes unopened known fresh)) steps initial queries))) /
          (Fintype.card (Unopened unopened → LeafTape) : ℝ) -
      (∑ fresh : Unopened unopened → LeafTape,
        born (event fresh) (post fresh
          (run (fullSourceOverlay old other targets unopenedᶜ (fun _ => header salt)
            (fun i => suffix (data i)) known) steps initial queries))) /
          (Fintype.card (Unopened unopened → LeafTape) : ℝ)| ≤
      2 * Real.sqrt (4 * (queries : ℝ) ^ 2 * (2 ^ 512 : ℝ)⁻¹) := by
  simp_rw [full_overlay_decomposition old other targets unopened known]
  exact conditioned_opened_tape_observation
    (sourceOverlay old targets unopenedᶜ (fun _ => header salt) (fun i => suffix (data i)) known)
    other targets unopened anchor known salt data steps initial normalized queries post event

end
end HegemonCrypto.SmallWood.V8SmzaRetainedOpenedOverlay
