import Q38OpenedRows
import Q38ConcreteAdaptivePrivacy
import HegemonCrypto.SmallWoodV8Smz9EagerOracleGame
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator
import SmzaRp04TracePrefixes
import SmzaRp05CurrentCoset406

/-! Current q38 1,176-byte leaf payload and exact opened-row reconstruction. -/
namespace HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaOpenedRows
open HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406 (evaluationPoint)
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 2000000

/-- The strict-v2 RP05 frame appends its own final zero counter.  This is
only the preceding 1,176 payload bytes: row count, 140 values, mask count,
and five values. -/
def q38OpenedPayload (rows : Fin 140 → Goldilocks)
    (masks : Fin 5 → Goldilocks) : Fin 1176 → CanonicalBytes.Byte :=
  Fin.append (rawWordBytes ⟨140, by norm_num⟩)
    (Fin.append (fieldVectorBytes rows)
      (Fin.append (rawWordBytes ⟨5, by norm_num⟩)
        (fieldVectorBytes masks)))

/-- The actual 406-coefficient row polynomial uses 38 tails followed by
368 committed heads, and the DECS mask has all 406 current coefficients. -/
def q38PhysicalSuffix (heads : Heads Goldilocks)
    (tails : Tails Goldilocks) (decsMask : Decs Goldilocks) :
    LeafIndex → Fin 1176 → CanonicalBytes.Byte :=
  fun index =>
    let point := evaluationPoint index
    q38OpenedPayload
      (fun row => interpolateValue (rowValues heads tails row) point)
      (fun polynomial =>
        (coefficientPolynomial (decsMask polynomial)).eval point)

/-- The current 406 interpolation coordinates are distinct in the field.
The historical sampler lemma has a 388-node type and is not applicable to
the current RP05 payload. -/
private theorem current_interpolation_nodes_distinct :
    Function.Injective (fun node : Fin 406 => (node.val : Goldilocks)) := by
  change Function.Injective
    (fun node : Fin 406 => HegemonCrypto.SmallWood.toGoldilocks node.val)
  exact HegemonCrypto.SmallWood.SmzaRp04TracePrefixes.consecutive_point_injective

/-- The same 1,176 bytes reconstructed solely from the public q38 opening
coordinates and the already-published D response. -/
def q38PublicSuffix
    (points : Fin 6 → Goldilocks)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : Gamma Goldilocks) (reply : Decs Goldilocks)
    (combinationHeads : PublicCombinationHeads Goldilocks)
    (early : Earlier Goldilocks)
    (targets : Fin 38 → Goldilocks) (later : Later Goldilocks)
    (opening : Fin 38) : Fin 1176 → CanonicalBytes.Byte :=
  let rows := reconstruct points injective combinationHeads early targets later
  let masks := recoverMasks gamma reply targets rows
  q38OpenedPayload (rows opening) (masks opening)

-- Prove the algebra at abstract field targets before specializing to domain
-- indices. Rewriting an unfolded evaluationPoint application compares the
-- semireducible LeafIndex and Fin domainSize carriers at instances transparency.
private theorem public_suffix_at_targets
    (points : Fin 6 → Goldilocks)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : Gamma Goldilocks)
    (heads : Heads Goldilocks) (tails : Tails Goldilocks)
    (decsMask : Decs Goldilocks) (targets : Fin 38 → Goldilocks)
    (opening : Fin 38) :
    q38PublicSuffix points injective gamma (response gamma heads tails decsMask)
        (lvcsPublicCombinationHeads points heads) (earlier points tails)
        targets (fullSubset heads tails targets) opening =
      q38OpenedPayload (openedRows heads tails targets opening)
        (fun polynomial => (coefficientPolynomial (decsMask polynomial)).eval
          (targets opening)) := by
  dsimp only [q38PublicSuffix]
  rw [recovered_public_masks_are_actual current_interpolation_nodes_distinct]
  rw [reconstruct_roundtrip]

/-- The retained opened leaf payload is byte-for-byte its public
reconstruction.  Neither an arbitrary unopened completion nor a historical
388-coefficient row is involved. -/
theorem q38_physical_suffix_opened_eq_public
    (points : Fin 6 → Goldilocks)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : Gamma Goldilocks)
    (heads : Heads Goldilocks) (tails : Tails Goldilocks)
    (decsMask : Decs Goldilocks)
    (indices : Fin 38 → LeafIndex) (opening : Fin 38) :
    q38PhysicalSuffix heads tails decsMask (indices opening) =
      q38PublicSuffix points injective gamma
        (response gamma heads tails decsMask)
        (lvcsPublicCombinationHeads points heads) (earlier points tails)
        (fun selected => evaluationPoint (indices selected))
        (fullSubset heads tails
          (fun selected => evaluationPoint (indices selected))) opening := by
  exact (public_suffix_at_targets points injective gamma heads tails decsMask
    (fun selected => evaluationPoint (indices selected)) opening).symm

/-- A total public payload table, whose values at the selected indices are
uniquely determined by the 38 opened public payloads.  Outside that finite
image its value is immaterial to the retained-opening game. -/
def q38SelectedPublicData (selected : Fin 38 → LeafIndex)
    (opened : Fin 38 → Fin 1176 → CanonicalBytes.Byte) : LeafIndex → Fin 1176 → CanonicalBytes.Byte :=
  fun index => if h : ∃ opening, selected opening = index then
    opened (Classical.choose h)
  else fun _ => 0

theorem q38_selected_public_data_at (selected : Fin 38 → LeafIndex)
    (distinct : Function.Injective selected)
    (opened : Fin 38 → Fin 1176 → CanonicalBytes.Byte) (opening : Fin 38) :
    q38SelectedPublicData selected opened (selected opening) = opened opening := by
  have hit : ∃ chosen, selected chosen = selected opening := ⟨opening, rfl⟩
  have chosen : Classical.choose hit = opening :=
    distinct (Classical.choose_spec hit)
  simp only [q38SelectedPublicData, dif_pos hit, chosen]

/-- The actual selected RP05 keys, including their 1,176 payload bytes,
are exactly the keys reconstructed from the published q38 opening. -/
theorem q38_selected_physical_keys_eq_public {Other : Type}
    (points : Fin 6 → Goldilocks)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : Gamma Goldilocks)
    (heads : Heads Goldilocks) (tails : Tails Goldilocks)
    (decsMask : Decs Goldilocks)
    (selected : Fin 38 → LeafIndex)
    (distinct : Function.Injective selected)
    (preamble : Statement) (salt : Fin 32 → CanonicalBytes.Byte)
    (tapes : LeafIndex → LeafTape) :
    (fun opening : Fin 38 =>
      (Sum.inl (rp05SourceLeafInput preamble salt
        (q38PhysicalSuffix heads tails decsMask (selected opening))
        (selected opening) (tapes (selected opening))) : Rp05LeafInput ⊕ Other)) =
    (fun opening : Fin 38 =>
      (Sum.inl (rp05SourceLeafInput preamble salt
        (q38SelectedPublicData selected
          (q38PublicSuffix points injective gamma
            (response gamma heads tails decsMask)
            (lvcsPublicCombinationHeads points heads) (earlier points tails)
            (fun i => evaluationPoint (selected i))
            (fullSubset heads tails (fun i => evaluationPoint (selected i))))
          (selected opening))
        (selected opening) (tapes (selected opening))) : Rp05LeafInput ⊕ Other)) := by
  funext opening
  rw [q38_selected_public_data_at selected distinct]
  rw [q38_physical_suffix_opened_eq_public points injective gamma heads tails
    decsMask selected opening]

/-- Consequently the programmed 38-key support is identical on both sides;
there is no extra arbitrary unopened key in the retained overlay. -/
theorem q38_selected_physical_support_eq_public {Other : Type}
    [DecidableEq (Rp05LeafInput ⊕ Other)]
    (points : Fin 6 → Goldilocks)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : Gamma Goldilocks)
    (heads : Heads Goldilocks) (tails : Tails Goldilocks)
    (decsMask : Decs Goldilocks)
    (selected : Fin 38 → LeafIndex)
    (distinct : Function.Injective selected)
    (preamble : Statement) (salt : Fin 32 → CanonicalBytes.Byte)
    (tapes : LeafIndex → LeafTape) :
    Finset.univ.image (fun opening : Fin 38 =>
      (Sum.inl (rp05SourceLeafInput preamble salt
        (q38PhysicalSuffix heads tails decsMask (selected opening))
        (selected opening) (tapes (selected opening))) : Rp05LeafInput ⊕ Other)) =
    Finset.univ.image (fun opening : Fin 38 =>
      (Sum.inl (rp05SourceLeafInput preamble salt
        (q38SelectedPublicData selected
          (q38PublicSuffix points injective gamma
            (response gamma heads tails decsMask)
            (lvcsPublicCombinationHeads points heads) (earlier points tails)
            (fun i => evaluationPoint (selected i))
            (fullSubset heads tails (fun i => evaluationPoint (selected i))))
          (selected opening))
        (selected opening) (tapes (selected opening))) : Rp05LeafInput ⊕ Other)) := by
  rw [q38_selected_physical_keys_eq_public points injective gamma heads tails
    decsMask selected distinct preamble salt tapes]

/-- With the same labels and tapes, the retained 38-key oracle overlay is
identical after replacing physical payloads by public reconstruction.  This
does not identify or alter the unopened 2^23 - 38 leaf coordinates. -/
theorem q38_selected_physical_overlay_eq_public {Other : Type}
    [Fintype Other] [DecidableEq Other]
    (points : Fin 6 → Goldilocks)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : Gamma Goldilocks)
    (heads : Heads Goldilocks) (tails : Tails Goldilocks)
    (decsMask : Decs Goldilocks)
    (selected : Fin 38 → LeafIndex)
    (distinct : Function.Injective selected)
    (preamble : Statement) (salt : Fin 32 → CanonicalBytes.Byte)
    (tapes : LeafIndex → LeafTape)
    (labels : Fin 38 → DigestRegister)
    (oracle : Rp05LeafInput ⊕ Other → DigestRegister) :
    updateRp05Batch 38 (fun opening : Fin 38 =>
      (Sum.inl (rp05SourceLeafInput preamble salt
        (q38PhysicalSuffix heads tails decsMask (selected opening))
        (selected opening) (tapes (selected opening))) : Rp05LeafInput ⊕ Other))
      labels oracle =
    updateRp05Batch 38 (fun opening : Fin 38 =>
      (Sum.inl (rp05SourceLeafInput preamble salt
        (q38SelectedPublicData selected
          (q38PublicSuffix points injective gamma
            (response gamma heads tails decsMask)
            (lvcsPublicCombinationHeads points heads) (earlier points tails)
            (fun i => evaluationPoint (selected i))
            (fullSubset heads tails (fun i => evaluationPoint (selected i))))
          (selected opening))
        (selected opening) (tapes (selected opening))) : Rp05LeafInput ⊕ Other))
      labels oracle := by
  rw [q38_selected_physical_keys_eq_public points injective gamma heads tails
    decsMask selected distinct preamble salt tapes]

end
end HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
