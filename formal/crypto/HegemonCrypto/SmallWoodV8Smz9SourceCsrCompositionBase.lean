import HegemonCrypto.SmallWoodV8Smz9SourceReplicateResiduals
import HegemonCrypto.SmallWoodV8Smz9SourceDense103
import HegemonCrypto.SmallWoodV8Smz9SourceBase7
import HegemonCrypto.SmallWoodV8Smz9SourceCipher12
import HegemonCrypto.SmallWoodV8Smz9SourceInactiveRaw92
import HegemonCrypto.SmallWoodV8Smz9SourcePrfResiduals
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleInitialResiduals
import HegemonCrypto.SmallWoodV8Smz9SourceInactiveMerkleRightRoots
import HegemonCrypto.SmallWoodV8Smz9SourceInitial288Endpoint
import HegemonCrypto.SmallWoodV8Smz9SourceAuthDigestCsr
import HegemonCrypto.SmallWoodV8Smz9SourcePolicyResiduals
import HegemonCrypto.SmallWoodV8Smz9SourceInlinePolicy192
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitial128
import HegemonCrypto.SmallWoodV8Smz9SourceInputKeyCsr12
import HegemonCrypto.SmallWoodV8Smz9SourceNote216
import HegemonCrypto.SmallWoodV8Smz9SourceNullifier32
import HegemonCrypto.SmallWoodV8Smz9SourcePublicDigest42
import HegemonCrypto.SmallWoodV8Smz9SourceLiveCsrRoots
import HegemonCrypto.SmallWoodV8Smz9SourceLiveRoleCsrRoots
import HegemonCrypto.SmallWoodV8Smz9SourceTailCsrRoots
import HegemonCrypto.SmallWoodV8Smz9SourceStableConfig112
import HegemonCrypto.SmallWoodV8Smz9SourceStableLeaf32
import HegemonCrypto.SmallWoodV8Smz9SourceStablePath128
import HegemonCrypto.SmallWoodV8Smz9SourceStableIssuer32
import HegemonCrypto.SmallWoodV8Smz9SourceStableOutput28
import HegemonCrypto.SmallWoodV8Smz9SourceStableRange66
import HegemonCrypto.SmallWoodV8Smz9SourceStablePadding24
/-! Indexed composition of the exact same typed source candidate.
No complete acceptance premise or caller-supplied constructor material. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceCsrCompositionBase
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood
open V8Smz9RelationProgramComponentsGenerated
open V8Smz9SourceFullTypedCandidate
open V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

abbrev sourceCsrPub (statement : V8PublicStatement) : Nat → F :=
  fun i => ((encodePublicStatement statement).getD i 0 : F)

def sourceCsrZero (statement : V8PublicStatement) (witness : V8Witness) (index : Nat) : Prop :=
  (exactCsrAttempts[index]?).map
    (actualCsrResidual (sourceCsrPub statement) (fullTypedSourceCandidate statement witness)) = some 0

theorem source_csr_reindex (statement : V8PublicStatement) (witness : V8Witness)
    {first second : Nat} (same : first = second)
    (zero : sourceCsrZero statement witness first) : sourceCsrZero statement witness second := by
  rw [← same]; exact zero

theorem source_csr_replicate (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 15561) : sourceCsrZero statement witness index.val :=
  V8Smz9SourceReplicateCsr.typed_all_15561_actual_replicate_csr_zero statement witness
    (typedSourceTail statement witness) (sourceCsrPub statement) index.val index.isLt

theorem source_csr_dense7 (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 7) : sourceCsrZero statement witness (15665 + index.val) :=
  V8Smz9SourceTypedPrefix.typed_all_seven_actual_csr_zero statement witness
    (typedSourceTail statement witness) index

theorem source_csr_prf16 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 16) :
    sourceCsrZero statement witness (15789 + index.val) := by
  obtain ⟨entry,found,_,_,zero⟩ :=
    V8Smz9SourcePrfInitial.full_candidate_actual_prf_all_16_zero statement witness valid index
  unfold sourceCsrZero
  rw [found,Option.map_some,zero]

theorem source_csr_initial288 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 288) :
    sourceCsrZero statement witness (V8Smz9SourceInitial288.initial288GlobalIndex index) := by
  obtain ⟨entry,found,_,_,zero⟩ :=
    V8Smz9SourceInitial288.full_candidate_actual_all_288_initial_zero statement witness valid index
  unfold sourceCsrZero
  rw [found,Option.map_some,zero]

def note216Reordered (index : Fin 216) : Fin 216 :=
  ⟨if index.val < 72 then index.val else if index.val < 108 then 144 + (index.val-72)
    else if index.val < 180 then 72 + (index.val-108) else 180 + (index.val-180), by split_ifs <;> omega⟩

theorem note216_contiguous_index (index : Fin 216) :
    V8Smz9SourceNoteFrames.note216Index (note216Reordered index).val =
      if index.val < 108 then 15810 + index.val else 18346 + (index.val-108) := by
  have checked : ∀ i : Fin 216,
      V8Smz9SourceNoteFrames.note216Index (note216Reordered i).val =
        if i.val < 108 then 15810 + i.val else 18346 + (i.val-108) := by decide
  exact checked index

theorem source_csr_note216 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 216) :
    sourceCsrZero statement witness
      (if index.val < 108 then 15810 + index.val else 18346 + (index.val-108)) :=
  source_csr_reindex statement witness (note216_contiguous_index index)
    (V8Smz9SourceNoteFrames.full_candidate_actual_note216_zero statement witness valid (note216Reordered index))

end
end HegemonCrypto.SmallWood.V8Smz9SourceCsrCompositionBase
