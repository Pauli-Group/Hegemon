import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityGenerated
import Mathlib.Data.List.GetD

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable

open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

inductive TailCsrFamily where
  | compatibilityCopy | sourcePadding | booleanCopy | booleanPadding
  | roleUnit | roleLimbs | roleSelector | roleInverse | rangePadding
  | multiplicationPadding | numericPadding
deriving DecidableEq, Repr

def tailCsrFamilies : List TailCsrFamily :=
  [.compatibilityCopy,.sourcePadding,.booleanCopy,.booleanPadding,.roleUnit,
   .roleLimbs,.roleSelector,.roleInverse,.rangePadding,.multiplicationPadding,.numericPadding]

def TailCsrFamily.number : TailCsrFamily → Nat
  | .compatibilityCopy => 37 | .sourcePadding => 39 | .booleanCopy => 44
  | .booleanPadding => 46 | .roleUnit => 48 | .roleLimbs => 49
  | .roleSelector => 50 | .roleInverse => 51 | .rangePadding => 61
  | .multiplicationPadding => 84 | .numericPadding => 85

def TailCsrFamily.start : TailCsrFamily → Nat
  | .compatibilityCopy => 19262 | .sourcePadding => 19298 | .booleanCopy => 19325
  | .booleanPadding => 19333 | .roleUnit => 19554 | .roleLimbs => 19588
  | .roleSelector => 19792 | .roleInverse => 19826 | .rangePadding => 20258
  | .multiplicationPadding => 20494 | .numericPadding => 20587

def TailCsrFamily.count : TailCsrFamily → Nat
  | .compatibilityCopy => 18 | .sourcePadding => 8 | .booleanCopy => 4
  | .booleanPadding => 11 | .roleUnit => 34 | .roleLimbs => 204
  | .roleSelector => 34 | .roleInverse => 34 | .rangePadding => 38
  | .multiplicationPadding => 93 | .numericPadding => 18

def booleanCopySource (index : Nat) : Nat := [2,4,21,22].getD index 0

def expectedTailCsrAttempt (family : TailCsrFamily) (index : Nat) : CsrExecutableAttempt :=
  let terms : List (Nat × Nat) := match family with
    | .compatibilityCopy => [(41502 + index,1)]
    | .sourcePadding => [(41528 + index,1)]
    | .booleanCopy => [(42115 + index,1),(41408 + booleanCopySource index,3)]
    | .booleanPadding => [(42165 + index,1)]
    | .roleUnit => [(41566 + index,1)]
    | .roleLimbs => [(41630 + index / 6 + 64 * (index % 6),1)]
    | .roleSelector => [(42014 + index,1)]
    | .roleInverse => [(42078 + index,1)]
    | .rangePadding => [(43866 + index,1)]
    | .multiplicationPadding => [(42273 + index / 3 + 64 * (index % 3),1)]
    | .numericPadding => [(42222 + index,1)]
  let target := match family with
    | .compatibilityCopy => 67 + index
    | .roleUnit | .roleInverse => 1
    | _ => 0
  attempt (family.start + index) family.number index 0 terms target

def expectedTailCsrChunk (family : TailCsrFamily) (index : Nat) : List CsrExecutableAttempt :=
  csrChunks037.getD ((family.start + index) / 32 - 592) []

private theorem member_compatibilityCopy_0 (index : Fin 18) :
    expectedTailCsrAttempt .compatibilityCopy (0 + index.val) ∈ expectedTailCsrChunk .compatibilityCopy (0 + index.val) := by
  have checked : ∀ i : Fin 18,
      expectedTailCsrAttempt .compatibilityCopy (0 + i.val) ∈ expectedTailCsrChunk .compatibilityCopy (0 + i.val) := by decide
  exact checked index

private theorem member_sourcePadding_0 (index : Fin 8) :
    expectedTailCsrAttempt .sourcePadding (0 + index.val) ∈ expectedTailCsrChunk .sourcePadding (0 + index.val) := by
  have checked : ∀ i : Fin 8,
      expectedTailCsrAttempt .sourcePadding (0 + i.val) ∈ expectedTailCsrChunk .sourcePadding (0 + i.val) := by decide
  exact checked index

private theorem member_booleanCopy_0 (index : Fin 4) :
    expectedTailCsrAttempt .booleanCopy (0 + index.val) ∈ expectedTailCsrChunk .booleanCopy (0 + index.val) := by
  have checked : ∀ i : Fin 4,
      expectedTailCsrAttempt .booleanCopy (0 + i.val) ∈ expectedTailCsrChunk .booleanCopy (0 + i.val) := by decide
  exact checked index

private theorem member_booleanPadding_0 (index : Fin 11) :
    expectedTailCsrAttempt .booleanPadding (0 + index.val) ∈ expectedTailCsrChunk .booleanPadding (0 + index.val) := by
  have checked : ∀ i : Fin 11,
      expectedTailCsrAttempt .booleanPadding (0 + i.val) ∈ expectedTailCsrChunk .booleanPadding (0 + i.val) := by decide
  exact checked index

private theorem member_roleUnit_0 (index : Fin 32) :
    expectedTailCsrAttempt .roleUnit (0 + index.val) ∈ expectedTailCsrChunk .roleUnit (0 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .roleUnit (0 + i.val) ∈ expectedTailCsrChunk .roleUnit (0 + i.val) := by decide
  exact checked index

private theorem member_roleUnit_32 (index : Fin 2) :
    expectedTailCsrAttempt .roleUnit (32 + index.val) ∈ expectedTailCsrChunk .roleUnit (32 + index.val) := by
  have checked : ∀ i : Fin 2,
      expectedTailCsrAttempt .roleUnit (32 + i.val) ∈ expectedTailCsrChunk .roleUnit (32 + i.val) := by decide
  exact checked index

private theorem member_roleLimbs_0 (index : Fin 32) :
    expectedTailCsrAttempt .roleLimbs (0 + index.val) ∈ expectedTailCsrChunk .roleLimbs (0 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .roleLimbs (0 + i.val) ∈ expectedTailCsrChunk .roleLimbs (0 + i.val) := by decide
  exact checked index

private theorem member_roleLimbs_32 (index : Fin 32) :
    expectedTailCsrAttempt .roleLimbs (32 + index.val) ∈ expectedTailCsrChunk .roleLimbs (32 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .roleLimbs (32 + i.val) ∈ expectedTailCsrChunk .roleLimbs (32 + i.val) := by decide
  exact checked index

private theorem member_roleLimbs_64 (index : Fin 32) :
    expectedTailCsrAttempt .roleLimbs (64 + index.val) ∈ expectedTailCsrChunk .roleLimbs (64 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .roleLimbs (64 + i.val) ∈ expectedTailCsrChunk .roleLimbs (64 + i.val) := by decide
  exact checked index

private theorem member_roleLimbs_96 (index : Fin 32) :
    expectedTailCsrAttempt .roleLimbs (96 + index.val) ∈ expectedTailCsrChunk .roleLimbs (96 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .roleLimbs (96 + i.val) ∈ expectedTailCsrChunk .roleLimbs (96 + i.val) := by decide
  exact checked index

private theorem member_roleLimbs_128 (index : Fin 32) :
    expectedTailCsrAttempt .roleLimbs (128 + index.val) ∈ expectedTailCsrChunk .roleLimbs (128 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .roleLimbs (128 + i.val) ∈ expectedTailCsrChunk .roleLimbs (128 + i.val) := by decide
  exact checked index

private theorem member_roleLimbs_160 (index : Fin 32) :
    expectedTailCsrAttempt .roleLimbs (160 + index.val) ∈ expectedTailCsrChunk .roleLimbs (160 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .roleLimbs (160 + i.val) ∈ expectedTailCsrChunk .roleLimbs (160 + i.val) := by decide
  exact checked index

private theorem member_roleLimbs_192 (index : Fin 12) :
    expectedTailCsrAttempt .roleLimbs (192 + index.val) ∈ expectedTailCsrChunk .roleLimbs (192 + index.val) := by
  have checked : ∀ i : Fin 12,
      expectedTailCsrAttempt .roleLimbs (192 + i.val) ∈ expectedTailCsrChunk .roleLimbs (192 + i.val) := by decide
  exact checked index

private theorem member_roleSelector_0 (index : Fin 32) :
    expectedTailCsrAttempt .roleSelector (0 + index.val) ∈ expectedTailCsrChunk .roleSelector (0 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .roleSelector (0 + i.val) ∈ expectedTailCsrChunk .roleSelector (0 + i.val) := by decide
  exact checked index

private theorem member_roleSelector_32 (index : Fin 2) :
    expectedTailCsrAttempt .roleSelector (32 + index.val) ∈ expectedTailCsrChunk .roleSelector (32 + index.val) := by
  have checked : ∀ i : Fin 2,
      expectedTailCsrAttempt .roleSelector (32 + i.val) ∈ expectedTailCsrChunk .roleSelector (32 + i.val) := by decide
  exact checked index

private theorem member_roleInverse_0 (index : Fin 32) :
    expectedTailCsrAttempt .roleInverse (0 + index.val) ∈ expectedTailCsrChunk .roleInverse (0 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .roleInverse (0 + i.val) ∈ expectedTailCsrChunk .roleInverse (0 + i.val) := by decide
  exact checked index

private theorem member_roleInverse_32 (index : Fin 2) :
    expectedTailCsrAttempt .roleInverse (32 + index.val) ∈ expectedTailCsrChunk .roleInverse (32 + index.val) := by
  have checked : ∀ i : Fin 2,
      expectedTailCsrAttempt .roleInverse (32 + i.val) ∈ expectedTailCsrChunk .roleInverse (32 + i.val) := by decide
  exact checked index

private theorem member_rangePadding_0 (index : Fin 32) :
    expectedTailCsrAttempt .rangePadding (0 + index.val) ∈ expectedTailCsrChunk .rangePadding (0 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .rangePadding (0 + i.val) ∈ expectedTailCsrChunk .rangePadding (0 + i.val) := by decide
  exact checked index

private theorem member_rangePadding_32 (index : Fin 6) :
    expectedTailCsrAttempt .rangePadding (32 + index.val) ∈ expectedTailCsrChunk .rangePadding (32 + index.val) := by
  have checked : ∀ i : Fin 6,
      expectedTailCsrAttempt .rangePadding (32 + i.val) ∈ expectedTailCsrChunk .rangePadding (32 + i.val) := by decide
  exact checked index

private theorem member_multiplicationPadding_0 (index : Fin 32) :
    expectedTailCsrAttempt .multiplicationPadding (0 + index.val) ∈ expectedTailCsrChunk .multiplicationPadding (0 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .multiplicationPadding (0 + i.val) ∈ expectedTailCsrChunk .multiplicationPadding (0 + i.val) := by decide
  exact checked index

private theorem member_multiplicationPadding_32 (index : Fin 32) :
    expectedTailCsrAttempt .multiplicationPadding (32 + index.val) ∈ expectedTailCsrChunk .multiplicationPadding (32 + index.val) := by
  have checked : ∀ i : Fin 32,
      expectedTailCsrAttempt .multiplicationPadding (32 + i.val) ∈ expectedTailCsrChunk .multiplicationPadding (32 + i.val) := by decide
  exact checked index

private theorem member_multiplicationPadding_64 (index : Fin 29) :
    expectedTailCsrAttempt .multiplicationPadding (64 + index.val) ∈ expectedTailCsrChunk .multiplicationPadding (64 + index.val) := by
  have checked : ∀ i : Fin 29,
      expectedTailCsrAttempt .multiplicationPadding (64 + i.val) ∈ expectedTailCsrChunk .multiplicationPadding (64 + i.val) := by decide
  exact checked index

private theorem member_numericPadding_0 (index : Fin 18) :
    expectedTailCsrAttempt .numericPadding (0 + index.val) ∈ expectedTailCsrChunk .numericPadding (0 + index.val) := by
  have checked : ∀ i : Fin 18,
      expectedTailCsrAttempt .numericPadding (0 + i.val) ∈ expectedTailCsrChunk .numericPadding (0 + i.val) := by decide
  exact checked index

theorem expected_tail_csr_chunk_member (family : TailCsrFamily) (index : Fin family.count) :
    expectedTailCsrAttempt family index.val ∈ expectedTailCsrChunk family index.val := by
  cases family with
  | compatibilityCopy =>
      simpa only [Nat.zero_add] using member_compatibilityCopy_0 index
  | sourcePadding =>
      simpa only [Nat.zero_add] using member_sourcePadding_0 index
  | booleanCopy =>
      simpa only [Nat.zero_add] using member_booleanCopy_0 index
  | booleanPadding =>
      simpa only [Nat.zero_add] using member_booleanPadding_0 index
  | roleUnit =>
      by_cases below32 : index.val < 32
      · have chunkProof := member_roleUnit_0 ⟨index.val - 0,by have bound : index.val < 34 := index.isLt; omega⟩
        simpa only [show 0 + (index.val - 0) = index.val by omega] using chunkProof
      have chunkProof := member_roleUnit_32 ⟨index.val - 32,by have bound : index.val < 34 := index.isLt; omega⟩
      simpa only [show 32 + (index.val - 32) = index.val by omega] using chunkProof
  | roleLimbs =>
      by_cases below32 : index.val < 32
      · have chunkProof := member_roleLimbs_0 ⟨index.val - 0,by have bound : index.val < 204 := index.isLt; omega⟩
        simpa only [show 0 + (index.val - 0) = index.val by omega] using chunkProof
      by_cases below64 : index.val < 64
      · have chunkProof := member_roleLimbs_32 ⟨index.val - 32,by have bound : index.val < 204 := index.isLt; omega⟩
        simpa only [show 32 + (index.val - 32) = index.val by omega] using chunkProof
      by_cases below96 : index.val < 96
      · have chunkProof := member_roleLimbs_64 ⟨index.val - 64,by have bound : index.val < 204 := index.isLt; omega⟩
        simpa only [show 64 + (index.val - 64) = index.val by omega] using chunkProof
      by_cases below128 : index.val < 128
      · have chunkProof := member_roleLimbs_96 ⟨index.val - 96,by have bound : index.val < 204 := index.isLt; omega⟩
        simpa only [show 96 + (index.val - 96) = index.val by omega] using chunkProof
      by_cases below160 : index.val < 160
      · have chunkProof := member_roleLimbs_128 ⟨index.val - 128,by have bound : index.val < 204 := index.isLt; omega⟩
        simpa only [show 128 + (index.val - 128) = index.val by omega] using chunkProof
      by_cases below192 : index.val < 192
      · have chunkProof := member_roleLimbs_160 ⟨index.val - 160,by have bound : index.val < 204 := index.isLt; omega⟩
        simpa only [show 160 + (index.val - 160) = index.val by omega] using chunkProof
      have chunkProof := member_roleLimbs_192 ⟨index.val - 192,by have bound : index.val < 204 := index.isLt; omega⟩
      simpa only [show 192 + (index.val - 192) = index.val by omega] using chunkProof
  | roleSelector =>
      by_cases below32 : index.val < 32
      · have chunkProof := member_roleSelector_0 ⟨index.val - 0,by have bound : index.val < 34 := index.isLt; omega⟩
        simpa only [show 0 + (index.val - 0) = index.val by omega] using chunkProof
      have chunkProof := member_roleSelector_32 ⟨index.val - 32,by have bound : index.val < 34 := index.isLt; omega⟩
      simpa only [show 32 + (index.val - 32) = index.val by omega] using chunkProof
  | roleInverse =>
      by_cases below32 : index.val < 32
      · have chunkProof := member_roleInverse_0 ⟨index.val - 0,by have bound : index.val < 34 := index.isLt; omega⟩
        simpa only [show 0 + (index.val - 0) = index.val by omega] using chunkProof
      have chunkProof := member_roleInverse_32 ⟨index.val - 32,by have bound : index.val < 34 := index.isLt; omega⟩
      simpa only [show 32 + (index.val - 32) = index.val by omega] using chunkProof
  | rangePadding =>
      by_cases below32 : index.val < 32
      · have chunkProof := member_rangePadding_0 ⟨index.val - 0,by have bound : index.val < 38 := index.isLt; omega⟩
        simpa only [show 0 + (index.val - 0) = index.val by omega] using chunkProof
      have chunkProof := member_rangePadding_32 ⟨index.val - 32,by have bound : index.val < 38 := index.isLt; omega⟩
      simpa only [show 32 + (index.val - 32) = index.val by omega] using chunkProof
  | multiplicationPadding =>
      by_cases below32 : index.val < 32
      · have chunkProof := member_multiplicationPadding_0 ⟨index.val - 0,by have bound : index.val < 93 := index.isLt; omega⟩
        simpa only [show 0 + (index.val - 0) = index.val by omega] using chunkProof
      by_cases below64 : index.val < 64
      · have chunkProof := member_multiplicationPadding_32 ⟨index.val - 32,by have bound : index.val < 93 := index.isLt; omega⟩
        simpa only [show 32 + (index.val - 32) = index.val by omega] using chunkProof
      have chunkProof := member_multiplicationPadding_64 ⟨index.val - 64,by have bound : index.val < 93 := index.isLt; omega⟩
      simpa only [show 64 + (index.val - 64) = index.val by omega] using chunkProof
  | numericPadding =>
      simpa only [Nat.zero_add] using member_numericPadding_0 index


end HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable
