import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNoteComposition
import HegemonCrypto.SmallWoodV8Smz9Compress14Endpoint

namespace HegemonCrypto.SmallWood.V8Smz9InputMerkleSources

open Hegemon.Transaction hiding Digest
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt FieldExpression)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex inputMerkleCall inputNoteCall inputDirectionRow)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def inlineIndex (step limb component : Nat) : Nat :=
  let slot := step * 7 + limb
  (252 + 4 * (slot / 64) + component) * 64 + slot % 64

def merkleCall (step : Nat) : Nat :=
  inputMerkleCall (step / 32) (step % 32)

def previousCall (step : Nat) : Nat :=
  if step % 32 = 0 then inputNoteCall (step / 32) + 2 else merkleCall step - 1

def initialAttempt (offset : Nat) : CsrExecutableAttempt :=
  let step := offset / 16
  let lane := offset % 16
  attempt (15918 + offset) 14 offset 0
    ([(hashInitialIndex (merkleCall step) lane, 1)] ++
      if lane < 14 then
        [(inlineIndex step (lane % 7) (if lane < 7 then 1 else 2), 158)]
      else [])
    (if lane < 14 then 0 else if lane = 14 then 128 else 544)

def currentAttempt (offset : Nat) : CsrExecutableAttempt :=
  let step := offset / 7
  let limb := offset % 7
  attempt (16942 + offset) 15 offset 0
    [(inlineIndex step limb 0, 1),
     (hashFinalIndex (previousCall step) limb, 158)] 0

def directionAttempt (offset : Nat) : CsrExecutableAttempt :=
  let step := offset / 7
  let limb := offset % 7
  attempt (17390 + offset) 16 offset 0
    [(inlineIndex step limb 3, 1),
     (rawIndex (inputDirectionRow (step / 32) (step % 32)), 158)] 0

def sourceChunks : List (List CsrExecutableAttempt) :=
  [V8Smz9ProgramCanonicalityCsr31.chunk001,
   V8Smz9ProgramCanonicalityCsr31.chunk002,
   V8Smz9ProgramCanonicalityCsr31.chunk003,
   V8Smz9ProgramCanonicalityCsr31.chunk004,
   V8Smz9ProgramCanonicalityCsr31.chunk005,
   V8Smz9ProgramCanonicalityCsr31.chunk006,
   V8Smz9ProgramCanonicalityCsr31.chunk007,
   V8Smz9ProgramCanonicalityCsr31.chunk008,
   V8Smz9ProgramCanonicalityCsr31.chunk009,
   V8Smz9ProgramCanonicalityCsr31.chunk010,
   V8Smz9ProgramCanonicalityCsr31.chunk011,
   V8Smz9ProgramCanonicalityCsr31.chunk012,
   V8Smz9ProgramCanonicalityCsr31.chunk013,
   V8Smz9ProgramCanonicalityCsr31.chunk014,
   V8Smz9ProgramCanonicalityCsr31.chunk015,
   V8Smz9ProgramCanonicalityCsr32.chunk000,
   V8Smz9ProgramCanonicalityCsr32.chunk001,
   V8Smz9ProgramCanonicalityCsr32.chunk002,
   V8Smz9ProgramCanonicalityCsr32.chunk003,
   V8Smz9ProgramCanonicalityCsr32.chunk004,
   V8Smz9ProgramCanonicalityCsr32.chunk005,
   V8Smz9ProgramCanonicalityCsr32.chunk006,
   V8Smz9ProgramCanonicalityCsr32.chunk007,
   V8Smz9ProgramCanonicalityCsr32.chunk008,
   V8Smz9ProgramCanonicalityCsr32.chunk009,
   V8Smz9ProgramCanonicalityCsr32.chunk010,
   V8Smz9ProgramCanonicalityCsr32.chunk011,
   V8Smz9ProgramCanonicalityCsr32.chunk012,
   V8Smz9ProgramCanonicalityCsr32.chunk013,
   V8Smz9ProgramCanonicalityCsr32.chunk014,
   V8Smz9ProgramCanonicalityCsr32.chunk015,
   V8Smz9ProgramCanonicalityCsr33.chunk000,
   V8Smz9ProgramCanonicalityCsr33.chunk001,
   V8Smz9ProgramCanonicalityCsr33.chunk002,
   V8Smz9ProgramCanonicalityCsr33.chunk003,
   V8Smz9ProgramCanonicalityCsr33.chunk004,
   V8Smz9ProgramCanonicalityCsr33.chunk005,
   V8Smz9ProgramCanonicalityCsr33.chunk006,
   V8Smz9ProgramCanonicalityCsr33.chunk007,
   V8Smz9ProgramCanonicalityCsr33.chunk008,
   V8Smz9ProgramCanonicalityCsr33.chunk009,
   V8Smz9ProgramCanonicalityCsr33.chunk010,
   V8Smz9ProgramCanonicalityCsr33.chunk011,
   V8Smz9ProgramCanonicalityCsr33.chunk012,
   V8Smz9ProgramCanonicalityCsr33.chunk013,
   V8Smz9ProgramCanonicalityCsr33.chunk014,
   V8Smz9ProgramCanonicalityCsr33.chunk015,
   V8Smz9ProgramCanonicalityCsr34.chunk000,
   V8Smz9ProgramCanonicalityCsr34.chunk001,
   V8Smz9ProgramCanonicalityCsr34.chunk002,
   V8Smz9ProgramCanonicalityCsr34.chunk003,
   V8Smz9ProgramCanonicalityCsr34.chunk004,
   V8Smz9ProgramCanonicalityCsr34.chunk005,
   V8Smz9ProgramCanonicalityCsr34.chunk006,
   V8Smz9ProgramCanonicalityCsr34.chunk007,
   V8Smz9ProgramCanonicalityCsr34.chunk008,
   V8Smz9ProgramCanonicalityCsr34.chunk009,
   V8Smz9ProgramCanonicalityCsr34.chunk010,
   V8Smz9ProgramCanonicalityCsr34.chunk011,
   V8Smz9ProgramCanonicalityCsr34.chunk012,
   V8Smz9ProgramCanonicalityCsr34.chunk013]

private theorem chunk_497_member :
    V8Smz9ProgramCanonicalityCsr31.chunk001 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk001 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))

private theorem chunk_498_member :
    V8Smz9ProgramCanonicalityCsr31.chunk002 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk002 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))

private theorem chunk_499_member :
    V8Smz9ProgramCanonicalityCsr31.chunk003 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk003 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))

private theorem chunk_500_member :
    V8Smz9ProgramCanonicalityCsr31.chunk004 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk004 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))

private theorem chunk_501_member :
    V8Smz9ProgramCanonicalityCsr31.chunk005 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk005 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))

private theorem chunk_502_member :
    V8Smz9ProgramCanonicalityCsr31.chunk006 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk006 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))

private theorem chunk_503_member :
    V8Smz9ProgramCanonicalityCsr31.chunk007 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk007 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))

private theorem chunk_504_member :
    V8Smz9ProgramCanonicalityCsr31.chunk008 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk008 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))

private theorem chunk_505_member :
    V8Smz9ProgramCanonicalityCsr31.chunk009 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk009 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))

private theorem chunk_506_member :
    V8Smz9ProgramCanonicalityCsr31.chunk010 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk010 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_507_member :
    V8Smz9ProgramCanonicalityCsr31.chunk011 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk011 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_508_member :
    V8Smz9ProgramCanonicalityCsr31.chunk012 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk012 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_509_member :
    V8Smz9ProgramCanonicalityCsr31.chunk013 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk013 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_510_member :
    V8Smz9ProgramCanonicalityCsr31.chunk014 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk014 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_511_member :
    V8Smz9ProgramCanonicalityCsr31.chunk015 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr31.chunk015 ∈ V8Smz9ProgramCanonicalityCsr31.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_512_member :
    V8Smz9ProgramCanonicalityCsr32.chunk000 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk000 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_self)))))))))))))))))))))))))))))))))

private theorem chunk_513_member :
    V8Smz9ProgramCanonicalityCsr32.chunk001 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk001 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))

private theorem chunk_514_member :
    V8Smz9ProgramCanonicalityCsr32.chunk002 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk002 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))

private theorem chunk_515_member :
    V8Smz9ProgramCanonicalityCsr32.chunk003 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk003 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))

private theorem chunk_516_member :
    V8Smz9ProgramCanonicalityCsr32.chunk004 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk004 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))

private theorem chunk_517_member :
    V8Smz9ProgramCanonicalityCsr32.chunk005 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk005 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))

private theorem chunk_518_member :
    V8Smz9ProgramCanonicalityCsr32.chunk006 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk006 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))

private theorem chunk_519_member :
    V8Smz9ProgramCanonicalityCsr32.chunk007 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk007 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))

private theorem chunk_520_member :
    V8Smz9ProgramCanonicalityCsr32.chunk008 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk008 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))

private theorem chunk_521_member :
    V8Smz9ProgramCanonicalityCsr32.chunk009 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk009 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_522_member :
    V8Smz9ProgramCanonicalityCsr32.chunk010 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk010 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_523_member :
    V8Smz9ProgramCanonicalityCsr32.chunk011 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk011 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_524_member :
    V8Smz9ProgramCanonicalityCsr32.chunk012 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk012 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_525_member :
    V8Smz9ProgramCanonicalityCsr32.chunk013 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk013 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_526_member :
    V8Smz9ProgramCanonicalityCsr32.chunk014 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk014 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_527_member :
    V8Smz9ProgramCanonicalityCsr32.chunk015 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr32.chunk015 ∈ V8Smz9ProgramCanonicalityCsr32.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_528_member :
    V8Smz9ProgramCanonicalityCsr33.chunk000 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk000 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_self))))))))))))))))))))))))))))))))))

private theorem chunk_529_member :
    V8Smz9ProgramCanonicalityCsr33.chunk001 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk001 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))

private theorem chunk_530_member :
    V8Smz9ProgramCanonicalityCsr33.chunk002 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk002 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))

private theorem chunk_531_member :
    V8Smz9ProgramCanonicalityCsr33.chunk003 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk003 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))

private theorem chunk_532_member :
    V8Smz9ProgramCanonicalityCsr33.chunk004 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk004 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))

private theorem chunk_533_member :
    V8Smz9ProgramCanonicalityCsr33.chunk005 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk005 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))

private theorem chunk_534_member :
    V8Smz9ProgramCanonicalityCsr33.chunk006 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk006 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))

private theorem chunk_535_member :
    V8Smz9ProgramCanonicalityCsr33.chunk007 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk007 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))

private theorem chunk_536_member :
    V8Smz9ProgramCanonicalityCsr33.chunk008 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk008 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_537_member :
    V8Smz9ProgramCanonicalityCsr33.chunk009 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk009 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_538_member :
    V8Smz9ProgramCanonicalityCsr33.chunk010 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk010 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_539_member :
    V8Smz9ProgramCanonicalityCsr33.chunk011 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk011 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_540_member :
    V8Smz9ProgramCanonicalityCsr33.chunk012 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk012 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_541_member :
    V8Smz9ProgramCanonicalityCsr33.chunk013 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk013 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_542_member :
    V8Smz9ProgramCanonicalityCsr33.chunk014 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk014 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_543_member :
    V8Smz9ProgramCanonicalityCsr33.chunk015 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr33.chunk015 ∈ V8Smz9ProgramCanonicalityCsr33.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_544_member :
    V8Smz9ProgramCanonicalityCsr34.chunk000 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk000 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_self)))))))))))))))))))))))))))))))))))

private theorem chunk_545_member :
    V8Smz9ProgramCanonicalityCsr34.chunk001 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk001 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))

private theorem chunk_546_member :
    V8Smz9ProgramCanonicalityCsr34.chunk002 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk002 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))

private theorem chunk_547_member :
    V8Smz9ProgramCanonicalityCsr34.chunk003 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk003 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))

private theorem chunk_548_member :
    V8Smz9ProgramCanonicalityCsr34.chunk004 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk004 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))

private theorem chunk_549_member :
    V8Smz9ProgramCanonicalityCsr34.chunk005 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk005 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))

private theorem chunk_550_member :
    V8Smz9ProgramCanonicalityCsr34.chunk006 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk006 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))

private theorem chunk_551_member :
    V8Smz9ProgramCanonicalityCsr34.chunk007 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk007 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_552_member :
    V8Smz9ProgramCanonicalityCsr34.chunk008 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk008 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_553_member :
    V8Smz9ProgramCanonicalityCsr34.chunk009 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk009 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_554_member :
    V8Smz9ProgramCanonicalityCsr34.chunk010 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk010 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_555_member :
    V8Smz9ProgramCanonicalityCsr34.chunk011 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk011 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_556_member :
    V8Smz9ProgramCanonicalityCsr34.chunk012 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk012 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self)))))))))))))))))))))))))))))))))))))))))))))))

private theorem chunk_557_member :
    V8Smz9ProgramCanonicalityCsr34.chunk013 ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ (show V8Smz9ProgramCanonicalityCsr34.chunk013 ∈ V8Smz9ProgramCanonicalityCsr34.chunkList from List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self))))))))))))))))))))))))))))))))))))))))))))))))

private theorem source_chunk_member {chunk : List CsrExecutableAttempt}
    (member : chunk ∈ sourceChunks) :
    chunk ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  simp only [sourceChunks, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · exact chunk_497_member
  · exact chunk_498_member
  · exact chunk_499_member
  · exact chunk_500_member
  · exact chunk_501_member
  · exact chunk_502_member
  · exact chunk_503_member
  · exact chunk_504_member
  · exact chunk_505_member
  · exact chunk_506_member
  · exact chunk_507_member
  · exact chunk_508_member
  · exact chunk_509_member
  · exact chunk_510_member
  · exact chunk_511_member
  · exact chunk_512_member
  · exact chunk_513_member
  · exact chunk_514_member
  · exact chunk_515_member
  · exact chunk_516_member
  · exact chunk_517_member
  · exact chunk_518_member
  · exact chunk_519_member
  · exact chunk_520_member
  · exact chunk_521_member
  · exact chunk_522_member
  · exact chunk_523_member
  · exact chunk_524_member
  · exact chunk_525_member
  · exact chunk_526_member
  · exact chunk_527_member
  · exact chunk_528_member
  · exact chunk_529_member
  · exact chunk_530_member
  · exact chunk_531_member
  · exact chunk_532_member
  · exact chunk_533_member
  · exact chunk_534_member
  · exact chunk_535_member
  · exact chunk_536_member
  · exact chunk_537_member
  · exact chunk_538_member
  · exact chunk_539_member
  · exact chunk_540_member
  · exact chunk_541_member
  · exact chunk_542_member
  · exact chunk_543_member
  · exact chunk_544_member
  · exact chunk_545_member
  · exact chunk_546_member
  · exact chunk_547_member
  · exact chunk_548_member
  · exact chunk_549_member
  · exact chunk_550_member
  · exact chunk_551_member
  · exact chunk_552_member
  · exact chunk_553_member
  · exact chunk_554_member
  · exact chunk_555_member
  · exact chunk_556_member
  · exact chunk_557_member

theorem source_entry_mem_exact (index : Nat) {entry : CsrExecutableAttempt}
    (member : entry ∈ sourceChunks.getD index []) : entry ∈ exactCsrAttempts := by
  cases found : sourceChunks[index]? with
  | none => simp only [List.getD_eq_getElem?_getD, found, Option.getD_none, List.not_mem_nil] at member
  | some chunk =>
    have chunkMember : chunk ∈ sourceChunks := List.mem_of_getElem? found
    have entryMember : entry ∈ chunk := by
      simpa only [List.getD_eq_getElem?_getD, found, Option.getD_some] using member
    rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨chunk, source_chunk_member chunkMember, entryMember⟩

private theorem initial_block_00 : ∀ digit : Fin 32,
    initialAttempt (32 * 0 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 0 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_01 : ∀ digit : Fin 32,
    initialAttempt (32 * 1 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 1 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_02 : ∀ digit : Fin 32,
    initialAttempt (32 * 2 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 2 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_03 : ∀ digit : Fin 32,
    initialAttempt (32 * 3 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 3 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_04 : ∀ digit : Fin 32,
    initialAttempt (32 * 4 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 4 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_05 : ∀ digit : Fin 32,
    initialAttempt (32 * 5 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 5 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_06 : ∀ digit : Fin 32,
    initialAttempt (32 * 6 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 6 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_07 : ∀ digit : Fin 32,
    initialAttempt (32 * 7 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 7 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_08 : ∀ digit : Fin 32,
    initialAttempt (32 * 8 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 8 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_09 : ∀ digit : Fin 32,
    initialAttempt (32 * 9 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 9 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_10 : ∀ digit : Fin 32,
    initialAttempt (32 * 10 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 10 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_11 : ∀ digit : Fin 32,
    initialAttempt (32 * 11 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 11 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_12 : ∀ digit : Fin 32,
    initialAttempt (32 * 12 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 12 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_13 : ∀ digit : Fin 32,
    initialAttempt (32 * 13 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 13 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_14 : ∀ digit : Fin 32,
    initialAttempt (32 * 14 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 14 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_15 : ∀ digit : Fin 32,
    initialAttempt (32 * 15 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 15 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_16 : ∀ digit : Fin 32,
    initialAttempt (32 * 16 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 16 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_17 : ∀ digit : Fin 32,
    initialAttempt (32 * 17 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 17 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_18 : ∀ digit : Fin 32,
    initialAttempt (32 * 18 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 18 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_19 : ∀ digit : Fin 32,
    initialAttempt (32 * 19 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 19 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_20 : ∀ digit : Fin 32,
    initialAttempt (32 * 20 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 20 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_21 : ∀ digit : Fin 32,
    initialAttempt (32 * 21 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 21 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_22 : ∀ digit : Fin 32,
    initialAttempt (32 * 22 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 22 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_23 : ∀ digit : Fin 32,
    initialAttempt (32 * 23 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 23 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_24 : ∀ digit : Fin 32,
    initialAttempt (32 * 24 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 24 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_25 : ∀ digit : Fin 32,
    initialAttempt (32 * 25 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 25 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_26 : ∀ digit : Fin 32,
    initialAttempt (32 * 26 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 26 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_27 : ∀ digit : Fin 32,
    initialAttempt (32 * 27 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 27 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_28 : ∀ digit : Fin 32,
    initialAttempt (32 * 28 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 28 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_29 : ∀ digit : Fin 32,
    initialAttempt (32 * 29 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 29 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_30 : ∀ digit : Fin 32,
    initialAttempt (32 * 30 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 30 + digit.val) / 32 - 497) [] := by decide

private theorem initial_block_31 : ∀ digit : Fin 32,
    initialAttempt (32 * 31 + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * 31 + digit.val) / 32 - 497) [] := by decide

private theorem initial_blocks (block : Fin 32) (digit : Fin 32) :
    initialAttempt (32 * block.val + digit.val) ∈
      sourceChunks.getD ((15918 + 32 * block.val + digit.val) / 32 - 497) [] := by
  fin_cases block
  · exact initial_block_00 digit
  · exact initial_block_01 digit
  · exact initial_block_02 digit
  · exact initial_block_03 digit
  · exact initial_block_04 digit
  · exact initial_block_05 digit
  · exact initial_block_06 digit
  · exact initial_block_07 digit
  · exact initial_block_08 digit
  · exact initial_block_09 digit
  · exact initial_block_10 digit
  · exact initial_block_11 digit
  · exact initial_block_12 digit
  · exact initial_block_13 digit
  · exact initial_block_14 digit
  · exact initial_block_15 digit
  · exact initial_block_16 digit
  · exact initial_block_17 digit
  · exact initial_block_18 digit
  · exact initial_block_19 digit
  · exact initial_block_20 digit
  · exact initial_block_21 digit
  · exact initial_block_22 digit
  · exact initial_block_23 digit
  · exact initial_block_24 digit
  · exact initial_block_25 digit
  · exact initial_block_26 digit
  · exact initial_block_27 digit
  · exact initial_block_28 digit
  · exact initial_block_29 digit
  · exact initial_block_30 digit
  · exact initial_block_31 digit

theorem exact_initial_attempt {offset : Nat} (bound : offset < 1024) :
    initialAttempt offset ∈ exactCsrAttempts := by
  have small : offset / 32 < 32 := by omega
  have remainder : offset % 32 < 32 := Nat.mod_lt _ (by decide)
  have equality : 32 * (offset / 32) + offset % 32 = offset := by omega
  have member := initial_blocks ⟨offset / 32, small⟩ ⟨offset % 32, remainder⟩
  simp only [equality] at member
  exact source_entry_mem_exact _ member

private theorem current_block_00 : ∀ digit : Fin 32,
    currentAttempt (32 * 0 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 0 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_01 : ∀ digit : Fin 32,
    currentAttempt (32 * 1 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 1 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_02 : ∀ digit : Fin 32,
    currentAttempt (32 * 2 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 2 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_03 : ∀ digit : Fin 32,
    currentAttempt (32 * 3 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 3 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_04 : ∀ digit : Fin 32,
    currentAttempt (32 * 4 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 4 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_05 : ∀ digit : Fin 32,
    currentAttempt (32 * 5 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 5 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_06 : ∀ digit : Fin 32,
    currentAttempt (32 * 6 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 6 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_07 : ∀ digit : Fin 32,
    currentAttempt (32 * 7 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 7 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_08 : ∀ digit : Fin 32,
    currentAttempt (32 * 8 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 8 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_09 : ∀ digit : Fin 32,
    currentAttempt (32 * 9 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 9 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_10 : ∀ digit : Fin 32,
    currentAttempt (32 * 10 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 10 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_11 : ∀ digit : Fin 32,
    currentAttempt (32 * 11 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 11 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_12 : ∀ digit : Fin 32,
    currentAttempt (32 * 12 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 12 + digit.val) / 32 - 497) [] := by decide

private theorem current_block_13 : ∀ digit : Fin 32,
    currentAttempt (32 * 13 + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * 13 + digit.val) / 32 - 497) [] := by decide

private theorem current_blocks (block : Fin 14) (digit : Fin 32) :
    currentAttempt (32 * block.val + digit.val) ∈
      sourceChunks.getD ((16942 + 32 * block.val + digit.val) / 32 - 497) [] := by
  fin_cases block
  · exact current_block_00 digit
  · exact current_block_01 digit
  · exact current_block_02 digit
  · exact current_block_03 digit
  · exact current_block_04 digit
  · exact current_block_05 digit
  · exact current_block_06 digit
  · exact current_block_07 digit
  · exact current_block_08 digit
  · exact current_block_09 digit
  · exact current_block_10 digit
  · exact current_block_11 digit
  · exact current_block_12 digit
  · exact current_block_13 digit

theorem exact_current_attempt {offset : Nat} (bound : offset < 448) :
    currentAttempt offset ∈ exactCsrAttempts := by
  have small : offset / 32 < 14 := by omega
  have remainder : offset % 32 < 32 := Nat.mod_lt _ (by decide)
  have equality : 32 * (offset / 32) + offset % 32 = offset := by omega
  have member := current_blocks ⟨offset / 32, small⟩ ⟨offset % 32, remainder⟩
  simp only [equality] at member
  exact source_entry_mem_exact _ member

private theorem direction_block_00 : ∀ digit : Fin 32,
    directionAttempt (32 * 0 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 0 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_01 : ∀ digit : Fin 32,
    directionAttempt (32 * 1 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 1 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_02 : ∀ digit : Fin 32,
    directionAttempt (32 * 2 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 2 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_03 : ∀ digit : Fin 32,
    directionAttempt (32 * 3 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 3 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_04 : ∀ digit : Fin 32,
    directionAttempt (32 * 4 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 4 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_05 : ∀ digit : Fin 32,
    directionAttempt (32 * 5 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 5 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_06 : ∀ digit : Fin 32,
    directionAttempt (32 * 6 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 6 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_07 : ∀ digit : Fin 32,
    directionAttempt (32 * 7 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 7 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_08 : ∀ digit : Fin 32,
    directionAttempt (32 * 8 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 8 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_09 : ∀ digit : Fin 32,
    directionAttempt (32 * 9 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 9 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_10 : ∀ digit : Fin 32,
    directionAttempt (32 * 10 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 10 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_11 : ∀ digit : Fin 32,
    directionAttempt (32 * 11 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 11 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_12 : ∀ digit : Fin 32,
    directionAttempt (32 * 12 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 12 + digit.val) / 32 - 497) [] := by decide

private theorem direction_block_13 : ∀ digit : Fin 32,
    directionAttempt (32 * 13 + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * 13 + digit.val) / 32 - 497) [] := by decide

private theorem direction_blocks (block : Fin 14) (digit : Fin 32) :
    directionAttempt (32 * block.val + digit.val) ∈
      sourceChunks.getD ((17390 + 32 * block.val + digit.val) / 32 - 497) [] := by
  fin_cases block
  · exact direction_block_00 digit
  · exact direction_block_01 digit
  · exact direction_block_02 digit
  · exact direction_block_03 digit
  · exact direction_block_04 digit
  · exact direction_block_05 digit
  · exact direction_block_06 digit
  · exact direction_block_07 digit
  · exact direction_block_08 digit
  · exact direction_block_09 digit
  · exact direction_block_10 digit
  · exact direction_block_11 digit
  · exact direction_block_12 digit
  · exact direction_block_13 digit

theorem exact_direction_attempt {offset : Nat} (bound : offset < 448) :
    directionAttempt offset ∈ exactCsrAttempts := by
  have small : offset / 32 < 14 := by omega
  have remainder : offset % 32 < 32 := Nat.mod_lt _ (by decide)
  have equality : 32 * (offset / 32) + offset % 32 = offset := by omega
  have member := direction_blocks ⟨offset / 32, small⟩ ⟨offset % 32, remainder⟩
  simp only [equality] at member
  exact source_entry_mem_exact _ member


end HegemonCrypto.SmallWood.V8Smz9InputMerkleSources
