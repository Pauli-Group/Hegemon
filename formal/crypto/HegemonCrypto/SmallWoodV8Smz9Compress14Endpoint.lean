import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNoteComposition


namespace HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint

open Hegemon.Transaction hiding Digest
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def callDigest (packed : List Nat) (call : Nat) : List Nat :=
  (packedFinalState packed call).take digestWords

def compressFrame (domain : Nat) (left right : Digest) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 7 then left.getD lane 0
    else if lane < 14 then right.getD (lane - 7) 0
    else if lane = 14 then domain else poseidon2V8SuiteMarker


attribute [local irreducible] Poseidon2Width16Kernel.permutation

theorem accepted_compress_digest {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {call : Nat} (callBound : call < 128) (domain : Nat) (left right : Digest)
    (frame : packedInitialState packed call = compressFrame domain left right) :
    callDigest packed call = poseidon2V8Compress14 domain left right := by
  unfold callDigest poseidon2V8Compress14
  change (packedFinalState packed call).take digestWords =
    (Poseidon2Width16Kernel.permutation (compressFrame domain left right)).take digestWords
  exact congrArg (fun state : List Nat => state.take digestWords)
    ((accepted_final_state_eq_kernel accepted callBound).trans
      (congrArg Poseidon2Width16Kernel.permutation frame))


end HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint
