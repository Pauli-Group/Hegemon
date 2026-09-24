import HegemonCrypto.SmallWoodV8Smz9StableHashCsr
import HegemonCrypto.SmallWoodV8Smz9Compress14Endpoint
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabled

namespace HegemonCrypto.SmallWood.V8Smz9StableConfigHash

open Hegemon.Transaction hiding Digest
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes (packedFinalState)
open HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint
open HegemonCrypto.SmallWood.V8Smz9StableHashCsr

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000
set_option Elab.async false

attribute [local irreducible] Poseidon2Width16Kernel.permutation

def chunkWord (packed : List Nat) (chunk lane : Nat) : Nat :=
  if chunk*14+lane < 55 then packedWord packed (41408+chunk*14+lane) else 0

def chunkLeft (packed : List Nat) (chunk : Nat) : Digest :=
  (List.range 7).map (chunkWord packed chunk)

def chunkRight (packed : List Nat) (chunk : Nat) : Digest :=
  (List.range 7).map (fun lane => chunkWord packed chunk (7+lane))

def chunkConstantAttempt (chunk lane : Nat) : CsrExecutableAttempt :=
  attempt (19860+16*chunk+lane) 52 (16*chunk+lane) 0
    [(hashInitialIndex (106+chunk) lane, 1)]
    (if lane = 14 then 551+chunk else if lane = 15 then 544 else 0)

def chunkConstantRows : List CsrExecutableAttempt :=
  (List.range 4).flatMap fun chunk =>
    ((List.range 16).filter (fun lane => decide (14 ≤ lane ∨ chunk*14+lane=55))).map
      (chunkConstantAttempt chunk)

theorem exact_chunk_constant_attempts (chunk : Fin 4) (lane : Fin 16)
    (constant : 14 ≤ lane.val ∨ chunk.val*14+lane.val=55) :
    chunkConstantAttempt chunk.val lane.val ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 52 &&
      (decide (14 ≤ entry.localIndex % 16) || entry.localIndex == 61)) =
        chunkConstantRows := by decide
  apply (List.mem_filter.mp (show chunkConstantAttempt chunk.val lane.val ∈
    exactCsrAttempts.filter (fun entry => entry.family == 52 &&
      (decide (14 ≤ entry.localIndex % 16) || entry.localIndex == 61)) from ?_)).1
  rw [checked]
  exact List.mem_flatMap.mpr ⟨chunk.val, List.mem_range.mpr chunk.isLt,
    List.mem_map.mpr ⟨lane.val, List.mem_filter.mpr
      ⟨List.mem_range.mpr lane.isLt, by simpa using constant⟩, rfl⟩⟩

def chunkConstant (chunk lane : Nat) : Nat :=
  if lane = 14 then stablecoinV8ConfigChunkDomains.getD chunk 0
  else if lane = 15 then poseidon2V8SuiteMarker else 0

theorem accepted_chunk_constant {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (chunk : Fin 4) (lane : Fin 16)
    (constant : 14 ≤ lane.val ∨ chunk.val*14+lane.val=55) :
    packedWord packed (hashInitialIndex (106+chunk.val) lane.val) =
      chunkConstant chunk.val lane.val := by
  apply accepted_constant_coordinate accepted (19860+16*chunk.val+lane.val) 52
    (16*chunk.val+lane.val) 0 _
    (if lane.val=14 then 551+chunk.val else if lane.val=15 then 544 else 0)
    (chunkConstant chunk.val lane.val)
  · exact exact_chunk_constant_attempts chunk lane constant
  · fin_cases chunk <;> fin_cases lane <;> decide
  · fin_cases chunk <;> fin_cases lane <;> decide

theorem accepted_chunk_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (chunk : Fin 4) {lane : Nat} (rate : lane < 14) :
    packedWord packed (hashInitialIndex (106+chunk.val) lane) =
      chunkWord packed chunk.val lane := by
  by_cases inConfig : chunk.val*14+lane < 55
  · have div : (chunk.val*14+lane)/14 = chunk.val := by omega
    have mod : (chunk.val*14+lane)%14 = lane := by omega
    have copy := accepted_stable_copy_equality accepted
      (word := chunk.val*14+lane) (by omega)
    simpa [stableCopyDestination, stableCopySource, stableSourceIndex,
      inConfig, div, mod, chunkWord, Nat.add_assoc] using copy
  · have endWord : chunk.val*14+lane=55 := by omega
    have constant := accepted_chunk_constant accepted chunk ⟨lane, by omega⟩ (Or.inr endWord)
    simpa [chunkWord, inConfig, chunkConstant,
      show lane ≠ 14 by omega, show lane ≠ 15 by omega] using constant

theorem accepted_chunk_initial {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (chunk : Fin 4) :
    packedInitialState packed (106+chunk.val) =
      compressFrame (stablecoinV8ConfigChunkDomains.getD chunk.val 0)
        (chunkLeft packed chunk.val) (chunkRight packed chunk.val) := by
  apply List.map_congr_left
  intro lane member
  have bound : lane < 16 := List.mem_range.mp member
  by_cases left : lane < 7
  · simpa [compressFrame, left, chunkLeft, List.getD_eq_getElem?_getD] using
      accepted_chunk_source accepted chunk (lane := lane) (by omega)
  · by_cases right : lane < 14
    · have subBound : lane-7 < 7 := by omega
      have addSub : 7+(lane-7)=lane := by omega
      simpa [compressFrame, left, right, chunkRight, List.getD_eq_getElem?_getD,
        subBound, addSub] using accepted_chunk_source accepted chunk right
    · have constant := accepted_chunk_constant accepted chunk ⟨lane, bound⟩ (Or.inl (by change 14 ≤ lane; omega))
      have last : lane=14 ∨ lane=15 := by omega
      rcases last with rfl | rfl <;> simpa [compressFrame, chunkConstant] using constant

theorem accepted_chunk_digest {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (chunk : Fin 4) :
    callDigest packed (106+chunk.val) =
      poseidon2V8Compress14 (stablecoinV8ConfigChunkDomains.getD chunk.val 0)
        (chunkLeft packed chunk.val) (chunkRight packed chunk.val) := by
  exact accepted_compress_digest accepted (by omega) _ _ _
    (accepted_chunk_initial accepted chunk)

def nodeChild (node side : Nat) : Nat :=
  if node < 2 then 106+2*node+side else 110+side

def nodeDomain (node : Nat) : Nat :=
  [stablecoinV8DomainConfigNode0, stablecoinV8DomainConfigNode1,
    stablecoinV8DomainConfigRoot].getD node 0

def nodeAttempt (node lane : Nat) : CsrExecutableAttempt :=
  attempt (19924+16*node+lane) 53 (16*node+lane) 0
    (if lane < 14 then [(hashInitialIndex (110+node) lane, 1),
        (hashFinalIndex (nodeChild node (lane/7)) (lane%7), 158)]
      else [(hashInitialIndex (110+node) lane, 1)])
    (if lane < 14 then 0 else if lane=14 then 555+node else 544)

theorem exact_node_attempts (node : Fin 3) (lane : Fin 16) :
    nodeAttempt node.val lane.val ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 53) =
      (List.range 3).flatMap (fun node => (List.range 16).map (nodeAttempt node)) := by decide
  apply (List.mem_filter.mp (show nodeAttempt node.val lane.val ∈ exactCsrAttempts.filter
    (fun entry => entry.family == 53) from ?_)).1
  rw [checked]
  exact List.mem_flatMap.mpr ⟨node.val, List.mem_range.mpr node.isLt,
    List.mem_map.mpr ⟨lane.val, List.mem_range.mpr lane.isLt, rfl⟩⟩

theorem accepted_node_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (node : Fin 3) (lane : Fin 14) :
    packedWord packed (hashInitialIndex (110+node.val) lane.val) =
      packedWord packed (hashFinalIndex (nodeChild node.val (lane.val/7)) (lane.val%7)) := by
  apply accepted_copied_coordinate accepted (19924+16*node.val+lane.val) 53
    (16*node.val+lane.val) 0 _ _
  simpa only [nodeAttempt, if_pos lane.isLt] using
    exact_node_attempts node ⟨lane.val, by omega⟩

theorem accepted_node_constant {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (node : Fin 3) (lane : Fin 16) (high : 14 ≤ lane.val) :
    packedWord packed (hashInitialIndex (110+node.val) lane.val) =
      if lane.val=14 then nodeDomain node.val else poseidon2V8SuiteMarker := by
  apply accepted_constant_coordinate accepted (19924+16*node.val+lane.val) 53
    (16*node.val+lane.val) 0 _ (if lane.val=14 then 555+node.val else 544)
    (if lane.val=14 then nodeDomain node.val else poseidon2V8SuiteMarker)
  · simpa only [nodeAttempt, if_neg (show ¬lane.val<14 by omega)] using
      exact_node_attempts node lane
  · fin_cases node <;> fin_cases lane <;> decide
  · fin_cases node <;> fin_cases lane <;> decide

theorem call_digest_word (packed : List Nat) (call : Nat) {lane : Nat} (bound : lane < 7) :
    (callDigest packed call).getD lane 0 = packedWord packed (hashFinalIndex call lane) := by
  simp [callDigest, packedFinalState, digestWords, List.getD_eq_getElem?_getD, bound]

theorem accepted_node_initial {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (node : Fin 3) :
    packedInitialState packed (110+node.val) = compressFrame (nodeDomain node.val)
      (callDigest packed (nodeChild node.val 0)) (callDigest packed (nodeChild node.val 1)) := by
  apply List.map_congr_left
  intro lane member
  have bound : lane < 16 := List.mem_range.mp member
  by_cases left : lane < 7
  · have div : lane/7=0 := by omega
    have mod : lane%7=lane := Nat.mod_eq_of_lt left
    simpa only [compressFrame, if_pos left, div, mod, call_digest_word packed _ left] using
      accepted_node_source accepted node ⟨lane, by omega⟩
  · by_cases right : lane < 14
    · have subBound : lane-7 < 7 := by omega
      have div : lane/7=1 := by omega
      have mod : lane%7=lane-7 := by omega
      simpa only [compressFrame, if_neg left, if_pos right, div, mod, call_digest_word packed _ subBound] using
        accepted_node_source accepted node ⟨lane, right⟩
    · simpa [compressFrame, left, right] using
        accepted_node_constant accepted node ⟨lane, bound⟩ (by change 14 ≤ lane; omega)

theorem accepted_node_digest {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (node : Fin 3) :
    callDigest packed (110+node.val) = poseidon2V8Compress14 (nodeDomain node.val)
      (callDigest packed (nodeChild node.val 0)) (callDigest packed (nodeChild node.val 1)) := by
  exact accepted_compress_digest accepted (by omega) _ _ _ (accepted_node_initial accepted node)

theorem encode_decode_config (witness : V8StablecoinWitness) :
    encodeV8StablecoinConfig (decodeV8StablecoinConfig witness) =
      (List.range 55).map (stableWitnessWord witness) := by rfl

theorem admitted_config_encoded_source {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    encodeV8StablecoinConfig
        (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin) =
      (List.range 55).map (fun word => packedWord packed (41408+word)) := by
  rw [encode_decode_config]
  apply List.map_congr_left
  intro word member
  exact admitted_stable_config_word_source domain (List.mem_range.mp member)

def rawConfigDigest (packed : List Nat) : Digest :=
  let chunk := fun c => poseidon2V8Compress14 (stablecoinV8ConfigChunkDomains.getD c 0)
    (chunkLeft packed c) (chunkRight packed c)
  poseidon2V8Compress14 stablecoinV8DomainConfigRoot
    (poseidon2V8Compress14 stablecoinV8DomainConfigNode0 (chunk 0) (chunk 1))
    (poseidon2V8Compress14 stablecoinV8DomainConfigNode1 (chunk 2) (chunk 3))

theorem accepted_config_digest_raw {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    callDigest packed 112 = rawConfigDigest packed := by
  have n0 := accepted_node_digest accepted ⟨0, by decide⟩
  have n1 := accepted_node_digest accepted ⟨1, by decide⟩
  have n2 := accepted_node_digest accepted ⟨2, by decide⟩
  change callDigest packed 110 = poseidon2V8Compress14 stablecoinV8DomainConfigNode0
    (callDigest packed 106) (callDigest packed 107) at n0
  change callDigest packed 111 = poseidon2V8Compress14 stablecoinV8DomainConfigNode1
    (callDigest packed 108) (callDigest packed 109) at n1
  change callDigest packed 112 = poseidon2V8Compress14 stablecoinV8DomainConfigRoot
    (callDigest packed 110) (callDigest packed 111) at n2
  have c0 := accepted_chunk_digest accepted ⟨0, by decide⟩
  have c1 := accepted_chunk_digest accepted ⟨1, by decide⟩
  have c2 := accepted_chunk_digest accepted ⟨2, by decide⟩
  have c3 := accepted_chunk_digest accepted ⟨3, by decide⟩
  change callDigest packed 106 = _ at c0
  change callDigest packed 107 = _ at c1
  change callDigest packed 108 = _ at c2
  change callDigest packed 109 = _ at c3
  rw [n2, n0, n1, c0, c1, c2, c3]
  rfl

theorem admitted_exact_config_digest_raw {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    exactV8StablecoinConfigDigest
        (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin) =
      rawConfigDigest packed := by
  unfold exactV8StablecoinConfigDigest
  rw [admitted_config_encoded_source domain]
  rfl

theorem admitted_config_digest {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    callDigest packed 112 = exactV8StablecoinConfigDigest
      (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin) :=
  (accepted_config_digest_raw domain.2.2).trans (admitted_exact_config_digest_raw domain).symm


end HegemonCrypto.SmallWood.V8Smz9StableConfigHash
