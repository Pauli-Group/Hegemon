import Hegemon.Transaction.Poseidon2V8SemanticSpecification

namespace Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives

open Poseidon2V8SemanticSpecification

set_option maxHeartbeats 0

/-!
Executable primitive model for the separate COMPFF01 compression mode.

The historical semantic specification, its raw-output compressor, and its receipts remain
unchanged. This module reuses its typed config, encoders, domains, counters, unchanged sponge,
and exact permutation. Only the compression frame and digest extraction change. The generated
values are finite cross-language conformance evidence, not an accepted-witness or compiler
refinement theorem, a G1/G7 qualification, or production authority.
-/

def compressionModeId : String := "hegemon-p2w16-compress14-left-feedforward-v1"
def compressionModeMarker : Nat := 0x434f_4d50_4646_3031

def compressionFrame (domain : Nat) (left right : Digest) : List Nat :=
  (List.range Poseidon2Width16Kernel.width).map fun lane =>
    if lane < digestWords then left.getD lane 0
    else if lane < 2 * digestWords then right.getD (lane - digestWords) 0
    else if lane = 2 * digestWords then domain
    else compressionModeMarker

def rawPermutation (domain : Nat) (left right : Digest) : List Nat :=
  Poseidon2Width16Kernel.permutation (compressionFrame domain left right)

def compress14 (domain : Nat) (left right : Digest) : Digest :=
  let raw := rawPermutation domain left right
  (List.range digestWords).map fun lane =>
    Poseidon2Width16Kernel.fieldAdd (raw.getD lane 0) (left.getD lane 0)

theorem compression_frame_has_sixteen_lanes (domain : Nat) (left right : Digest) :
    (compressionFrame domain left right).length = 16 := by
  simp [compressionFrame, Poseidon2Width16Kernel.width]

theorem compressed_digest_has_seven_lanes (domain : Nat) (left right : Digest) :
    (compress14 domain left right).length = 7 := by
  simp [compress14, digestWords]

theorem compression_marker_is_separate :
    compressionModeMarker ≠ poseidon2V8SuiteMarker ∧
      compressionModeMarker ≠ poseidon2V8SpongeModeMarker := by decide

def stablecoinIssuerCommitment
    (assetId policyVersion : Nat) (issuerSecret : Digest) : Digest :=
  compress14 stablecoinV8DomainIssuerCommitment issuerSecret
    [assetId, policyVersion, 0, 0, 0, 0, 0]

def stablecoinIssuerAuthorization (actionIntent issuerSecret : Digest) : Digest :=
  compress14 stablecoinV8DomainIssuerAuthorization issuerSecret actionIntent

def stablecoinConfigDigest (config : V8StablecoinConfigOpening) : Digest :=
  let fields := encodeV8StablecoinConfig config
  let chunks := (List.range 4).map fun chunk =>
    (List.range 14).map fun lane => fields.getD (chunk * 14 + lane) 0
  let digests := (List.range 4).map fun chunk =>
    let words := chunks.getD chunk []
    compress14 (stablecoinV8ConfigChunkDomains.getD chunk 0)
      (words.take 7) ((words.drop 7).take 7)
  let left := compress14 stablecoinV8DomainConfigNode0
    (digests.getD 0 []) (digests.getD 1 [])
  let right := compress14 stablecoinV8DomainConfigNode1
    (digests.getD 2 []) (digests.getD 3 [])
  compress14 stablecoinV8DomainConfigRoot left right

def stablecoinLeaf
    (index : Nat) (configDigest : Digest) (counters : V8StablecoinCounters) : Digest :=
  compress14 stablecoinV8DomainStateLeaf configDigest
    [counters.epochId, counters.mintedInEpoch, counters.totalDebt, counters.sequence, index, 0, 0]

def stablecoinRoot
    (assetId : Nat) (configDigest : Digest) (counters : V8StablecoinCounters)
    (siblings : List Digest) : Digest :=
  let index := assetId % (2 ^ stablecoinV8Depth)
  let leaf := stablecoinLeaf index configDigest counters
  (List.range stablecoinV8Depth).foldl (fun current level =>
    let sibling := siblings.getD level []
    if (index / (2 ^ level)) % 2 = 0 then
      compress14 (stablecoinV8DomainStateNode0 + level) current sibling
    else compress14 (stablecoinV8DomainStateNode0 + level) sibling current) leaf

def katConfig : V8StablecoinConfigOpening :=
  { stablecoinV8KatConfig with
      issuerCommitment := stablecoinIssuerCommitment 1001 7 stablecoinV8KatIssuerSecret }

def katConfigDigest : Digest := stablecoinConfigDigest katConfig
def katBeforeRoot : Digest :=
  stablecoinRoot 1001 katConfigDigest stablecoinV8KatBefore stablecoinV8KatSiblings
def katMintAfterRoot : Digest :=
  stablecoinRoot 1001 katConfigDigest stablecoinV8MintKatAfter stablecoinV8KatSiblings
def katBurnAfterRoot : Digest :=
  stablecoinRoot 1001 katConfigDigest stablecoinV8BurnKatAfter stablecoinV8KatSiblings

/-- Fixed protocol packing inventory: all 128 call positions, across both 64-lane groups. -/
def packedCallCount : Nat := 128

def caseLeft (call : Nat) : Digest :=
  (List.range digestWords).map fun lane => call * 17 + lane
def caseRight (call : Nat) : Digest :=
  (List.range digestWords).map fun lane => call * 19 + lane + digestWords

end Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives
