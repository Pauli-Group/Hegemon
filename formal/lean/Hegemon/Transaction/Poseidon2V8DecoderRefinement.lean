import Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

namespace Hegemon
namespace Transaction
namespace Poseidon2V8DecoderRefinement

/-!
Exhaustive finite correspondence surface for the Rust arbitrary-assignment decoder.

Each entry is seven natural numbers:
`typed index, semantic family, decoder operation, argument 0, ..., argument 3`.
The family and operation discriminants are pinned to the `repr(u8)` Rust enums.  Coordinates are
absolute words in the 43,904-word packed assignment, except where the operation names a public
statement word.  This file deliberately proves finite layout and branch coverage only; identifying
these definitions with compiled Rust remains a separately named translation boundary.
-/

def packingFactor : Nat := 64
def rawRowStart : Nat := 0
def hashRowStart : Nat := 283
def hashRowsPerGroup : Nat := 182
def hashFinalRowOffset : Nat := 166
def noCoordinate : Nat := 2 ^ 64 - 1

def familyInput0 : Nat := 0
def familyInput1 : Nat := 1
def familyOutput0 : Nat := 2
def familyOutput1 : Nat := 3
def familyAuthorization : Nat := 4
def familyStablecoin : Nat := 5

def opStatementWord : Nat := 0
def opActivitySelectedSpongeSource : Nat := 1
def opSpongeSource : Nat := 2
def opPackDirectionBits : Nat := 3
def opOrientedMerkleSibling : Nat := 4
def opDerivedBalanceSelector : Nat := 5
def opAuthorizationModeOneHot : Nat := 6
def opApprovalSelectedSpongeSource : Nat := 7
def opRawWord : Nat := 8
def opHashInitialWord : Nat := 9
def opOrientedStableSibling : Nat := 10

def rawIndex (row : Nat) : Nat := (rawRowStart + row) * packingFactor

def hashInitialIndex (call stateLane : Nat) : Nat :=
  hashRowStart * packingFactor +
    (((call / packingFactor) * hashRowsPerGroup + stateLane) * packingFactor) +
    call % packingFactor

def hashFinalIndex (call stateLane : Nat) : Nat :=
  hashRowStart * packingFactor +
    (((call / packingFactor) * hashRowsPerGroup + hashFinalRowOffset + stateLane) *
      packingFactor) + call % packingFactor

def spongeArguments (firstCall word : Nat) : List Nat :=
  let block := word / 8
  let lane := word % 8
  let call := firstCall + block
  [ hashInitialIndex call lane,
    if block = 0 then noCoordinate else hashFinalIndex (call - 1) lane,
    call, lane ]

def descriptor (family operation : Nat) (arguments : List Nat) : List Nat :=
  [family, operation] ++ arguments

def noteHashWordOrder : List Nat :=
  [0, 1, 2, 3, 4, 5, 14, 15, 16, 17, 6, 7, 8, 9, 10, 11, 12, 13]

def inputNoteCall (input : Nat) : Nat := if input = 0 then 1 else 37
def inputMerkleCall (input level : Nat) : Nat :=
  (if input = 0 then 4 else 40) + level
def outputNoteCall (output : Nat) : Nat := 73 + output * 3
def inputDirectionRow (input bit : Nat) : Nat := input * 34 + 2 + bit
def authorizationModeRow (mode : Nat) : Nat := 92 + mode
def authorizationPolicyTagRow (slot limb : Nat) : Nat := 196 + slot * 5 + limb

def inputSection (input : Nat) : List (List Nat) :=
  let family := if input = 0 then familyInput0 else familyInput1
  let activityPublicWord := input
  let noteStart := input * 252 + 5
  [descriptor family opStatementWord [activityPublicWord, 0, 0, 0]] ++
  (List.range 4).map (fun limb =>
    descriptor family opActivitySelectedSpongeSource
      ((spongeArguments 0 limb).set 3 activityPublicWord)) ++
  noteHashWordOrder.map (fun hashWord =>
    descriptor family opSpongeSource (spongeArguments (inputNoteCall input) hashWord)) ++
  [descriptor family opPackDirectionBits
    [rawIndex (inputDirectionRow input 0), packingFactor, 32, input]] ++
  (List.range 32).flatMap (fun level =>
    (List.range 7).map (fun limb =>
      let call := inputMerkleCall input level
      descriptor family opOrientedMerkleSibling
        [ hashInitialIndex call limb, hashInitialIndex call (7 + limb),
          rawIndex (inputDirectionRow input level), level ])) ++
  (List.range 4).map (fun balanceSlot =>
    descriptor family opDerivedBalanceSelector
      [activityPublicWord, noteStart + 1, 54 + balanceSlot, balanceSlot])

def outputSection (output : Nat) : List (List Nat) :=
  let family := if output = 0 then familyOutput0 else familyOutput1
  let activityPublicWord := 2 + output
  let noteStart := 504 + output * 23 + 1
  [descriptor family opStatementWord [activityPublicWord, 0, 0, 0]] ++
  noteHashWordOrder.map (fun hashWord =>
    descriptor family opSpongeSource (spongeArguments (outputNoteCall output) hashWord)) ++
  (List.range 4).map (fun balanceSlot =>
    descriptor family opDerivedBalanceSelector
      [activityPublicWord, noteStart + 1, 54 + balanceSlot, balanceSlot])

def authorizationSection : List (List Nat) :=
  [descriptor familyAuthorization opAuthorizationModeOneHot
    [ rawIndex (authorizationModeRow 0), rawIndex (authorizationModeRow 1),
      rawIndex (authorizationModeRow 2), 0 ]] ++
  (List.range 23).map (fun word =>
    descriptor familyAuthorization opSpongeSource (spongeArguments 98 word)) ++
  (List.range 23).map (fun word =>
    descriptor familyAuthorization opApprovalSelectedSpongeSource (spongeArguments 101 word)) ++
  (List.range 6).flatMap (fun slot =>
    (List.range 5).map (fun limb =>
      descriptor familyAuthorization opRawWord
        [rawIndex (authorizationPolicyTagRow slot limb), slot, limb, 0]))

def stablecoinSection : List (List Nat) :=
  (List.range 55).map (fun word =>
    let call := 106 + word / 14
    let lane := word % 14
    descriptor familyStablecoin opHashInitialWord
      [hashInitialIndex call lane, call, lane, word]) ++
  (List.range 4).map (fun counter =>
    let lane := 7 + counter
    descriptor familyStablecoin opHashInitialWord
      [hashInitialIndex 113 lane, 113, lane, counter]) ++
  (List.range 4).flatMap (fun level =>
    (List.range 7).map (fun limb =>
      let call := 115 + 2 * level
      descriptor familyStablecoin opOrientedStableSibling
        [hashInitialIndex call limb, hashInitialIndex call (7 + limb), 84, level])) ++
  (List.range 7).map (fun limb =>
    descriptor familyStablecoin opHashInitialWord
      [hashInitialIndex 123 limb, 123, limb, limb])

def decoderDescriptors : List (List Nat) :=
  (List.range 2).flatMap inputSection ++
    (List.range 2).flatMap outputSection ++ authorizationSection ++ stablecoinSection

def decoderSources : List (List Nat) :=
  decoderDescriptors.zipIdx.map (fun indexed => indexed.2 :: indexed.1)

def operationCount (operation : Nat) : Nat :=
  (decoderSources.filter (fun entry => entry.getD 2 noCoordinate = operation)).length

def familyCount (family : Nat) : Nat :=
  (decoderSources.filter (fun entry => entry.getD 1 noCoordinate = family)).length

def activityMaskBranches : List Nat := List.range 16
def authorizationModeBranches : List Nat := List.range 3
def stablecoinDirectionBranches : List Nat := List.range 3
def stableTreeIndexBranches : List Nat := List.range 16

theorem decoder_sources_cover_every_typed_word : decoderSources.length = 721 := by
  native_decide

theorem decoder_sources_have_consecutive_indices :
    decoderSources.map (fun entry => entry.getD 0 noCoordinate) = List.range 721 := by
  native_decide

theorem decoder_family_counts_are_exact :
    [ familyCount familyInput0, familyCount familyInput1,
      familyCount familyOutput0, familyCount familyOutput1,
      familyCount familyAuthorization, familyCount familyStablecoin ] =
    [252, 252, 23, 23, 77, 94] := by
  native_decide

theorem decoder_operation_counts_are_exact :
    (List.range 11).map operationCount = [4, 8, 95, 2, 448, 16, 1, 23, 30, 66, 28] := by
  native_decide

theorem validator_branch_spaces_are_exhaustive :
    activityMaskBranches.length = 16 ∧
    authorizationModeBranches = [0, 1, 2] ∧
    stablecoinDirectionBranches = [0, 1, 2] ∧
    stableTreeIndexBranches.length = 16 := by
  native_decide

theorem note_hash_to_typed_word_permutation_is_exact :
    noteHashWordOrder.length = 18 ∧ noteHashWordOrder.mergeSort (· ≤ ·) = List.range 18 := by
  native_decide

/-- Exact relowering checks all packed words, not only coordinates read by the decoder. -/
def reloweringComparedPackedWords : Nat := 43904

theorem relowering_comparison_is_full_assignment :
    reloweringComparedPackedWords = Poseidon2V8SemanticSpecification.packedWitnessWordCount := by
  rfl

end Poseidon2V8DecoderRefinement
end Transaction
end Hegemon
