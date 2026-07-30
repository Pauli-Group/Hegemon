import HegemonCrypto.SmallWoodTranscript
import Mathlib.Data.List.GetD

/-!
# Exact SHA-512 digest and Goldilocks-XOF boundary

The active SmallWood implementation uses SHA-512 in two different ways:

* Merkle nodes and intermediate transcript commitments are raw 512-bit digests.
* Verifier challenges are canonical Goldilocks elements obtained by scanning consecutive
  SHA-512 counter blocks and rejecting 64-bit words outside the field.

Those objects are not interchangeable.  In particular, a raw SHA-512 digest word need not be a
canonical Goldilocks representative.  This module models the exact split without assuming a
particular implementation of SHA-512.  The oracle returns one raw eight-word digest for one exact
byte preimage; rejection sampling is then a deterministic construction over that oracle.
-/

namespace HegemonCrypto.SmallWood.Sha512Xof

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-- One raw 512-bit SHA-512 digest, represented in Rust's little-endian `u64` word order. -/
abbrev RawDigest := Fin digestWordCount -> Word

/-- The hash-function boundary: one exact byte string maps to one raw 512-bit digest. -/
abbrev RawOracle := List Byte -> RawDigest

/-- Number of distinct counter blocks addressable by the production `u64` counter. -/
def counterBlockCount : Nat := 2 ^ 64

/-- Number of raw 64-bit candidates addressable before counter exhaustion. -/
def candidateCapacity : Nat := digestWordCount * counterBlockCount

theorem candidate_capacity_is_positive : 0 < candidateCapacity := by
  unfold candidateCapacity counterBlockCount digestWordCount
  positivity

/-- Raw digest words in their production transcript order. -/
def RawDigest.words (digest : RawDigest) : List Word :=
  List.ofFn digest

theorem RawDigest.words_length (digest : RawDigest) :
    digest.words.length = digestWordCount := by
  simp [RawDigest.words]

/-- The eight little-endian words retain the complete raw SHA-512 digest. -/
theorem RawDigest.words_injective :
    Function.Injective RawDigest.words := by
  intro left right sameWords
  exact List.ofFn_injective sameWords

/-- Exact raw SHA-512 digest call used by Merkle and transcript commitment hashes. -/
def rawDigest
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (counter : Nat := 0) : RawDigest :=
  oracle (sha512BlockPreimage domain words counter)

/-- The modeled digest call uses exactly the production preimage grammar. -/
theorem rawDigest_eq_oracle_preimage
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (counter : Nat := 0) :
    rawDigest oracle domain words counter =
      oracle
        (encodeLE 8 domain.length
          ++ domain
          ++ encodeLE 8 words.length
          ++ flattenWordBytes words
          ++ encodeLE 8 counter) := by
  rfl

/-- Different in-range `u64` counters produce different SHA-512 request byte strings. -/
theorem sha512BlockPreimage_counter_injective
    (domain : List Byte)
    (words : List Word)
    {left right : Nat}
    (leftBound : left < counterBlockCount)
    (rightBound : right < counterBlockCount)
    (samePreimage :
      sha512BlockPreimage domain words left =
        sha512BlockPreimage domain words right) :
    left = right := by
  let requestPrefix :=
    encodeLE 8 domain.length
      ++ domain
      ++ encodeLE 8 words.length
      ++ flattenWordBytes words
  have leftForm :
      sha512BlockPreimage domain words left =
        requestPrefix ++ encodeLE 8 left := by
    simp [sha512BlockPreimage, requestPrefix, List.append_assoc]
  have rightForm :
      sha512BlockPreimage domain words right =
        requestPrefix ++ encodeLE 8 right := by
    simp [sha512BlockPreimage, requestPrefix, List.append_assoc]
  rw [leftForm, rightForm] at samePreimage
  have sameCounterEncoding :
      encodeLE 8 left = encodeLE 8 right := by
    exact List.append_right_injective requestPrefix samePreimage
  apply encodeLE_injective_of_lt
    (width := 8) (left := left) (right := right)
  · simpa [counterBlockCount] using leftBound
  · simpa [counterBlockCount] using rightBound
  · exact sameCounterEncoding

/-- Exact ordered raw SHA-512 requests made by a counter-mode scan of `digestCalls` blocks. -/
def queriedBlockPreimages
    (domain : List Byte)
    (words : List Word)
    (digestCalls : Nat) : List (List Byte) :=
  (List.range digestCalls).map fun counter =>
    sha512BlockPreimage domain words counter

theorem queriedBlockPreimages_length
    (domain : List Byte)
    (words : List Word)
    (digestCalls : Nat) :
    (queriedBlockPreimages domain words digestCalls).length =
      digestCalls := by
  simp [queriedBlockPreimages]

theorem queriedBlockPreimages_get
    (domain : List Byte)
    (words : List Word)
    (digestCalls : Nat)
    (index : Fin digestCalls) :
    (queriedBlockPreimages domain words digestCalls).get
        ⟨index.val, by
          rw [queriedBlockPreimages_length]
          exact index.isLt⟩ =
      sha512BlockPreimage domain words index.val := by
  simp [queriedBlockPreimages]

theorem queriedBlockPreimages_nodup
    (domain : List Byte)
    (words : List Word)
    {digestCalls : Nat}
    (withinCounterSpace : digestCalls ≤ counterBlockCount) :
    (queriedBlockPreimages domain words digestCalls).Nodup := by
  unfold queriedBlockPreimages
  apply List.nodup_range.map_on
  intro left leftMembership right rightMembership samePreimage
  apply sha512BlockPreimage_counter_injective domain words
  · exact (List.mem_range.mp leftMembership).trans_le withinCounterSpace
  · exact (List.mem_range.mp rightMembership).trans_le withinCounterSpace
  · exact samePreimage

/--
The `candidateIndex`-th 64-bit word in the counter-mode stream.  Each SHA-512 block contributes
exactly eight words.
-/
def rawCandidate
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (candidateIndex : Nat) : Word :=
  let lane : Fin digestWordCount :=
    ⟨candidateIndex % digestWordCount,
      Nat.mod_lt _ (by decide : 0 < digestWordCount)⟩
  rawDigest oracle domain words (candidateIndex / digestWordCount) lane

/-- Canonical Goldilocks rejection rule used by `read_sha512_xof_words`. -/
def acceptCandidate (candidate : Word) : Option FieldWord :=
  if accepted : candidate.val < goldilocksModulus then
    some ⟨candidate.val, accepted⟩
  else
    none

theorem acceptCandidate_some_iff
    (candidate : Word)
    (fieldWord : FieldWord) :
    acceptCandidate candidate = some fieldWord ↔
      candidate.val = fieldWord.val := by
  unfold acceptCandidate
  by_cases accepted : candidate.val < goldilocksModulus
  · simp [accepted]
    constructor
    · intro equal
      exact congrArg Fin.val equal
    · intro valueEqual
      apply Fin.ext
      exact valueEqual
  · simp [accepted]
    intro valueEqual
    exact accepted (valueEqual.trans_lt fieldWord.isLt)

/-- Accepted field words among the first `candidateCount` raw stream words. -/
def acceptedCandidates
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (candidateCount : Nat) : List FieldWord :=
  (List.range candidateCount).filterMap fun candidateIndex =>
    acceptCandidate (rawCandidate oracle domain words candidateIndex)

theorem acceptedCandidates_mono_prefix
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    {shorter longer : Nat}
    (bounded : shorter ≤ longer) :
    List.IsPrefix
      (acceptedCandidates oracle domain words shorter)
      (acceptedCandidates oracle domain words longer) := by
  obtain ⟨extra, rfl⟩ := Nat.exists_eq_add_of_le bounded
  simp only [acceptedCandidates, List.range_add]
  rw [List.filterMap_append]
  exact List.prefix_append _ _

/--
One finite witness that the production rejection sampler can return `outputCount` words before a
declared scan bound.  The selected output is always the first accepted prefix; later accepted
words cannot change it.
-/
structure OutputPrefix
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (outputCount : Nat) where
  candidateCount : Nat
  withinCounterSpace : candidateCount ≤ candidateCapacity
  output : List FieldWord
  enough :
    outputCount ≤
      (acceptedCandidates oracle domain words candidateCount).length
  exactPrefix :
    output =
      (acceptedCandidates oracle domain words candidateCount).take outputCount

namespace OutputPrefix

theorem output_length
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount : Nat}
    (sample : OutputPrefix oracle domain words outputCount) :
    sample.output.length = outputCount := by
  rw [sample.exactPrefix, List.length_take, min_eq_left sample.enough]

/-- Any two successful scan bounds produce the same requested field-XOF prefix. -/
theorem output_unique
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount : Nat}
    (left right : OutputPrefix oracle domain words outputCount) :
    left.output = right.output := by
  wlog order : left.candidateCount ≤ right.candidateCount generalizing left right
  · exact (this right left (Nat.le_of_not_ge order)).symm
  have prefixProof := acceptedCandidates_mono_prefix oracle domain words order
  rw [left.exactPrefix, right.exactPrefix]
  rcases prefixProof with ⟨suffix, suffixEquation⟩
  rw [← suffixEquation]
  exact (List.take_append_of_le_length left.enough).symm

/--
Any successful bounded scan extends to the complete production counter space without changing
the selected prefix.  This is the deterministic reason the total logical oracle may be defined
over the complete counter space even though the native scanner stops as soon as it has enough
accepted words.
-/
def extendToCapacity
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount : Nat}
    (sample : OutputPrefix oracle domain words outputCount) :
    OutputPrefix oracle domain words outputCount := by
  have prefixProof :=
    acceptedCandidates_mono_prefix oracle domain words
      sample.withinCounterSpace
  refine
    { candidateCount := candidateCapacity
      withinCounterSpace := Nat.le_refl _
      output := sample.output
      enough := ?_
      exactPrefix := ?_ }
  · exact sample.enough.trans prefixProof.length_le
  · rw [sample.exactPrefix]
    rcases prefixProof with ⟨suffix, suffixEquation⟩
    rw [← suffixEquation]
    exact (List.take_append_of_le_length sample.enough).symm

end OutputPrefix

/--
The exact potentially failing operation implemented by the native SHA-512 field-XOF. Counter
exhaustion is represented by the absence of `OutputPrefix`; it is not silently treated as a field
sample.
-/
def CanSqueeze
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (outputCount : Nat) : Prop :=
  Nonempty (OutputPrefix oracle domain words outputCount)

/--
Executable finite scan used to compare native output with the mathematical first-accepted prefix.
The caller supplies the number of raw words scanned; production admissibility separately requires
that count to remain inside `candidateCapacity`.
-/
def squeezeWithin
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (outputCount candidateCount : Nat) : Option (List FieldWord) :=
  let accepted := acceptedCandidates oracle domain words candidateCount
  if _enough : outputCount ≤ accepted.length then
    some (accepted.take outputCount)
  else
    none

theorem squeezeWithin_eq_some_iff
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount candidateCount : Nat}
    {output : List FieldWord} :
    squeezeWithin oracle domain words outputCount candidateCount = some output ↔
      outputCount ≤
          (acceptedCandidates oracle domain words candidateCount).length ∧
        output =
          (acceptedCandidates oracle domain words candidateCount).take outputCount := by
  unfold squeezeWithin
  by_cases enough :
      outputCount ≤
        (acceptedCandidates oracle domain words candidateCount).length
  · rw [dif_pos enough]
    constructor
    · intro sameOutput
      exact ⟨enough, (Option.some.inj sameOutput).symm⟩
    · rintro ⟨_bounded, sameOutput⟩
      exact congrArg some sameOutput.symm
  · simp [enough]

/-- A successful bounded execution is exactly one valid first-prefix witness. -/
def outputPrefixOfSqueezeWithin
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount candidateCount : Nat}
    {output : List FieldWord}
    (withinCounterSpace : candidateCount ≤ candidateCapacity)
    (success :
      squeezeWithin oracle domain words outputCount candidateCount = some output) :
    OutputPrefix oracle domain words outputCount :=
  { candidateCount,
    withinCounterSpace,
    output,
    enough := (squeezeWithin_eq_some_iff.mp success).1,
    exactPrefix := (squeezeWithin_eq_some_iff.mp success).2 }

theorem squeezeWithin_output_length
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount candidateCount : Nat}
    {output : List FieldWord}
    (success :
      squeezeWithin oracle domain words outputCount candidateCount = some output) :
    output.length = outputCount := by
  have result := squeezeWithin_eq_some_iff.mp success
  rw [result.2, List.length_take, min_eq_left result.1]

/-- Number of raw 64-bit candidates present after complete processing of `digestCalls` blocks. -/
def candidatesAfterDigestCalls (digestCalls : Nat) : Nat :=
  digestWordCount * digestCalls

/--
Exact successful execution shape of the production `read_sha512_xof_words` loop.  For a nonempty
request, the final block is the first block boundary at which enough accepted words exist.
-/
structure NativeBlockScan
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (outputCount : Nat) where
  digestCalls : Nat
  withinCounterSpace : digestCalls ≤ counterBlockCount
  zeroCallsIffZeroOutput : digestCalls = 0 ↔ outputCount = 0
  enough :
    outputCount ≤
      (acceptedCandidates oracle domain words
        (candidatesAfterDigestCalls digestCalls)).length
  previousInsufficient :
    0 < digestCalls ->
      (acceptedCandidates oracle domain words
        (candidatesAfterDigestCalls (digestCalls - 1))).length <
          outputCount
  output : List FieldWord
  exactPrefix :
    output =
      (acceptedCandidates oracle domain words
        (candidatesAfterDigestCalls digestCalls)).take outputCount

namespace NativeBlockScan

theorem output_length
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount : Nat}
    (scan : NativeBlockScan oracle domain words outputCount) :
    scan.output.length = outputCount := by
  rw [scan.exactPrefix, List.length_take, min_eq_left scan.enough]

theorem queried_raw_digest_count
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount : Nat}
    (scan : NativeBlockScan oracle domain words outputCount) :
    (queriedBlockPreimages domain words scan.digestCalls).length =
      scan.digestCalls :=
  queriedBlockPreimages_length domain words scan.digestCalls

theorem queried_raw_digest_preimages_nodup
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount : Nat}
    (scan : NativeBlockScan oracle domain words outputCount) :
    (queriedBlockPreimages domain words scan.digestCalls).Nodup :=
  queriedBlockPreimages_nodup domain words scan.withinCounterSpace

/-- A native block scan is one valid logical-prefix witness at its exact physical scan bound. -/
def toOutputPrefix
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount : Nat}
    (scan : NativeBlockScan oracle domain words outputCount) :
    OutputPrefix oracle domain words outputCount where
  candidateCount := candidatesAfterDigestCalls scan.digestCalls
  withinCounterSpace := by
    unfold candidatesAfterDigestCalls candidateCapacity
    exact Nat.mul_le_mul_left digestWordCount scan.withinCounterSpace
  output := scan.output
  enough := scan.enough
  exactPrefix := scan.exactPrefix

end NativeBlockScan

/-- Every successful exact XOF execution returns only canonical Goldilocks words. -/
theorem successful_output_is_canonical
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount : Nat}
    (sample : OutputPrefix oracle domain words outputCount)
    (word : FieldWord)
    (_membership : word ∈ sample.output) :
    word.val < goldilocksModulus :=
  word.isLt

/-! ## Exact refinement to the prefix-consistent logical field oracle -/

/--
Replace the final eight-byte counter of one canonical counter-zero request.  This is the operation
performed by the native SHA-512 field-XOF before each subsequent digest call.
-/
def counterPreimageFromBase
    (basePreimage : List Byte)
    (counter : Nat) : List Byte :=
  basePreimage.take (basePreimage.length - 8) ++ encodeLE 8 counter

theorem counterPreimageFromBase_sha512BlockPreimage
    (domain : List Byte)
    (words : List Word)
    (counter : Nat) :
    counterPreimageFromBase (sha512BlockPreimage domain words 0) counter =
      sha512BlockPreimage domain words counter := by
  let requestPrefix :=
    encodeLE 8 domain.length
      ++ domain
      ++ encodeLE 8 words.length
      ++ flattenWordBytes words
  have zeroForm :
      sha512BlockPreimage domain words 0 =
        requestPrefix ++ encodeLE 8 0 := by
    simp [sha512BlockPreimage, requestPrefix, List.append_assoc]
  have counterForm :
      sha512BlockPreimage domain words counter =
        requestPrefix ++ encodeLE 8 counter := by
    simp [sha512BlockPreimage, requestPrefix, List.append_assoc]
  have prefixLength :
      (sha512BlockPreimage domain words 0).length - 8 =
        requestPrefix.length := by
    rw [zeroForm]
    simp [encodeLE_length]
  rw [counterForm, counterPreimageFromBase, prefixLength, zeroForm]
  simp

/-- One raw candidate addressed only by the canonical counter-zero request bytes. -/
def rawCandidateFromBase
    (oracle : RawOracle)
    (basePreimage : List Byte)
    (candidateIndex : Nat) : Word :=
  let lane : Fin digestWordCount :=
    ⟨candidateIndex % digestWordCount,
      Nat.mod_lt _ (by decide : 0 < digestWordCount)⟩
  oracle
    (counterPreimageFromBase basePreimage
      (candidateIndex / digestWordCount))
    lane

theorem rawCandidateFromBase_sha512BlockPreimage
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (candidateIndex : Nat) :
    rawCandidateFromBase oracle
        (sha512BlockPreimage domain words 0) candidateIndex =
      rawCandidate oracle domain words candidateIndex := by
  unfold rawCandidateFromBase rawCandidate rawDigest
  rw [counterPreimageFromBase_sha512BlockPreimage]

/-- Canonical accepted field words obtained from one base request. -/
def acceptedCandidatesFromBase
    (oracle : RawOracle)
    (basePreimage : List Byte)
    (candidateCount : Nat) : List FieldWord :=
  (List.range candidateCount).filterMap fun candidateIndex =>
    acceptCandidate
      (rawCandidateFromBase oracle basePreimage candidateIndex)

theorem acceptedCandidatesFromBase_sha512BlockPreimage
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (candidateCount : Nat) :
    acceptedCandidatesFromBase oracle
        (sha512BlockPreimage domain words 0) candidateCount =
      acceptedCandidates oracle domain words candidateCount := by
  unfold acceptedCandidatesFromBase acceptedCandidates
  simp_rw [rawCandidateFromBase_sha512BlockPreimage]

/--
Total logical field oracle induced by the complete finite production counter space.  The zero
fallback is unreachable for every request whose required prefix exists; keeping the function total
matches `SmallWoodTranscript.Oracle` without pretending counter exhaustion is impossible.
-/
def logicalFieldOracleOfRaw (oracle : RawOracle) : Oracle :=
  fun basePreimage outputIndex =>
    (acceptedCandidatesFromBase oracle basePreimage candidateCapacity).getD
      outputIndex 0

theorem logicalFieldOracleOfRaw_eq_acceptedCandidate
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (outputIndex : Nat)
    (available :
      outputIndex <
        (acceptedCandidates oracle domain words candidateCapacity).length) :
    logicalFieldOracleOfRaw oracle
        (sha512BlockPreimage domain words 0) outputIndex =
      (acceptedCandidates oracle domain words candidateCapacity).get
        ⟨outputIndex, available⟩ := by
  unfold logicalFieldOracleOfRaw
  rw [acceptedCandidatesFromBase_sha512BlockPreimage]
  exact List.getD_eq_get _ _ ⟨outputIndex, available⟩

/--
Every successful full-counter-space squeeze is exactly the prefix returned by the induced logical
oracle.  This is the deterministic native-to-Lean rejection-sampling refinement; no distributional
or cryptographic assumption appears in the theorem.
-/
theorem fieldHashWords_logicalFieldOracleOfRaw_eq_output
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (outputCount : Nat)
    (sample : OutputPrefix oracle domain words outputCount)
    (fullCounterSpace : sample.candidateCount = candidateCapacity) :
    fieldHashWords (logicalFieldOracleOfRaw oracle)
        domain words outputCount =
      sample.output := by
  have enoughFull :
      outputCount ≤
        (acceptedCandidates oracle domain words candidateCapacity).length := by
    simpa [fullCounterSpace] using sample.enough
  rw [sample.exactPrefix, fullCounterSpace]
  apply List.ext_getElem
  · simp [fieldHashWords, enoughFull]
  · intro index leftBound rightBound
    simp only [fieldHashWords, List.getElem_map, List.getElem_range,
      List.getElem_take]
    have indexOutput : index < outputCount := by
      simpa [fieldHashWords] using leftBound
    have available :
        index <
          (acceptedCandidates oracle domain words candidateCapacity).length :=
      lt_of_lt_of_le indexOutput enoughFull
    rw [logicalFieldOracleOfRaw_eq_acceptedCandidate
      oracle domain words index available]
    rfl

/--
The logical oracle agrees with every successful bounded native scan, not only a scanner that
needlessly traverses the complete `u64` counter space.
-/
theorem fieldHashWords_logicalFieldOracleOfRaw_eq_bounded_output
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (outputCount : Nat)
    (sample : OutputPrefix oracle domain words outputCount) :
    fieldHashWords (logicalFieldOracleOfRaw oracle)
        domain words outputCount =
      sample.output := by
  exact fieldHashWords_logicalFieldOracleOfRaw_eq_output
    oracle domain words outputCount sample.extendToCapacity rfl

/--
The executable finite scanner and the logical field oracle agree whenever the scanner succeeds
after examining the complete production counter space.
-/
theorem squeezeWithin_logicalFieldOracleOfRaw
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (outputCount : Nat)
    (output : List FieldWord)
    (success :
      squeezeWithin oracle domain words outputCount candidateCapacity =
        some output) :
    fieldHashWords (logicalFieldOracleOfRaw oracle)
        domain words outputCount =
      output := by
  exact fieldHashWords_logicalFieldOracleOfRaw_eq_output
    oracle domain words outputCount
    (outputPrefixOfSqueezeWithin (Nat.le_refl _) success)
    rfl

/--
General finite-scanner refinement used by the production transcript.  The only operational
premise is that the successful scan stayed inside the deployed `u64` counter space.
-/
theorem squeezeWithin_logicalFieldOracleOfRaw_of_within
    (oracle : RawOracle)
    (domain : List Byte)
    (words : List Word)
    (outputCount candidateCount : Nat)
    (output : List FieldWord)
    (withinCounterSpace : candidateCount ≤ candidateCapacity)
    (success :
      squeezeWithin oracle domain words outputCount candidateCount =
        some output) :
    fieldHashWords (logicalFieldOracleOfRaw oracle)
        domain words outputCount =
      output := by
  exact fieldHashWords_logicalFieldOracleOfRaw_eq_bounded_output
    oracle domain words outputCount
    (outputPrefixOfSqueezeWithin withinCounterSpace success)

/-- Exact native block scan and prefix-consistent logical field-XOF return the same output. -/
theorem NativeBlockScan.logicalFieldOracle_eq_output
    {oracle : RawOracle}
    {domain : List Byte}
    {words : List Word}
    {outputCount : Nat}
    (scan : NativeBlockScan oracle domain words outputCount) :
    fieldHashWords (logicalFieldOracleOfRaw oracle)
        domain words outputCount =
      scan.output :=
  fieldHashWords_logicalFieldOracleOfRaw_eq_bounded_output
    oracle domain words outputCount scan.toOutputPrefix

end HegemonCrypto.SmallWood.Sha512Xof
