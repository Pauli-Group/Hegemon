import HegemonCrypto.SmallWoodV8Smz9ZeroKnowledge
import Mathlib.Analysis.SpecificLimits.Basic
import Mathlib.Data.Fintype.Pi
import Mathlib.Data.List.OfFn

/-!
# V8/SMZ9 runtime rejection sampling

This file proves the deterministic mapping performed after raw randomness is
obtained.  A raw 64-bit word is accepted exactly when it is below the
Goldilocks modulus and is then used unchanged.  Consequently the accepted-word
space is equivalent to the ideal field-coin space, every field coin has one
accepted preimage, and the number of possible rejected prefixes depends only
on prefix length.

The theorem boundary is intentional.  The Rust production path obtains bytes
from `getrandom::fill`, while the executable whole-view sampler accepts a
`CryptoRng + RngCore`.  This file does not model an operating system or certify
either provider.  Applying the equivalences to runtime distributions requires
the external premise that every successful provider call returns jointly fresh
independent uniform bytes (also across concurrent calls).  Provider failure is
a prover abort.  Deterministic fixtures establish only mapping and consumption.
-/

namespace HegemonCrypto
namespace SmallWood
namespace V8Smz9RuntimeRandomness

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge
open scoped BigOperators

abbrev rawWordCardinality : Nat := 2 ^ 64
abbrev fieldModulus : Nat := goldilocksModulus
abbrev rejectedWordCount : Nat := rawWordCardinality - fieldModulus

def osEntropyExternalPremise : String :=
  "successful getrandom fills are jointly fresh independent uniform bytes"

def cryptoRngExternalPremise : String :=
  "caller CryptoRng and RngCore outputs are jointly fresh independent uniform bits"

theorem exact_runtime_rejection_geometry :
    rawWordCardinality = 18446744073709551616 ∧
      fieldModulus = 18446744069414584321 ∧
      rejectedWordCount = 4294967295 := by
  decide

theorem field_modulus_lt_raw_word_cardinality :
    fieldModulus < rawWordCardinality := by
  decide

abbrev RawWord := Fin rawWordCardinality
abbrev IdealFieldCoin := Fin fieldModulus

/-- The Rust predicate: accept a canonical representative and do no modular reduction. -/
def decodeCandidate (candidate : RawWord) : Option IdealFieldCoin :=
  if accepted : candidate.val < fieldModulus then
    some ⟨candidate.val, accepted⟩
  else
    none

/-- The unique raw-word representative of one ideal Goldilocks coin. -/
def encodeCoin (coin : IdealFieldCoin) : RawWord :=
  ⟨coin.val, coin.isLt.trans field_modulus_lt_raw_word_cardinality⟩

theorem decode_encode_coin (coin : IdealFieldCoin) :
    decodeCandidate (encodeCoin coin) = some coin := by
  simp only [decodeCandidate, encodeCoin, coin.isLt, ↓reduceDIte]

abbrev AcceptedRawWord := { candidate : RawWord // candidate.val < fieldModulus }

/-- Accepted machine words and ideal field coins are in exact one-to-one correspondence. -/
def acceptedRawWordEquiv : IdealFieldCoin ≃ AcceptedRawWord where
  toFun coin := ⟨encodeCoin coin, coin.isLt⟩
  invFun candidate := ⟨candidate.val.val, candidate.property⟩
  left_inv coin := by
    apply Fin.ext
    rfl
  right_inv candidate := by
    apply Subtype.ext
    apply Fin.ext
    rfl

theorem accepted_raw_word_cardinality :
    Fintype.card AcceptedRawWord = fieldModulus := by
  rw [← Fintype.card_congr acceptedRawWordEquiv]
  simp

/-- Canonical coordinate equivalence to the Goldilocks type used by the ZK coin model. -/
noncomputable def idealFieldCoinEquivGoldilocks : IdealFieldCoin ≃ Goldilocks :=
  ZMod.finEquiv fieldModulus

abbrev RejectedRawWord := { candidate : RawWord // fieldModulus ≤ candidate.val }

/-- Rejected words are the contiguous suffix `[p, 2^64)`. -/
def rejectedRawWordEquiv : Fin rejectedWordCount ≃ RejectedRawWord where
  toFun offset := by
    refine ⟨⟨fieldModulus + offset.val, ?_⟩, Nat.le_add_right _ _⟩
    have offsetBound := offset.isLt
    unfold rejectedWordCount at offsetBound
    omega
  invFun candidate := by
    refine ⟨candidate.val.val - fieldModulus, ?_⟩
    have candidateBound := candidate.val.isLt
    unfold rejectedWordCount
    omega
  left_inv offset := by
    apply Fin.ext
    simp only
    omega
  right_inv candidate := by
    apply Subtype.ext
    apply Fin.ext
    simp only
    omega

theorem rejected_raw_word_cardinality :
    Fintype.card RejectedRawWord = rejectedWordCount := by
  rw [← Fintype.card_congr rejectedRawWordEquiv]
  simp

theorem rejected_candidate_decodes_to_none (candidate : RejectedRawWord) :
    decodeCandidate candidate.val = none := by
  simp [decodeCandidate, Nat.not_lt.mpr candidate.property]

/-- First-accept rejection sampler over an explicit finite candidate prefix. -/
def firstAccepted : List RawWord → Option IdealFieldCoin
  | [] => none
  | candidate :: candidates =>
      match decodeCandidate candidate with
      | some coin => some coin
      | none => firstAccepted candidates

theorem first_accepted_after_rejected_prefix
    (rejected : List RejectedRawWord)
    (coin : IdealFieldCoin) :
    firstAccepted (rejected.map Subtype.val ++ [encodeCoin coin]) = some coin := by
  induction rejected with
  | nil => simp [firstAccepted, decode_encode_coin]
  | cons candidate rejected inductionHypothesis =>
      simp only [List.map_cons, List.cons_append, firstAccepted]
      rw [rejected_candidate_decodes_to_none]
      exact inductionHypothesis

/-- Rejected candidates before acceptance on exactly attempt `attempt`. -/
abbrev RejectedPrefix (attempt : Nat) := Fin attempt → RejectedRawWord

def candidateTrace
    {attempt : Nat}
    (rejected : RejectedPrefix attempt)
    (coin : IdealFieldCoin) : List RawWord :=
  (List.ofFn rejected).map Subtype.val ++ [encodeCoin coin]

theorem candidate_trace_returns_exact_coin
    {attempt : Nat}
    (rejected : RejectedPrefix attempt)
    (coin : IdealFieldCoin) :
    firstAccepted (candidateTrace rejected coin) = some coin := by
  exact first_accepted_after_rejected_prefix (List.ofFn rejected) coin

/-- Scan all accepted outputs, preserving their order and skipping every rejected candidate. -/
def scanAccepted : List RawWord → List IdealFieldCoin
  | [] => []
  | candidate :: candidates =>
      match decodeCandidate candidate with
      | some coin => coin :: scanAccepted candidates
      | none => scanAccepted candidates

theorem scan_accepted_after_rejected_segment
    (rejected : List RejectedRawWord)
    (coin : IdealFieldCoin)
    (remaining : List RawWord) :
    scanAccepted
        (rejected.map Subtype.val ++ encodeCoin coin :: remaining) =
      coin :: scanAccepted remaining := by
  induction rejected with
  | nil => simp [scanAccepted, decode_encode_coin]
  | cons candidate rejected inductionHypothesis =>
      simp only [List.map_cons, List.cons_append, scanAccepted]
      rw [rejected_candidate_decodes_to_none]
      exact inductionHypothesis

/-- One successful output together with its arbitrary finite rejected prefix. -/
abbrev TerminatingSegment := List RejectedRawWord × IdealFieldCoin

def segmentCandidates (segment : TerminatingSegment) : List RawWord :=
  segment.1.map Subtype.val ++ [encodeCoin segment.2]

def terminatingTraceCandidates (segments : List TerminatingSegment) : List RawWord :=
  segments.flatMap segmentCandidates

def terminatingTraceOutputs (segments : List TerminatingSegment) : List IdealFieldCoin :=
  segments.map Prod.snd

/--
Exact arbitrary-rejection/multi-output scan theorem for the source-injectable Rust loop.  Every
finite terminating trace decodes to precisely its ordered ideal outputs, independent of how many
rejections preceded each output.
-/
theorem scan_terminating_trace_returns_exact_outputs
    (segments : List TerminatingSegment) :
    scanAccepted (terminatingTraceCandidates segments) =
      terminatingTraceOutputs segments := by
  induction segments with
  | nil => rfl
  | cons segment segments inductionHypothesis =>
      rw [terminatingTraceCandidates, List.flatMap_cons]
      simp only [segmentCandidates, terminatingTraceOutputs, List.map_cons]
      rw [List.append_assoc]
      change
        scanAccepted
            (segment.1.map Subtype.val ++
              encodeCoin segment.2 :: terminatingTraceCandidates segments) = _
      rw [scan_accepted_after_rejected_segment, inductionHypothesis]
      rfl

/-- Every eventual output has exactly `rejectedWordCount ^ attempt` raw rejection prefixes. -/
theorem exact_attempt_fiber_cardinality (attempt : Nat) :
    Fintype.card (RejectedPrefix attempt) = rejectedWordCount ^ attempt := by
  simp [RejectedPrefix, rejected_raw_word_cardinality]

/-- Per-output rejection counts for a terminating `count`-coin execution. -/
abbrev RejectionSchedule (count : Nat) := Fin count → Nat

/-- All rejected words once a schedule is fixed.  This nuisance space is independent of outputs. -/
abbrev RejectionNuisance
    {count : Nat}
    (schedule : RejectionSchedule count) :=
  (index : Fin count) → Fin (schedule index) → RejectedRawWord

theorem rejection_nuisance_cardinality
    {count : Nat}
    (schedule : RejectionSchedule count) :
    Fintype.card (RejectionNuisance schedule) =
      ∏ index : Fin count, rejectedWordCount ^ schedule index := by
  simp [RejectionNuisance, rejected_raw_word_cardinality]

def scheduledSegments
    {count : Nat}
    (schedule : RejectionSchedule count)
    (rejected : RejectionNuisance schedule)
    (outputs : Fin count → IdealFieldCoin) : List TerminatingSegment :=
  List.ofFn fun index => ⟨List.ofFn (rejected index), outputs index⟩

theorem scan_scheduled_trace_returns_exact_outputs
    {count : Nat}
    (schedule : RejectionSchedule count)
    (rejected : RejectionNuisance schedule)
    (outputs : Fin count → IdealFieldCoin) :
    scanAccepted
        (terminatingTraceCandidates (scheduledSegments schedule rejected outputs)) =
      List.ofFn outputs := by
  rw [scan_terminating_trace_returns_exact_outputs]
  simp [terminatingTraceOutputs, scheduledSegments, Function.comp_def]

/-- Exact ideal rejection probability after one fresh uniform raw word. -/
noncomputable def idealRejectionRatio : ℝ :=
  rejectedWordCount / rawWordCardinality

theorem ideal_rejection_ratio_nonnegative : 0 ≤ idealRejectionRatio := by
  norm_num [idealRejectionRatio, rejectedWordCount, rawWordCardinality,
    fieldModulus, goldilocksModulus]

theorem ideal_rejection_ratio_lt_one : idealRejectionRatio < 1 := by
  norm_num [idealRejectionRatio, rejectedWordCount, rawWordCardinality,
    fieldModulus, goldilocksModulus]

/--
The numeric expression that would be the consecutive-rejection tail under an iid uniform source
converges to zero.  This is not a probability-space or runtime-source pushforward theorem.
-/
theorem ideal_rejection_tail_tends_to_zero :
    Filter.Tendsto (fun attempts : Nat => idealRejectionRatio ^ attempts)
      Filter.atTop (nhds 0) :=
  tendsto_pow_atTop_nhds_zero_of_lt_one
    ideal_rejection_ratio_nonnegative ideal_rejection_ratio_lt_one

/-- Coordinate space for `count` independently sampled ideal field coins. -/
abbrev RuntimeFieldCoins (count : Nat) := Fin count → IdealFieldCoin

def witnessInterpolationFieldCoinCount : Nat :=
  witnessPolynomialCount * piopOpeningCount
def nonlinearPiopFieldCoinCount : Nat :=
  nonlinearMaskPolynomialCount * (nonlinearMaskPolynomialDegree + 1)
def linearPiopFieldCoinCount : Nat :=
  linearMaskPolynomialCount * linearMaskPolynomialDegree
def pcsUnstackFieldCoinCount : Nat :=
  partialEvaluationColumnCount * piopOpeningCount
def lvcsTailFieldCoinCount : Nat := lvcsRowCount * decsOpeningCount
def decsMaskFieldCoinCount : Nat := decsEta * decsPolynomialCoefficientCount
def honestAlgebraicFieldCoinCount : Nat :=
  witnessInterpolationFieldCoinCount + nonlinearPiopFieldCoinCount +
    linearPiopFieldCoinCount + pcsUnstackFieldCoinCount +
    lvcsTailFieldCoinCount + decsMaskFieldCoinCount

def honestSaltBytes : Nat := 32
def honestLeafTapeCount : Nat := 2 ^ 23
def honestLeafTapeBytesEach : Nat := 64
def honestLeafTapeBytes : Nat := honestLeafTapeCount * honestLeafTapeBytesEach

theorem exact_honest_runtime_coin_inventory :
    witnessInterpolationFieldCoinCount = 4116 ∧
      nonlinearPiopFieldCoinCount = 2445 ∧
      linearPiopFieldCoinCount = 660 ∧
      pcsUnstackFieldCoinCount = 240 ∧
      lvcsTailFieldCoinCount = 2800 ∧
      decsMaskFieldCoinCount = 1940 ∧
      honestAlgebraicFieldCoinCount = 12201 ∧
      honestSaltBytes = 32 ∧
      honestLeafTapeCount = 8388608 ∧
      honestLeafTapeBytesEach = 64 ∧
      honestLeafTapeBytes = 536870912 := by
  decide

/-- Exact six-role algebraic coin surface consumed by the honest SMZ9 prover. -/
abbrev Smz9HonestAlgebraicCoins (F : Type*) :=
  WitnessInterpolationCoins F ×
    PcsUnstackCoins F ×
    NonlinearPiopMaskCoins F ×
    LinearPiopMaskCoins F ×
    LvcsRandomTailCoins F ×
    DecsPolynomialCoins F

abbrev RuntimeByte := Fin 256
abbrev FlatRuntimeBytes (count : Nat) := Fin count → RuntimeByte
abbrev Smz9SaltCoins := Fin honestSaltBytes → RuntimeByte
abbrev Smz9LeafTapeCoins :=
  Fin honestLeafTapeCount → Fin honestLeafTapeBytesEach → RuntimeByte

/-- The salt helper copies all 32 bytes without transformation. -/
def saltByteIdentityEquiv : FlatRuntimeBytes honestSaltBytes ≃ Smz9SaltCoins :=
  Equiv.refl _

/-- Fixed-width chunking is a bijective re-indexing of the complete DECS tape byte vector. -/
def leafTapePartitionEquiv :
    FlatRuntimeBytes honestLeafTapeBytes ≃ Smz9LeafTapeCoins :=
  (Equiv.arrowCongr finProdFinEquiv.symm (Equiv.refl RuntimeByte)).trans
    (Equiv.curry (Fin honestLeafTapeCount) (Fin honestLeafTapeBytesEach) RuntimeByte)

/-- Joint salt/tape byte mapping; this proves layout only, not source uniformity. -/
def fixedByteCoinLayoutEquiv :
    (FlatRuntimeBytes honestSaltBytes × FlatRuntimeBytes honestLeafTapeBytes) ≃
      (Smz9SaltCoins × Smz9LeafTapeCoins) :=
  Equiv.prodCongr saltByteIdentityEquiv leafTapePartitionEquiv

/--
Combined ideal honest-prover coin type.  QROM lazy-program inputs and outputs are intentionally not
fields: they are hybrid coins, not bytes drawn by the honest OS-backed prover.
-/
structure Smz9HonestRuntimeCoins where
  algebraic : Smz9HonestAlgebraicCoins Goldilocks
  salt : Smz9SaltCoins
  leafTapes : Smz9LeafTapeCoins

/-- Pointwise accepted-word decoding is a bijection onto the formal fresh-coin space. -/
noncomputable def repeatedAcceptedRawWordEquiv (count : Nat) :
    (Fin count → AcceptedRawWord) ≃ RuntimeFieldCoins count :=
  Equiv.piCongrRight fun _ => acceptedRawWordEquiv.symm

theorem runtime_field_coin_space_cardinality (count : Nat) :
    Fintype.card (RuntimeFieldCoins count) = fieldModulus ^ count := by
  simp [RuntimeFieldCoins]

/--
Accepted-coordinate bijection for one already-accepted vector.  The file does not prove the
distributional pushforward of the unbounded runtime loop or a full raw-source equivalence to
`Smz9HonestRuntimeCoins`; those remain separate obligations together with a quantum-computational
distinguishing bound for the complete joint runtime coin law.
-/
theorem accepted_runtime_words_biject_to_ideal_field_coins (count : Nat) :
    Nonempty ((Fin count → AcceptedRawWord) ≃ RuntimeFieldCoins count) := by
  exact ⟨repeatedAcceptedRawWordEquiv count⟩

end V8Smz9RuntimeRandomness
end SmallWood
end HegemonCrypto
