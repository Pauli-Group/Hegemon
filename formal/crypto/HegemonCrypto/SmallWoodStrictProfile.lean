import HegemonCrypto.SmallWoodBcsQrom

/-!
# Strict finite-QROM profile for the measured SmallWood LPPC/DECS path

This file is the arithmetic mirror of
`.agent/hardening/smallwood-pqc-zk/strict_profile.py`.  It fixes the active
SmallWood parameters rather than searching for a new backend:

* `q_low = 2^64` and `q_work = 2^128` are global quantum-query budgets;
* the PCS/PIOP/DECS knowledge error is the exact four-term active ledger;
* CMS Fiat--Shamir, SHA-512 collision, and PCS oracle/database bridge losses
  use the constants in `SmallWoodBcsQrom`;
* 448-bit SHAKE relation commitments are charged for 79 semantic hash targets;
* the four-round SHA-512 transcript is charged for the 11,574 worst-case
  physical requests;
* canonical nonce and fixed first-distinct DECS sampler exhaustion are retained;
* opening/decs proof-of-work bits are zero, so the grinding term is proved zero,
  and the global history multiplier is exactly one.

The resulting inequalities are ideal-model arithmetic only.  In particular, these
theorems do not establish compiled-prover distribution refinement, a complete
zero-knowledge simulator, SHA-512/SHAKE concrete-QROM reductions, canonical
relation refinement, native verifier refinement, or independent review.  Those
premises remain receipt-bound in the fail-closed profile checker; no capability or
production authority is derived from the inequalities below.
-/

namespace HegemonCrypto.SmallWood.StrictProfile

open HegemonCrypto.SmallWood.BcsQrom
open Hegemon.Transaction.SmallWoodNoGrindingSoundness

set_option maxHeartbeats 0
set_option maxRecDepth 100000
set_option exponentiation.threshold 1024

/-! Profile constants are definitions so a changed value breaks the checked ledger. -/

def lowQueryExponent : Nat := 64
def lowTargetBits : Nat := 128
def workQueryExponent : Nat := 128
def relationHashBits : Nat := 448
def transcriptHashBits : Nat := 512
def relationHashTargets : Nat := 79
def transcriptHashWorstCaseRequests : Nat := 11574
def relationHashCollisionFactor : Nat := 4
def transcriptHashCollisionFactor : Nat := 4
def cmsFiatShamirFactor : Nat := 12
def cmsTranscriptCollisionFactor : Nat := 48
def cmsOracleBridgeFactor : Nat := 2
def globalHistoryUnionMultiplier : Nat := 1
def openingPowBits : Nat := 0
def decsPowBits : Nat := 0
def piopNonceTrials : Nat := 16
def decsCandidateCount : Nat := 50

def lowQueryBound : Nat := 2 ^ lowQueryExponent
def workQueryBound : Nat := 2 ^ workQueryExponent

def activeProfileParametersAreStrict : Prop :=
  lowQueryExponent = 64 ∧
    lowTargetBits = 128 ∧
    workQueryExponent = 128 ∧
    relationHashBits = 448 ∧
    transcriptHashBits = 512 ∧
    relationHashTargets = 79 ∧
    transcriptHashWorstCaseRequests = 11574 ∧
    relationHashCollisionFactor = 4 ∧
    transcriptHashCollisionFactor = 4 ∧
    cmsFiatShamirFactor = 12 ∧
    cmsTranscriptCollisionFactor = 48 ∧
    cmsOracleBridgeFactor = 2 ∧
    globalHistoryUnionMultiplier = 1 ∧
    openingPowBits = 0 ∧
    decsPowBits = 0 ∧
    piopNonceTrials = 16 ∧
    decsCandidateCount = 50

theorem active_profile_parameters_are_strict :
    activeProfileParametersAreStrict := by
  decide

/-! Exact first-distinct DECS sampler model used by the Python checker. -/

def stirlingSecondKind : Nat → Nat → Nat
  | 0, 0 => 1
  | 0, _ + 1 => 0
  | _ + 1, 0 => 0
  | value + 1, blocks + 1 =>
      stirlingSecondKind value blocks +
        (blocks + 1) * stirlingSecondKind value (blocks + 1)

def decsDomainSize : Nat := 1048576
def decsOpenings : Nat := 23
def decsBucket : Nat := (goldilocksOrder - 1) / decsDomainSize

theorem active_field_order_mod_decs_domain :
    goldilocksOrder % decsDomainSize = 1 := by
  decide

def decsDistinctResidueSequences (accepted : Nat) : Nat :=
  (List.range (Nat.min (decsOpenings - 1) accepted + 1)).foldl
    (fun total distinct =>
      total + fallingProduct decsDomainSize distinct *
        stirlingSecondKind accepted distinct)
    0

def decsSamplerBadRawStreams : Nat :=
  (List.range (decsCandidateCount + 1)).foldl
    (fun total accepted =>
      total + binomial decsCandidateCount accepted *
        decsBucket ^ accepted * decsDistinctResidueSequences accepted)
    0

def decsSamplerExhaustionLoss : Rat :=
  (decsSamplerBadRawStreams : Rat) / (goldilocksOrder : Rat) ^ decsCandidateCount

def piopSamplerExhaustionLoss : Rat :=
  (1 -
      (fallingProduct (goldilocksOrder - activePackingFactor)
        activeProfile.nbOpenedEvals : Rat) /
        (goldilocksOrder : Rat) ^ activeProfile.nbOpenedEvals) ^ piopNonceTrials

/-! Every ideal finite-QROM term has a stable named definition. -/

def strictPcsIopFiatShamirLoss (queries : Nat) : Rat :=
  (cmsFiatShamirFactor * queries ^ 2 : Nat) *
    ((aggregateErrorNumerator : Rat) / aggregateErrorDenominator)

def strictTranscriptCollisionLoss (queries : Nat) : Rat :=
  (cmsTranscriptCollisionFactor * queries ^ 3 : Nat) /
    (2 ^ transcriptHashBits : Nat)

def strictPcsOracleDatabaseBridgeLoss : Rat :=
  (cmsOracleBridgeFactor * activeBaseGameArityUpperBound ^ 2 : Nat) /
    (2 ^ transcriptHashBits : Nat)

def strictRelationHashCollisionUnionLoss (queries : Nat) : Rat :=
  (relationHashCollisionFactor * relationHashTargets * queries ^ 3 : Nat) /
    (2 ^ relationHashBits : Nat)

def strictTranscriptHashRequestUnionLoss (queries : Nat) : Rat :=
  (transcriptHashCollisionFactor * transcriptHashWorstCaseRequests * queries ^ 3 : Nat) /
    (2 ^ transcriptHashBits : Nat)

/-- The active profile has no opening or DECS proof-of-work/grinding. -/
def strictGrindingLoss : Rat :=
  ((openingPowBits + decsPowBits : Nat) : Rat) * 0

/-- The query budget is already global; no extra per-proof history union is allowed. -/
def strictGlobalHistoryUnionLoss : Rat :=
  (globalHistoryUnionMultiplier : Rat) - 1

def strictFiniteQromBound (queries : Nat) : Rat :=
  strictPcsIopFiatShamirLoss queries +
    strictTranscriptCollisionLoss queries +
    strictPcsOracleDatabaseBridgeLoss +
    piopSamplerExhaustionLoss +
    decsSamplerExhaustionLoss +
    strictRelationHashCollisionUnionLoss queries +
    strictTranscriptHashRequestUnionLoss queries +
    strictGrindingLoss +
    strictGlobalHistoryUnionLoss

theorem strict_grinding_loss_eq_zero :
    strictGrindingLoss = 0 := by
  norm_num [strictGrindingLoss, openingPowBits, decsPowBits]

theorem strict_global_history_union_loss_eq_zero :
    strictGlobalHistoryUnionLoss = 0 := by
  norm_num [strictGlobalHistoryUnionLoss, globalHistoryUnionMultiplier]

theorem strict_finite_qrom_at_2pow64_supports_128_bits :
    strictFiniteQromBound lowQueryBound <= (1 : Rat) / 2 ^ lowTargetBits := by
  unfold strictFiniteQromBound lowQueryBound lowTargetBits
  unfold strictPcsIopFiatShamirLoss strictTranscriptCollisionLoss
    strictPcsOracleDatabaseBridgeLoss strictRelationHashCollisionUnionLoss
    strictTranscriptHashRequestUnionLoss strictGrindingLoss
    strictGlobalHistoryUnionLoss piopSamplerExhaustionLoss
    decsSamplerExhaustionLoss
  set_option maxRecDepth 100000 in
    set_option exponentiation.threshold 1024 in
      decide

theorem strict_finite_qrom_at_2pow128_lt_half :
    strictFiniteQromBound workQueryBound < (1 : Rat) / 2 := by
  unfold strictFiniteQromBound workQueryBound
  unfold strictPcsIopFiatShamirLoss strictTranscriptCollisionLoss
    strictPcsOracleDatabaseBridgeLoss strictRelationHashCollisionUnionLoss
    strictTranscriptHashRequestUnionLoss strictGrindingLoss
    strictGlobalHistoryUnionLoss piopSamplerExhaustionLoss
    decsSamplerExhaustionLoss
  set_option maxRecDepth 100000 in
    set_option exponentiation.threshold 1024 in
      decide

/-!
The arithmetic theorem above is not a security authority.  This proposition is the explicit
receipt boundary consumed by the external fail-closed checker: no theorem in this file can
construct it from the finite-QROM inequalities.
-/
structure DeployedSecurityPremises : Prop where
  compiledProverDistributionRefinement : Prop
  completeZeroKnowledgeReduction : Prop
  sha512ConcreteQromReduction : Prop
  shake256ConcreteQromReduction : Prop
  canonicalRelationRefinement : Prop
  compiledVerifierRefinement : Prop
  globalHistoryComposition : Prop
  independentComposedReview : Prop

def deployedSecurityAuthority (premises : DeployedSecurityPremises) : Prop :=
  premises.compiledProverDistributionRefinement ∧
    premises.completeZeroKnowledgeReduction ∧
    premises.sha512ConcreteQromReduction ∧
    premises.shake256ConcreteQromReduction ∧
    premises.canonicalRelationRefinement ∧
    premises.compiledVerifierRefinement ∧
    premises.globalHistoryComposition ∧
    premises.independentComposedReview

end HegemonCrypto.SmallWood.StrictProfile
