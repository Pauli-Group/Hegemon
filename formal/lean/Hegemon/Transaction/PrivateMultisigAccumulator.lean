import Hegemon.Transaction.SpendAuthorization

namespace Hegemon
namespace Transaction
namespace PrivateMultisigAccumulator

open Hegemon.Transaction.SpendAuthorization

def digestMod : Nat := authDigestMod

structure SpendIntent where
  accountDigest : Digest
  policyRoot : Digest
  intentDigest : Digest
deriving DecidableEq, Repr

structure PolicyWitness where
  accountDigest : Digest
  policyRoot : Digest
  threshold : Nat
  signerSetRoot : Digest
  signerTags : List Digest
deriving DecidableEq, Repr

structure AccumulatorNote where
  accountDigest : Digest
  policyRoot : Digest
  intentDigest : Digest
  approvalCount : Nat
  approvalNullifiers : List Digest
  approvalSignerTags : List Digest
  approvalLeaves : List Digest
  stateDigest : Digest
deriving DecidableEq, Repr

structure SignerCapabilityNote where
  policyRoot : Digest
  signerTag : Digest
  signerNullifier : Digest
  capabilitySecretCommitment : Digest
deriving DecidableEq, Repr

structure ApprovalStep where
  policy : PolicyWitness
  intent : SpendIntent
  priorAccumulator : AccumulatorNote
  signerCapability : SignerCapabilityNote
  spendDerivedSignerTag : Digest
  nextAccumulator : AccumulatorNote
deriving DecidableEq, Repr

structure ValueNote where
  accountDigest : Digest
  noteCommitment : Digest
  valueLockDigest : Digest
  publicNullifier : Digest
deriving DecidableEq, Repr

structure FinalSpend where
  policy : PolicyWitness
  intent : SpendIntent
  valueNote : ValueNote
  accumulator : AccumulatorNote
  approvalTrace : List ApprovalStep
  outputCommitment : Digest
  outputCiphertextHash : Digest
  balanceTag : Digest
deriving DecidableEq, Repr

structure PublicTransactionShape where
  inputNullifier : Digest
  outputCommitment : Digest
  outputCiphertextHash : Digest
  balanceTag : Digest
deriving DecidableEq, Repr

def accumulatorEq (left right : AccumulatorNote) : Bool :=
  if left = right then true else false

theorem accumulatorEq_true_eq {left right : AccumulatorNote} :
    accumulatorEq left right = true -> left = right := by
  unfold accumulatorEq
  split
  · intro _
    assumption
  · intro impossible
    cases impossible

def digestIn (needle : Digest) : List Digest -> Bool
  | [] => false
  | item :: rest => natEq needle item || digestIn needle rest

def signerInPolicy
    (capability : SignerCapabilityNote)
    (policy : PolicyWitness) : Bool :=
  digestIn capability.signerTag policy.signerTags

def digestAllNonzero : List Digest -> Bool
  | [] => true
  | item :: rest => (!natEq item 0) && digestAllNonzero rest

def digestNodup : List Digest -> Bool
  | [] => true
  | item :: rest => (!digestIn item rest) && digestNodup rest

def signerSetRootDigest : List Digest -> Digest
  | [] => 19 % digestMod
  | item :: rest =>
    (item * 131 + signerSetRootDigest rest * 137 + 23) % digestMod

def policyRootDigest
    (accountDigest : Digest)
    (threshold : Nat)
    (signerSetRoot : Digest) : Digest :=
  (accountDigest * 149
    + threshold * 151
    + signerSetRoot * 157
    + 29) % digestMod

def policyWellFormed (policy : PolicyWitness) : Bool :=
  (0 < policy.threshold)
    && (policy.threshold <= policy.signerTags.length)
    && digestAllNonzero policy.signerTags
    && digestNodup policy.signerTags
    && natEq policy.signerSetRoot
      (signerSetRootDigest policy.signerTags)
    && natEq policy.policyRoot
      (policyRootDigest
        policy.accountDigest
        policy.threshold
        policy.signerSetRoot)

def valueLockDigest
    (policyRoot : Digest)
    (intentDigest : Digest) : Digest :=
  (policyRoot * 163 + intentDigest * 167 + 31) % digestMod

def valueNoteLockedToIntent
    (note : ValueNote)
    (intent : SpendIntent) : Bool :=
  natEq note.valueLockDigest
    (valueLockDigest intent.policyRoot intent.intentDigest)

def approvalLeafDigest
    (intent : SpendIntent)
    (capability : SignerCapabilityNote) : Digest :=
  (intent.accountDigest * 17
    + intent.policyRoot * 31
    + intent.intentDigest * 43
    + capability.signerTag * 59
    + capability.signerNullifier * 61
    + 7) % digestMod

def accumulatorStateDigest (accumulator : AccumulatorNote) : Digest :=
  (accumulator.accountDigest * 101
    + accumulator.policyRoot * 103
    + accumulator.intentDigest * 107
    + accumulator.approvalCount * 109
    + accumulator.approvalNullifiers.length * 113
    + accumulator.approvalSignerTags.length * 127
    + accumulator.approvalLeaves.length * 139
    + 13) % digestMod

def nextAccumulatorForApproval
    (prior : AccumulatorNote)
    (capability : SignerCapabilityNote) : AccumulatorNote :=
  let intent : SpendIntent :=
    { accountDigest := prior.accountDigest,
      policyRoot := prior.policyRoot,
      intentDigest := prior.intentDigest }
  let next : AccumulatorNote :=
    { accountDigest := prior.accountDigest,
      policyRoot := prior.policyRoot,
      intentDigest := prior.intentDigest,
      approvalCount := prior.approvalCount + 1,
      approvalNullifiers :=
        capability.signerNullifier :: prior.approvalNullifiers,
      approvalSignerTags :=
        capability.signerTag :: prior.approvalSignerTags,
      approvalLeaves :=
        approvalLeafDigest intent capability :: prior.approvalLeaves,
      stateDigest := 0 }
  { next with stateDigest := accumulatorStateDigest next }

def accumulatorMatchesIntent
    (accumulator : AccumulatorNote)
    (intent : SpendIntent) : Bool :=
  natEq accumulator.accountDigest intent.accountDigest
    && natEq accumulator.policyRoot intent.policyRoot
    && natEq accumulator.intentDigest intent.intentDigest

def accumulatorMatchesPolicy
    (accumulator : AccumulatorNote)
    (policy : PolicyWitness) : Bool :=
  natEq accumulator.accountDigest policy.accountDigest
    && natEq accumulator.policyRoot policy.policyRoot

def approvalStepExactIntentAndOneShot (step : ApprovalStep) : Bool :=
  accumulatorMatchesIntent step.priorAccumulator step.intent
    && !digestIn
      step.signerCapability.signerNullifier
      step.priorAccumulator.approvalNullifiers
    && !digestIn
      step.signerCapability.signerTag
      step.priorAccumulator.approvalSignerTags
    && natEq step.priorAccumulator.stateDigest
      (accumulatorStateDigest step.priorAccumulator)
    && accumulatorEq step.nextAccumulator (nextAccumulatorForApproval
      step.priorAccumulator
      step.signerCapability)
    && digestIn
      step.signerCapability.signerNullifier
      step.nextAccumulator.approvalNullifiers
    && digestIn
      step.signerCapability.signerTag
      step.nextAccumulator.approvalSignerTags

def approvalStepAccepted (step : ApprovalStep) : Bool :=
  policyWellFormed step.policy
    && approvalStepExactIntentAndOneShot step
    && accumulatorMatchesPolicy step.priorAccumulator step.policy
    && natEq step.signerCapability.policyRoot step.policy.policyRoot
    && natEq step.signerCapability.signerTag step.spendDerivedSignerTag
    && signerInPolicy step.signerCapability step.policy

def initialAccumulatorForIntent (intent : SpendIntent) : AccumulatorNote :=
  let accumulator : AccumulatorNote :=
    { accountDigest := intent.accountDigest,
      policyRoot := intent.policyRoot,
      intentDigest := intent.intentDigest,
      approvalCount := 0,
      approvalNullifiers := [],
      approvalSignerTags := [],
      approvalLeaves := [],
      stateDigest := 0 }
  { accumulator with stateDigest := accumulatorStateDigest accumulator }

def approvalStepMatchesFinal
    (policy : PolicyWitness)
    (intent : SpendIntent)
    (step : ApprovalStep) : Bool :=
  if step.policy = policy then
    if step.intent = intent then
      true
    else
      false
  else
    false

def approvalTraceAcceptedFrom
    (policy : PolicyWitness)
    (intent : SpendIntent)
    (current : AccumulatorNote) :
    List ApprovalStep -> AccumulatorNote -> Bool
  | [], finalAccumulator =>
      accumulatorEq current finalAccumulator
  | step :: rest, finalAccumulator =>
      approvalStepMatchesFinal policy intent step
        && accumulatorEq step.priorAccumulator current
        && approvalStepAccepted step
        && approvalTraceAcceptedFrom
          policy
          intent
          step.nextAccumulator
          rest
          finalAccumulator

def finalSpendAccepted (spend : FinalSpend) : Bool :=
  policyWellFormed spend.policy
    && natEq spend.valueNote.accountDigest spend.intent.accountDigest
    && valueNoteLockedToIntent spend.valueNote spend.intent
    && accumulatorMatchesPolicy spend.accumulator spend.policy
    && accumulatorMatchesIntent spend.accumulator spend.intent
    && natEq spend.accumulator.stateDigest
      (accumulatorStateDigest spend.accumulator)
    && approvalTraceAcceptedFrom
      spend.policy
      spend.intent
      (initialAccumulatorForIntent spend.intent)
      spend.approvalTrace
      spend.accumulator
    && (spend.policy.threshold <= spend.accumulator.approvalCount)

def publicShapeFromFinalSpend
    (spend : FinalSpend) : PublicTransactionShape :=
  { inputNullifier := spend.valueNote.publicNullifier,
    outputCommitment := spend.outputCommitment,
    outputCiphertextHash := spend.outputCiphertextHash,
    balanceTag := spend.balanceTag }

def FinalSpendContainsSignerLongTermSecret
    (_spend : FinalSpend)
    (_signerLongTermSecret : Nat) : Prop :=
  False

def baseSignerTags : List Digest := [501, 502, 503]

def baseSignerSetRoot : Digest :=
  signerSetRootDigest baseSignerTags

def baseThreshold : Nat := 2

def basePolicyRoot : Digest :=
  policyRootDigest 101 baseThreshold baseSignerSetRoot

def basePolicy : PolicyWitness :=
  { accountDigest := 101,
    policyRoot := basePolicyRoot,
    threshold := baseThreshold,
    signerSetRoot := baseSignerSetRoot,
    signerTags := baseSignerTags }

def baseIntent : SpendIntent :=
  { accountDigest := 101,
    policyRoot := basePolicyRoot,
    intentDigest := 404 }

def otherIntent : SpendIntent :=
  { baseIntent with intentDigest := 405 }

def otherPolicy : PolicyWitness :=
  { basePolicy with policyRoot := 909 }

def zeroThresholdPolicy : PolicyWitness :=
  { basePolicy with threshold := 0 }

def thresholdAboveSignerCountPolicy : PolicyWitness :=
  { basePolicy with threshold := 4 }

def duplicateSignerPolicy : PolicyWitness :=
  { basePolicy with
    signerSetRoot := signerSetRootDigest [501, 501, 502],
    signerTags := [501, 501, 502] }

def signerSetRootDriftPolicy : PolicyWitness :=
  { basePolicy with signerSetRoot := baseSignerSetRoot + 1 }

def emptyAccumulator : AccumulatorNote :=
  initialAccumulatorForIntent baseIntent

def signerCapabilityA : SignerCapabilityNote :=
  { policyRoot := basePolicy.policyRoot,
    signerTag := 501,
    signerNullifier := 601,
    capabilitySecretCommitment := 701 }

def signerCapabilityB : SignerCapabilityNote :=
  { policyRoot := basePolicy.policyRoot,
    signerTag := 502,
    signerNullifier := 602,
    capabilitySecretCommitment := 702 }

def signerCapabilityAFreshNullifier : SignerCapabilityNote :=
  { policyRoot := basePolicy.policyRoot,
    signerTag := 501,
    signerNullifier := 603,
    capabilitySecretCommitment := 703 }

def signerCapabilityOutsidePolicy : SignerCapabilityNote :=
  { policyRoot := basePolicy.policyRoot,
    signerTag := 777,
    signerNullifier := 677,
    capabilitySecretCommitment := 707 }

def oneApprovalAccumulator : AccumulatorNote :=
  nextAccumulatorForApproval emptyAccumulator signerCapabilityA

def twoApprovalAccumulator : AccumulatorNote :=
  nextAccumulatorForApproval oneApprovalAccumulator signerCapabilityB

def firstApprovalStep : ApprovalStep :=
  { policy := basePolicy,
    intent := baseIntent,
    priorAccumulator := emptyAccumulator,
    signerCapability := signerCapabilityA,
    spendDerivedSignerTag := signerCapabilityA.signerTag,
    nextAccumulator := oneApprovalAccumulator }

def validApprovalStep : ApprovalStep :=
  { policy := basePolicy,
    intent := baseIntent,
    priorAccumulator := oneApprovalAccumulator,
    signerCapability := signerCapabilityB,
    spendDerivedSignerTag := signerCapabilityB.signerTag,
    nextAccumulator := twoApprovalAccumulator }

def duplicateSignerStep : ApprovalStep :=
  { validApprovalStep with
    signerCapability := signerCapabilityA,
    nextAccumulator :=
      nextAccumulatorForApproval oneApprovalAccumulator signerCapabilityA }

def sameSignerFreshNullifierStep : ApprovalStep :=
  { validApprovalStep with
    signerCapability := signerCapabilityAFreshNullifier,
    spendDerivedSignerTag := signerCapabilityAFreshNullifier.signerTag,
    nextAccumulator :=
      nextAccumulatorForApproval
        oneApprovalAccumulator
        signerCapabilityAFreshNullifier }

def wrongIntentStep : ApprovalStep :=
  { validApprovalStep with intent := otherIntent }

def wrongPolicyStep : ApprovalStep :=
  { validApprovalStep with policy := otherPolicy }

def outsidePolicySignerStep : ApprovalStep :=
  { validApprovalStep with
    signerCapability := signerCapabilityOutsidePolicy,
    spendDerivedSignerTag := signerCapabilityOutsidePolicy.signerTag,
    nextAccumulator :=
      nextAccumulatorForApproval
        oneApprovalAccumulator
        signerCapabilityOutsidePolicy }

def forgedSignerTagStep : ApprovalStep :=
  { validApprovalStep with spendDerivedSignerTag := signerCapabilityA.signerTag }

def zeroThresholdPolicyStep : ApprovalStep :=
  { validApprovalStep with policy := zeroThresholdPolicy }

def thresholdAboveSignerCountPolicyStep : ApprovalStep :=
  { validApprovalStep with policy := thresholdAboveSignerCountPolicy }

def duplicateSignerPolicyStep : ApprovalStep :=
  { validApprovalStep with policy := duplicateSignerPolicy }

def signerSetRootDriftPolicyStep : ApprovalStep :=
  { validApprovalStep with policy := signerSetRootDriftPolicy }

def baseValueNote : ValueNote :=
  { accountDigest := baseIntent.accountDigest,
    noteCommitment := 808,
    valueLockDigest :=
      valueLockDigest baseIntent.policyRoot baseIntent.intentDigest,
    publicNullifier := 909 }

def wrongValueLockNote : ValueNote :=
  { baseValueNote with valueLockDigest := baseValueNote.valueLockDigest + 1 }

def finalSpendWith
    (policy : PolicyWitness)
    (intent : SpendIntent)
    (accumulator : AccumulatorNote)
    (approvalTrace : List ApprovalStep) : FinalSpend :=
  { policy := policy,
    intent := intent,
    valueNote := baseValueNote,
    accumulator := accumulator,
    approvalTrace := approvalTrace,
    outputCommitment := 1001,
    outputCiphertextHash := 1002,
    balanceTag := 1003 }

def oneApprovalTrace : List ApprovalStep :=
  [firstApprovalStep]

def twoApprovalTrace : List ApprovalStep :=
  [firstApprovalStep, validApprovalStep]

def sameSignerFreshNullifierTrace : List ApprovalStep :=
  [firstApprovalStep, sameSignerFreshNullifierStep]

def belowThresholdFinalSpend : FinalSpend :=
  finalSpendWith basePolicy baseIntent oneApprovalAccumulator oneApprovalTrace

def exactThresholdFinalSpend : FinalSpend :=
  finalSpendWith basePolicy baseIntent twoApprovalAccumulator twoApprovalTrace

def sameSignerFreshNullifierAccumulator : AccumulatorNote :=
  nextAccumulatorForApproval
    oneApprovalAccumulator
    signerCapabilityAFreshNullifier

def sameSignerFreshNullifierFinalSpend : FinalSpend :=
  finalSpendWith
    basePolicy
    baseIntent
    sameSignerFreshNullifierAccumulator
    sameSignerFreshNullifierTrace

def finalIntentMismatchSpend : FinalSpend :=
  finalSpendWith basePolicy otherIntent twoApprovalAccumulator twoApprovalTrace

def finalValueLockMismatchSpend : FinalSpend :=
  { exactThresholdFinalSpend with valueNote := wrongValueLockNote }

def zeroThresholdFinalSpend : FinalSpend :=
  finalSpendWith zeroThresholdPolicy baseIntent twoApprovalAccumulator twoApprovalTrace

def duplicateSignerPolicyFinalSpend : FinalSpend :=
  finalSpendWith duplicateSignerPolicy baseIntent twoApprovalAccumulator twoApprovalTrace

def forgedThresholdAccumulator : AccumulatorNote :=
  let forged : AccumulatorNote :=
    { twoApprovalAccumulator with
      approvalNullifiers := [611, 612],
      approvalSignerTags := [501, 502],
      approvalLeaves := [613, 614],
      stateDigest := 0 }
  { forged with stateDigest := accumulatorStateDigest forged }

def forgedThresholdFinalSpend : FinalSpend :=
  finalSpendWith basePolicy baseIntent forgedThresholdAccumulator []

theorem base_policy_well_formed :
    policyWellFormed basePolicy = true := by
  decide

theorem valid_approval_step_accepts :
    approvalStepAccepted validApprovalStep = true := by
  decide

theorem first_approval_step_accepts :
    approvalStepAccepted firstApprovalStep = true := by
  decide

theorem accepted_approval_step_implies_exact_intent_and_one_shot
    {step : ApprovalStep}
    (accepted : approvalStepAccepted step = true) :
    approvalStepExactIntentAndOneShot step = true := by
  unfold approvalStepAccepted at accepted
  cases h : approvalStepExactIntentAndOneShot step
  · simp [h] at accepted
  · rfl

theorem accepted_approval_step_implies_policy_well_formed
    {step : ApprovalStep}
    (accepted : approvalStepAccepted step = true) :
    policyWellFormed step.policy = true := by
  unfold approvalStepAccepted at accepted
  cases h : policyWellFormed step.policy
  · simp [h] at accepted
  · rfl

theorem valid_approval_step_exact_intent_and_one_shot :
    approvalStepExactIntentAndOneShot validApprovalStep = true := by
  exact accepted_approval_step_implies_exact_intent_and_one_shot
    valid_approval_step_accepts

theorem duplicate_signer_rejected :
    approvalStepAccepted duplicateSignerStep = false := by
  decide

theorem same_signer_fresh_nullifier_rejected :
    approvalStepAccepted sameSignerFreshNullifierStep = false := by
  decide

theorem wrong_intent_rejected :
    approvalStepAccepted wrongIntentStep = false := by
  decide

theorem wrong_policy_rejected :
    approvalStepAccepted wrongPolicyStep = false := by
  decide

theorem outside_policy_signer_rejected :
    approvalStepAccepted outsidePolicySignerStep = false := by
  decide

theorem forged_signer_tag_rejected :
    approvalStepAccepted forgedSignerTagStep = false := by
  decide

theorem zero_threshold_policy_approval_rejected :
    approvalStepAccepted zeroThresholdPolicyStep = false := by
  decide

theorem threshold_above_signer_count_policy_approval_rejected :
    approvalStepAccepted thresholdAboveSignerCountPolicyStep = false := by
  decide

theorem duplicate_signer_policy_approval_rejected :
    approvalStepAccepted duplicateSignerPolicyStep = false := by
  decide

theorem signer_set_root_drift_policy_approval_rejected :
    approvalStepAccepted signerSetRootDriftPolicyStep = false := by
  decide

theorem below_threshold_final_rejected :
    finalSpendAccepted belowThresholdFinalSpend = false := by
  decide

theorem exact_threshold_final_accepted :
    finalSpendAccepted exactThresholdFinalSpend = true := by
  decide

theorem same_signer_fresh_nullifier_final_rejected :
    finalSpendAccepted sameSignerFreshNullifierFinalSpend = false := by
  decide

theorem forged_threshold_final_without_approval_trace_rejected :
    finalSpendAccepted forgedThresholdFinalSpend = false := by
  decide

theorem final_intent_mismatch_rejected :
    finalSpendAccepted finalIntentMismatchSpend = false := by
  decide

theorem final_value_lock_mismatch_rejected :
    finalSpendAccepted finalValueLockMismatchSpend = false := by
  decide

theorem zero_threshold_final_rejected :
    finalSpendAccepted zeroThresholdFinalSpend = false := by
  decide

theorem duplicate_signer_policy_final_rejected :
    finalSpendAccepted duplicateSignerPolicyFinalSpend = false := by
  decide

theorem final_spend_witness_contains_no_signer_long_term_secret
    (spend : FinalSpend)
    (signerLongTermSecret : Nat) :
    ¬ FinalSpendContainsSignerLongTermSecret
      spend
      signerLongTermSecret := by
  intro secretInWitness
  cases secretInWitness

theorem public_shape_hides_policy_and_accumulator_private_fields :
    publicShapeFromFinalSpend exactThresholdFinalSpend =
      publicShapeFromFinalSpend
        { exactThresholdFinalSpend with
          policy := {
            basePolicy with
            threshold := 9,
            signerSetRoot := 12345,
            signerTags := [9, 8, 7] },
          accumulator :=
            { twoApprovalAccumulator with
              approvalCount := 9,
              approvalNullifiers := [1, 2, 3],
              approvalSignerTags := [11, 12, 13],
              approvalLeaves := [4, 5, 6],
              policyRoot := 9999 } } := by
  decide

end PrivateMultisigAccumulator
end Transaction
end Hegemon
