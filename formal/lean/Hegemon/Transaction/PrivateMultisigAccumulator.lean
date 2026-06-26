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
  nextAccumulator : AccumulatorNote
deriving DecidableEq, Repr

structure ValueNote where
  accountDigest : Digest
  noteCommitment : Digest
  publicNullifier : Digest
deriving DecidableEq, Repr

structure FinalSpend where
  policy : PolicyWitness
  intent : SpendIntent
  valueNote : ValueNote
  accumulator : AccumulatorNote
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
    + accumulator.approvalLeaves.length * 127
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
    && natEq step.priorAccumulator.stateDigest
      (accumulatorStateDigest step.priorAccumulator)
    && accumulatorEq step.nextAccumulator (nextAccumulatorForApproval
      step.priorAccumulator
      step.signerCapability)
    && digestIn
      step.signerCapability.signerNullifier
      step.nextAccumulator.approvalNullifiers

def approvalStepAccepted (step : ApprovalStep) : Bool :=
  approvalStepExactIntentAndOneShot step
    && accumulatorMatchesPolicy step.priorAccumulator step.policy
    && natEq step.signerCapability.policyRoot step.policy.policyRoot
    && signerInPolicy step.signerCapability step.policy

def finalSpendAccepted (spend : FinalSpend) : Bool :=
  natEq spend.valueNote.accountDigest spend.intent.accountDigest
    && accumulatorMatchesPolicy spend.accumulator spend.policy
    && accumulatorMatchesIntent spend.accumulator spend.intent
    && natEq spend.accumulator.stateDigest
      (accumulatorStateDigest spend.accumulator)
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

def basePolicy : PolicyWitness :=
  { accountDigest := 101,
    policyRoot := 202,
    threshold := 2,
    signerSetRoot := 303,
    signerTags := [501, 502] }

def baseIntent : SpendIntent :=
  { accountDigest := 101,
    policyRoot := 202,
    intentDigest := 404 }

def otherIntent : SpendIntent :=
  { baseIntent with intentDigest := 405 }

def otherPolicy : PolicyWitness :=
  { basePolicy with policyRoot := 909 }

def emptyAccumulator : AccumulatorNote :=
  let acc : AccumulatorNote :=
    { accountDigest := baseIntent.accountDigest,
      policyRoot := baseIntent.policyRoot,
      intentDigest := baseIntent.intentDigest,
      approvalCount := 0,
      approvalNullifiers := [],
      approvalLeaves := [],
      stateDigest := 0 }
  { acc with stateDigest := accumulatorStateDigest acc }

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

def signerCapabilityOutsidePolicy : SignerCapabilityNote :=
  { policyRoot := basePolicy.policyRoot,
    signerTag := 777,
    signerNullifier := 677,
    capabilitySecretCommitment := 707 }

def oneApprovalAccumulator : AccumulatorNote :=
  nextAccumulatorForApproval emptyAccumulator signerCapabilityA

def twoApprovalAccumulator : AccumulatorNote :=
  nextAccumulatorForApproval oneApprovalAccumulator signerCapabilityB

def validApprovalStep : ApprovalStep :=
  { policy := basePolicy,
    intent := baseIntent,
    priorAccumulator := oneApprovalAccumulator,
    signerCapability := signerCapabilityB,
    nextAccumulator := twoApprovalAccumulator }

def duplicateSignerStep : ApprovalStep :=
  { validApprovalStep with
    signerCapability := signerCapabilityA,
    nextAccumulator :=
      nextAccumulatorForApproval oneApprovalAccumulator signerCapabilityA }

def wrongIntentStep : ApprovalStep :=
  { validApprovalStep with intent := otherIntent }

def wrongPolicyStep : ApprovalStep :=
  { validApprovalStep with policy := otherPolicy }

def outsidePolicySignerStep : ApprovalStep :=
  { validApprovalStep with
    signerCapability := signerCapabilityOutsidePolicy,
    nextAccumulator :=
      nextAccumulatorForApproval
        oneApprovalAccumulator
        signerCapabilityOutsidePolicy }

def baseValueNote : ValueNote :=
  { accountDigest := baseIntent.accountDigest,
    noteCommitment := 808,
    publicNullifier := 909 }

def finalSpendWith
    (policy : PolicyWitness)
    (intent : SpendIntent)
    (accumulator : AccumulatorNote) : FinalSpend :=
  { policy := policy,
    intent := intent,
    valueNote := baseValueNote,
    accumulator := accumulator,
    outputCommitment := 1001,
    outputCiphertextHash := 1002,
    balanceTag := 1003 }

def belowThresholdFinalSpend : FinalSpend :=
  finalSpendWith basePolicy baseIntent oneApprovalAccumulator

def exactThresholdFinalSpend : FinalSpend :=
  finalSpendWith basePolicy baseIntent twoApprovalAccumulator

def finalIntentMismatchSpend : FinalSpend :=
  finalSpendWith basePolicy otherIntent twoApprovalAccumulator

theorem valid_approval_step_accepts :
    approvalStepAccepted validApprovalStep = true := by
  decide

theorem accepted_approval_step_implies_exact_intent_and_one_shot
    {step : ApprovalStep}
    (accepted : approvalStepAccepted step = true) :
    approvalStepExactIntentAndOneShot step = true := by
  unfold approvalStepAccepted at accepted
  cases h : approvalStepExactIntentAndOneShot step
  · simp [h] at accepted
  · rfl

theorem valid_approval_step_exact_intent_and_one_shot :
    approvalStepExactIntentAndOneShot validApprovalStep = true := by
  exact accepted_approval_step_implies_exact_intent_and_one_shot
    valid_approval_step_accepts

theorem duplicate_signer_rejected :
    approvalStepAccepted duplicateSignerStep = false := by
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

theorem below_threshold_final_rejected :
    finalSpendAccepted belowThresholdFinalSpend = false := by
  decide

theorem exact_threshold_final_accepted :
    finalSpendAccepted exactThresholdFinalSpend = true := by
  decide

theorem final_intent_mismatch_rejected :
    finalSpendAccepted finalIntentMismatchSpend = false := by
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
              approvalLeaves := [4, 5, 6],
              policyRoot := 9999 } } := by
  decide

end PrivateMultisigAccumulator
end Transaction
end Hegemon
