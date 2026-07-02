import Hegemon.Shielded.Nullifier

namespace Hegemon
namespace Native
namespace TransferStateAdmission

open Hegemon.Shielded

inductive TransferNullifierState where
  | valid
  | zero
  | alreadySpent
  | duplicate
  | alreadyPending
deriving DecidableEq, Repr

inductive TransferStateReject where
  | unknownAnchor
  | nullifierZero
  | nullifierAlreadySpent
  | duplicateNullifier
  | nullifierAlreadyPending
  | commitmentZero
  | stablecoinPolicyUnauthorized
  | sidecarCiphertextMissing
  | sidecarCiphertextSizeMissing
  | sidecarCiphertextSizeMismatch
deriving DecidableEq, Repr

structure TransferStateInput where
  anchorKnown : Bool
  nullifierState : TransferNullifierState
  commitmentsNonzero : Bool
  stablecoinPolicyAuthorized : Bool
  sidecarRoute : Bool
  sidecarCiphertextsAvailable : Bool
  sidecarCiphertextSizesPresent : Bool
  sidecarCiphertextSizesMatch : Bool
deriving DecidableEq, Repr

structure TransferNullifierRowsInput where
  spent : List Nullifier
  pending : List Nullifier
  action : List Nullifier
deriving DecidableEq, Repr

def deriveMempoolNullifierStateGo
    (spent : List Nullifier)
    (pending seen : List Nullifier) :
    List Nullifier -> TransferNullifierState
  | [] => TransferNullifierState.valid
  | key :: rest =>
      if isZeroNullifier key then
        TransferNullifierState.zero
      else if key ∈ spent then
        TransferNullifierState.alreadySpent
      else if key ∈ pending then
        if key ∈ seen then
          TransferNullifierState.duplicate
        else
          TransferNullifierState.alreadyPending
      else
        deriveMempoolNullifierStateGo spent (key :: pending) (key :: seen) rest

def deriveMempoolNullifierState (input : TransferNullifierRowsInput) :
    TransferNullifierState :=
  deriveMempoolNullifierStateGo input.spent input.pending [] input.action

def deriveBlockNullifierStateGo :
    List Nullifier -> List Nullifier -> TransferNullifierState
  | _, [] => TransferNullifierState.valid
  | spent, key :: rest =>
      if isZeroNullifier key then
        TransferNullifierState.zero
      else if key ∈ spent then
        TransferNullifierState.duplicate
      else
        deriveBlockNullifierStateGo (key :: spent) rest

def deriveBlockNullifierState (input : TransferNullifierRowsInput) :
    TransferNullifierState :=
  deriveBlockNullifierStateGo input.spent input.action

def evaluateTransferState
    (input : TransferStateInput) : Except TransferStateReject Unit :=
  if input.anchorKnown = false then
    Except.error TransferStateReject.unknownAnchor
  else
    match input.nullifierState with
    | TransferNullifierState.valid =>
        if input.commitmentsNonzero = false then
          Except.error TransferStateReject.commitmentZero
        else if input.stablecoinPolicyAuthorized = false then
          Except.error TransferStateReject.stablecoinPolicyUnauthorized
        else if input.sidecarRoute = false then
          Except.ok ()
        else if input.sidecarCiphertextsAvailable = false then
          Except.error TransferStateReject.sidecarCiphertextMissing
        else if input.sidecarCiphertextSizesPresent = false then
          Except.error TransferStateReject.sidecarCiphertextSizeMissing
        else if input.sidecarCiphertextSizesMatch = false then
          Except.error TransferStateReject.sidecarCiphertextSizeMismatch
        else
          Except.ok ()
    | TransferNullifierState.zero =>
        Except.error TransferStateReject.nullifierZero
    | TransferNullifierState.alreadySpent =>
        Except.error TransferStateReject.nullifierAlreadySpent
    | TransferNullifierState.duplicate =>
        Except.error TransferStateReject.duplicateNullifier
    | TransferNullifierState.alreadyPending =>
        Except.error TransferStateReject.nullifierAlreadyPending

def transferStateAccepts (input : TransferStateInput) : Bool :=
  match evaluateTransferState input with
  | Except.ok _ => true
  | Except.error _ => false

def transferStateRejection
    (input : TransferStateInput) : Option TransferStateReject :=
  match evaluateTransferState input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def transferStatePreconditions (input : TransferStateInput) : Bool :=
  if input.anchorKnown = false then
    false
  else
    match input.nullifierState with
    | TransferNullifierState.valid =>
        if input.commitmentsNonzero = false then
          false
        else if input.stablecoinPolicyAuthorized = false then
          false
        else if input.sidecarRoute = false then
          true
        else if input.sidecarCiphertextsAvailable = false then
          false
        else if input.sidecarCiphertextSizesPresent = false then
          false
        else if input.sidecarCiphertextSizesMatch = false then
          false
        else
          true
    | _ => false

theorem accepts_iff_state_preconditions (input : TransferStateInput) :
    transferStateAccepts input = transferStatePreconditions input := by
  cases input with
  | mk anchorKnown nullifierState commitmentsNonzero stablecoinPolicyAuthorized sidecarRoute
      sidecarCiphertextsAvailable sidecarCiphertextSizesPresent
      sidecarCiphertextSizesMatch =>
      unfold transferStateAccepts transferStatePreconditions evaluateTransferState
      cases anchorKnown <;> cases nullifierState <;> cases commitmentsNonzero <;>
        cases stablecoinPolicyAuthorized <;> cases sidecarRoute <;>
        cases sidecarCiphertextsAvailable <;> cases sidecarCiphertextSizesPresent <;>
        cases sidecarCiphertextSizesMatch <;> rfl

def validTransferState : TransferStateInput :=
  {
    anchorKnown := true,
    nullifierState := TransferNullifierState.valid,
    commitmentsNonzero := true,
    stablecoinPolicyAuthorized := true,
    sidecarRoute := true,
    sidecarCiphertextsAvailable := true,
    sidecarCiphertextSizesPresent := true,
    sidecarCiphertextSizesMatch := true
  }

theorem valid_transfer_state_accepts :
    evaluateTransferState validTransferState = Except.ok () := by
  rfl

theorem unknown_anchor_rejects
    {input : TransferStateInput}
    (unknown : input.anchorKnown = false) :
    evaluateTransferState input =
      Except.error TransferStateReject.unknownAnchor := by
  unfold evaluateTransferState
  simp [unknown]

theorem nullifier_zero_rejects
    {input : TransferStateInput}
    (anchor : input.anchorKnown = true)
    (zero : input.nullifierState = TransferNullifierState.zero) :
    evaluateTransferState input =
      Except.error TransferStateReject.nullifierZero := by
  unfold evaluateTransferState
  simp [anchor, zero]

theorem nullifier_already_spent_rejects
    {input : TransferStateInput}
    (anchor : input.anchorKnown = true)
    (spent : input.nullifierState = TransferNullifierState.alreadySpent) :
    evaluateTransferState input =
      Except.error TransferStateReject.nullifierAlreadySpent := by
  unfold evaluateTransferState
  simp [anchor, spent]

theorem duplicate_nullifier_rejects
    {input : TransferStateInput}
    (anchor : input.anchorKnown = true)
    (duplicate : input.nullifierState = TransferNullifierState.duplicate) :
    evaluateTransferState input =
      Except.error TransferStateReject.duplicateNullifier := by
  unfold evaluateTransferState
  simp [anchor, duplicate]

theorem nullifier_already_pending_rejects
    {input : TransferStateInput}
    (anchor : input.anchorKnown = true)
    (pending : input.nullifierState = TransferNullifierState.alreadyPending) :
    evaluateTransferState input =
      Except.error TransferStateReject.nullifierAlreadyPending := by
  unfold evaluateTransferState
  simp [anchor, pending]

theorem commitment_zero_rejects
    {input : TransferStateInput}
    (anchor : input.anchorKnown = true)
    (nullifiers : input.nullifierState = TransferNullifierState.valid)
    (zero : input.commitmentsNonzero = false) :
    evaluateTransferState input =
      Except.error TransferStateReject.commitmentZero := by
  unfold evaluateTransferState
  simp [anchor, nullifiers, zero]

theorem stablecoin_policy_unauthorized_rejects
    {input : TransferStateInput}
    (anchor : input.anchorKnown = true)
    (nullifiers : input.nullifierState = TransferNullifierState.valid)
    (commitments : input.commitmentsNonzero = true)
    (unauthorized : input.stablecoinPolicyAuthorized = false) :
    evaluateTransferState input =
      Except.error TransferStateReject.stablecoinPolicyUnauthorized := by
  unfold evaluateTransferState
  simp [anchor, nullifiers, commitments, unauthorized]

theorem sidecar_ciphertext_missing_rejects
    {input : TransferStateInput}
    (anchor : input.anchorKnown = true)
    (nullifiers : input.nullifierState = TransferNullifierState.valid)
    (commitments : input.commitmentsNonzero = true)
    (stablecoin : input.stablecoinPolicyAuthorized = true)
    (sidecar : input.sidecarRoute = true)
    (missing : input.sidecarCiphertextsAvailable = false) :
    evaluateTransferState input =
      Except.error TransferStateReject.sidecarCiphertextMissing := by
  unfold evaluateTransferState
  simp [anchor, nullifiers, commitments, stablecoin, sidecar, missing]

theorem sidecar_ciphertext_size_missing_rejects
    {input : TransferStateInput}
    (anchor : input.anchorKnown = true)
    (nullifiers : input.nullifierState = TransferNullifierState.valid)
    (commitments : input.commitmentsNonzero = true)
    (stablecoin : input.stablecoinPolicyAuthorized = true)
    (sidecar : input.sidecarRoute = true)
    (available : input.sidecarCiphertextsAvailable = true)
    (missing : input.sidecarCiphertextSizesPresent = false) :
    evaluateTransferState input =
      Except.error TransferStateReject.sidecarCiphertextSizeMissing := by
  unfold evaluateTransferState
  simp [anchor, nullifiers, commitments, stablecoin, sidecar, available, missing]

theorem sidecar_ciphertext_size_mismatch_rejects
    {input : TransferStateInput}
    (anchor : input.anchorKnown = true)
    (nullifiers : input.nullifierState = TransferNullifierState.valid)
    (commitments : input.commitmentsNonzero = true)
    (stablecoin : input.stablecoinPolicyAuthorized = true)
    (sidecar : input.sidecarRoute = true)
    (available : input.sidecarCiphertextsAvailable = true)
    (present : input.sidecarCiphertextSizesPresent = true)
    (mismatch : input.sidecarCiphertextSizesMatch = false) :
    evaluateTransferState input =
      Except.error TransferStateReject.sidecarCiphertextSizeMismatch := by
  unfold evaluateTransferState
  simp [anchor, nullifiers, commitments, stablecoin, sidecar, available, present, mismatch]

theorem unknown_anchor_precedes_nullifier :
    evaluateTransferState
      { validTransferState with
        anchorKnown := false,
        nullifierState := TransferNullifierState.zero } =
      Except.error TransferStateReject.unknownAnchor := by
  rfl

theorem nullifier_precedes_commitment_zero :
    evaluateTransferState
      { validTransferState with
        nullifierState := TransferNullifierState.duplicate,
        commitmentsNonzero := false } =
      Except.error TransferStateReject.duplicateNullifier := by
  rfl

def sampleNullifierA : Nullifier :=
  Hegemon.patternedBytes 48 0x71

def sampleNullifierB : Nullifier :=
  Hegemon.patternedBytes 48 0xb2

theorem mempool_same_action_duplicate_derives_duplicate :
    deriveMempoolNullifierState
      { spent := [],
        pending := [],
        action := [sampleNullifierA, sampleNullifierA] } =
      TransferNullifierState.duplicate := by
  rfl

theorem mempool_fresh_doubleton_derives_duplicate
    (key : Nullifier)
    (spent pending : List Nullifier)
    (nonzero : isZeroNullifier key = false)
    (notSpent : key ∉ spent)
    (notPending : key ∉ pending) :
    deriveMempoolNullifierState
      { spent := spent,
        pending := pending,
        action := [key, key] } =
      TransferNullifierState.duplicate := by
  unfold deriveMempoolNullifierState
  simp [deriveMempoolNullifierStateGo, nonzero, notSpent, notPending]

theorem mempool_prior_pending_precedes_action_duplicate :
    deriveMempoolNullifierState
      { spent := [],
        pending := [sampleNullifierA],
        action := [sampleNullifierA, sampleNullifierA] } =
      TransferNullifierState.alreadyPending := by
  rfl

theorem mempool_prior_pending_precedes_action_duplicate_of_mem
    (key : Nullifier)
    (spent pending : List Nullifier)
    (nonzero : isZeroNullifier key = false)
    (notSpent : key ∉ spent)
    (inPending : key ∈ pending) :
    deriveMempoolNullifierState
      { spent := spent,
        pending := pending,
        action := [key, key] } =
      TransferNullifierState.alreadyPending := by
  unfold deriveMempoolNullifierState
  simp [deriveMempoolNullifierStateGo, nonzero, notSpent, inPending]

theorem block_same_action_duplicate_derives_duplicate :
    deriveBlockNullifierState
      { spent := [],
        pending := [],
        action := [sampleNullifierA, sampleNullifierA] } =
      TransferNullifierState.duplicate := by
  rfl

theorem block_fresh_doubleton_derives_duplicate
    (key : Nullifier)
    (spent pending : List Nullifier)
    (nonzero : isZeroNullifier key = false)
    (notSpent : key ∉ spent) :
    deriveBlockNullifierState
      { spent := spent,
        pending := pending,
        action := [key, key] } =
      TransferNullifierState.duplicate := by
  unfold deriveBlockNullifierState
  simp [deriveBlockNullifierStateGo, nonzero, notSpent]

theorem block_prior_spent_duplicate_derives_duplicate :
    deriveBlockNullifierState
      { spent := [sampleNullifierA],
        pending := [],
        action := [sampleNullifierA] } =
      TransferNullifierState.duplicate := by
  rfl

theorem block_prior_spent_duplicate_derives_duplicate_of_mem
    (key : Nullifier)
    (spent pending : List Nullifier)
    (nonzero : isZeroNullifier key = false)
    (inSpent : key ∈ spent) :
    deriveBlockNullifierState
      { spent := spent,
        pending := pending,
        action := [key] } =
      TransferNullifierState.duplicate := by
  unfold deriveBlockNullifierState
  simp [deriveBlockNullifierStateGo, nonzero, inSpent]

theorem block_pending_only_does_not_reject_import :
    deriveBlockNullifierState
      { spent := [],
        pending := [sampleNullifierA],
        action := [sampleNullifierA] } =
      TransferNullifierState.valid := by
  rfl

theorem block_pending_only_valid_when_unspent
    (key : Nullifier)
    (spent pending : List Nullifier)
    (nonzero : isZeroNullifier key = false)
    (notSpent : key ∉ spent) :
    deriveBlockNullifierState
      { spent := spent,
        pending := key :: pending,
        action := [key] } =
      TransferNullifierState.valid := by
  unfold deriveBlockNullifierState
  simp [deriveBlockNullifierStateGo, nonzero, notSpent]

theorem commitment_zero_precedes_stablecoin_policy :
    evaluateTransferState
      { validTransferState with
        commitmentsNonzero := false,
        stablecoinPolicyAuthorized := false } =
      Except.error TransferStateReject.commitmentZero := by
  rfl

theorem stablecoin_policy_precedes_sidecar_materialization :
    evaluateTransferState
      { validTransferState with
        stablecoinPolicyAuthorized := false,
        sidecarCiphertextsAvailable := false,
        sidecarCiphertextSizesPresent := false,
        sidecarCiphertextSizesMatch := false } =
      Except.error TransferStateReject.stablecoinPolicyUnauthorized := by
  rfl

theorem inline_ignores_sidecar_availability :
    evaluateTransferState
      { validTransferState with
        sidecarRoute := false,
        sidecarCiphertextsAvailable := false,
        sidecarCiphertextSizesPresent := false,
        sidecarCiphertextSizesMatch := false } =
      Except.ok () := by
  rfl

end TransferStateAdmission
end Native
end Hegemon
