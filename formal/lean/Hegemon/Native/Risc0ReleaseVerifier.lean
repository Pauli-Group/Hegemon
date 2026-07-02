namespace Hegemon
namespace Native
namespace Risc0ReleaseVerifier

inductive Risc0ReleaseReject where
  | imageIdMismatch
  | journalDecodeFailed
  | verifierDisabled
deriving DecidableEq, Repr

structure Risc0ReleaseInput where
  imageIdMatches : Bool
  journalDecodes : Bool
  verifierEnabled : Bool
deriving DecidableEq, Repr

def evaluateRisc0ReleaseVerifier
    (input : Risc0ReleaseInput) : Except Risc0ReleaseReject Unit :=
  if input.imageIdMatches = false then
    Except.error Risc0ReleaseReject.imageIdMismatch
  else if input.journalDecodes = false then
    Except.error Risc0ReleaseReject.journalDecodeFailed
  else if input.verifierEnabled = false then
    Except.error Risc0ReleaseReject.verifierDisabled
  else
    Except.ok ()

def risc0ReleaseVerifierAccepts (input : Risc0ReleaseInput) : Bool :=
  match evaluateRisc0ReleaseVerifier input with
  | Except.ok _ => true
  | Except.error _ => false

def risc0ReleaseVerifierRejection
    (input : Risc0ReleaseInput) : Option Risc0ReleaseReject :=
  match evaluateRisc0ReleaseVerifier input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def risc0ReleasePreconditions (input : Risc0ReleaseInput) : Bool :=
  input.imageIdMatches && input.journalDecodes && input.verifierEnabled

theorem accepts_iff_release_preconditions (input : Risc0ReleaseInput) :
    risc0ReleaseVerifierAccepts input = risc0ReleasePreconditions input := by
  cases input with
  | mk imageIdMatches journalDecodes verifierEnabled =>
      unfold risc0ReleaseVerifierAccepts
        risc0ReleasePreconditions evaluateRisc0ReleaseVerifier
      cases imageIdMatches <;> cases journalDecodes <;> cases verifierEnabled <;> rfl

theorem release_build_never_accepts
    {input : Risc0ReleaseInput}
    (disabled : input.verifierEnabled = false) :
    risc0ReleaseVerifierAccepts input = false := by
  cases input with
  | mk imageIdMatches journalDecodes verifierEnabled =>
      cases imageIdMatches <;> cases journalDecodes <;> cases verifierEnabled <;>
        simp [risc0ReleaseVerifierAccepts, evaluateRisc0ReleaseVerifier] at disabled ⊢

def validFutureVerifier : Risc0ReleaseInput :=
  {
    imageIdMatches := true,
    journalDecodes := true,
    verifierEnabled := true
  }

def releaseDisabledVerifier : Risc0ReleaseInput :=
  {
    imageIdMatches := true,
    journalDecodes := true,
    verifierEnabled := false
  }

theorem valid_future_verifier_accepts :
    evaluateRisc0ReleaseVerifier validFutureVerifier = Except.ok () := by
  rfl

theorem release_disabled_rejects :
    evaluateRisc0ReleaseVerifier releaseDisabledVerifier =
      Except.error Risc0ReleaseReject.verifierDisabled := by
  rfl

theorem image_id_mismatch_rejects
    {input : Risc0ReleaseInput}
    (mismatch : input.imageIdMatches = false) :
    evaluateRisc0ReleaseVerifier input =
      Except.error Risc0ReleaseReject.imageIdMismatch := by
  unfold evaluateRisc0ReleaseVerifier
  simp [mismatch]

theorem journal_decode_failure_rejects
    {input : Risc0ReleaseInput}
    (image : input.imageIdMatches = true)
    (decode : input.journalDecodes = false) :
    evaluateRisc0ReleaseVerifier input =
      Except.error Risc0ReleaseReject.journalDecodeFailed := by
  unfold evaluateRisc0ReleaseVerifier
  simp [image, decode]

theorem disabled_rejects_after_prechecks
    {input : Risc0ReleaseInput}
    (image : input.imageIdMatches = true)
    (decode : input.journalDecodes = true)
    (disabled : input.verifierEnabled = false) :
    evaluateRisc0ReleaseVerifier input =
      Except.error Risc0ReleaseReject.verifierDisabled := by
  unfold evaluateRisc0ReleaseVerifier
  simp [image, decode, disabled]

end Risc0ReleaseVerifier
end Native
end Hegemon
