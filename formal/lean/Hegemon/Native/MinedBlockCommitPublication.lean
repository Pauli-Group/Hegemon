import Hegemon.Native.AtomicCommitManifestAdmission
import Hegemon.Native.BlockCommitmentAdmission
import Hegemon.Native.MinedWorkAdmission

namespace Hegemon
namespace Native
namespace MinedBlockCommitPublication

open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockCommitmentAdmission
open Hegemon.Native.MinedWorkAdmission

structure MinedBlockCommitPublicationInput where
  minedWork : MinedWorkInput
  blockCommitment : CommitmentInput
  commitManifest : AtomicCommitManifestInput
deriving DecidableEq, Repr

def isMinedBlockCommitKind (kind : AtomicCommitKind) : Bool :=
  match kind with
  | AtomicCommitKind.minedBlockCommit => true
  | _ => false

def minedBlockCommitPublicationAccepts
    (input : MinedBlockCommitPublicationInput) : Bool :=
  minedWorkAccepts input.minedWork
    && commitmentAccepts input.blockCommitment
    && isMinedBlockCommitKind input.commitManifest.kind
    && atomicCommitManifestAccepts input.commitManifest

def minedBlockCommitPublicationPreconditions
    (input : MinedBlockCommitPublicationInput) : Bool :=
  minedWorkPreconditions input.minedWork
    && commitmentPreconditions input.blockCommitment
    && isMinedBlockCommitKind input.commitManifest.kind
    && atomicCommitManifestPreconditions input.commitManifest

structure MinedBlockCommitPublicationFacts
    (input : MinedBlockCommitPublicationInput) where
  minedWorkAccepted : minedWorkAccepts input.minedWork = true
  blockCommitmentAccepted : commitmentAccepts input.blockCommitment = true
  commitManifestAccepted :
    atomicCommitManifestAccepts input.commitManifest = true
  minedWorkPreconditionsHold :
    minedWorkPreconditions input.minedWork = true
  blockCommitmentPreconditionsHold :
    commitmentPreconditions input.blockCommitment = true
  commitManifestPreconditionsHold :
    atomicCommitManifestPreconditions input.commitManifest = true
  commitManifestIsMined :
    isMinedBlockCommitKind input.commitManifest.kind = true
  commitManifestKind :
    input.commitManifest.kind = AtomicCommitKind.minedBlockCommit

inductive MinedBlockCommitPublicationReject where
  | minedWorkRejected
  | blockCommitmentRejected
  | commitKindMismatch
  | commitManifestRejected
deriving DecidableEq, Repr

def evaluateMinedBlockCommitPublicationRejection
    (input : MinedBlockCommitPublicationInput) :
    Option MinedBlockCommitPublicationReject :=
  if minedWorkAccepts input.minedWork = false then
    some MinedBlockCommitPublicationReject.minedWorkRejected
  else if commitmentAccepts input.blockCommitment = false then
    some MinedBlockCommitPublicationReject.blockCommitmentRejected
  else if isMinedBlockCommitKind input.commitManifest.kind = false then
    some MinedBlockCommitPublicationReject.commitKindMismatch
  else if atomicCommitManifestAccepts input.commitManifest = false then
    some MinedBlockCommitPublicationReject.commitManifestRejected
  else
    none

def minedBlockCommitPublicationRejectionAccepts
    (input : MinedBlockCommitPublicationInput) : Bool :=
  evaluateMinedBlockCommitPublicationRejection input = none

theorem mined_commit_kind_eq_of_accepts
    {kind : AtomicCommitKind}
    (accepted : isMinedBlockCommitKind kind = true) :
    kind = AtomicCommitKind.minedBlockCommit := by
  cases kind <;> simp [isMinedBlockCommitKind] at accepted ⊢

theorem accepts_iff_mined_block_commit_publication_preconditions
    {input : MinedBlockCommitPublicationInput} :
    minedBlockCommitPublicationAccepts input = true ↔
      minedBlockCommitPublicationPreconditions input = true := by
  simp [
    minedBlockCommitPublicationAccepts,
    minedBlockCommitPublicationPreconditions,
    Bool.and_eq_true,
    accepts_iff_mined_work_preconditions,
    accepts_iff_commitment_preconditions,
    accepts_iff_atomic_commit_manifest_preconditions
  ]

theorem rejection_accepts_iff_publication_accepts
    {input : MinedBlockCommitPublicationInput} :
    minedBlockCommitPublicationRejectionAccepts input = true ↔
      minedBlockCommitPublicationAccepts input = true := by
  unfold minedBlockCommitPublicationRejectionAccepts
    evaluateMinedBlockCommitPublicationRejection
    minedBlockCommitPublicationAccepts
  cases hMined : minedWorkAccepts input.minedWork <;>
    cases hCommitment : commitmentAccepts input.blockCommitment <;>
    cases hKind : isMinedBlockCommitKind input.commitManifest.kind <;>
    cases hManifest :
      atomicCommitManifestAccepts input.commitManifest <;>
    simp

theorem accepted_mined_block_commit_publication_facts
    {input : MinedBlockCommitPublicationInput}
    (accepted :
      minedBlockCommitPublicationAccepts input = true) :
    MinedBlockCommitPublicationFacts input := by
  have acceptedParts :
      ((minedWorkAccepts input.minedWork = true
        ∧ commitmentAccepts input.blockCommitment = true)
        ∧ isMinedBlockCommitKind input.commitManifest.kind = true)
        ∧ atomicCommitManifestAccepts input.commitManifest = true := by
    simpa [
      minedBlockCommitPublicationAccepts,
      Bool.and_eq_true
    ] using accepted
  have minedPreconditions :
      minedWorkPreconditions input.minedWork = true :=
    (accepts_iff_mined_work_preconditions).mp acceptedParts.left.left.left
  have commitmentPreconditions :
      commitmentPreconditions input.blockCommitment = true :=
    (accepts_iff_commitment_preconditions).mp acceptedParts.left.left.right
  have manifestPreconditions :
      atomicCommitManifestPreconditions input.commitManifest = true :=
    (accepts_iff_atomic_commit_manifest_preconditions).mp
      acceptedParts.right
  exact
    {
      minedWorkAccepted := acceptedParts.left.left.left,
      blockCommitmentAccepted := acceptedParts.left.left.right,
      commitManifestAccepted := acceptedParts.right,
      minedWorkPreconditionsHold := minedPreconditions,
      blockCommitmentPreconditionsHold := commitmentPreconditions,
      commitManifestPreconditionsHold := manifestPreconditions,
      commitManifestIsMined := acceptedParts.left.right,
      commitManifestKind :=
        mined_commit_kind_eq_of_accepts acceptedParts.left.right
    }

theorem accepted_mined_block_commit_publication_rejection_facts
    {input : MinedBlockCommitPublicationInput}
    (accepted :
      minedBlockCommitPublicationRejectionAccepts input = true) :
    MinedBlockCommitPublicationFacts input :=
  accepted_mined_block_commit_publication_facts
    ((rejection_accepts_iff_publication_accepts).mp accepted)

def validMinedBlockCommitPublication :
    MinedBlockCommitPublicationInput :=
  {
    minedWork := MinedWorkAdmission.valid,
    blockCommitment := BlockCommitmentAdmission.valid,
    commitManifest := AtomicCommitManifestAdmission.validMinedBlockCommit
  }

theorem valid_mined_block_commit_publication_accepts :
    evaluateMinedBlockCommitPublicationRejection
      validMinedBlockCommitPublication = none := by
  decide

theorem mined_work_rejects_before_block_commitment :
    evaluateMinedBlockCommitPublicationRejection
      { validMinedBlockCommitPublication with
        minedWork := MinedWorkAdmission.parentMismatch,
        blockCommitment :=
          { BlockCommitmentAdmission.valid with
            txCountMatches := false } } =
      some MinedBlockCommitPublicationReject.minedWorkRejected := by
  decide

theorem block_commitment_rejects_before_commit_kind :
    evaluateMinedBlockCommitPublicationRejection
      { validMinedBlockCommitPublication with
        blockCommitment :=
          { BlockCommitmentAdmission.valid with
            supplyDigestMatches := false },
        commitManifest :=
          AtomicCommitManifestAdmission.validCanonicalReorgCommit } =
      some MinedBlockCommitPublicationReject.blockCommitmentRejected := by
  decide

theorem commit_kind_rejects_before_manifest_shape :
    evaluateMinedBlockCommitPublicationRejection
      { validMinedBlockCommitPublication with
        commitManifest :=
          { AtomicCommitManifestAdmission.validCanonicalReorgCommit with
            blockRecordWrites := 0 } } =
      some MinedBlockCommitPublicationReject.commitKindMismatch := by
  decide

theorem commit_manifest_rejects_after_mined_kind :
    evaluateMinedBlockCommitPublicationRejection
      { validMinedBlockCommitPublication with
        commitManifest :=
          { AtomicCommitManifestAdmission.validMinedBlockCommit with
            pendingActionRemovals := 0 } } =
      some MinedBlockCommitPublicationReject.commitManifestRejected := by
  decide

end MinedBlockCommitPublication
end Native
end Hegemon
