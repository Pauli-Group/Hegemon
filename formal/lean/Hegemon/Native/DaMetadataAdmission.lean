namespace Hegemon
namespace Native
namespace DaMetadataAdmission

/-! Executable admission for the native V2 transfer-ciphertext DA metadata
committed by a block. This does not cover proof/action-body availability. -/

inductive Reject where
  | daRoot
  | daChunkSize
  | daSampleCount
  | daBlobLen
  | daChunkCount
deriving DecidableEq, Repr

structure Input where
  daRootMatches : Bool
  daChunkSizeMatches : Bool
  daSampleCountMatches : Bool
  daBlobLenMatches : Bool
  daChunkCountMatches : Bool
deriving DecidableEq, Repr

def evaluate (input : Input) : Except Reject Unit :=
  if input.daRootMatches = false then Except.error Reject.daRoot
  else if input.daChunkSizeMatches = false then Except.error Reject.daChunkSize
  else if input.daSampleCountMatches = false then Except.error Reject.daSampleCount
  else if input.daBlobLenMatches = false then Except.error Reject.daBlobLen
  else if input.daChunkCountMatches = false then Except.error Reject.daChunkCount
  else Except.ok ()

def valid : Input :=
  {
    daRootMatches := true
    daChunkSizeMatches := true
    daSampleCountMatches := true
    daBlobLenMatches := true
    daChunkCountMatches := true
  }

theorem accepts_iff_all_metadata_matches (input : Input) :
    evaluate input = Except.ok () ↔
      input.daRootMatches = true ∧
      input.daChunkSizeMatches = true ∧
      input.daSampleCountMatches = true ∧
      input.daBlobLenMatches = true ∧
      input.daChunkCountMatches = true := by
  cases input with
  | mk root chunkSize sampleCount blobLen chunkCount =>
      cases root <;> cases chunkSize <;> cases sampleCount <;>
        cases blobLen <;> cases chunkCount <;> simp [evaluate]

theorem valid_accepts : evaluate valid = Except.ok () := by rfl

theorem rejection_precedence_is_root_params_len_count :
    evaluate
      {
        daRootMatches := false
        daChunkSizeMatches := false
        daSampleCountMatches := false
        daBlobLenMatches := false
        daChunkCountMatches := false
      } = Except.error Reject.daRoot := by
  rfl

end DaMetadataAdmission
end Native
end Hegemon
