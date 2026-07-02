import Hegemon.Wallet.NoteCiphertextDecrypt

namespace Hegemon
namespace Privacy
namespace CiphertextArchiveBoundary

open Hegemon.Wallet.NoteCiphertextWire
open Hegemon.Wallet.NoteCiphertextDecrypt

inductive CiphertextArchiveBoundaryRejection where
  | indexGap
  | indexBeyondLeafCount
deriving DecidableEq, Repr

inductive WalletPageAdmissionRejection where
  | pageTooLarge
deriving DecidableEq, Repr

inductive WalletSyncSnapshotAdmissionRejection where
  | depthMismatch
  | leafCountExceedsTreeCapacity
  | ciphertextIndexExceedsTreeCapacity
  | commitmentSnapshotTooLarge
  | ciphertextSnapshotTooLarge
deriving DecidableEq, Repr

structure CiphertextArchiveBoundaryCase where
  name : String
  leafCount : Nat
  archiveIndices : List Nat
deriving DecidableEq, Repr

structure WalletPageAdmissionCase where
  name : String
  requestedLimit : Nat
  returnedEntries : Nat
deriving DecidableEq, Repr

structure WalletSyncSnapshotAdmissionCase where
  name : String
  expectedDepth : Nat
  depth : Nat
  leafCount : Nat
  nextIndex : Nat
  commitmentCursor : Nat
  ciphertextCursor : Nat
  treeCapacity : Nat
  maxSnapshotGap : Nat
deriving DecidableEq, Repr

def firstRejectionFrom
    (expectedIndex leafCount : Nat) :
    List Nat -> Option CiphertextArchiveBoundaryRejection
  | [] => none
  | index :: rest =>
      if index != expectedIndex then
        some CiphertextArchiveBoundaryRejection.indexGap
      else if leafCount <= index then
        some CiphertextArchiveBoundaryRejection.indexBeyondLeafCount
      else
        firstRejectionFrom (expectedIndex + 1) leafCount rest

def firstRejection
    (case : CiphertextArchiveBoundaryCase) :
    Option CiphertextArchiveBoundaryRejection :=
  firstRejectionFrom 0 case.leafCount case.archiveIndices

def accepts (case : CiphertextArchiveBoundaryCase) : Bool :=
  firstRejection case = none

def walletPageRejection
    (case : WalletPageAdmissionCase) :
    Option WalletPageAdmissionRejection :=
  if case.returnedEntries ≤ case.requestedLimit then
    none
  else
    some WalletPageAdmissionRejection.pageTooLarge

def walletPageAccepts (case : WalletPageAdmissionCase) : Bool :=
  walletPageRejection case = none

def walletSyncSnapshotRejection
    (case : WalletSyncSnapshotAdmissionCase) :
    Option WalletSyncSnapshotAdmissionRejection :=
  if case.depth ≠ case.expectedDepth then
    some WalletSyncSnapshotAdmissionRejection.depthMismatch
  else if case.treeCapacity < case.leafCount then
    some WalletSyncSnapshotAdmissionRejection.leafCountExceedsTreeCapacity
  else if case.treeCapacity < case.nextIndex then
    some WalletSyncSnapshotAdmissionRejection.ciphertextIndexExceedsTreeCapacity
  else if case.maxSnapshotGap < case.leafCount - case.commitmentCursor then
    some WalletSyncSnapshotAdmissionRejection.commitmentSnapshotTooLarge
  else if case.maxSnapshotGap < case.nextIndex - case.ciphertextCursor then
    some WalletSyncSnapshotAdmissionRejection.ciphertextSnapshotTooLarge
  else
    none

def walletSyncSnapshotAccepts
    (case : WalletSyncSnapshotAdmissionCase) : Bool :=
  walletSyncSnapshotRejection case = none

def archiveIndicesContiguousFrom :
    Nat -> List Nat -> Prop
  | _expectedIndex, [] => True
  | expectedIndex, index :: rest =>
      index = expectedIndex
        ∧ archiveIndicesContiguousFrom (expectedIndex + 1) rest

def archiveIndicesContiguous (case : CiphertextArchiveBoundaryCase) : Prop :=
  archiveIndicesContiguousFrom 0 case.archiveIndices

structure AcceptedCiphertextArchivePublicationFacts
    (case : CiphertextArchiveBoundaryCase) : Prop where
  accepted :
    accepts case = true
  noFirstRejection :
    firstRejection case = none
  contiguousFromZero :
    archiveIndicesContiguous case
  rowsBelowLeafCount :
    ∀ index, index ∈ case.archiveIndices -> index < case.leafCount

structure AcceptedWalletPageAdmissionFacts
    (case : WalletPageAdmissionCase) : Prop where
  accepted :
    walletPageAccepts case = true
  returnedEntriesWithinLimit :
    case.returnedEntries ≤ case.requestedLimit

structure AcceptedWalletSyncSnapshotAdmissionFacts
    (case : WalletSyncSnapshotAdmissionCase) : Prop where
  accepted :
    walletSyncSnapshotAccepts case = true
  depthMatches :
    case.depth = case.expectedDepth
  leafCountWithinTreeCapacity :
    case.leafCount ≤ case.treeCapacity
  nextIndexWithinTreeCapacity :
    case.nextIndex ≤ case.treeCapacity
  commitmentGapWithinLimit :
    case.leafCount - case.commitmentCursor ≤ case.maxSnapshotGap
  ciphertextGapWithinLimit :
    case.nextIndex - case.ciphertextCursor ≤ case.maxSnapshotGap

theorem accepts_iff_no_first_rejection
    (case : CiphertextArchiveBoundaryCase) :
    accepts case = true ↔ firstRejection case = none := by
  unfold accepts
  constructor
  · intro accepted
    exact of_decide_eq_true accepted
  · intro noRejection
    exact decide_eq_true noRejection

theorem wallet_page_accepts_iff_returned_entries_within_limit
    (case : WalletPageAdmissionCase) :
    walletPageAccepts case = true ↔
      case.returnedEntries ≤ case.requestedLimit := by
  unfold walletPageAccepts walletPageRejection
  by_cases within : case.returnedEntries ≤ case.requestedLimit
  · simp [within]
  · simp [within]

theorem accepted_wallet_page_admission_binds_returned_entries_to_limit
    {case : WalletPageAdmissionCase}
    (accepted : walletPageAccepts case = true) :
    AcceptedWalletPageAdmissionFacts case := by
  have within :=
    (wallet_page_accepts_iff_returned_entries_within_limit case).mp accepted
  exact {
    accepted := accepted
    returnedEntriesWithinLimit := within
  }

theorem accepted_wallet_sync_snapshot_admission_binds_snapshot_bounds
    {case : WalletSyncSnapshotAdmissionCase}
    (accepted : walletSyncSnapshotAccepts case = true) :
    AcceptedWalletSyncSnapshotAdmissionFacts case := by
  unfold walletSyncSnapshotAccepts walletSyncSnapshotRejection at accepted
  by_cases depthBad : case.depth ≠ case.expectedDepth
  · simp [depthBad] at accepted
  ·
    have depthMatches : case.depth = case.expectedDepth := by
      exact Decidable.not_not.mp depthBad
    by_cases leafOver : case.treeCapacity < case.leafCount
    · simp [depthBad, leafOver] at accepted
    ·
      have leafWithin : case.leafCount ≤ case.treeCapacity := Nat.le_of_not_gt leafOver
      by_cases ciphertextOver : case.treeCapacity < case.nextIndex
      · simp [depthBad, leafOver, ciphertextOver] at accepted
      ·
        have ciphertextWithin : case.nextIndex ≤ case.treeCapacity := Nat.le_of_not_gt ciphertextOver
        by_cases commitmentGapOver :
          case.maxSnapshotGap < case.leafCount - case.commitmentCursor
        · simp [depthBad, leafOver, ciphertextOver, commitmentGapOver] at accepted
        ·
          have commitmentGapWithin :
              case.leafCount - case.commitmentCursor ≤ case.maxSnapshotGap :=
            Nat.le_of_not_gt commitmentGapOver
          by_cases ciphertextGapOver :
            case.maxSnapshotGap < case.nextIndex - case.ciphertextCursor
          · simp [
              depthBad,
              leafOver,
              ciphertextOver,
              commitmentGapOver,
              ciphertextGapOver
            ] at accepted
          ·
            have ciphertextGapWithin :
                case.nextIndex - case.ciphertextCursor ≤ case.maxSnapshotGap :=
              Nat.le_of_not_gt ciphertextGapOver
            exact {
              accepted := by
                simp [
                  walletSyncSnapshotAccepts,
                  walletSyncSnapshotRejection,
                  depthBad,
                  leafOver,
                  ciphertextOver,
                  commitmentGapOver,
                  ciphertextGapOver
                ]
              depthMatches := depthMatches
              leafCountWithinTreeCapacity := leafWithin
              nextIndexWithinTreeCapacity := ciphertextWithin
              commitmentGapWithinLimit := commitmentGapWithin
              ciphertextGapWithinLimit := ciphertextGapWithin
            }

theorem first_rejection_from_head_gap
    {expectedIndex leafCount index : Nat}
    {rest : List Nat}
    (gap : index ≠ expectedIndex) :
    firstRejectionFrom expectedIndex leafCount (index :: rest) =
      some CiphertextArchiveBoundaryRejection.indexGap := by
  simp [firstRejectionFrom, gap]

theorem first_rejection_from_head_beyond_leaf_count
    {expectedIndex leafCount : Nat}
    {rest : List Nat}
    (beyond : leafCount <= expectedIndex) :
    firstRejectionFrom expectedIndex leafCount (expectedIndex :: rest) =
      some CiphertextArchiveBoundaryRejection.indexBeyondLeafCount := by
  simp [firstRejectionFrom, beyond]

theorem accepts_empty_archive
    (leafCount : Nat) :
    accepts
      { name := "empty"
        leafCount := leafCount
        archiveIndices := [] } = true := by
  rfl

theorem first_rejection_from_none_contiguous
    {expectedIndex leafCount : Nat}
    {archiveIndices : List Nat}
    (accepted :
      firstRejectionFrom expectedIndex leafCount archiveIndices = none) :
    archiveIndicesContiguousFrom expectedIndex archiveIndices := by
  induction archiveIndices generalizing expectedIndex with
  | nil =>
      simp [archiveIndicesContiguousFrom]
  | cons index rest ih =>
      unfold firstRejectionFrom at accepted
      by_cases indexMatches : index = expectedIndex
      · subst index
        by_cases beyondLeafCount : leafCount <= expectedIndex
        · simp [beyondLeafCount] at accepted
        · simp [beyondLeafCount] at accepted
          exact ⟨rfl, ih accepted⟩
      · simp [indexMatches] at accepted

theorem first_rejection_from_none_rows_below_leaf_count
    {expectedIndex leafCount : Nat}
    {archiveIndices : List Nat}
    (accepted :
      firstRejectionFrom expectedIndex leafCount archiveIndices = none) :
    ∀ index, index ∈ archiveIndices -> index < leafCount := by
  induction archiveIndices generalizing expectedIndex with
  | nil =>
      intro index member
      simp at member
  | cons head rest ih =>
      unfold firstRejectionFrom at accepted
      by_cases indexMatches : head = expectedIndex
      · subst head
        by_cases beyondLeafCount : leafCount <= expectedIndex
        · simp [beyondLeafCount] at accepted
        · simp [beyondLeafCount] at accepted
          intro index member
          simp at member
          rcases member with rfl | restMember
          ·
            omega
          · exact ih accepted index restMember
      · simp [indexMatches] at accepted

theorem accepted_ciphertext_archive_publication_binds_contiguous_indices_below_leaf_count
    {case : CiphertextArchiveBoundaryCase}
    (accepted : accepts case = true) :
    AcceptedCiphertextArchivePublicationFacts case := by
  have noRejection :=
    (accepts_iff_no_first_rejection case).mp accepted
  exact {
    accepted := accepted
    noFirstRejection := noRejection
    contiguousFromZero :=
      first_rejection_from_none_contiguous noRejection
    rowsBelowLeafCount :=
      first_rejection_from_none_rows_below_leaf_count noRejection
  }

structure AcceptedCiphertextArchiveWalletCiphertextEquivalenceFacts
    (case : CiphertextArchiveBoundaryCase)
    (wire daBytes publicCiphertextHash : List Byte)
    (summary : NoteCiphertextSummary)
    (material : DecryptMaterialSummary)
    (cryptoAuthenticates : Bool)
    (ciphertextHashMatches : List Byte -> List Byte -> Prop)
    (residuals : NoteCiphertextPrimitiveResidualAssumptions) :
    Prop where
  archivePublication :
    AcceptedCiphertextArchivePublicationFacts case
  ciphertextProductionBoundary :
    ChainCiphertextProductionDecryptEquivalenceFacts
      wire
      daBytes
      publicCiphertextHash
      summary
      material
      cryptoAuthenticates
      ciphertextHashMatches
      residuals
  archiveRowsBelowLeafCount :
    ∀ index, index ∈ case.archiveIndices -> index < case.leafCount

theorem accepted_ciphertext_archive_publication_binds_wallet_ciphertext_production_equivalence
    {case : CiphertextArchiveBoundaryCase}
    {wire daBytes publicCiphertextHash : List Byte}
    {summary : NoteCiphertextSummary}
    {material : DecryptMaterialSummary}
    {cryptoAuthenticates : Bool}
    {ciphertextHashMatches : List Byte -> List Byte -> Prop}
    {residuals : NoteCiphertextPrimitiveResidualAssumptions}
    (archiveAccepted : accepts case = true)
    (bounded : bytesBounded wire)
    (parsed : parseChainNoteCiphertext wire = some summary)
    (projected : projectChainDaBytes wire = some daBytes)
    (decryptAccepted :
      evaluateDecrypt
        {
          ciphertext := summary,
          material := material,
          cryptoAuthenticates := cryptoAuthenticates
        } = none)
    (hashMatches : ciphertextHashMatches daBytes publicCiphertextHash)
    (mlKemAssumption : residuals.mlKemIndCcaSecurity)
    (aeadAssumption : residuals.aeadCiphertextSecurity)
    (kdfAssumption : residuals.walletKdfDomainSeparation)
    (rngAssumption : residuals.encryptionRngFreshness) :
    AcceptedCiphertextArchiveWalletCiphertextEquivalenceFacts
      case
      wire
      daBytes
      publicCiphertextHash
      summary
      material
      cryptoAuthenticates
      ciphertextHashMatches
      residuals := by
  let archivePublication :=
    accepted_ciphertext_archive_publication_binds_contiguous_indices_below_leaf_count
      archiveAccepted
  exact {
    archivePublication := archivePublication
    ciphertextProductionBoundary :=
      accepted_chain_ciphertext_decrypt_binds_production_serialization_profile
        bounded
        parsed
        projected
        decryptAccepted
        hashMatches
        mlKemAssumption
        aeadAssumption
        kdfAssumption
        rngAssumption
    archiveRowsBelowLeafCount :=
      archivePublication.rowsBelowLeafCount
  }

def emptyArchive : CiphertextArchiveBoundaryCase :=
  { name := "empty-archive"
    leafCount := 0
    archiveIndices := [] }

def twoRowsAtLeafCount : CiphertextArchiveBoundaryCase :=
  { name := "two-rows-at-leaf-count"
    leafCount := 2
    archiveIndices := [0, 1] }

def prefixBelowLeafCount : CiphertextArchiveBoundaryCase :=
  { name := "prefix-below-leaf-count"
    leafCount := 4
    archiveIndices := [0, 1] }

def startsAtOneGap : CiphertextArchiveBoundaryCase :=
  { name := "starts-at-one-gap"
    leafCount := 2
    archiveIndices := [1] }

def interiorGap : CiphertextArchiveBoundaryCase :=
  { name := "interior-gap"
    leafCount := 3
    archiveIndices := [0, 2] }

def rowBeyondLeafCount : CiphertextArchiveBoundaryCase :=
  { name := "row-beyond-leaf-count"
    leafCount := 1
    archiveIndices := [0, 1] }

def zeroLeafNonemptyArchive : CiphertextArchiveBoundaryCase :=
  { name := "zero-leaf-nonempty-archive"
    leafCount := 0
    archiveIndices := [0] }

def sparseButInRangeRejects : CiphertextArchiveBoundaryCase :=
  { name := "sparse-but-in-range-rejects"
    leafCount := 4
    archiveIndices := [0, 1, 3] }

def emptyWalletPage : WalletPageAdmissionCase :=
  { name := "empty-wallet-page"
    requestedLimit := 0
    returnedEntries := 0 }

def exactWalletPageLimit : WalletPageAdmissionCase :=
  { name := "exact-wallet-page-limit"
    requestedLimit := 128
    returnedEntries := 128 }

def shortWalletPage : WalletPageAdmissionCase :=
  { name := "short-wallet-page"
    requestedLimit := 256
    returnedEntries := 64 }

def oversizedWalletPage : WalletPageAdmissionCase :=
  { name := "oversized-wallet-page"
    requestedLimit := 128
    returnedEntries := 129 }

def zeroLimitNonemptyWalletPage : WalletPageAdmissionCase :=
  { name := "zero-limit-nonempty-wallet-page"
    requestedLimit := 0
    returnedEntries := 1 }

def validWalletSyncSnapshot : WalletSyncSnapshotAdmissionCase :=
  { name := "valid-wallet-sync-snapshot"
    expectedDepth := 32
    depth := 32
    leafCount := 10
    nextIndex := 10
    commitmentCursor := 0
    ciphertextCursor := 0
    treeCapacity := 4294967296
    maxSnapshotGap := 1048576 }

def walletSyncSnapshotDepthMismatch : WalletSyncSnapshotAdmissionCase :=
  { validWalletSyncSnapshot with
    name := "wallet-sync-depth-mismatch"
    depth := 33 }

def walletSyncSnapshotLeafCountOverCapacity : WalletSyncSnapshotAdmissionCase :=
  { validWalletSyncSnapshot with
    name := "wallet-sync-leaf-count-over-capacity"
    leafCount := 4294967297 }

def walletSyncSnapshotNextIndexOverCapacity : WalletSyncSnapshotAdmissionCase :=
  { validWalletSyncSnapshot with
    name := "wallet-sync-next-index-over-capacity"
    nextIndex := 4294967297 }

def walletSyncSnapshotCommitmentGapTooLarge : WalletSyncSnapshotAdmissionCase :=
  { validWalletSyncSnapshot with
    name := "wallet-sync-commitment-gap-too-large"
    leafCount := 1048578 }

def walletSyncSnapshotCiphertextGapTooLarge : WalletSyncSnapshotAdmissionCase :=
  { validWalletSyncSnapshot with
    name := "wallet-sync-ciphertext-gap-too-large"
    nextIndex := 1048578 }

def walletSyncSnapshotCursorAheadAcceptedForReset : WalletSyncSnapshotAdmissionCase :=
  { validWalletSyncSnapshot with
    name := "wallet-sync-cursor-ahead-accepted-for-reset"
    leafCount := 3
    nextIndex := 3
    commitmentCursor := 10
    ciphertextCursor := 10 }

def allCases : List CiphertextArchiveBoundaryCase :=
  [ emptyArchive
  , twoRowsAtLeafCount
  , prefixBelowLeafCount
  , startsAtOneGap
  , interiorGap
  , sparseButInRangeRejects
  ]

def walletPageCases : List WalletPageAdmissionCase :=
  [ emptyWalletPage
  , exactWalletPageLimit
  , shortWalletPage
  , oversizedWalletPage
  , zeroLimitNonemptyWalletPage
  ]

def walletSyncSnapshotCases : List WalletSyncSnapshotAdmissionCase :=
  [ validWalletSyncSnapshot
  , walletSyncSnapshotDepthMismatch
  , walletSyncSnapshotLeafCountOverCapacity
  , walletSyncSnapshotNextIndexOverCapacity
  , walletSyncSnapshotCommitmentGapTooLarge
  , walletSyncSnapshotCiphertextGapTooLarge
  , walletSyncSnapshotCursorAheadAcceptedForReset
  ]

theorem two_rows_at_leaf_count_accepts :
    accepts twoRowsAtLeafCount = true := by
  decide

theorem prefix_below_leaf_count_accepts :
    accepts prefixBelowLeafCount = true := by
  decide

theorem starts_at_one_gap_rejects :
    firstRejection startsAtOneGap =
      some CiphertextArchiveBoundaryRejection.indexGap := by
  decide

theorem interior_gap_rejects :
    firstRejection interiorGap =
      some CiphertextArchiveBoundaryRejection.indexGap := by
  decide

theorem row_beyond_leaf_count_rejects :
    firstRejection rowBeyondLeafCount =
      some CiphertextArchiveBoundaryRejection.indexBeyondLeafCount := by
  decide

theorem zero_leaf_nonempty_archive_rejects :
    firstRejection zeroLeafNonemptyArchive =
      some CiphertextArchiveBoundaryRejection.indexBeyondLeafCount := by
  decide

theorem exact_wallet_page_limit_accepts :
    walletPageAccepts exactWalletPageLimit = true := by
  decide

theorem oversized_wallet_page_rejects :
    walletPageRejection oversizedWalletPage =
      some WalletPageAdmissionRejection.pageTooLarge := by
  decide

theorem zero_limit_nonempty_wallet_page_rejects :
    walletPageRejection zeroLimitNonemptyWalletPage =
      some WalletPageAdmissionRejection.pageTooLarge := by
  decide

theorem valid_wallet_sync_snapshot_accepts :
    walletSyncSnapshotAccepts validWalletSyncSnapshot = true := by
  decide

theorem wallet_sync_snapshot_depth_mismatch_rejects :
    walletSyncSnapshotRejection walletSyncSnapshotDepthMismatch =
      some WalletSyncSnapshotAdmissionRejection.depthMismatch := by
  decide

theorem wallet_sync_snapshot_leaf_count_over_capacity_rejects :
    walletSyncSnapshotRejection walletSyncSnapshotLeafCountOverCapacity =
      some WalletSyncSnapshotAdmissionRejection.leafCountExceedsTreeCapacity := by
  decide

theorem wallet_sync_snapshot_next_index_over_capacity_rejects :
    walletSyncSnapshotRejection walletSyncSnapshotNextIndexOverCapacity =
      some WalletSyncSnapshotAdmissionRejection.ciphertextIndexExceedsTreeCapacity := by
  decide

theorem wallet_sync_snapshot_commitment_gap_too_large_rejects :
    walletSyncSnapshotRejection walletSyncSnapshotCommitmentGapTooLarge =
      some WalletSyncSnapshotAdmissionRejection.commitmentSnapshotTooLarge := by
  decide

theorem wallet_sync_snapshot_ciphertext_gap_too_large_rejects :
    walletSyncSnapshotRejection walletSyncSnapshotCiphertextGapTooLarge =
      some WalletSyncSnapshotAdmissionRejection.ciphertextSnapshotTooLarge := by
  decide

end CiphertextArchiveBoundary
end Privacy
end Hegemon
