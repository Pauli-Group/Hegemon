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

structure CiphertextArchiveBoundaryCase where
  name : String
  leafCount : Nat
  archiveIndices : List Nat
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

theorem accepts_iff_no_first_rejection
    (case : CiphertextArchiveBoundaryCase) :
    accepts case = true ↔ firstRejection case = none := by
  unfold accepts
  constructor
  · intro accepted
    exact of_decide_eq_true accepted
  · intro noRejection
    exact decide_eq_true noRejection

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

def allCases : List CiphertextArchiveBoundaryCase :=
  [ emptyArchive
  , twoRowsAtLeafCount
  , prefixBelowLeafCount
  , startsAtOneGap
  , interiorGap
  , rowBeyondLeafCount
  , zeroLeafNonemptyArchive
  , sparseButInRangeRejects
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

end CiphertextArchiveBoundary
end Privacy
end Hegemon
