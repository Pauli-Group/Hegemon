import HegemonCrypto.SmallWoodProductionMerkleExtraction
import Mathlib.Data.List.GetD

/-!
# Compact production Merkle multi-opening extraction

The deployed SmallWood verifier does not carry 26 independent depth-19 authentication paths.
At each level it reuses an opened sibling subtree when one is available and otherwise consumes
one digest from that leaf's compact path.  Duplicate subtree indexes must carry the same digest,
all path cursors must be exhausted exactly, and every reconstructed leaf must reach one root.

This file mirrors that algorithm as a total Lean function and proves the deterministic extraction
statement needed by BCS: if every hash operation used by an accepted compact opening appears in
the measured SHA-512 database, then every opened row has a completely recorded path to the common
root.  No collision or random-oracle assumption is used here.
-/

namespace HegemonCrypto.SmallWood.CompactMerkleExtraction

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.ProductionMerkleExtraction
open HegemonCrypto.SmallWood.RecordedMerkleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.Sha512Xof

abbrev OpeningIndex := Fin decsOpenedEvaluations
abbrev ProductionOpeningCoordinates :=
  OpeningIndex -> Fin decsEvaluationCount
abbrev ProductionOpeningRows := OpeningIndex -> ProductionRow
abbrev ProductionCompactPaths := OpeningIndex -> List ActiveDigest

/-- Bottom-up subtree index after `level` executions of Rust's `index /= 2`. -/
def compactCurrentIndex
    (coordinates : ProductionOpeningCoordinates)
    (level : Nat)
    (opening : OpeningIndex) : Nat :=
  (coordinates opening).val / 2 ^ level

/-- Sibling subtree index used by the deployed verifier at one level. -/
def compactSiblingIndex
    (coordinates : ProductionOpeningCoordinates)
    (level : Nat)
    (opening : OpeningIndex) : Nat :=
  let current := compactCurrentIndex coordinates level opening
  if current % 2 = 0 then current + 1 else current - 1

/-- Whether another opened leaf already supplies the required sibling subtree. -/
def HasOpenedSibling
    (coordinates : ProductionOpeningCoordinates)
    (level : Nat)
    (opening : OpeningIndex) : Prop :=
  ∃ sibling : OpeningIndex,
    compactCurrentIndex coordinates level sibling =
      compactSiblingIndex coordinates level opening

/--
Number of compact-path digests consumed before `level`.  This is the Rust
`auth_path_cursors[opening]` value on entry to that level.
-/
noncomputable def compactPathCursor
    (coordinates : ProductionOpeningCoordinates)
    (opening : OpeningIndex) : Nat -> Nat
  | 0 => 0
  | level + 1 => by
      classical
      exact
        compactPathCursor coordinates opening level +
          if HasOpenedSibling coordinates level opening then 0 else 1

/--
Digest of each opened subtree after `level` bottom-up reductions.  The selected opened sibling
is immaterial when duplicate-subtree consistency holds; `Classical.choose` gives a canonical
total model without encoding Rust's `BTreeMap` implementation detail into the theorem.
-/
noncomputable def compactLevelHash
    (hash : HashInput ProductionRow ActiveDigest -> ActiveDigest)
    (fallback : ActiveDigest)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths) :
    Nat -> OpeningIndex -> ActiveDigest
  | 0, opening => hash (.leaf (rows opening))
  | level + 1, opening => by
      classical
      let child :=
        compactLevelHash hash fallback coordinates rows paths level opening
      let sibling :=
        if found : HasOpenedSibling coordinates level opening then
          compactLevelHash hash fallback coordinates rows paths level
            (Classical.choose found)
        else
          (paths opening).getD
            (compactPathCursor coordinates opening level) fallback
      exact
        match productionPathSideAtLevel (coordinates opening) level with
        | .left => hash (.node child sibling)
        | .right => hash (.node sibling child)

/-- Digest selected as the sibling of one opened subtree at one level. -/
noncomputable def compactSiblingDigest
    (hash : HashInput ProductionRow ActiveDigest -> ActiveDigest)
    (fallback : ActiveDigest)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (level : Nat)
    (opening : OpeningIndex) : ActiveDigest := by
  classical
  exact
    if found : HasOpenedSibling coordinates level opening then
      compactLevelHash hash fallback coordinates rows paths level
        (Classical.choose found)
    else
      (paths opening).getD
        (compactPathCursor coordinates opening level) fallback

/-- Exact ordered node input hashed by the verifier at one level. -/
noncomputable def compactNodeInput
    (hash : HashInput ProductionRow ActiveDigest -> ActiveDigest)
    (fallback : ActiveDigest)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (level : Nat)
    (opening : OpeningIndex) :
    HashInput ProductionRow ActiveDigest :=
  let child :=
    compactLevelHash hash fallback coordinates rows paths level opening
  let sibling :=
    compactSiblingDigest hash fallback coordinates rows paths level opening
  match productionPathSideAtLevel (coordinates opening) level with
  | .left => .node child sibling
  | .right => .node sibling child

theorem compact_level_hash_succ
    (hash : HashInput ProductionRow ActiveDigest -> ActiveDigest)
    (fallback : ActiveDigest)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (level : Nat)
    (opening : OpeningIndex) :
    compactLevelHash hash fallback coordinates rows paths (level + 1) opening =
      hash
        (compactNodeInput hash fallback coordinates rows paths level opening) := by
  classical
  cases side :
      productionPathSideAtLevel (coordinates opening) level <;>
    simp [compactLevelHash, compactNodeInput, compactSiblingDigest, side]

/-- Exact compact-path lengths accepted by `decs_recompute_root`. -/
def CompactPathsExact
    (coordinates : ProductionOpeningCoordinates)
    (paths : ProductionCompactPaths)
    (depth : Nat) : Prop :=
  ∀ opening,
    (paths opening).length =
      compactPathCursor coordinates opening depth

theorem compact_path_cursor_step_le
    (coordinates : ProductionOpeningCoordinates)
    (opening : OpeningIndex)
    (level : Nat) :
    compactPathCursor coordinates opening level ≤
      compactPathCursor coordinates opening (level + 1) := by
  classical
  simp only [compactPathCursor]
  split <;> omega

theorem compact_path_cursor_mono
    (coordinates : ProductionOpeningCoordinates)
    (opening : OpeningIndex)
    {shorter longer : Nat}
    (bounded : shorter ≤ longer) :
    compactPathCursor coordinates opening shorter ≤
      compactPathCursor coordinates opening longer := by
  exact
    (monotone_nat_of_le_succ fun level =>
      compact_path_cursor_step_le coordinates opening level) bounded

theorem compact_path_cursor_lt_length_of_missing_sibling
    (coordinates : ProductionOpeningCoordinates)
    (paths : ProductionCompactPaths)
    (depth level : Nat)
    (opening : OpeningIndex)
    (pathsExact : CompactPathsExact coordinates paths depth)
    (withinDepth : level < depth)
    (missing : ¬HasOpenedSibling coordinates level opening) :
    compactPathCursor coordinates opening level <
      (paths opening).length := by
  have stepEquation :
      compactPathCursor coordinates opening (level + 1) =
        compactPathCursor coordinates opening level + 1 := by
    classical
    simp [compactPathCursor, missing]
  have remaining :
      compactPathCursor coordinates opening (level + 1) ≤
        compactPathCursor coordinates opening depth :=
    compact_path_cursor_mono coordinates opening
      (Nat.succ_le_iff.mpr withinDepth)
  rw [pathsExact opening]
  omega

/-- Exact path shape guarantees that a missing sibling reads a transmitted digest, not fallback. -/
theorem compact_sibling_digest_of_missing_sibling
    (hash : HashInput ProductionRow ActiveDigest -> ActiveDigest)
    (fallback : ActiveDigest)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (depth level : Nat)
    (opening : OpeningIndex)
    (pathsExact : CompactPathsExact coordinates paths depth)
    (withinDepth : level < depth)
    (missing : ¬HasOpenedSibling coordinates level opening) :
    compactSiblingDigest
        hash fallback coordinates rows paths level opening ∈
      paths opening := by
  classical
  have cursorBound :=
    compact_path_cursor_lt_length_of_missing_sibling
      coordinates paths depth level opening pathsExact withinDepth missing
  rw [compactSiblingDigest, dif_neg missing,
    List.getD_eq_getElem (l := paths opening) (d := fallback) cursorBound]
  exact List.getElem_mem ..

/-- Rust rejects duplicate subtree indexes whose reconstructed digests differ. -/
def DuplicateSubtreesConsistent
    (hash : HashInput ProductionRow ActiveDigest -> ActiveDigest)
    (fallback : ActiveDigest)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (depth : Nat) : Prop :=
  ∀ level, level ≤ depth ->
    ∀ left right,
      compactCurrentIndex coordinates level left =
          compactCurrentIndex coordinates level right ->
        compactLevelHash hash fallback coordinates rows paths level left =
          compactLevelHash hash fallback coordinates rows paths level right

/-- Every opened leaf reaches the same root after exactly `depth` levels. -/
def CommonCompactRoot
    (hash : HashInput ProductionRow ActiveDigest -> ActiveDigest)
    (fallback : ActiveDigest)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (depth : Nat)
    (root : ActiveDigest) : Prop :=
  ∀ opening,
    compactLevelHash hash fallback coordinates rows paths depth opening = root

/--
Pure acceptance facts enforced by the deployed compact Merkle verifier.  Keeping them separate
from oracle recording makes the computational boundary explicit: acceptance is deterministic,
while a later QROM theorem supplies the measured hash claims.
-/
structure CompactVerifierAccepted
    (hash : HashInput ProductionRow ActiveDigest -> ActiveDigest)
    (fallback : ActiveDigest)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (depth : Nat)
    (root : ActiveDigest) : Prop where
  pathsExact : CompactPathsExact coordinates paths depth
  duplicateSubtrees :
    DuplicateSubtreesConsistent
      hash fallback coordinates rows paths depth
  commonRoot :
    CommonCompactRoot
      hash fallback coordinates rows paths depth root

/--
All hash calls actually used by the compact verifier are present in one measured database.
This is the exact deterministic premise supplied by the adaptive oracle/database bridge.
-/
structure CompactClaimsRecorded
    (database :
      Database (HashInput ProductionRow ActiveDigest) ActiveDigest)
    (hash : HashInput ProductionRow ActiveDigest -> ActiveDigest)
    (fallback : ActiveDigest)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    (depth : Nat) : Prop where
  leaves :
    ∀ opening,
      database (.leaf (rows opening)) =
        some
          (compactLevelHash
            hash fallback coordinates rows paths 0 opening)
  nodes :
    ∀ level, level < depth ->
      ∀ opening,
        database
            (compactNodeInput
              hash fallback coordinates rows paths level opening) =
          some
            (compactLevelHash
              hash fallback coordinates rows paths (level + 1) opening)

/--
Every prefix of a compact path whose hash claims were recorded is a recorded-query Merkle
opening.  The side order is exactly the root-to-leaf order consumed by `RecordedOpening`.
-/
theorem compact_prefix_is_recorded
    {database :
      Database (HashInput ProductionRow ActiveDigest) ActiveDigest}
    {hash : HashInput ProductionRow ActiveDigest -> ActiveDigest}
    {fallback : ActiveDigest}
    {coordinates : ProductionOpeningCoordinates}
    {rows : ProductionOpeningRows}
    {paths : ProductionCompactPaths}
    {depth : Nat}
    (claims :
      CompactClaimsRecorded
        database hash fallback coordinates rows paths depth)
    (level : Nat)
    (withinDepth : level ≤ depth)
    (opening : OpeningIndex) :
    RecordedOpening database
      (rows opening)
      (productionPathSidesAtDepth level (coordinates opening))
      (compactLevelHash
        hash fallback coordinates rows paths level opening) := by
  induction level with
  | zero =>
      exact RecordedOpening.leaf _ _ (claims.leaves opening)
  | succ level inductionHypothesis =>
      have childOpening :=
        inductionHypothesis (Nat.le_trans (Nat.le_succ level) withinDepth)
      have levelWithinDepth : level < depth := by
        omega
      have nodeRecorded := claims.nodes level levelWithinDepth opening
      simp only [productionPathSidesAtDepth]
      cases side :
          productionPathSideAtLevel (coordinates opening) level with
      | left =>
          apply RecordedOpening.left childOpening
          simpa [compactNodeInput, side] using nodeRecorded
      | right =>
          apply RecordedOpening.right childOpening
          simpa [compactNodeInput, side] using nodeRecorded

/--
An accepted depth-19 production compact opening contributes one completely recorded row for
every verifier-selected coordinate.
-/
theorem accepted_compact_opening_records_every_row
    (rawOracle : RawOracle)
    (salt : ProductionSalt)
    (fallback : ActiveDigest)
    {database : ProductionHashDatabase}
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    {root : ActiveDigest}
    (accepted :
      CompactVerifierAccepted
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth root)
    (claims :
      CompactClaimsRecorded
        (productionMerkleDatabase salt database)
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth) :
    ∀ opening,
      RecordedProductionRow
        salt database root (coordinates opening) (rows opening) := by
  intro opening
  unfold RecordedProductionRow RecordedAt productionPathSides
  rw [← accepted.commonRoot opening]
  exact compact_prefix_is_recorded
    claims activeMerkleDepth (Nat.le_refl _) opening

/--
Collision freedom upgrades recorded compact acceptance to equality with the canonical
polynomial-completed interactive oracle used by the SmallWood extractor.
-/
theorem accepted_compact_rows_eq_extracted_oracle
    (rawOracle : RawOracle)
    (salt : ProductionSalt)
    (fallback : ActiveDigest)
    {database : ProductionHashDatabase}
    (collisionFree : CollisionFree database)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (paths : ProductionCompactPaths)
    {root : ActiveDigest}
    (accepted :
      CompactVerifierAccepted
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth root)
    (claims :
      CompactClaimsRecorded
        (productionMerkleDatabase salt database)
        (productionMerkleHash rawOracle salt)
        fallback coordinates rows paths activeMerkleDepth) :
    ∀ opening,
      extractedCommittedOracle salt database root (coordinates opening) =
        rows opening := by
  intro opening
  exact recorded_production_row_eq_extracted
    salt collisionFree
    (accepted_compact_opening_records_every_row
      rawOracle salt fallback coordinates rows paths accepted claims opening)

end HegemonCrypto.SmallWood.CompactMerkleExtraction
