import HegemonCrypto.NativeLaunchFrozenRecordedSource
import HegemonCrypto.NativeLaunchPrefixFppSelector
import HegemonCrypto.NativeLaunchEventCoverageDecs

/-! Deterministic single-instance DECS support and actual decoder-failure cover.
Both desired source readback and response equality are derived internally.
The fixed prefix/claim response rule below has no wire or point argument, but
its actual causal selection before a challenge is NOT constructed here.
Compact success does not imply distinct queries: that condition is explicit.
No Rust false-accept implication, QROM bound, source polynomial, privacy or
production authority is claimed. All eight production gates remain open. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchDerivedDecsFailureCover
open NativeLaunchAdaptiveHistoryCodec (Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchFppHistoryBinding
open NativeLaunchMerklePathBinding (rootFrame)
open NativeLaunchCompactMerkleBinding (nodeHash)
open NativeLaunchCompactMerklePath (reconstruct)
open NativeLaunchAuthenticatedReadback (Position wireOpenings)
open NativeLaunchRecordedWireReadback
open NativeLaunchFrozenRecordedSource
open NativeLaunchFppResponseHistory (rebuiltKey)
open NativeLaunchPrefixFppSelector (selectedResponse parseFinal response_or_collision_or_late)
open SmallWood
open SmallWood.NativeLaunchRelationModelResponse
open SmallWood.V8Smz9McaRecovery (BoundedResponse QuerySample)
open SmallWood.V8Smz9McaDecoder (responseSupport responseDecoder decoderFailureEvent)
open SmallWood.NativeHtlcUniversalMatrix (BadMatrix accepted_decoder_failure_implies_bad_matrix_or_small_support)
local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq
noncomputable section
open Classical

/-- A fixed-prefix, fixed-claim response rule. This is a meaningful bounded
single-instance rule, not a constructed adaptive matrix/claim family. -/
def responseRule (H : Oracle) (prefixHistory : History) (branch : Branch) (claimed : Digest) :
    Matrix → BoundedResponse Goldilocks MaskRow (degree branch) :=
  fun _ => selectedResponse H prefixHistory branch claimed

structure Inputs (branch : Branch) where
  H : Oracle
  earlier : History
  prefixHistory : History
  wire : WireFields branch Position
  salt : Fin 4 → Word
  tapes : Fin (queryCount branch) → Fin 8 → Word
  statement : Statement (NativeLaunchCommitmentReadback.family branch)
  compact : Fin (queryCount branch) → List Digest
  bareRoot : Digest
  point : Position → Goldilocks
  matrix : Matrix
  tail : List Word
  claimed : Digest

namespace Inputs
variable {branch : Branch} (I : Inputs branch)

def leading : Digest := I.H (rootFrame I.salt I.bareRoot I.statement)
def key : RawInput := rebuiltKey I.leading I.statement I.point I.wire I.matrix
def finalKey : RawInput := reconstructedFinal I.H (NativeLaunchCommitmentReadback.family branch) I.key I.tail
def data := recordedData I.H I.earlier (sharedContext (branch := branch) I.salt I.statement) I.leading
def masks := recordedMasks I.H I.earlier (sharedContext (branch := branch) I.salt I.statement) I.leading
def response := responseRule I.H I.prefixHistory branch I.claimed
def support := responseSupport I.point (degree branch) I.data I.masks I.response I.matrix
def LeafCollision : Prop := RelevantCollision I.H (commonHistory I.H I.earlier I.wire I.salt I.tapes I.statement I.compact)
def SourceChange : Prop := WireReadbackChanged I.H I.earlier I.wire I.salt I.tapes I.statement I.compact I.bareRoot
def FppCollision : Prop := RelevantCollision I.H (relevantInputs I.H I.prefixHistory
  (NativeLaunchCommitmentReadback.family branch) I.key I.tail)
def LateFinal : Prop := I.finalKey ∉ I.prefixHistory ∧
  reconstructedDigest I.H (NativeLaunchCommitmentReadback.family branch) I.key I.tail = I.claimed
def LateFpp : Prop := I.finalKey ∈ I.prefixHistory ∧ I.key ∉ I.prefixHistory ∧
  parseFinal (NativeLaunchCommitmentReadback.family branch) I.finalKey = some (I.H I.key, I.tail)

/-- Both finite collision sets and all three actual change/late-key events. -/
def Exceptional : Prop := I.LeafCollision ∨ I.SourceChange ∨ I.FppCollision ∨ I.LateFinal ∨ I.LateFpp

structure Accepted : Prop where
  compact : (reconstruct (nodeHash I.H (NativeLaunchCommitmentReadback.family branch))
    (wireOpenings I.H I.wire I.salt I.tapes I.statement I.compact) 23).map (fun result => result.root) = some I.bareRoot
  physical : 8 + I.tail.length < 2^64
  fpp : reconstructedDigest I.H (NativeLaunchCommitmentReadback.family branch) I.key I.tail = I.claimed

theorem derived_source (accepted : I.Accepted) (clean : ¬ I.LeafCollision) (stable : ¬ I.SourceChange) :
    SourceReadback I.wire I.data I.masks := by
  exact earlier_source_readback_of_no_change I.H I.earlier I.wire I.salt I.tapes I.statement I.compact
    I.bareRoot accepted.compact clean stable

theorem derived_response (accepted : I.Accepted) (clean : ¬ I.FppCollision)
    (noFinal : ¬ I.LateFinal) (noFpp : ¬ I.LateFpp) :
    I.response I.matrix = calculatedResponse I.point I.wire I.matrix := by
  rcases response_or_collision_or_late I.H I.prefixHistory I.leading I.statement I.point I.wire I.matrix
    I.tail I.claimed accepted.physical accepted.fpp with same | collision | lateFinal | lateFpp
  · exact same
  · exact False.elim (clean collision)
  · exact False.elim (noFinal lateFinal)
  · exact False.elim (noFpp lateFpp)

theorem query_support (accepted : I.Accepted)
    (distinct : Function.Injective (fun index => I.point (I.wire.positions index)))
    (clean : ¬ I.Exceptional) (index : Fin (queryCount branch)) :
    I.wire.positions index ∈ I.support := by
  have leaf : ¬ I.LeafCollision := fun h => clean (Or.inl h)
  have stable : ¬ I.SourceChange := fun h => clean (Or.inr (Or.inl h))
  have fpp : ¬ I.FppCollision := fun h => clean (Or.inr (Or.inr (Or.inl h)))
  have final : ¬ I.LateFinal := fun h => clean (Or.inr (Or.inr (Or.inr (Or.inl h))))
  have late : ¬ I.LateFpp := fun h => clean (Or.inr (Or.inr (Or.inr (Or.inr h))))
  exact query_agrees_with_prior_response I.point I.wire I.matrix I.data I.masks I.response distinct
    (I.derived_source accepted leaf stable) (I.derived_response accepted fpp final late) index

theorem failed_query_cover (accepted : I.Accepted)
    (distinct : Function.Injective (fun index => I.point (I.wire.positions index)))
    (index : Fin (queryCount branch)) (failed : I.wire.positions index ∉ I.support) : I.Exceptional := by
  by_contra clean
  exact failed (I.query_support accepted distinct clean index)

theorem all_query_support_cover (accepted : I.Accepted)
    (distinct : Function.Injective (fun index => I.point (I.wire.positions index))) :
    I.Exceptional ∨ ∀ index, I.wire.positions index ∈ I.support := by
  by_cases exceptional : I.Exceptional
  · exact Or.inl exceptional
  · exact Or.inr (I.query_support accepted distinct exceptional)

/-- Actual typed wire sample; its cardinality is derived from the explicit
query-point injection, not inferred from modeled compact reconstruction. -/
def sample (distinct : Function.Injective (fun index => I.point (I.wire.positions index))) :
    QuerySample Position (queryCount branch) :=
  SmallWood.NativeLaunchEventCoverageDecs.wireQuery I.point I.wire distinct

/-- Join with the EXISTING calculated decoder's `none` predicate. This is not
an implication from Rust semantic false acceptance to decoder failure. -/
theorem decoder_failure_cover (accepted : I.Accepted)
    (distinct : Function.Injective (fun index => I.point (I.wire.positions index)))
    (failed : responseDecoder I.point (degree branch) I.data I.masks I.response I.matrix = none) :
    I.Exceptional ∨ I.sample distinct ∈ decoderFailureEvent I.point (degree branch) (queryCount branch)
      I.data I.masks I.response I.matrix := by
  by_cases exceptional : I.Exceptional
  · exact Or.inl exceptional
  · apply Or.inr
    apply Finset.mem_filter.mpr
    refine ⟨Finset.mem_univ _, ?_, failed⟩
    intro position member
    obtain ⟨index, _, same⟩ := Finset.mem_image.mp member
    rw [← same]
    exact I.query_support accepted distinct exceptional index

/-- Original decoder failure is covered by the five concrete commitment
events, the existing universal bad-matrix event, or small full support containing
the actual typed sample. This is deterministic and has no probability claim. -/
theorem semantic_decoder_partition (accepted : I.Accepted)
    (distinct : Function.Injective (fun index => I.point (I.wire.positions index)))
    (injective : Function.Injective I.point) (threshold : Nat) (valid : degree branch < threshold)
    (failed : responseDecoder I.point (degree branch) I.data I.masks I.response I.matrix = none) :
    I.Exceptional ∨ BadMatrix I.point (degree branch) threshold I.data I.masks I.matrix ∨
      (I.support.card < threshold ∧ (I.sample distinct).val ⊆ I.support) := by
  rcases I.decoder_failure_cover accepted distinct failed with exceptional | failure
  · exact Or.inl exceptional
  · exact Or.inr (accepted_decoder_failure_implies_bad_matrix_or_small_support I.point injective
      (degree branch) threshold (queryCount branch) valid I.data I.masks I.response I.matrix
      (I.sample distinct) failure)

end Inputs
end
end HegemonCrypto.NativeLaunchDerivedDecsFailureCover
