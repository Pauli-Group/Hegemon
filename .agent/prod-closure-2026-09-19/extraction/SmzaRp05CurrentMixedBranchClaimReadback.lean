import SmzaRp05AdaptiveRetainedAdviceTransport
import SmzaRp05PhysicalAcceptedReplayLite

/-! # Active-read claims on the exact mixed fixed-table branch

This records only the active-key reads executed by `mixedRun`. Fixed-table
reads are excluded from the active database transcript, as required by the
conditioned state representation. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentMixedBranchClaimReadback

open Classical
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05AdaptiveRetainedAdviceTransport
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05ConditionedExecution
open SmzaRp05PhysicalTerminalRead
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRoleDomainConditioning
open SmzaChallengeStageTargets (Role)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- Claims in the active CMS database, retaining the actual answer branch
and omitting fixed-table reads. -/
def mixedBranchClaims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest) :
    (program : Program Result) → Branches decode program →
      List (ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter)
  | .done _, _ => []
  | .read raw next, ⟨answer, branch⟩ =>
      if live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw) then
        (⟨encode raw, live⟩, answer) ::
          mixedBranchClaims ctx blockCap encode decode
            (next (decode raw answer)) branch
      else
        mixedBranchClaims ctx blockCap encode decode
          (next (decode raw answer)) branch

private theorem global_decompress_zero
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    : globalDecompress (0 : ActiveState ctx blockCap) = 0 := by
  have atZero (key : ActiveKey ctx.role blockCap ctx.keyBytes) :
      decompressAt key (0 : ActiveState ctx blockCap) = 0 := by
    funext basis
    unfold decompressAt
    have fiberZero :
        databaseFiberState (0 : ActiveState ctx blockCap)
          basis.input basis.phase basis.workspace key
          ((DatabaseFiber.databaseEquiv key) basis.database).1 = 0 := by
      ext coordinate
      simp [database_fiber_state_apply]
    dsimp only
    rw [fiberZero]
    simp
  have listZero : ∀ inputs : List (ActiveKey ctx.role blockCap ctx.keyBytes),
      decompressList inputs (0 : ActiveState ctx blockCap) = 0 := by
    intro inputs
    induction inputs with
    | nil => rfl
    | cons key inputs ih =>
        simp only [decompress_list_cons, ih, atZero]
  simpa [globalDecompress] using
    listZero ((Finset.univ : Finset (ActiveKey ctx.role blockCap ctx.keyBytes)).toList)

set_option linter.unusedSectionVars false in
private theorem knownAt_zero
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (answer : VectorOutput Counter) :
    KnownAt key answer (globalDecompress (0 : ActiveState ctx blockCap)) := by
  rw [global_decompress_zero]
  funext basis
  simp [coordinateEventProjection]

/-- Later mixed reads preserve a known active coordinate. A fixed-table
read either leaves the state unchanged or kills the inconsistent branch. -/
private theorem mixedRun_preserves_known
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : ActiveState ctx blockCap)
    (key : ActiveKey ctx.role blockCap ctx.keyBytes)
    (answer : VectorOutput Counter)
    (known : KnownAt key answer (globalDecompress state)) :
    KnownAt key answer
      (globalDecompress (mixedRun ctx blockCap fixed encode decode program branch state)) := by
  induction program generalizing state with
  | done result => simpa [mixedRun] using known
  | read raw next ih =>
      rcases branch with ⟨observed, branch⟩
      by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
      · simp only [mixedRun, dif_pos live]
        have knownAfterRead : KnownAt key answer
            (globalDecompress (physicalReadBranch ⟨encode raw, live⟩ observed state)) := by
          rw [SmzaRp05PhysicalTerminalRead.physical_read_branch_standard_view]
          exact SmzaRp05PhysicalAcceptedReplayLite.known_at_coordinate_event_projection
            key answer ⟨encode raw, live⟩ observed (globalDecompress state) known
        exact ih (decode raw observed) branch _ knownAfterRead
      · by_cases fixedMatches : fixed ⟨encode raw, live⟩ = observed
        · simp only [mixedRun, dif_neg live, if_pos fixedMatches]
          exact ih (decode raw observed) branch state known
        · simp only [mixedRun, dif_neg live, if_neg fixedMatches]
          exact ih (decode raw observed) branch 0
            (knownAt_zero ctx blockCap key answer)

/-- Every active call in the literal mixed execution is recorded in the
same terminal active database, in its standard decompressed view. -/
theorem mixed_branch_claim_known_at_standard
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (initial : ActiveState ctx blockCap)
    (claim : ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter)
    (member : claim ∈ mixedBranchClaims ctx blockCap encode decode program branch) :
    KnownAt claim.1 claim.2
      (globalDecompress (mixedRun ctx blockCap fixed encode decode program branch initial)) := by
  induction program generalizing initial with
  | done result => simp [mixedBranchClaims] at member
  | read raw next ih =>
      rcases branch with ⟨observed, branch⟩
      by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
      · simp only [mixedRun, dif_pos live]
        simp [mixedBranchClaims, live] at member
        rcases member with head | tail
        · cases head
          exact mixedRun_preserves_known ctx blockCap fixed encode decode
            (next (decode raw observed)) branch
            (physicalReadBranch ⟨encode raw, live⟩ observed initial)
            ⟨encode raw, live⟩ observed
            (by
              rw [SmzaRp05PhysicalTerminalRead.physical_read_branch_standard_view]
              exact SmzaRp05PhysicalAcceptedReplayLite.coordinate_event_projection_idempotent
                ⟨encode raw, live⟩ observed (globalDecompress initial))
        · exact ih (decode raw observed) branch
            (physicalReadBranch ⟨encode raw, live⟩ observed initial) tail
      · simp [mixedBranchClaims, live] at member
        by_cases fixedMatches : fixed ⟨encode raw, live⟩ = observed
        · simp only [mixedRun, dif_neg live, if_pos fixedMatches]
          exact ih (decode raw observed) branch initial member
        · simp only [mixedRun, dif_neg live, if_neg fixedMatches]
          exact ih (decode raw observed) branch 0 member

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentMixedBranchClaimReadback
