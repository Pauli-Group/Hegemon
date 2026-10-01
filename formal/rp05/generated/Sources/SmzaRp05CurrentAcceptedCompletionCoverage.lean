import SmzaRp05CurrentAcceptedXViewRoleCoverage
import SmzaRp05CurrentClaimsXViewCompletion
import SmzaRp05CurrentPhysicalBranchClaimsConsistent
import SmzaRp05CurrentPhysicalNonchallengeClaims
import SmzaRp05CurrentNonchallengeRecordView

/-! # Accepted classification from an actual compressed branch

The full verifier classifier is applied to a same-view completion of the
actual physical branch database. Existence of that completion is derived
from same-branch recorded claims; only nonchallenge claims must already agree
with the measured X-view.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCompletionCoverage

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution (XKey xView)
open SmzaRp05CurrentSelectedChallengeClaims
  (nonchallengeRawKeySet nonchallenge_raw_key_set_unrecognized)
open SmzaRp05CurrentPhysicalNonchallengeClaims (branchNonchallengeClaims)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchClaims branchKeys branchAnswers branchResult physicalRun)
open SmzaRp05CurrentPhysicalBranchClaimsConsistent
  (nonzero_physical_branch_claims_consistent)
open SmzaRp05CurrentClaimsXViewCompletion (claims_completion_preserving_view)
open SmzaRp05CurrentAcceptedXViewRoleCoverage
  (currentAcceptedXViewRoleSelector accepted_grouped_failure_is_xview_selected_or_filtered_collision)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05CurrentNonchallengeRecordView
  (grouped_one_statement_view_eq_of_nonchallenge_key_agreement)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05LeafNamespace (Namespace)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp05FilteredReadback (globalLeafStatement)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 16000
set_option maxHeartbeats 1500000
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

local instance : DecidableEq RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

/-- On any nonzero actual branch, if every recorded nonchallenge claim is
present in its physical database, the accepted same-stage classifier yields
either its erased-record collision or a role selector on that same branch's
literal X-view. Full claims are obtained by completion from the actual
branch's transcript, and the completion preserves the supplied view. -/
theorem accepted_nonchallenge_consistent_branch_has_selector_or_collision
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest) (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
      branch = some ())
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (keyBytesExact : ∀ key, ctx.keyBytes key = groupRepresentative
      (included (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire) key))
    (initial : State (Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (Work (Counter := GroupCounter) (BaseWork := BaseWork)))
    (nonzero : normSquared (physicalRun (encode (producer.bind fun wire =>
      verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
      branch initial) ≠ 0)
    (database : Database (Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (nonchallengeClaims : ClaimsDatabaseEvent
      (branchNonchallengeClaims ctx.keyBytes
        (encode (producer.bind fun wire =>
          verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
        (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
        branch)
      database)
    (work : Work (Counter := GroupCounter) (BaseWork := BaseWork)) :
    ¬ SmzaRecordedTracePath.RecordsCollisionFree
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords (rawRecords
            (fun key => groupRepresentative (included
              (producer.bind fun wire =>
                verifierProgram ns currentDsl statement pending nonce wire) key))
            (vectorOutputBytes groupZero) database))) ∨
      ∃ role, currentAcceptedXViewRoleSelector producer ns statement pending nonce
        fallback typed parsed noPackedWitness fuel enough ctx keyBytesExact role branch
        (xView (nonchallengeRawKeySet ctx) database) work := by
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  let claims := branchClaims (branchKeys (encode actualProgram) groupedDecode
    actualProgram branch) (branchAnswers (encode actualProgram) groupedDecode
    actualProgram branch)
  let xKeys := nonchallengeRawKeySet ctx
  let view := xView xKeys database
  have consistent : ∃ completion : Database (Key actualProgram)
      (VectorOutput GroupCounter), ClaimsDatabaseEvent claims completion := by
    simpa only [actualProgram, claims] using
      nonzero_physical_branch_claims_consistent
        (encode actualProgram) groupedDecode actualProgram branch initial nonzero
  have viewClaims : ∀ claim ∈ claims, ∀ member : claim.1 ∈ xKeys,
      view ⟨claim.1, member⟩ = some claim.2 := by
    intro claim claimMember member
    have nonchallenge : claim ∈ branchNonchallengeClaims ctx.keyBytes
        (encode actualProgram) groupedDecode actualProgram branch := by
      unfold branchNonchallengeClaims
      apply List.mem_filter.mpr
      refine ⟨claimMember, ?_⟩
      have parsedNone := nonchallenge_raw_key_set_unrecognized ctx claim.1 member
      simp [parsedNone]
    calc
      view ⟨claim.1, member⟩ = database claim.1 := rfl
      _ = some claim.2 := nonchallengeClaims claim nonchallenge
  obtain ⟨completion, completionClaims, completionView⟩ :=
    claims_completion_preserving_view claims xKeys view consistent viewClaims
  have agreesOnX : ∀ key, parseStageQuery
      (groupRepresentative (included actualProgram key)) = none →
      completion key = database key := by
    intro key parsedNone
    have member : key ∈ xKeys := by
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_univ key, ?_⟩
      rw [keyBytesExact key]
      exact parsedNone
    calc
      completion key = view ⟨key, member⟩ := completionView key member
      _ = database key := rfl
  have classified := accepted_grouped_failure_is_xview_selected_or_filtered_collision
    producer ns statement pending nonce branch accepted completion completionClaims
    fallback typed parsed noPackedWitness fuel enough ctx keyBytesExact work
  rcases classified with collision | ⟨role, selected⟩
  · have recordsEq := grouped_one_statement_view_eq_of_nonchallenge_key_agreement
      actualProgram completion database agreesOnX (globalLeafStatement ns)
      statement.toBytes
    have collision' : ¬ SmzaRecordedTracePath.RecordsCollisionFree
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords (rawRecords
            (fun key => groupRepresentative (included actualProgram key))
            (vectorOutputBytes groupZero) completion))) := by
      simpa only [actualProgram] using collision
    exact Or.inl
      ((congrArg (fun records => ¬ SmzaRecordedTracePath.RecordsCollisionFree records)
        recordsEq).mp collision')
  · have sameView : xView xKeys completion = xView xKeys database := by
      funext key
      exact completionView key.val key.property
    rw [sameView] at selected
    exact Or.inr ⟨role, selected⟩

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCompletionCoverage
