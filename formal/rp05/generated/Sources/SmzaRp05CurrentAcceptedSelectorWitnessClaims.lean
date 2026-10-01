import SmzaRp05CurrentAcceptedSelectorClaims
import SmzaRp05CurrentAcceptedXViewRoleCoverage

/-! # The accepted selector's actual transcript fixes its unrecognized claims

The selector witness contains both the exact branch-claim database and its
agreement with the supplied nonchallenge view.  This derives, rather than
assumes, the claim-consistency premise needed by the selector projection
transport.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSelectorWitnessClaims

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsOracleDatabaseBridge
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRoleDomainConditioning
open SmzaRp05ConditionedExecution (XKey)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentSelectedChallengeClaims
open SmzaRp05CurrentAcceptedXViewRoleCoverage
open SmzaRp05CurrentAcceptedSelectorClaims
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- For the exact accepted selector witness, every unrecognized active
branch claim agrees with its key in the selected nonchallenge X-view. -/
theorem current_accepted_selector_supplies_unrecognized_claims
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : SmzaRp05CurrentPublicStatementTransport.parseCurrentPublicStatement?
      statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked
        (encodePublicStatement typed) packed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (keyBytesExact : ∀ key, ctx.keyBytes key = groupRepresentative
      (included (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire) key))
    (role : Role)
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (view : XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter))
    (work : Work (Counter := GroupCounter) (BaseWork := BaseWork))
    (selected : currentAcceptedXViewRoleSelector producer ns statement pending nonce
      fallback typed parsed noPackedWitness fuel enough ctx keyBytesExact role branch
      view work) :
    ∀ claim (member : claim ∈ unrecognizedActiveBranchClaims ctx blockCap
      (encode (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
      branch),
      view ⟨claim.1.val,
        by
          apply Finset.mem_filter.mpr
          exact ⟨Finset.mem_univ _, of_decide_eq_true
            (List.mem_filter.mp member).2⟩⟩ = some claim.2 := by
  dsimp only [currentAcceptedXViewRoleSelector] at selected
  rcases selected with ⟨database, viewMatches, recordedClaims, _collisionFree, _evidence⟩
  intro claim member
  have branchMember := unrecognized_active_claim_mem_branch_claims
    ctx blockCap
    (encode (producer.bind fun wire =>
      verifierProgram ns currentDsl statement pending nonce wire))
    groupedDecode
    (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
    branch claim member
  have claimValue := recordedClaims (claim.1.val, claim.2) branchMember
  have keyMember : claim.1.val ∈ nonchallengeRawKeySet ctx := by
    apply Finset.mem_filter.mpr
    exact ⟨Finset.mem_univ _, of_decide_eq_true
      (List.mem_filter.mp member).2⟩
  exact (viewMatches claim.1.val keyMember).symm.trans claimValue

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSelectorWitnessClaims
