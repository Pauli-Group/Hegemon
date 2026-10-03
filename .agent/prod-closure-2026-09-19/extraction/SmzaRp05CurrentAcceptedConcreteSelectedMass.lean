import SmzaRp05CurrentAcceptedSelectorWitnessClaims
import SmzaRp05CurrentAcceptedSelectedFiberMass
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05OrdinarySoundnessExecution

/-! # Concrete accepted-selector mass on current grouped contexts

This specializes the selector-to-claims bridge and the exact selected-fiber
mass identity to the actual current grouped key embedding.  Role contexts
share their raw key bytes by construction; no context-equality premise or
probability premise is introduced.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedConcreteSelectedMass

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaChallengeStageTargets (Role)
open SmzaRoleDomainConditioning
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution
  (FixedTable XKey xView fixedFiberToActive otherRoleTransform
    fixedOtherKeys mem_fixed_other_keys)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05CurrentAcceptedSelectorWitnessClaims
open SmzaRp05CurrentAcceptedSelectorProjectionTransport
open SmzaRp05CurrentAcceptedSelectedFiberMass
open SmzaRp05CurrentSelectedChallengeClaims
  (nonchallengeRawKeySet nonchallenge_raw_key_set_unrecognized
    unrecognizedActiveBranchClaims)
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05CurrentGroupedContext
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentAcceptedXViewRoleCoverage (currentAcceptedXViewRoleSelector)
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 16000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

private def actualVerifierProgram
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) : Program Unit :=
  producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire

/-- For any one of the four roles, the literal accepted selector derived from
the current grouped context has exactly the selected X-view mass covered by
the ordinary fixed-fiber sum.  The remaining theorem inputs are only the
ordinary execution budget/context data, not a selector-probability premise. -/
theorem current_grouped_accepted_selector_mass_le_selected_fibers
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked
        (encodePublicStatement typed) packed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (role : Role)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix
      (Key := Key (actualVerifierProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork)
      (cap := cap) 0 finish queries)
    (registers : RegisterBasis
      (Input := Key (actualVerifierProgram producer ns statement pending nonce))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (blockCap : Role → Nat)
    (dummy : ActiveKey
      (currentGroupedContext (actualVerifierProgram producer ns statement pending nonce)
        model bounded ns role (advice role) outerFuel innerFuel (fun _ => ∅)).role
      blockCap
      (currentGroupedContext (actualVerifierProgram producer ns statement pending nonce)
        model bounded ns role (advice role) outerFuel innerFuel (fun _ => ∅)).keyBytes) :
    let actualProgram := actualVerifierProgram producer ns statement pending nonce
    let ctx := currentGroupedContext actualProgram model bounded ns role (advice role)
      outerFuel innerFuel (fun _ => ∅)
    let select : Branches groupedDecode actualProgram →
      (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter)) →
      Work (Counter := GroupCounter) (BaseWork := BaseWork) → Prop :=
      fun branch view work => currentAcceptedXViewRoleSelector producer ns statement
        pending nonce fallback typed parsed noPackedWitness fuel enough ctx
        (by intro key; rfl) role branch view work
    letI := physicalBranchesFintype groupedDecode actualProgram
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    (∑ branch : Branches groupedDecode actualProgram,
      normSquared (workspaceEventProjection
        (fun work database => select branch
          (xView (nonchallengeRawKeySet ctx) database) work)
        (physicalRun (encode actualProgram) groupedDecode actualProgram branch initial))) ≤
    (∑ branch : Branches groupedDecode actualProgram,
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (selectedRoleState ctx blockCap (encode actualProgram)
          groupedDecode actualProgram branch fixed
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap initial))
          (select branch))) := by
  classical
  let actualProgram := actualVerifierProgram producer ns statement pending nonce
  let ctx := currentGroupedContext (BaseWork := BaseWork)
    actualProgram model bounded ns role (advice role)
    outerFuel innerFuel (fun _ => ∅)
  let select : Branches groupedDecode actualProgram →
      (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter)) →
      Work (Counter := GroupCounter) (BaseWork := BaseWork) → Prop :=
    fun branch view work => currentAcceptedXViewRoleSelector producer ns statement
      pending nonce fallback typed parsed noPackedWitness fuel enough ctx
      (by intro key; rfl) role branch view work
  have claimAgreement : ∀ branch view work, select branch view work →
      ∀ claim (member : claim ∈ unrecognizedActiveBranchClaims ctx blockCap
        (encode actualProgram) groupedDecode actualProgram branch),
        view ⟨claim.1.val,
          by
            apply Finset.mem_filter.mpr
            exact ⟨Finset.mem_univ _, of_decide_eq_true
              (List.mem_filter.mp member).2⟩⟩ = some claim.2 := by
    intro branch view work selected
    exact current_accepted_selector_supplies_unrecognized_claims
      producer ns statement pending nonce fallback typed parsed noPackedWitness fuel enough
      ctx blockCap (by intro key; rfl) role branch view work selected
  have outside : ∀ key, key ∈ fixedOtherKeys ctx blockCap →
      key ∉ nonchallengeRawKeySet ctx := by
    intro key fixedMember nonchallengeMember
    have parsedNone := nonchallenge_raw_key_set_unrecognized ctx key nonchallengeMember
    have fixedOther := (mem_fixed_other_keys ctx blockCap key).mp fixedMember
    exact fixedOther (by simp [RoleActive, parsedNone])
  simpa only [actualProgram, ctx, select] using
    accepted_xview_selector_mass_le_ordinary_selected_fiber_mass ctx
      ordinaryProgram registers (encode actualProgram) groupedDecode actualProgram
      blockCap dummy select claimAgreement outside

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedConcreteSelectedMass
