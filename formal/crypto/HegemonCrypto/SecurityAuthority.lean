/-!
# Formal-crypto security-claim authority

The research package proves claims at several deliberately non-production scopes.
This indexed certificate type makes that scope part of theorem types. There is no
constructor for `deployedEndToEnd`: adding one requires an explicit source change
rather than relabeling an ideal-model or caller-supplied theorem.
-/

namespace HegemonCrypto.SecurityAuthority

/-- Authority carried by an exported formal-crypto security claim. -/
inductive SecurityClaimScope where
  | idealLogicalQrom
  | callerSuppliedVerifier
  | conditionalSupply
  | deployedEndToEnd
deriving DecidableEq, Repr

/--
Kernel-checked claim tagged with its actual assurance scope. The absence of a
`deployedEndToEnd` constructor is intentional.
-/
inductive ScopedSecurityClaim : SecurityClaimScope → Prop → Prop where
  | ofIdealLogicalQrom {claim : Prop} :
      claim → ScopedSecurityClaim .idealLogicalQrom claim
  | ofCallerSuppliedVerifier {claim : Prop} :
      claim → ScopedSecurityClaim .callerSuppliedVerifier claim
  | ofConditionalSupply {claim : Prop} :
      claim → ScopedSecurityClaim .conditionalSupply claim

/-- Recover the proposition for internal composition; this does not mint a different scoped claim. -/
theorem ScopedSecurityClaim.holds
    {scope : SecurityClaimScope}
    {claim : Prop}
    (certificate : ScopedSecurityClaim scope claim) : claim := by
  cases certificate with
  | ofIdealLogicalQrom proof => exact proof
  | ofCallerSuppliedVerifier proof => exact proof
  | ofConditionalSupply proof => exact proof

/-- The public certificate API intentionally cannot construct deployed end-to-end authority. -/
theorem deployed_end_to_end_scope_has_no_constructor
    {claim : Prop} :
    ScopedSecurityClaim .deployedEndToEnd claim → False := by
  intro certificate
  cases certificate

end HegemonCrypto.SecurityAuthority
