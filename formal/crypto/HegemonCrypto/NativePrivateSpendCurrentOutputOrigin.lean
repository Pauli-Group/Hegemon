import HegemonCrypto.NativePrivateSpendCurrentRoleTransport

/-! Actual non-Approval output origins and current HTLC owner transport.
Staged, uncompiled. Certificates are operation data; arbitrary source values
and their StructuralSemantics/Satisfies evidence remain separate. Ordinary
recipients are unrestricted seven-word digests, with no SingleKey preimage. -/
namespace HegemonCrypto.NativePrivateSpendCurrentOutputOrigin
open NativePrivateSpendCurrentRoleTransport NativePrivateSpendCurrentProtocolHistory
open NativePrivateSpendCurrentSixCaseSemantics NativePrivateSpendCurrentAcceptedHistory
open NativePrivateSpendCurrentEvaluatorIdentity NativePrivateSpendCurrentSpongeEvaluatorIdentity
open NativePrivateSpendCurrentSourceCallContract NativePrivateSpendRoleBridge
open NativePrivateSpendArithmeticTopology NativePrivateSpendPackedLowering
open NativePrivateSpendSymbolicBridge NativePrivateSpendSpongeBridge
open NativeLaunchConstraintAdapterBridge NativePrivateSpendLocalSemantics
open NativePrivateSpendCurrentRoleGames NativePrivateSpendCompffPrimitiveGames
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
noncomputable section
set_option autoImplicit false
variable [Fact (Nat.Prime modulus)]

/-- Exact existing source ranges for bytes32 words and timeout; no HTLC
message, digest or accepted-history equality is stored here. -/
structure HtlcFrameChecked (g : Graph K) (r : Roles) where
  chain : ∀ i : Fin 8, RangeData g (r.chain i) 32
  hashlock : ∀ i : Fin 8, RangeData g (r.hashlock i) 32
  timeout : RangeData g r.timeout 48

/-- Canonical current game input read from the same source assignment. The
narrow byte/timeout bounds are derived from the actual range operations. -/
def sourceHtlcInput (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (r : Roles) (checked : HtlcFrameChecked g r) :
    HtlcOwnerInput where
  chain := fun i => ⟨natural z (r.chain i),
    range_natural_bound g layout z sem (r.chain i) 32 (checked.chain i) (by norm_num [modulus])⟩
  hashlock := fun i => ⟨natural z (r.hashlock i),
    range_natural_bound g layout z sem (r.hashlock i) 32 (checked.hashlock i) (by norm_num [modulus])⟩
  claimAuthority := fun i => canonicalWord z (r.claimAuthority i)
  refundAuthority := fun i => canonicalWord z (r.refundAuthority i)
  claimRecipient := fun i => canonicalWord z (r.claimRecipient i)
  refundRecipient := fun i => canonicalWord z (r.refundRecipient i)
  timeout := ⟨natural z r.timeout,
    range_natural_bound g layout z sem r.timeout 48 checked.timeout (by norm_num [modulus])⟩
  key := fun i => canonicalWord z (r.htlcKey i)

theorem source_htlc_message (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (r : Roles) (checked : HtlcFrameChecked g r) :
    decoded z (NativePrivateSpendRoleBridge.htlcMessage r) =
      NativePrivateSpendCurrentRoleGames.htlcMessage
        (sourceHtlcInput g layout z sem r checked) := by
  simp only [decoded, NativePrivateSpendRoleBridge.htlcMessage,
    NativePrivateSpendCurrentRoleGames.htlcMessage, sourceHtlcInput,
    byteWords, canonicalDigestWords, NativePrivateSpendCurrentRoleGames.words,
    canonicalWord, natural, List.map_append, List.map_ofFn, List.map_cons, List.map_nil]
  rfl

theorem source_htlc_owner (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (r : Roles)
    (frame : HtlcFrameChecked g r) (calls : CallsChecked g r) :
    digestNaturals z r.htlcOwner =
      htlcOwner (sourceHtlcInput g layout z sem r frame) := by
  have policy := source_sponge_digest g layout z sem _ _ _ calls.htlcPolicy
    (by simp [NativePrivateSpendRoleBridge.htlcMessage]; norm_num [modulus])
  rw [source_htlc_message g layout z sem r frame] at policy
  have outer := source_compression_digest g layout z sem _ _ _ _ calls.htlcOwner
  rw [source_padded_key, policy] at outer
  have policyDomainExact : NativePrivateSpendRoleBridge.htlcPolicyDomain.val =
      NativePrivateSpendCurrentRoleGames.htlcPolicyDomain := by
    change (0x505348504f4c0001 : ZMod modulus).val = 0x505348504f4c0001
    exact ZMod.val_ofNat_of_lt (by decide : 0x505348504f4c0001 < modulus)
  have ownerDomainExact : NativePrivateSpendRoleBridge.htlcOwnerDomain.val =
      nativeHtlcOwnerDomain := by
    change (0x5053484f574e0001 : ZMod modulus).val = 0x5053484f574e0001
    exact ZMod.val_ofNat_of_lt (by decide : 0x5053484f574e0001 < modulus)
  simpa only [htlcOwner, policyDomainExact, ownerDomainExact, sourceHtlcInput] using outer

/-- Both ordinary wrappers use their actual unrestricted recipient words.
The HTLC ranges are source operation data; calls and routes are separate. -/
structure OutputOriginChecked (g : Graph K) (r : Roles) (v : RouteRoles) where
  recipient0 : DigestWords
  recipient1 : DigestWords
  ordinary0 : OrdinaryOutputChecked g recipient0 v.normal0Owner
  ordinary1 : OrdinaryOutputChecked g recipient1 v.normal1Owner
  htlcFrame : HtlcFrameChecked g r

/-- Output1 is always ordinary. For non-Approval output0, the actual Lock
selector chooses current HTLC; its zero branch chooses the ordinary wrapper. -/
theorem nonapproval_output_origins (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (r : Roles) (v : RouteRoles) (calls : CallsChecked g r)
    (routes : RouteChecked g r v) (checked : OutputOriginChecked g r v)
    (nonApproval : natural z (v.modes 1) ≠ 1) :
    ((natural z (v.modes 3) = 0 ∧
      digestNaturals z v.output0Owner = ordinaryRecipientOwner (digestNaturals z checked.recipient0)) ∨
     (natural z (v.modes 3) = 1 ∧
      digestNaturals z v.output0Owner = htlcOwner
        (sourceHtlcInput g layout z sem r checked.htlcFrame))) ∧
      digestNaturals z v.output1Owner = ordinaryRecipientOwner (digestNaturals z checked.recipient1) := by
  have equations := source_route_equations g layout z sem r v routes
  have ordinary0 := source_ordinary_output g layout z sem _ _ checked.ordinary0
  have ordinary1 := source_ordinary_output g layout z sem _ _ checked.ordinary1
  have output1 : digestNaturals z v.output1Owner = digestNaturals z v.normal1Owner := by
    apply congrArg List.ofFn
    funext lane
    exact congrArg ZMod.val (equations.normalOutput1 lane)
  have approvalZero : read z (v.modes 1) = 0 := by
    rcases boolean_sound g layout z sem _ (routes.selector.guards 1) with zero | one
    · exact zero
    · exfalso
      apply nonApproval
      simp only [natural, one, ZMod.val_one]
  refine ⟨?_, output1.trans ordinary1⟩
  rcases boolean_sound g layout z sem _ (routes.selector.guards 3) with zero | one
  · left
    have normalOne : read z v.normal = 1 := by
      simpa only [approvalZero, zero, sub_zero] using equations.normal
    have normalNat : natural z v.normal = 1 := by
      simpa only [natural, ZMod.val_one] using congrArg ZMod.val normalOne
    have output0 : digestNaturals z v.output0Owner = digestNaturals z v.normal0Owner := by
      apply congrArg List.ofFn
      funext lane
      exact congrArg ZMod.val
        (NativePrivateSpendHtlcRecipient.selected_gate g layout z sem _ _ _
          (routes.normalOutput0 lane) normalNat)
    exact ⟨by simpa only [natural, ZMod.val_zero] using congrArg ZMod.val zero,
      output0.trans ordinary0⟩
  · right
    have lockNat : natural z (v.modes 3) = 1 := by
      simpa only [natural, ZMod.val_one] using congrArg ZMod.val one
    have output0 : digestNaturals z v.output0Owner = digestNaturals z r.htlcOwner := by
      apply congrArg List.ofFn
      funext lane
      exact congrArg ZMod.val
        (NativePrivateSpendHtlcRecipient.selected_gate g layout z sem _ _ _
          (routes.lockOutput lane) lockNat)
    exact ⟨lockNat, output0.trans (source_htlc_owner g layout z sem r checked.htlcFrame calls)⟩

/-- The relation premise is discharged through the existing data-only CSR
certificate; output-origin conclusions are never fields of that certificate. -/
theorem relation_nonapproval_output_origins (relation : Current.Relation)
    (packed : Current.Values) (valid : Current.Satisfies relation packed)
    (g : Graph K) (layout : Layout K) (csr : NativePrivateSpendCsrCertificate.RawCSR K)
    (certificate : RelationCertificate relation g layout csr)
    (r : Roles) (v : RouteRoles) (calls : CallsChecked g r)
    (routes : RouteChecked g r v) (checked : OutputOriginChecked g r v)
    (nonApproval : natural (sourceAssignment packed) (v.modes 1) ≠ 1) :
    let z := sourceAssignment packed
    let sem := relation_derives_structural_semantics relation packed valid g layout csr certificate
    ((natural z (v.modes 3) = 0 ∧
      digestNaturals z v.output0Owner = ordinaryRecipientOwner (digestNaturals z checked.recipient0)) ∨
     (natural z (v.modes 3) = 1 ∧
      digestNaturals z v.output0Owner = htlcOwner
        (sourceHtlcInput g layout z sem r checked.htlcFrame))) ∧
      digestNaturals z v.output1Owner = ordinaryRecipientOwner (digestNaturals z checked.recipient1) := by
  exact nonapproval_output_origins g layout (sourceAssignment packed)
    (relation_derives_structural_semantics relation packed valid g layout csr certificate)
    r v calls routes checked nonApproval
end
end HegemonCrypto.NativePrivateSpendCurrentOutputOrigin
