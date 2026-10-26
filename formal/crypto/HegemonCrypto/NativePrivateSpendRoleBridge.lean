import HegemonCrypto.NativePrivateSpendSpongeBridge

/-! Ten concrete current-source calls for six exported roles. All assumptions
are graph/Word topology certificates; the field role equations are conclusions.
This is not yet the complete note/credential/Merkle/SHA/history theorem. -/
namespace HegemonCrypto.NativePrivateSpendRoleBridge
open NativePrivateSpendSymbolicBridge NativePrivateSpendSpongeBridge
open NativePrivateSpendPackedLowering NativePrivateSpendCsrCertificate
open NativePrivateSpendArithmeticTopology NativePrivateSpendLocalSemantics
open NativeLaunchConstraintAdapterBridge
noncomputable section
set_option autoImplicit false
variable [Fact (Nat.Prime modulus)]

abbrev Bits3 := Fin 3 → Word K

def zeros7 : DigestWords := fun _ => .constant 0

def paddedKey (key : Fin 5 → Word K) : DigestWords := fun i =>
  if h : i.val < 5 then key ⟨i.val,h⟩ else .constant 0

structure Roles where
  chain : Fin 8 → Word K
  tags : Fin 21 → Word K
  intent : Fin 54 → Word K
  treasuryKey : Fin 5 → Word K
  approved : Bits3
  signer : Bits3
  next : Bits3
  count : Word K
  nextCount : Word K
  hashlock : Fin 8 → Word K
  claimAuthority : DigestWords
  refundAuthority : DigestWords
  claimRecipient : Fin 4 → Word K
  refundRecipient : Fin 4 → Word K
  timeout : Word K
  htlcKey : Fin 5 → Word K
  policyRoot : DigestWords
  intentDigest : DigestWords
  accumulatorInner : DigestWords
  accumulator : DigestWords
  nextAccumulatorInner : DigestWords
  nextAccumulator : DigestWords
  valueInner : DigestWords
  valueOwner : DigestWords
  htlcPolicy : DigestWords
  htlcOwner : DigestWords

def policyDomain : K := 0x48415038504f4c01
def intentDomain : K := 0x5053494e544e0001
def accumulatorDomain : K := 0x5053414343550001
def bindDomain : K := 0x484d424456320001
def valueDomain : K := 0x48564c4b56320001
def htlcPolicyDomain : K := 0x505348504f4c0001
def htlcOwnerDomain : K := 0x5053484f574e0001

def policyMessage (r : Roles) : List (Word K) :=
  [.constant 2,.constant 3] ++ List.ofFn r.tags ++ List.replicate 21 (.constant 0)

def accumulatorMessage (r : Roles) (bits : Bits3) (count : Word K) : List (Word K) :=
  List.ofFn r.policyRoot ++ List.ofFn r.intentDigest ++ [.constant 2,.constant 3,count] ++
    List.ofFn bits ++ List.replicate 3 (.constant 0)

def htlcMessage (r : Roles) : List (Word K) :=
  List.ofFn r.chain ++ List.ofFn r.hashlock ++ List.ofFn r.claimAuthority ++
    List.ofFn r.refundAuthority ++ List.ofFn r.claimRecipient ++
    List.ofFn r.refundRecipient ++ [r.timeout]

theorem exact_message_lengths (r : Roles) :
    (policyMessage r).length = 44 ∧ (List.ofFn r.intent).length = 54 ∧
    (accumulatorMessage r r.approved r.count).length = 23 ∧
    (htlcMessage r).length = 39 := by
  simp [policyMessage, accumulatorMessage, htlcMessage]

structure ThreeSumChecked (g : Graph K) (bits : Bits3) (count : Word K) where
  subtotal : Fin 4 → Word K
  first : subtotal 0 = .constant 0
  step : ∀ i : Fin 3, AddData g (subtotal ⟨i.val,by omega⟩) (bits i)
    (subtotal ⟨i.val+1,by omega⟩)
  last : subtotal 3 = count

theorem three_sum_sound (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (bits : Bits3) (count : Word K)
    (checked : ThreeSumChecked g bits count) :
    read z count = (read z (bits 0) + read z (bits 1)) + read z (bits 2) := by
  have h0 := add_sound g layout z sem (checked.step 0)
  have h1 := add_sound g layout z sem (checked.step 1)
  have h2 := add_sound g layout z sem (checked.step 2)
  change read z (checked.subtotal 1) = read z (checked.subtotal 0) + read z (bits 0) at h0
  change read z (checked.subtotal 2) = read z (checked.subtotal 1) + read z (bits 1) at h1
  change read z (checked.subtotal 3) = read z (checked.subtotal 2) + read z (bits 2) at h2
  rw [←checked.last, h2, h1, h0, checked.first]
  simp only [NativeLaunchConstraintAdapterBridge.read, zero_add]

/-- These are finite operation/frame/locator data, not role-output equations. -/
structure CallsChecked (g : Graph K) (r : Roles) where
  nextAdd : ∀ i : Fin 3, AddData g (r.approved i) (r.signer i) (r.next i)
  count : ThreeSumChecked g r.approved r.count
  nextCount : ThreeSumChecked g r.next r.nextCount
  policy : SpongeChecked g policyDomain (policyMessage r) r.policyRoot
  intent : SpongeChecked g intentDomain (List.ofFn r.intent) r.intentDigest
  accumulatorInner : SpongeChecked g accumulatorDomain
    (accumulatorMessage r r.approved r.count) r.accumulatorInner
  accumulator : CompressChecked g bindDomain (paddedKey r.treasuryKey) r.accumulatorInner r.accumulator
  nextAccumulatorInner : SpongeChecked g accumulatorDomain
    (accumulatorMessage r r.next r.nextCount) r.nextAccumulatorInner
  nextAccumulator : CompressChecked g bindDomain (paddedKey r.treasuryKey)
    r.nextAccumulatorInner r.nextAccumulator
  valueInner : CompressChecked g valueDomain r.policyRoot zeros7 r.valueInner
  valueOwner : CompressChecked g bindDomain (paddedKey r.treasuryKey) r.valueInner r.valueOwner
  htlcPolicy : SpongeChecked g htlcPolicyDomain (htlcMessage r) r.htlcPolicy
  htlcOwner : CompressChecked g htlcOwnerDomain (paddedKey r.htlcKey) r.htlcPolicy r.htlcOwner

def SpongeEquation (z : Nat → K) (domain : K) (message : List (Word K))
    (role : DigestWords) : Prop :=
  ∀ lane : Fin 7, read z (role lane) = (spongeNaturals z domain message |>.getD lane.val 0 : K)

def CompressEquation (z : Nat → K) (domain : K) (left right role : DigestWords) : Prop :=
  ∀ lane : Fin 7, read z (role lane) =
    (Kernel.permutation (stateNaturals z (compressFrame domain left right)) |>.getD lane.val 0 : K) +
      read z (left lane)

/-- Semantic conclusion for all ten calls and the three approval-bit additions.
All calls share exactly this z and these role locators, so intermediates cannot
be replaced by unrelated values from a different proof or outcome. -/
structure RoleEquations (z : Nat → K) (r : Roles) : Prop where
  nextAdd : ∀ i : Fin 3, read z (r.next i) = read z (r.approved i) + read z (r.signer i)
  count : read z r.count = (read z (r.approved 0) + read z (r.approved 1)) + read z (r.approved 2)
  nextCount : read z r.nextCount = (read z (r.next 0) + read z (r.next 1)) + read z (r.next 2)
  policy : SpongeEquation z policyDomain (policyMessage r) r.policyRoot
  intent : SpongeEquation z intentDomain (List.ofFn r.intent) r.intentDigest
  accumulatorInner : SpongeEquation z accumulatorDomain
    (accumulatorMessage r r.approved r.count) r.accumulatorInner
  accumulator : CompressEquation z bindDomain (paddedKey r.treasuryKey) r.accumulatorInner r.accumulator
  nextAccumulatorInner : SpongeEquation z accumulatorDomain
    (accumulatorMessage r r.next r.nextCount) r.nextAccumulatorInner
  nextAccumulator : CompressEquation z bindDomain (paddedKey r.treasuryKey)
    r.nextAccumulatorInner r.nextAccumulator
  valueInner : CompressEquation z valueDomain r.policyRoot zeros7 r.valueInner
  valueOwner : CompressEquation z bindDomain (paddedKey r.treasuryKey) r.valueInner r.valueOwner
  htlcPolicy : SpongeEquation z htlcPolicyDomain (htlcMessage r) r.htlcPolicy
  htlcOwner : CompressEquation z htlcOwnerDomain (paddedKey r.htlcKey) r.htlcPolicy r.htlcOwner

theorem packed_role_equations (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (data : CitationData g layout csr) (coverage : Covers g layout) (z : Nat → K)
    (linear : RawSatisfied csr z)
    (products : ∀ batch lane, Products.productResidual (occurrence layout z batch lane) = 0)
    (r : Roles) (checked : CallsChecked g r) : RoleEquations z r := by
  have sem := citation_data_structural g layout csr data coverage z linear products
  refine {
    nextAdd := fun i => add_sound g layout z sem (checked.nextAdd i)
    count := three_sum_sound g layout z sem _ _ checked.count
    nextCount := three_sum_sound g layout z sem _ _ checked.nextCount
    policy := ?_, intent := ?_, accumulatorInner := ?_, accumulator := ?_
    nextAccumulatorInner := ?_, nextAccumulator := ?_, valueInner := ?_, valueOwner := ?_
    htlcPolicy := ?_, htlcOwner := ?_ }
  · exact fun lane => packed_sponge_role g layout csr data coverage z linear products _ _ _ checked.policy lane
  · exact fun lane => packed_sponge_role g layout csr data coverage z linear products _ _ _ checked.intent lane
  · exact fun lane => packed_sponge_role g layout csr data coverage z linear products _ _ _ checked.accumulatorInner lane
  · exact fun lane => packed_compress_role g layout csr data coverage z linear products _ _ _ _ checked.accumulator lane
  · exact fun lane => packed_sponge_role g layout csr data coverage z linear products _ _ _ checked.nextAccumulatorInner lane
  · exact fun lane => packed_compress_role g layout csr data coverage z linear products _ _ _ _ checked.nextAccumulator lane
  · exact fun lane => packed_compress_role g layout csr data coverage z linear products _ _ _ _ checked.valueInner lane
  · exact fun lane => packed_compress_role g layout csr data coverage z linear products _ _ _ _ checked.valueOwner lane
  · exact fun lane => packed_sponge_role g layout csr data coverage z linear products _ _ _ checked.htlcPolicy lane
  · exact fun lane => packed_compress_role g layout csr data coverage z linear products _ _ _ _ checked.htlcOwner lane

end
end HegemonCrypto.NativePrivateSpendRoleBridge
