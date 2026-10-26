import HegemonCrypto.NativePrivateSpendG1SourceComposition

namespace HegemonCrypto.NativePrivateSpendSelectedNullifier
open NativePrivateSpendG1SourceComposition NativePrivateSpendCurrentSourceCallContract
open NativePrivateSpendRoleBridge NativePrivateSpendSpongeBridge NativePrivateSpendSymbolicBridge
open NativePrivateSpendArithmeticTopology NativePrivateSpendPackedLowering
open NativePrivateSpendCsrCertificate NativePrivateSpendLocalSemantics NativeLaunchConstraintAdapterBridge
noncomputable section
variable [Fact (Nat.Prime modulus)]

/-- Rust select(bit,a,b) = a + bit*(b-a), with actual ordered operations. -/
structure SelectData (g : Graph K) (bit a b out : Word K) where
  difference : Word K
  product : Word K
  subtract : SubData g b a difference
  multiply : MulData g bit difference product
  add : AddData g a product out

theorem select_sound (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (bit a b out : Word K)
    (c : SelectData g bit a b out) :
    read z out = read z a + read z bit * (read z b - read z a) := by
  rw [add_sound g layout z sem c.add, mul_sound g layout z sem c.multiply,
    sub_sound g layout z sem c.subtract]

/-- w is the compiler-bound input-slot lookup, not canonical wire index identity. -/
def occupied (w : Nat → Word K) (slot : Fin 2) := w (83 + 255*slot.val)
def legacy (w : Nat → Word K) (slot : Fin 2) := w (84 + 255*slot.val)
def key (w : Nat → Word K) (slot : Fin 2) (i : Fin 5) := w (328 + 255*slot.val+i.val)
def dummyKey (w : Nat → Word K) (slot : Fin 2) (i : Fin 5) := w (333 + 255*slot.val+i.val)
def position (w : Nat → Word K) (slot : Fin 2) := w (103 + 255*slot.val)
def rho (w : Nat → Word K) (slot : Fin 2) (i : Fin 4) := w (91 + 255*slot.val+i.val)
def owner (w : Nat → Word K) (slot : Fin 2) (i : Fin 7) :=
  w (85 + 255*slot.val + if i.val<4 then 14+i.val else 6+i.val)

structure CredentialData (g : Graph K) (ord policy hashUse : Word K)
    (ordinary treasury htlc selected : Fin 5 → Word K) where
  ordProduct : Fin 5 → Word K
  policyProduct : Fin 5 → Word K
  hashProduct : Fin 5 → Word K
  firstSum : Fin 5 → Word K
  ordMul : ∀ i, MulData g ord (ordinary i) (ordProduct i)
  policyMul : ∀ i, MulData g policy (treasury i) (policyProduct i)
  hashMul : ∀ i, MulData g hashUse (htlc i) (hashProduct i)
  addFirst : ∀ i, AddData g (ordProduct i) (policyProduct i) (firstSum i)
  addLast : ∀ i, AddData g (firstSum i) (hashProduct i) (selected i)

theorem credential_sound (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (ord policy hashUse : Word K)
    (ordinary treasury htlc selected : Fin 5 → Word K)
    (c : CredentialData g ord policy hashUse ordinary treasury htlc selected) (i : Fin 5) :
    read z (selected i) = read z ord * read z (ordinary i) +
      read z policy * read z (treasury i) + read z hashUse * read z (htlc i) := by
  rw [add_sound g layout z sem (c.addLast i), add_sound g layout z sem (c.addFirst i),
    mul_sound g layout z sem (c.ordMul i), mul_sound g layout z sem (c.policyMul i),
    mul_sound g layout z sem (c.hashMul i)]

structure NullifierChecked (g : Graph K) (w : Nat → Word K) (slot : Fin 2)
    (r : Roles) (ord policy hashUse : Word K) where
  selectedKey : Fin 5 → Word K
  realDigest : DigestWords
  dummyDigest : DigestWords
  selectedDigest : DigestWords
  credential : CredentialData g ord policy hashUse (key w slot) r.treasuryKey r.htlcKey selectedKey
  realCall : SpongeChecked g (0x484e554c56320001 : K)
    (List.ofFn selectedKey ++ [.constant 0,.constant 0,position w slot] ++ List.ofFn (rho w slot)) realDigest
  dummyCall : SpongeChecked g (0x5053444e554c0001 : K)
    (List.ofFn r.chain ++ List.ofFn (dummyKey w slot)) dummyDigest
  occupiedBoolean : BooleanData g (occupied w slot)
  select : ∀ i, SelectData g (occupied w slot) (dummyDigest i) (realDigest i) (selectedDigest i)
  publicGate : ∀ i : Fin 7, GateData g (.constant 1) (selectedDigest i)
    (.wire (25 + 7*slot.val+i.val))

/-- Both branches are computed. Public NF chooses real at occupied=1 and dummy
at occupied=0, with full7 limbs and the SAME current public vector. -/
theorem selected_nullifier (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (binding : g.publicBindings = NativePrivateSpendCsrCertificate.public77 pub)
    (w : Nat → Word K) (slot : Fin 2) (r : Roles) (ord policy hashUse : Word K)
    (c : NullifierChecked g w slot r ord policy hashUse) :
    SpongeEquation z (0x484e554c56320001 : K)
      (List.ofFn c.selectedKey ++ [.constant 0,.constant 0,position w slot] ++ List.ofFn (rho w slot)) c.realDigest ∧
    SpongeEquation z (0x5053444e554c0001 : K)
      (List.ofFn r.chain ++ List.ofFn (dummyKey w slot)) c.dummyDigest ∧
    (read z (occupied w slot)=0 ∨ read z (occupied w slot)=1) ∧
    (∀ i : Fin 7, pub ⟨25+7*slot.val+i.val,by omega⟩ =
      read z (c.dummyDigest i) + read z (occupied w slot) *
        (read z (c.realDigest i)-read z (c.dummyDigest i))) := by
  refine ⟨source_sponge g layout z sem _ _ _ c.realCall,
    source_sponge g layout z sem _ _ _ c.dummyCall,
    boolean_sound g layout z sem _ c.occupiedBoolean, ?_⟩
  intro i
  have chosen := select_sound g layout z sem _ _ _ _ (c.select i)
  have gate := gate_equation g layout z sem _ _ _ (c.publicGate i)
  have eq : read z (c.selectedDigest i) = z (25+7*slot.val+i.val) := by
    simpa only [NativeLaunchConstraintAdapterBridge.read,one_mul,sub_eq_zero] using gate
  have publicLane := certified_public77 g layout z sem pub binding ⟨25+7*slot.val+i.val,by omega⟩
  exact publicLane.symm.trans (eq.symm.trans chosen)

structure OwnerChecked (g : Graph K) (w : Nat → Word K) (slot : Fin 2)
    (ordActive : Word K) where
  who : DigestWords
  fresh : DigestWords
  chosen : DigestWords
  single : SpongeChecked g (0x48534b4156320001 : K)
    (List.ofFn (key w slot) ++ [.constant 0,.constant 0]) who
  ordinary : SpongeChecked g (0x50534f574e520001 : K) (List.ofFn who) fresh
  select : ∀ i, SelectData g (legacy w slot) (fresh i) (who i) (chosen i)
  legacyBoolean : BooleanData g (legacy w slot)
  ownerGate : ∀ i, GateData g ordActive (owner w slot i) (chosen i)

theorem owner_meaning (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (w : Nat → Word K) (slot : Fin 2)
    (ordActive : Word K) (c : OwnerChecked g w slot ordActive) :
    SpongeEquation z (0x48534b4156320001 : K)
      (List.ofFn (key w slot) ++ [.constant 0,.constant 0]) c.who ∧
    SpongeEquation z (0x50534f574e520001 : K) (List.ofFn c.who) c.fresh ∧
    (∀ i, read z ordActive * (read z (owner w slot i) -
      (read z (c.fresh i) + read z (legacy w slot) *
        (read z (c.who i)-read z (c.fresh i)))) = 0) := by
  refine ⟨source_sponge g layout z sem _ _ _ c.single,
    source_sponge g layout z sem _ _ _ c.ordinary, ?_⟩
  intro i
  have h := gate_equation g layout z sem _ _ _ (c.ownerGate i)
  rw [select_sound g layout z sem _ _ _ _ (c.select i)] at h
  exact h
end
end HegemonCrypto.NativePrivateSpendSelectedNullifier
