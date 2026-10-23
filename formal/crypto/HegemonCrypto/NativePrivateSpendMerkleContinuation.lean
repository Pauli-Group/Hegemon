import HegemonCrypto.NativePrivateSpendSelectedNullifier

namespace HegemonCrypto.NativePrivateSpendMerkleContinuation
open NativePrivateSpendSelectedNullifier NativePrivateSpendG1SourceComposition
open NativePrivateSpendCurrentSourceCallContract NativePrivateSpendRoleBridge
open NativePrivateSpendSymbolicBridge NativePrivateSpendSpongeBridge
open NativePrivateSpendPackedLowering NativePrivateSpendArithmeticTopology
open NativePrivateSpendCsrCertificate NativePrivateSpendLocalSemantics NativeLaunchConstraintAdapterBridge
noncomputable section
variable [Fact (Nat.Prime modulus)]

def noteWords (w : Nat → Word K) (slot : Fin 2) (i : Fin 18) :=
  w (85 + 255*slot.val + i.val)
def siblingWords (w : Nat → Word K) (slot : Fin 2) (level : Fin 32) (lane : Fin 7) :=
  w (104 + 255*slot.val + 7*level.val + lane.val)

structure MerkleChecked (g : Graph K) (w : Nat → Word K) (slot : Fin 2) where
  states : Fin 33 → DigestWords
  left : Fin 32 → DigestWords
  right : Fin 32 → DigestWords
  positionRange : RangeData g (position w slot) 32
  noteCall : SpongeChecked g (1 : K) (List.ofFn (noteWords w slot)) (states 0)
  leftSelect : ∀ level lane, SelectData g (.wire (positionRange.bits level).val)
    (states ⟨level.val,by omega⟩ lane) (siblingWords w slot level lane) (left level lane)
  rightSelect : ∀ level lane, SelectData g (.wire (positionRange.bits level).val)
    (siblingWords w slot level lane) (states ⟨level.val,by omega⟩ lane) (right level lane)
  compress : ∀ level, CompressChecked g (4 : K) (left level) (right level)
    (states ⟨level.val+1,by omega⟩)
  rootGate : ∀ lane : Fin 7, GateData g (occupied w slot) (states 32 lane) (.wire (17+lane.val))

/-- Each link records derived select equations and the pinned kernel compression.
No step/result callback is supplied to the source certificate. -/
def Link (z : Nat → K) (bit : Word K) (before sibling left right after : DigestWords) : Prop :=
  (read z bit = 0 ∨ read z bit = 1) ∧
  (∀ lane, read z (left lane) = read z (before lane) + read z bit *
    (read z (sibling lane)-read z (before lane))) ∧
  (∀ lane, read z (right lane) = read z (sibling lane) + read z bit *
    (read z (before lane)-read z (sibling lane))) ∧
  CompressEquation z (4 : K) left right after

inductive Path (z : Nat → K) : Nat → DigestWords → DigestWords → Prop
  | nil (state : DigestWords) : Path z 0 state state
  | snoc {n : Nat} {first before after sibling left right : DigestWords} {bit : Word K}
      (segment : Path z n first before) (link : Link z bit before sibling left right after) :
      Path z (n+1) first after

theorem merkle_link (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (w : Nat → Word K) (slot : Fin 2)
    (c : MerkleChecked g w slot) (level : Fin 32) :
    Link z (.wire (c.positionRange.bits level).val)
      (c.states ⟨level.val,by omega⟩) (siblingWords w slot level)
      (c.left level) (c.right level) (c.states ⟨level.val+1,by omega⟩) := by
  exact ⟨boolean_sound g layout z sem _ (c.positionRange.guards level),
    fun lane => select_sound g layout z sem _ _ _ _ (c.leftSelect level lane),
    fun lane => select_sound g layout z sem _ _ _ _ (c.rightSelect level lane),
    source_compress g layout z sem _ _ _ _ (c.compress level)⟩

theorem merkle_prefix (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (w : Nat → Word K) (slot : Fin 2)
    (c : MerkleChecked g w slot) (n : Nat) (bound : n ≤ 32) :
    Path z n (c.states 0) (c.states ⟨n,by omega⟩) := by
  induction n with
  | zero => exact .nil _
  | succ n ih =>
    exact .snoc (ih (by omega)) (merkle_link g layout z sem w slot c ⟨n,by omega⟩)

theorem occupied_merkle_root (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (publicBinding : g.publicBindings = NativePrivateSpendCsrCertificate.public77 pub)
    (w : Nat → Word K) (slot : Fin 2) (c : MerkleChecked g w slot) :
    SpongeEquation z (1 : K) (List.ofFn (noteWords w slot)) (c.states 0) ∧
    Path z 32 (c.states 0) (c.states 32) ∧
    natural z (position w slot) < 2^32 ∧
    (∀ lane : Fin 7, read z (occupied w slot) *
      (read z (c.states 32 lane)-pub ⟨17+lane.val,by omega⟩)=0) := by
  refine ⟨source_sponge g layout z sem _ _ _ c.noteCall,
    merkle_prefix g layout z sem w slot c 32 (by omega),
    range_natural_bound g layout z sem _ 32 c.positionRange (by norm_num [modulus]), ?_⟩
  intro lane
  have gate := gate_equation g layout z sem _ _ _ (c.rootGate lane)
  have publicLane := certified_public77 g layout z sem pub publicBinding ⟨17+lane.val,by omega⟩
  simpa only [NativeLaunchConstraintAdapterBridge.read,publicLane] using gate

/-- The direction bits above recompose the SAME source position Word. -/
theorem direction_position_binding (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (w : Nat → Word K) (slot : Fin 2)
    (c : MerkleChecked g w slot) :
    read z (position w slot) =
      (recompose (rangeBits g z (position w slot) 32 c.positionRange) 32 : K) := by
  have h := sem.equalities _ _ c.positionRange.finish
  rw [range_prefix g layout z sem _ 32 c.positionRange 32 (by omega)] at h
  exact h

/-- Both source slots reuse the identical graph, assignment and public77. -/
theorem both_input_roots (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (publicBinding : g.publicBindings = NativePrivateSpendCsrCertificate.public77 pub)
    (w : Nat → Word K) (checked : ∀ slot : Fin 2, MerkleChecked g w slot) :
    ∀ slot : Fin 2, Path z 32 ((checked slot).states 0) ((checked slot).states 32) :=
  fun slot => (occupied_merkle_root g layout z sem pub publicBinding w slot (checked slot)).2.1
end
end HegemonCrypto.NativePrivateSpendMerkleContinuation
