import HegemonCrypto.NativePrivateSpendCurrentRoleTransport
import HegemonCrypto.SmallWoodMerkleExtraction

/-! The current graph path is an ordinary opening of the actual NOTE sponge
and COMPFF Merkle compressor. No historical raw-compression path is reused.
All direction and hash equations below are conclusions from source graph
operations; no OpensAt or leaf-origin premise is supplied. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentMerklePath
open NativePrivateSpendCurrentSixCaseSemantics NativePrivateSpendCurrentRoleTransport
open NativePrivateSpendCurrentEvaluatorIdentity NativePrivateSpendMerkleContinuation
open NativePrivateSpendCurrentSpongeEvaluatorIdentity NativePrivateSpendSymbolicBridge
open NativePrivateSpendPackedLowering NativePrivateSpendArithmeticTopology
open NativePrivateSpendLocalSemantics NativeLaunchConstraintAdapterBridge
open NativePrivateSpendSelectedNullifier NativePrivateSpendSpongeBridge
open HegemonCrypto.SmallWood.MerkleExtraction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
noncomputable section
variable [Fact (Nat.Prime modulus)]

def currentPathHash : HashInput (List Nat) Digest → Digest
  | .leaf payload => poseidon2V8Sponge 1 payload
  | .node left right => P.compress14 4 left right

def sourceLeaf (z : Nat → K) (w : Nat → Word K) (slot : Fin 2) : List Nat :=
  decoded z (List.ofFn (noteWords w slot))

def sourceStep (g : Graph K) (z : Nat → K) (w : Nat → Word K)
    (slot : Fin 2) (checked : MerkleChecked g w slot) (level : Fin 32) :
    AuthenticationStep Digest :=
  ⟨digestNaturals z (siblingWords w slot level),
    if read z (.wire (checked.positionRange.bits level).val) = 0 then .left else .right⟩

/-- Root-first order: the most recently evaluated graph compression is the
head, while the recursive tail denotes its actual child prefix. -/
def sourcePath (g : Graph K) (z : Nat → K) (w : Nat → Word K)
    (slot : Fin 2) (checked : MerkleChecked g w slot) :
    (count : Nat) → count ≤ 32 → AuthenticationPath Digest
  | 0, _ => []
  | count + 1, bound => sourceStep g z w slot checked ⟨count, by omega⟩ ::
      sourcePath g z w slot checked count (by omega)

theorem source_step_children (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (w : Nat → Word K) (slot : Fin 2)
    (checked : MerkleChecked g w slot) (level : Fin 32) :
    (read z (.wire (checked.positionRange.bits level).val) = 0 ∧
      digestNaturals z (checked.left level) = digestNaturals z (checked.states ⟨level.val, by omega⟩) ∧
      digestNaturals z (checked.right level) = digestNaturals z (siblingWords w slot level)) ∨
    (read z (.wire (checked.positionRange.bits level).val) = 1 ∧
      digestNaturals z (checked.left level) = digestNaturals z (siblingWords w slot level) ∧
      digestNaturals z (checked.right level) = digestNaturals z (checked.states ⟨level.val, by omega⟩)) := by
  have link := merkle_link g layout z sem w slot checked level
  rcases link.1 with zero | one
  · refine Or.inl ⟨zero, ?_, ?_⟩
    · apply congrArg List.ofFn
      funext lane
      have left := link.2.1 lane
      rw [zero, zero_mul, add_zero] at left
      exact congrArg ZMod.val left
    · apply congrArg List.ofFn
      funext lane
      have right := link.2.2.1 lane
      rw [zero, zero_mul, add_zero] at right
      exact congrArg ZMod.val right
  · refine Or.inr ⟨one, ?_, ?_⟩
    · apply congrArg List.ofFn
      funext lane
      have left := link.2.1 lane
      rw [one, one_mul] at left
      have same : read z (checked.left level lane) =
          read z (siblingWords w slot level lane) := by linear_combination left
      exact congrArg ZMod.val same
    · apply congrArg List.ofFn
      funext lane
      have right := link.2.2.1 lane
      rw [one, one_mul] at right
      have same : read z (checked.right level lane) =
          read z (checked.states ⟨level.val, by omega⟩ lane) := by linear_combination right
      exact congrArg ZMod.val same

omit [Fact (Nat.Prime modulus)] in
/-- Constructor equations expose only the hash interface, before local opacity. -/
theorem currentPathHash_leaf_eq (payload : List Nat) :
    currentPathHash (.leaf payload) = poseidon2V8Sponge 1 payload := rfl

omit [Fact (Nat.Prime modulus)] in
theorem currentPathHash_node_eq (left right : Digest) :
    currentPathHash (.node left right) = P.compress14 4 left right := rfl

omit [Fact (Nat.Prime modulus)] in
theorem rootFromPath_nil_eq {Payload DigestValue : Type*}
    (hash : HashInput Payload DigestValue → DigestValue) (leaf : Payload) :
    rootFromPath hash leaf [] = hash (.leaf leaf) := rfl

omit [Fact (Nat.Prime modulus)] in
theorem rootFromPath_cons_left_eq {Payload DigestValue : Type*}
    (hash : HashInput Payload DigestValue → DigestValue) (leaf : Payload)
    (sibling : DigestValue) (tail : AuthenticationPath DigestValue) :
    rootFromPath hash leaf (⟨sibling, ChildSide.left⟩ :: tail) =
      hash (.node (rootFromPath hash leaf tail) sibling) := rfl

omit [Fact (Nat.Prime modulus)] in
theorem rootFromPath_cons_right_eq {Payload DigestValue : Type*}
    (hash : HashInput Payload DigestValue → DigestValue) (leaf : Payload)
    (sibling : DigestValue) (tail : AuthenticationPath DigestValue) :
    rootFromPath hash leaf (⟨sibling, ChildSide.right⟩ :: tail) =
      hash (.node sibling (rootFromPath hash leaf tail)) := rfl

omit [Fact (Nat.Prime modulus)] in
theorem pathSides_cons_eq {DigestValue : Type*}
    (step : AuthenticationStep DigestValue) (tail : AuthenticationPath DigestValue) :
    pathSides (step :: tail) = step.childSide :: pathSides tail := rfl

omit [Fact (Nat.Prime modulus)] in
theorem pathSides_cons_length_eq {DigestValue : Type*}
    (step : AuthenticationStep DigestValue) (tail : AuthenticationPath DigestValue) :
    (pathSides (step :: tail)).length = Nat.succ (pathSides tail).length := rfl

attribute [local irreducible]
  currentPathHash
  HegemonCrypto.SmallWood.MerkleExtraction.rootFromPath
  Hegemon.Transaction.Poseidon2V8SemanticSpecification.poseidon2V8Sponge
  Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives.compress14

theorem source_path_root (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (w : Nat → Word K) (slot : Fin 2)
    (checked : MerkleChecked g w slot) (count : Nat) (bound : count ≤ 32) :
    rootFromPath currentPathHash (sourceLeaf z w slot)
      (sourcePath g z w slot checked count bound) =
        digestNaturals z (checked.states ⟨count, by omega⟩) := by
  induction count with
  | zero =>
    have note := source_sponge_digest g layout z sem (1 : K)
      (List.ofFn (noteWords w slot)) (checked.states 0) checked.noteCall
      (by simp; norm_num [modulus])
    have pathNil : sourcePath g z w slot checked 0 bound = [] := rfl
    have rootNil :
        rootFromPath currentPathHash (sourceLeaf z w slot)
          (sourcePath g z w slot checked 0 bound) =
            poseidon2V8Sponge 1 (sourceLeaf z w slot) :=
      (congrArg (rootFromPath currentPathHash (sourceLeaf z w slot)) pathNil).trans
        ((rootFromPath_nil_eq currentPathHash (sourceLeaf z w slot)).trans
          (currentPathHash_leaf_eq (sourceLeaf z w slot)))
    have domain : (1 : K).val = 1 :=
      by simpa only [Nat.cast_one] using
        (ZMod.val_natCast_of_lt (n := modulus) (a := 1) (by decide : 1 < modulus))
    exact rootNil.trans
      ((congrArg (fun d : Nat => poseidon2V8Sponge d (sourceLeaf z w slot))
        domain).symm.trans note.symm)
  | succ count ih =>
    have smaller : count ≤ 32 := by omega
    let level : Fin 32 := ⟨count, by omega⟩
    have hash := source_compression_digest g layout z sem (4 : K)
      (checked.left level) (checked.right level)
      (checked.states ⟨count + 1, by omega⟩) (checked.compress level)
    have domain : (4 : K).val = 4 :=
      by simpa only [Nat.cast_ofNat] using
        (ZMod.val_natCast_of_lt (n := modulus) (a := 4) (by decide : 4 < modulus))
    have hashAtFour :
        digestNaturals z (checked.states ⟨count + 1, Nat.lt_succ_of_le bound⟩) =
          P.compress14 4 (digestNaturals z (checked.left level))
            (digestNaturals z (checked.right level)) :=
      hash.trans
        (congrArg (fun d : Nat => P.compress14 d
          (digestNaturals z (checked.left level))
          (digestNaturals z (checked.right level))) domain)
    have pathCons : sourcePath g z w slot checked (count + 1) bound =
        sourceStep g z w slot checked level ::
          sourcePath g z w slot checked count smaller := rfl
    rcases source_step_children g layout z sem w slot checked level with
      ⟨zero, left, right⟩ | ⟨one, left, right⟩
    · have stepLeft : sourceStep g z w slot checked level =
          ⟨digestNaturals z (siblingWords w slot level), ChildSide.left⟩ := by
        simp only [sourceStep, if_pos zero]
      have rootLeft :
          rootFromPath currentPathHash (sourceLeaf z w slot)
            (sourcePath g z w slot checked (count + 1) bound) =
              P.compress14 4
                (rootFromPath currentPathHash (sourceLeaf z w slot)
                  (sourcePath g z w slot checked count smaller))
                (digestNaturals z (siblingWords w slot level)) :=
        (congrArg (rootFromPath currentPathHash (sourceLeaf z w slot))
          (pathCons.trans
            (congrArg (fun step : AuthenticationStep Digest =>
              step :: sourcePath g z w slot checked count smaller) stepLeft))).trans
          ((rootFromPath_cons_left_eq currentPathHash (sourceLeaf z w slot)
            (digestNaturals z (siblingWords w slot level))
            (sourcePath g z w slot checked count smaller)).trans
            (currentPathHash_node_eq
              (rootFromPath currentPathHash (sourceLeaf z w slot)
                (sourcePath g z w slot checked count smaller))
              (digestNaturals z (siblingWords w slot level))))
      exact rootLeft.trans
        ((congrArg (fun child : Digest => P.compress14 4 child
          (digestNaturals z (siblingWords w slot level))) (ih smaller)).trans
          (hashAtFour.trans
            (congrArg₂ (fun l r : Digest => P.compress14 4 l r)
              left right)).symm)
    · have notZero : read z (.wire (checked.positionRange.bits level).val) ≠ 0 := by
        rw [one]
        exact one_ne_zero
      have stepRight : sourceStep g z w slot checked level =
          ⟨digestNaturals z (siblingWords w slot level), ChildSide.right⟩ := by
        simp only [sourceStep, if_neg notZero]
      have rootRight :
          rootFromPath currentPathHash (sourceLeaf z w slot)
            (sourcePath g z w slot checked (count + 1) bound) =
              P.compress14 4
                (digestNaturals z (siblingWords w slot level))
                (rootFromPath currentPathHash (sourceLeaf z w slot)
                  (sourcePath g z w slot checked count smaller)) :=
        (congrArg (rootFromPath currentPathHash (sourceLeaf z w slot))
          (pathCons.trans
            (congrArg (fun step : AuthenticationStep Digest =>
              step :: sourcePath g z w slot checked count smaller) stepRight))).trans
          ((rootFromPath_cons_right_eq currentPathHash (sourceLeaf z w slot)
            (digestNaturals z (siblingWords w slot level))
            (sourcePath g z w slot checked count smaller)).trans
            (currentPathHash_node_eq
              (digestNaturals z (siblingWords w slot level))
              (rootFromPath currentPathHash (sourceLeaf z w slot)
                (sourcePath g z w slot checked count smaller))))
      exact rootRight.trans
        ((congrArg (fun child : Digest => P.compress14 4
          (digestNaturals z (siblingWords w slot level)) child)
          (ih smaller)).trans
          (hashAtFour.trans
            (congrArg₂ (fun l r : Digest => P.compress14 4 l r)
              left right)).symm)

theorem source_path_length (g : Graph K) (z : Nat → K) (w : Nat → Word K)
    (slot : Fin 2) (checked : MerkleChecked g w slot) (count : Nat) (bound : count ≤ 32) :
    (pathSides (sourcePath g z w slot checked count bound)).length = count := by
  induction count with
  | zero => rfl
  | succ count ih =>
    have smaller : count ≤ 32 := by omega
    let level : Fin 32 := ⟨count, by omega⟩
    have pathCons : sourcePath g z w slot checked (count + 1) bound =
        sourceStep g z w slot checked level ::
          sourcePath g z w slot checked count smaller := rfl
    exact (congrArg (fun path : AuthenticationPath Digest => (pathSides path).length)
      pathCons).trans
        ((pathSides_cons_length_eq (sourceStep g z w slot checked level)
          (sourcePath g z w slot checked count smaller)).trans
          (congrArg Nat.succ (ih smaller)))

/-- The retained PR205 root-first binary index, without its old hash suite. -/
def sideIndex : List ChildSide → Nat
  | [] => 0
  | .left :: tail => sideIndex tail
  | .right :: tail => 2 ^ tail.length + sideIndex tail

omit [Fact (Nat.Prime modulus)] in
theorem sideIndex_left_eq (tail : List ChildSide) :
    sideIndex (.left :: tail) = sideIndex tail := rfl

omit [Fact (Nat.Prime modulus)] in
theorem sideIndex_right_eq (tail : List ChildSide) :
    sideIndex (.right :: tail) = 2 ^ tail.length + sideIndex tail := rfl

omit [Fact (Nat.Prime modulus)] in
theorem recompose_succ_zero_eq (bits : Nat → Nat) (count : Nat)
    (zero : bits count = 0) :
    recompose bits (count + 1) = recompose bits count := by
  rw [recompose, zero, zero_mul, add_zero]

omit [Fact (Nat.Prime modulus)] in
theorem recompose_succ_one_eq (bits : Nat → Nat) (count : Nat)
    (one : bits count = 1) :
    recompose bits (count + 1) = recompose bits count + 2 ^ count := by
  rw [recompose, one, one_mul]

theorem source_path_index (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (w : Nat → Word K) (slot : Fin 2)
    (checked : MerkleChecked g w slot) (count : Nat) (bound : count ≤ 32) :
    sideIndex (pathSides (sourcePath g z w slot checked count bound)) =
      recompose (rangeBits g z (position w slot) 32 checked.positionRange) count := by
  induction count with
  | zero => rfl
  | succ count ih =>
    have within : count < 32 := by omega
    have smaller : count ≤ 32 := by omega
    let level : Fin 32 := ⟨count, within⟩
    have pathCons : sourcePath g z w slot checked (count + 1) bound =
        sourceStep g z w slot checked level ::
          sourcePath g z w slot checked count smaller := rfl
    rcases (merkle_link g layout z sem w slot checked level).1 with zero | one
    · have wireZero : z (checked.positionRange.bits level).val = 0 := zero
      have digit : rangeBits g z (position w slot) 32 checked.positionRange count = 0 := by
        simp only [rangeBits, dif_pos within]
        change bitNat (z (checked.positionRange.bits level).val) = 0
        exact (congrArg bitNat wireZero).trans (if_neg (zero_ne_one : (0 : K) ≠ 1))
      have stepLeft : sourceStep g z w slot checked level =
          ⟨digestNaturals z (siblingWords w slot level), ChildSide.left⟩ := by
        simp only [sourceStep, if_pos zero]
      have direction : (sourceStep g z w slot checked level).childSide = ChildSide.left :=
        congrArg AuthenticationStep.childSide stepLeft
      have sides : pathSides (sourcePath g z w slot checked (count + 1) bound) =
          ChildSide.left :: pathSides (sourcePath g z w slot checked count smaller) :=
        (congrArg pathSides pathCons).trans
          ((pathSides_cons_eq (sourceStep g z w slot checked level)
            (sourcePath g z w slot checked count smaller)).trans
            (congrArg (fun side : ChildSide =>
              side :: pathSides (sourcePath g z w slot checked count smaller)) direction))
      exact (congrArg sideIndex sides).trans
        ((sideIndex_left_eq (pathSides (sourcePath g z w slot checked count smaller))).trans
          ((ih smaller).trans
            (recompose_succ_zero_eq
              (rangeBits g z (position w slot) 32 checked.positionRange) count digit).symm))
    · have wireOne : z (checked.positionRange.bits level).val = 1 := one
      have notZero : read z (.wire (checked.positionRange.bits level).val) ≠ 0 := by
        rw [one]
        exact one_ne_zero
      have digit : rangeBits g z (position w slot) 32 checked.positionRange count = 1 := by
        simp only [rangeBits, dif_pos within]
        change bitNat (z (checked.positionRange.bits level).val) = 1
        exact (congrArg bitNat wireOne).trans (if_pos (rfl : (1 : K) = 1))
      have stepRight : sourceStep g z w slot checked level =
          ⟨digestNaturals z (siblingWords w slot level), ChildSide.right⟩ := by
        simp only [sourceStep, if_neg notZero]
      have direction : (sourceStep g z w slot checked level).childSide = ChildSide.right :=
        congrArg AuthenticationStep.childSide stepRight
      have sides : pathSides (sourcePath g z w slot checked (count + 1) bound) =
          ChildSide.right :: pathSides (sourcePath g z w slot checked count smaller) :=
        (congrArg pathSides pathCons).trans
          ((pathSides_cons_eq (sourceStep g z w slot checked level)
            (sourcePath g z w slot checked count smaller)).trans
            (congrArg (fun side : ChildSide =>
              side :: pathSides (sourcePath g z w slot checked count smaller)) direction))
      have index : sideIndex (pathSides (sourcePath g z w slot checked (count + 1) bound)) =
          2 ^ count + recompose (rangeBits g z (position w slot) 32 checked.positionRange) count :=
        (congrArg sideIndex sides).trans
          ((sideIndex_right_eq (pathSides (sourcePath g z w slot checked count smaller))).trans
            (congrArg₂ (fun n value : Nat => 2 ^ n + value)
              (source_path_length g z w slot checked count smaller) (ih smaller)))
      exact index.trans
        ((Nat.add_comm _ _).trans
          (recompose_succ_one_eq
            (rangeBits g z (position w slot) 32 checked.positionRange) count digit).symm)

theorem source_position_is_path_index (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (w : Nat → Word K) (slot : Fin 2)
    (checked : MerkleChecked g w slot) :
    natural z (position w slot) =
      sideIndex (pathSides (sourcePath g z w slot checked 32 (by omega))) := by
  rw [source_path_index g layout z sem w slot checked 32 (by omega)]
  have bound := recompose_bound
    (rangeBits g z (position w slot) 32 checked.positionRange)
    (fun index => by
      unfold rangeBits
      split_ifs
      · exact bitNat_cases _
      · exact Or.inl rfl) 32
  have small : recompose (rangeBits g z (position w slot) 32 checked.positionRange) 32 < modulus :=
    bound.trans (by decide : 2 ^ 32 < modulus)
  have equation := congrArg ZMod.val
    (direction_position_binding g layout z sem w slot checked)
  simpa only [natural, ZMod.val_natCast, Nat.mod_eq_of_lt small] using equation

/-- Occupied current input opens the source public root at offsets17..23.
This is a source equation, not an assumption of successful history readback. -/
theorem occupied_source_opens (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (binding : g.publicBindings = NativePrivateSpendCsrCertificate.public77 pub)
    (w : Nat → Word K) (slot : Fin 2) (checked : MerkleChecked g w slot)
    (active : natural z (occupied w slot) = 1) :
    OpensAt currentPathHash (List.ofFn fun lane : Fin 7 => (pub ⟨17 + lane.val, by omega⟩).val)
      (pathSides (sourcePath g z w slot checked 32 (by omega)))
      (sourceLeaf z w slot) (sourcePath g z w slot checked 32 (by omega)) := by
  refine ⟨rfl, ?_⟩
  rw [source_path_root g layout z sem w slot checked 32 (by omega)]
  apply congrArg List.ofFn
  funext lane
  have root := (occupied_merkle_root g layout z sem pub binding w slot checked).2.2.2 lane
  have one : read z (occupied w slot) = 1 := by
    rw [← natural_cast z (occupied w slot), active, Nat.cast_one]
  rw [one, one_mul] at root
  exact congrArg ZMod.val (sub_eq_zero.mp root)
end
end HegemonCrypto.NativePrivateSpendCurrentMerklePath
