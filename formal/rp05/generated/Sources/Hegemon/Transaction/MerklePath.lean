namespace Hegemon
namespace Transaction

abbrev Digest := Nat

def digestMod : Nat := 18446744069414584321

def merkleNatEq (left right : Nat) : Bool :=
  if left = right then true else false

def mockMerkleNode (left right : Digest) : Digest :=
  (left * 1315423911 + right * 2654435761 + 97) % digestMod

def foldPathStep
    (node : Digest -> Digest -> Digest)
    (current : Digest)
    (position : Nat)
    (sibling : Digest) : Digest :=
  if position % 2 = 0 then
    node current sibling
  else
    node sibling current

def foldPathWith
    (node : Digest -> Digest -> Digest)
    (leaf : Digest)
    (position : Nat) :
    List Digest -> Digest
  | [] => leaf
  | sibling :: rest =>
      let next := foldPathStep node leaf position sibling
      foldPathWith node next (position / 2) rest

def verifyPathWithDepth
    (node : Digest -> Digest -> Digest)
    (depth leaf position : Nat)
    (siblings : List Digest)
    (root : Digest) : Bool :=
  if siblings.length = depth then
    merkleNatEq (foldPathWith node leaf position siblings) root
  else
    false

theorem merkleNatEq_self (value : Nat) :
    merkleNatEq value value = true := by
  unfold merkleNatEq
  simp

theorem merkleNatEq_false_of_ne
    {left right : Nat}
    (notEq : left ≠ right) :
    merkleNatEq left right = false := by
  unfold merkleNatEq
  split
  · contradiction
  · rfl

theorem foldPath_empty
    (node : Digest -> Digest -> Digest)
    (leaf position : Nat) :
    foldPathWith node leaf position [] = leaf := by
  rfl

theorem foldPath_even_step
    (node : Digest -> Digest -> Digest)
    {leaf position sibling : Nat}
    (evenBit : position % 2 = 0) :
    foldPathStep node leaf position sibling = node leaf sibling := by
  unfold foldPathStep
  simp [evenBit]

theorem foldPath_odd_step
    (node : Digest -> Digest -> Digest)
    {leaf position sibling : Nat}
    (oddBit : position % 2 ≠ 0) :
    foldPathStep node leaf position sibling = node sibling leaf := by
  unfold foldPathStep
  simp [oddBit]

theorem verifyPath_accepts_computed_root
    (node : Digest -> Digest -> Digest)
    {depth leaf position : Nat}
    {siblings : List Digest}
    (lengthOk : siblings.length = depth) :
    verifyPathWithDepth
      node
      depth
      leaf
      position
      siblings
      (foldPathWith node leaf position siblings) = true := by
  unfold verifyPathWithDepth
  simp [lengthOk, merkleNatEq_self]

theorem verifyPath_rejects_wrong_length
    (node : Digest -> Digest -> Digest)
    {depth leaf position root : Nat}
    {siblings : List Digest}
    (wrongLength : siblings.length ≠ depth) :
    verifyPathWithDepth node depth leaf position siblings root = false := by
  unfold verifyPathWithDepth
  simp [wrongLength]

theorem verifyPath_rejects_wrong_root
    (node : Digest -> Digest -> Digest)
    {depth leaf position root : Nat}
    {siblings : List Digest}
    (lengthOk : siblings.length = depth)
    (wrongRoot : foldPathWith node leaf position siblings ≠ root) :
    verifyPathWithDepth node depth leaf position siblings root = false := by
  unfold verifyPathWithDepth
  simp [lengthOk, merkleNatEq_false_of_ne wrongRoot]

theorem mockPath_position_one_accepts :
    verifyPathWithDepth
      mockMerkleNode
      2
      10
      1
      [20, 30]
      (foldPathWith mockMerkleNode 10 1 [20, 30]) = true := by
  exact verifyPath_accepts_computed_root mockMerkleNode rfl

end Transaction
end Hegemon
