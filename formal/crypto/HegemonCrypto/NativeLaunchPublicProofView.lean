import HegemonCrypto.NativeLaunchWireTypes

set_option autoImplicit false
set_option maxHeartbeats 1000000
set_option maxRecDepth 5000
namespace HegemonCrypto.NativeLaunchPublicProofView
open CanonicalBytes NativeLaunchRelationModelStatement
open SmallWood.NativeLaunchRelationModelResponse (Branch queryCount)

abbrev RawDigest := Fin 64 → Byte
structure Config where
  mpolDegree : Nat
  mlinDegree : Nat
  lvcsRows : Nat
  lvcsOpened : Nat
  lvcsCols : Nat
  unstackedCols : Nat
  polys : Nat

def dims (b : Branch) (c : Config) : Fin 8 → Nat × Nat
  | 0 => (5, c.mpolDegree + 1 - 6)
  | 1 => (5, c.mlinDegree + 1 - 7)
  | 2 => (c.lvcsOpened, queryCount b)
  | 3 => (queryCount b, c.lvcsRows - c.lvcsOpened)
  | 4 => (6, c.unstackedCols - c.polys)
  | 5 => (queryCount b, 5)
  | 6 => (5, c.lvcsCols)
  | 7 => (6, c.polys)

def ShapeGuard (b : Branch) (c : Config) : Prop :=
  6 ≤ c.mpolDegree + 1 ∧ 7 ≤ c.mlinDegree + 1 ∧
  c.lvcsOpened ≤ c.lvcsRows ∧ c.polys ≤ c.unstackedCols ∧
  ∀ i, (dims b c i).1 ≤ 96 ∧ (dims b c i).2 < 2^16 ∧
    ((dims b c i).1 = 0 ↔ (dims b c i).2 = 0)

structure Path where
  count : Fin 24
  nodes : Fin count.val → RawDigest

structure View (b : Branch) (c : Config) where
  shape : ShapeGuard b c
  salt : Fin 32 → Byte
  nonce : Fin (2^32)
  hPiop : RawDigest
  matrices : (i : Fin 8) → Fin ((dims b c i).1 * (dims b c i).2) → FieldWord
  paths : Fin (queryCount b) → Path
  tapes : Fin (queryCount b) → RawDigest

def encodeFields : List FieldWord → List Byte
  | [] => []
  | x :: xs => encodeLE 8 x.val ++ encodeFields xs

theorem fields_length (xs : List FieldWord) : (encodeFields xs).length = 8 * xs.length := by
  induction xs with
  | nil => rfl
  | cons x xs ih => simp [encodeFields, encodeLE_length, ih]; omega

def matrixBytes (rows cols : Nat) (values : Fin (rows * cols) → FieldWord) : List Byte :=
  encodeLE 2 rows ++ encodeLE 2 cols ++ encodeFields (List.ofFn values)

theorem matrix_length (rows cols : Nat) (values : Fin (rows * cols) → FieldWord) :
    (matrixBytes rows cols values).length = 4 + 8 * (rows * cols) := by
  simp [matrixBytes, fields_length, encodeLE_length]; omega

def encodeDigests : List RawDigest → List Byte
  | [] => []
  | x :: xs => List.ofFn x ++ encodeDigests xs

theorem digests_length (xs : List RawDigest) : (encodeDigests xs).length = 64 * xs.length := by
  induction xs with
  | nil => rfl
  | cons x xs ih => simp [encodeDigests, ih]; omega

def pathNodes {b : Branch} (paths : Fin (queryCount b) → Path) : List RawDigest :=
  (List.ofFn fun i => List.ofFn (paths i).nodes).flatten

def authBytes {b : Branch} (paths : Fin (queryCount b) → Path) : List Byte :=
  encodeLE 2 (queryCount b) ++ List.ofFn (fun i =>
    (⟨(paths i).count.val, lt_trans (paths i).count.isLt (by decide)⟩ : Byte)) ++
  encodeDigests (pathNodes paths)

theorem auth_length {b : Branch} (paths : Fin (queryCount b) → Path) :
    (authBytes paths).length = 2 + queryCount b + 64 * (pathNodes paths).length := by
  simp [authBytes, encodeLE_length, digests_length, Nat.add_assoc]

theorem path_depth {b : Branch} (paths : Fin (queryCount b) → Path) (i : Fin (queryCount b)) :
    (List.ofFn (paths i).nodes).length ≤ 23 := by
  simp only [List.length_ofFn]
  exact Nat.le_of_lt_succ (paths i).count.isLt

def tapeBytes {b : Branch} (tapes : Fin (queryCount b) → RawDigest) : List Byte :=
  encodeDigests (List.ofFn tapes)

theorem tapes_length {b : Branch} (tapes : Fin (queryCount b) → RawDigest) :
    (tapeBytes tapes).length = 64 * queryCount b := by simp [tapeBytes, digests_length]

def magic : Branch → List Byte
  | .rp06 => [83,77,90,66]
  | _ => [83,77,90,67]

theorem native_identity : magic .rp06 = [83,77,90,66] ∧
    magic .htlcLock = [83,77,90,67] ∧ queryCount .rp06 = 38 ∧ queryCount .htlcClaim = 58 := by decide

def matrix {b : Branch} {c : Config} (v : View b c) (i : Fin 8) : List Byte :=
  matrixBytes (dims b c i).1 (dims b c i).2 (v.matrices i)

def encode {b : Branch} {c : Config} (v : View b c) : List Byte :=
  magic b ++ List.ofFn v.salt ++ encodeLE 4 v.nonce.val ++ List.ofFn v.hPiop ++
  matrix v 0 ++ matrix v 1 ++ matrix v 2 ++ matrix v 3 ++ matrix v 4 ++
  authBytes v.paths ++ tapeBytes v.tapes ++ matrix v 5 ++ matrix v 6 ++
  [1] ++ matrix v 7 ++ encodeLE 4 0 ++ encodeLE 4 0

theorem complete_byte_order {b : Branch} {c : Config} (v : View b c) :
    encode v = [magic b, List.ofFn v.salt, encodeLE 4 v.nonce.val, List.ofFn v.hPiop,
      matrix v 0, matrix v 1, matrix v 2, matrix v 3, matrix v 4, authBytes v.paths,
      tapeBytes v.tapes, matrix v 5, matrix v 6, [1], matrix v 7,
      encodeLE 4 0, encodeLE 4 0].flatten := by
  simp [encode, List.append_assoc]

theorem path_node_count {b : Branch} (paths : Fin (queryCount b) → Path) :
    (pathNodes paths).length = (List.ofFn fun i => (paths i).count.val).sum := by
  simp [pathNodes, List.length_flatten, Function.comp_def]

def matrixTotal {b : Branch} {c : Config} (v : View b c) : Nat :=
  (matrix v 0).length + (matrix v 1).length + (matrix v 2).length +
  (matrix v 3).length + (matrix v 4).length + (matrix v 5).length +
  (matrix v 6).length + (matrix v 7).length

theorem complete_length {b : Branch} {c : Config} (v : View b c) :
    (encode v).length = 115 + matrixTotal v + queryCount b +
      64 * (pathNodes v.paths).length + 64 * queryCount b := by
  have ml : (magic b).length = 4 := by cases b <;> rfl
  simp only [encode, List.length_append, List.length_ofFn, encodeLE_length,
    List.length_cons, List.length_nil, auth_length, tapes_length, ml]
  unfold matrixTotal
  omega

theorem matrix_wire_guard {b : Branch} {c : Config} (v : View b c) (i : Fin 8) :
    (dims b c i).1 < 2^16 ∧ (dims b c i).2 < 2^16 ∧
    ((dims b c i).1 = 0 ↔ (dims b c i).2 = 0) := by
  have h := v.shape.2.2.2.2 i
  exact ⟨lt_of_le_of_lt h.1 (by decide), h.2⟩

theorem nonce_roundtrip {b : Branch} {c : Config} (v : View b c) :
    decodeLE (encodeLE 4 v.nonce.val) = v.nonce.val := by
  rw [decodeLE_encodeLE]
  exact Nat.mod_eq_of_lt (show v.nonce.val < 256^4 from v.nonce.isLt)

theorem nonce_bytes_injective {left right : Fin (2^32)}
    (same : encodeLE 4 left.val = encodeLE 4 right.val) : left = right := by
  exact Fin.ext (encodeLE_injective_of_lt left.isLt right.isLt same)

end HegemonCrypto.NativeLaunchPublicProofView
