import HegemonCrypto.NativeLaunchPublicProofParser

set_option autoImplicit false
set_option maxHeartbeats 1000000
set_option maxRecDepth 5000
namespace HegemonCrypto.NativeLaunchPublicViewCodec
open CanonicalBytes SmallWoodProofWire NativeLaunchPublicProofView
open NativeLaunchRelationModelStatement (FieldWord)
open SmallWood.NativeLaunchRelationModelResponse (Branch)

theorem field_chunk_bound (xs : List FieldWord) (i : Nat) (bound : i < xs.length) :
    decodeLE (((encodeFields xs).drop (i * 8)).take 8) < fieldOrder := by
  induction xs generalizing i with
  | nil => simp at bound
  | cons x xs ih =>
    cases i with
    | zero =>
      have take : ((encodeLE 8 x.val) ++ encodeFields xs).take 8 = encodeLE 8 x.val :=
        List.take_left' (encodeLE_length 8 x.val)
      have small : x.val < 256^8 := lt_trans x.isLt (by decide)
      have order : fieldOrder = 18446744069414584321 := by decide
      rw [order]
      simpa only [encodeFields, Nat.zero_mul, List.drop_zero, take, decodeLE_encodeLE,
        Nat.mod_eq_of_lt small] using x.isLt
    | succ i =>
      have ib : i < xs.length := Nat.lt_of_succ_lt_succ bound
      have step : (i+1)*8 = (encodeLE 8 x.val).length + i*8 := by rw [encodeLE_length]; omega
      rw [encodeFields, step, ← List.drop_drop, List.drop_left]
      exact ih i ib


theorem fields_canonical (xs : List FieldWord) : fieldWordsCanonicalB (encodeFields xs) = true := by
  unfold fieldWordsCanonicalB
  simp only [Bool.and_eq_true, beq_iff_eq]
  constructor
  · rw [fields_length]; omega
  · apply List.all_eq_true.mpr
    intro i member
    apply decide_eq_true_eq.mpr
    have count : (encodeFields xs).length / 8 = xs.length := by rw [fields_length]; omega
    exact field_chunk_bound xs i (by simpa [count] using List.mem_range.mp member)

def rawMatrix {b : Branch} {c : Config} (v : View b c) (i : Fin 8) : MatrixWire :=
  ⟨encodeLE 2 (dims b c i).1, encodeLE 2 (dims b c i).2,
    encodeFields (List.ofFn (v.matrices i))⟩

theorem matrix_rows {b : Branch} {c : Config} (v : View b c) (i : Fin 8) :
    (rawMatrix v i).rowCount = (dims b c i).1 := by
  unfold rawMatrix MatrixWire.rowCount
  rw [decodeLE_encodeLE]
  exact Nat.mod_eq_of_lt (matrix_wire_guard v i).1

theorem matrix_columns {b : Branch} {c : Config} (v : View b c) (i : Fin 8) :
    (rawMatrix v i).columnCount = (dims b c i).2 := by
  unfold rawMatrix MatrixWire.columnCount
  rw [decodeLE_encodeLE]
  exact Nat.mod_eq_of_lt (matrix_wire_guard v i).2.1

theorem raw_matrix_canonical {b : Branch} {c : Config} (v : View b c) (i : Fin 8) :
    (rawMatrix v i).Canonical := by
  unfold MatrixWire.Canonical
  rw [matrix_rows, matrix_columns]
  refine ⟨encodeLE_length _ _, encodeLE_length _ _, (v.shape.2.2.2.2 i).1,
    (matrix_wire_guard v i).2.2, ?_, fields_canonical _⟩
  simp only [rawMatrix, fields_length, List.length_ofFn]
  omega

theorem raw_matrix_encode {b : Branch} {c : Config} (v : View b c) (i : Fin 8) :
    (rawMatrix v i).encode = matrix v i := rfl

theorem typed_matrix_prefix_roundtrip {b : Branch} {c : Config}
    (v : View b c) (i : Fin 8) (suffix : List Byte) :
    decodeMatrixPrefix (matrix v i ++ suffix) = some (rawMatrix v i, suffix) := by
  rw [← raw_matrix_encode]
  exact decodeMatrixPrefix_encode _ suffix (raw_matrix_canonical v i)

end HegemonCrypto.NativeLaunchPublicViewCodec
