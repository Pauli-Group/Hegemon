import Mathlib.Data.List.GetD
import Lean.Elab.Tactic.Omega

/-! Generic lookup identity for a list of equal-sized chunks and one short tail. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ChunkedListLookup

set_option autoImplicit false

theorem getD_flatten_fixed_prefix {α : Type*} (initial : List (List α))
    (tail : List α) (width : Nat) (positive : 0 < width)
    (full : ∀ chunk, chunk ∈ initial → chunk.length = width)
    (short : tail.length ≤ width) (fallback : α) (index : Nat)
    (inRange : index < (initial ++ [tail]).flatten.length) :
    (initial ++ [tail]).flatten.getD index fallback =
      ((initial ++ [tail]).getD (index / width) []).getD
        (index % width) fallback := by
  induction initial generalizing index with
  | nil =>
      have below : index < width := by
        have inTail : index < tail.length := by simpa using inRange
        omega
      simp [Nat.div_eq_of_lt below, Nat.mod_eq_of_lt below]
  | cons chunk rest ih =>
      have chunkLength : chunk.length = width := full chunk (by simp)
      have restFull : ∀ value, value ∈ rest → value.length = width := by
        intro value member
        exact full value (by simp [member])
      have flattenEq : ((chunk :: rest) ++ [tail]).flatten =
          chunk ++ (rest ++ [tail]).flatten := rfl
      by_cases low : index < width
      · have inChunk : index < chunk.length := by simpa [chunkLength] using low
        rw [flattenEq, List.getD_append chunk _ fallback index inChunk]
        simp [Nat.div_eq_of_lt low, Nat.mod_eq_of_lt low]
      · have lower : width ≤ index := by omega
        have tailRange : index - width < (rest ++ [tail]).flatten.length := by
          rw [flattenEq] at inRange
          simp only [List.length_append, chunkLength] at inRange
          omega
        have indexEq : index = (index - width) + width := by omega
        have divEq : index / width = (index - width) / width + 1 := by
          calc
            index / width = ((index - width) + width) / width :=
              congrArg (fun value => value / width) indexEq
            _ = (index - width) / width + 1 := Nat.add_div_right _ positive
        have modEq : index % width = (index - width) % width := by
          calc
            index % width = ((index - width) + width) % width :=
              congrArg (fun value => value % width) indexEq
            _ = (index - width) % width := Nat.add_mod_right _ _
        rw [flattenEq, List.getD_append_right chunk _ fallback index
          (by simpa [chunkLength] using lower), chunkLength]
        rw [ih restFull (index - width) tailRange]
        simp [divEq, modEq]

end HegemonCrypto.SmallWood.SmzaRp05ChunkedListLookup
