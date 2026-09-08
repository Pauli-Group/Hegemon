import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootInputs

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthRootTables

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def singleZeroOffset (index : Nat) : Nat :=
  if index < 14 then 46 + index / 2 + 7 * (index % 2)
  else if index < 20 then [60,61,62,69,76,77].getD (index - 14) 0
  else if index < 26 then 43 + index
  else if index < 32 then 44 + index
  else if index < 58 then 46 + index
  else if index < 64 then 76 + index
  else if index < 94 then 40 + index
  else 46 + index

def SingleZeroValid (index : Nat) : Prop :=
  exactNonlinearRoots[133 + index]? = some (1244 + index) ∧
  exactNonlinearExpressions[1244 + index]? =
    some (.mul 216 (216 + singleZeroOffset index)) ∧
  exactNonlinearExpressions[216 + singleZeroOffset index]? =
    some (.witnessRow (92 + singleZeroOffset index)) ∧
  46 ≤ singleZeroOffset index ∧ singleZeroOffset index < 155

instance (index : Nat) : Decidable (SingleZeroValid index) := by
  unfold SingleZeroValid
  infer_instance

theorem single_chunk0 : ∀ i : Fin 14, SingleZeroValid i.val := by decide
theorem single_chunk1 : ∀ i : Fin 14, SingleZeroValid (14 + i.val) := by decide
theorem single_chunk2 : ∀ i : Fin 14, SingleZeroValid (28 + i.val) := by decide
theorem single_chunk3 : ∀ i : Fin 14, SingleZeroValid (42 + i.val) := by decide
theorem single_chunk4 : ∀ i : Fin 14, SingleZeroValid (56 + i.val) := by decide
theorem single_chunk5 : ∀ i : Fin 14, SingleZeroValid (70 + i.val) := by decide
theorem single_chunk6 : ∀ i : Fin 14, SingleZeroValid (84 + i.val) := by decide
theorem single_chunk7 : ∀ i : Fin 11, SingleZeroValid (98 + i.val) := by decide

theorem actual_single_zero_table (index : Fin 109) : SingleZeroValid index.val := by
  by_cases h0 : index.val < 14
  · exact single_chunk0 ⟨index.val,h0⟩
  by_cases h1 : index.val < 28
  · simpa only [Nat.add_sub_of_le (show 14 ≤ index.val by omega)] using single_chunk1 ⟨index.val-14,by omega⟩
  by_cases h2 : index.val < 42
  · simpa only [Nat.add_sub_of_le (show 28 ≤ index.val by omega)] using single_chunk2 ⟨index.val-28,by omega⟩
  by_cases h3 : index.val < 56
  · simpa only [Nat.add_sub_of_le (show 42 ≤ index.val by omega)] using single_chunk3 ⟨index.val-42,by omega⟩
  by_cases h4 : index.val < 70
  · simpa only [Nat.add_sub_of_le (show 56 ≤ index.val by omega)] using single_chunk4 ⟨index.val-56,by omega⟩
  by_cases h5 : index.val < 84
  · simpa only [Nat.add_sub_of_le (show 70 ≤ index.val by omega)] using single_chunk5 ⟨index.val-70,by omega⟩
  by_cases h6 : index.val < 98
  · simpa only [Nat.add_sub_of_le (show 84 ≤ index.val by omega)] using single_chunk6 ⟨index.val-84,by omega⟩
  · simpa only [Nat.add_sub_of_le (show 98 ≤ index.val by omega)] using single_chunk7 ⟨index.val-98,by omega⟩

theorem actual_mode_table (index : Fin 3) :
    exactNonlinearRoots[129 + index.val]? = some (1236 + 2 * index.val) ∧
    exactNonlinearExpressions[216 + index.val]? = some (.witnessRow (92 + index.val)) ∧
    exactNonlinearExpressions[1235 + 2 * index.val]? = some (.sub (216 + index.val) 1) ∧
    exactNonlinearExpressions[1236 + 2 * index.val]? =
      some (.mul (216 + index.val) (1235 + 2 * index.val)) := by
  fin_cases index <;> decide

def finalZeroOffset (index : Nat) : Nat :=
  if index < 9 then 69 + index else if index < 16 then 88 + index else 118 + index

theorem actual_final_zero_table (index : Fin 22) :
    exactNonlinearRoots[449 + index.val]? = some (2014 + index.val) ∧
    exactNonlinearExpressions[2014 + index.val]? =
      some (.mul 218 (if index.val = 9 then 1559 else 216 + finalZeroOffset index.val)) ∧
    exactNonlinearExpressions[216 + finalZeroOffset index.val]? =
      some (.witnessRow (92 + finalZeroOffset index.val)) ∧
    finalZeroOffset index.val < 155 := by
  fin_cases index <;> decide

noncomputable section

theorem actual_single_zero_formula (pub rows : Nat → F) (index : Fin 109) :
    fieldAt exactNonlinearExpressions pub rows (1244 + index.val) =
      rows 92 * rows (92 + singleZeroOffset index.val) := by
  have table := actual_single_zero_table index
  have gate := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[216]? = some (.witnessRow 92) by decide)
  have source := actual_node_field_equation pub rows table.2.2.1
  have root := actual_node_field_equation pub rows table.2.1
  simp only [expressionField] at gate source root
  rw [gate,source] at root
  exact root

theorem actual_mode_formula (pub rows : Nat → F) (index : Fin 3) :
    fieldAt exactNonlinearExpressions pub rows (1236 + 2 * index.val) =
      rows (92 + index.val) * (rows (92 + index.val) - 1) := by
  have table := actual_mode_table index
  have one := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have source := actual_node_field_equation pub rows table.2.1
  have difference := actual_node_field_equation pub rows table.2.2.1
  have root := actual_node_field_equation pub rows table.2.2.2
  simp only [expressionField,Nat.cast_one] at one source difference root
  rw [difference,source,one] at root
  exact root

theorem actual_mode_sum_formula (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 1243 = rows 92 + rows 93 + rows 94 - 1 := by
  have one := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have s := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[216]? = some (.witnessRow 92) by decide)
  have a := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have f := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have sa := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1241]? = some (.add 216 217) by decide)
  have saf := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1242]? = some (.add 218 1241) by decide)
  have root := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1243]? = some (.sub 1242 1) by decide)
  simp only [expressionField,Nat.cast_one] at one s a f sa saf root
  rw [saf,sa,s,a,f,one] at root
  simpa only [add_comm,add_left_comm,add_assoc] using root

theorem actual_final_zero_formula (pub rows : Nat → F) (index : Fin 22) :
    fieldAt exactNonlinearExpressions pub rows (2014 + index.val) =
      rows 94 * (rows (92 + finalZeroOffset index.val) - if index.val = 9 then 1 else 0) := by
  have table := actual_final_zero_table index
  have gate := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have source := actual_node_field_equation pub rows table.2.2.1
  have root := actual_node_field_equation pub rows table.2.1
  simp only [expressionField] at gate source root
  by_cases special : index.val = 9
  · have one := actual_node_field_equation pub rows
      (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
    have difference := actual_node_field_equation pub rows
      (show exactNonlinearExpressions[1559]? = some (.sub 313 1) by decide)
    simp only [special,if_true,finalZeroOffset] at source root ⊢
    norm_num at source
    simp only [expressionField,Nat.cast_one] at one difference
    rw [gate,difference,source,one] at root
    exact root
  · simp only [if_neg special] at root ⊢
    rw [gate,source] at root
    simpa only [sub_zero] using root

end


end HegemonCrypto.SmallWood.V8Smz9SourceAuthRootTables
