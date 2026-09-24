import HegemonCrypto.SmallWoodRelation

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

/-!
# Historical SmallWood relation is not the SMZ9 relation

The checked-in historical relation fixes a `699 x 64` witness.  The V8 SMZ9 program fixes a
`686 x 64` witness instead.  These theorems make that length-incompatible boundary explicit,
so an SMZ9 extraction cannot be silently credited to the old relation.
-/

namespace HegemonCrypto.SmallWood.V8Smz9HistoricalRelationIncompatibility

open HegemonCrypto.SmallWood
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

def smz9PackedWitnessWordCount : Nat := 686 * 64

/-- Every witness in the existing historical relation has the old `699 x 64` length. -/
theorem historical_relation_witness_length_eq_44736
    {statement : Statement}
    {witness : Witness}
    (relation : (statement, witness) ∈ Relation) :
    witness.length = 44736 := by
  have outputBindings :=
    production_output_hash_linear_bindings_are_map_bound relation.1
  simp only [productionOutputHashLinearBindingsBoundB,
    Bool.and_eq_true] at outputBindings
  have dimensions :
      statement.lppcRowCount = 699 ∧ statement.lppcPackingFactor = 64 :=
    of_decide_eq_true outputBindings.1
  have witnessLength :=
    (production_smallwood_air_rows_are_implementation_equivalent
      relation.1 relation.2).witnessLength
  rw [dimensions.1, dimensions.2] at witnessLength
  norm_num at witnessLength
  exact witnessLength

/-- A 43,904-word SMZ9 witness cannot inhabit the historical 44,736-word relation. -/
theorem historical_relation_excludes_smz9_packed_witness
    {statement : Statement}
    {witness : Witness}
    (smz9Length : witness.length = smz9PackedWitnessWordCount) :
    ¬ (statement, witness) ∈ Relation := by
  intro relation
  have historicalLength := historical_relation_witness_length_eq_44736 relation
  have exactSmz9Length : witness.length = 43904 := by
    simpa [smz9PackedWitnessWordCount] using smz9Length
  omega

end HegemonCrypto.SmallWood.V8Smz9HistoricalRelationIncompatibility
