import HegemonCrypto.SmallWoodV8Smz9SemanticCryptographicLinks
import HegemonCrypto.SmallWoodV8Smz9Poseidon2TemplateRefinement

/-! Exact source-index certificates and arithmetic-template binding for the two
HGV8RP03 hash groups. Finite data checks are not assumed primitive equality. -/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
  (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
  (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement

set_option maxHeartbeats 0
set_option maxRecDepth 1000000
set_option Elab.async false

abbrev Query := Nat × FieldExpression

def orderedAdd (a b : Nat) : FieldExpression := .add (min a b) (max a b)
def orderedMul (a b : Nat) : FieldExpression := .mul (min a b) (max a b)

def externalBase (group stage : Nat) : Nat :=
  (if group = 0 then [2036,2252,2468,2684,2900,4364,4580,4796,5012]
    else [5100,5300,5500,5700,5900,7310,7510,7710,7910]).getD stage 0

def externalInputNode (group stage lane : Nat) : Nat :=
  if stage = 0 then 407 + 182 * group + lane
  else externalBase group stage - 76 + 5 * lane

def externalOutputNode (group stage lane : Nat) : Nat :=
  externalBase group stage + 28 + 11 * (lane % 4) + outputOffset (lane / 4)

def internalProductNode (group round lane : Nat) : Nat :=
  let root := (hashRootPair group (64 + round)).1
  if group = 0 ∧ round = 0 then root + 23 + 3 * lane
  else root + 22 + 2 * lane

def internalOutputNode (group round lane : Nat) : Nat :=
  internalProductNode group round lane + 1

def sboxBase (group wire : Nat) : Nat :=
  if wire < 64 then externalBase group (wire / 16 + 1) - 80 + 5 * (wire % 16)
  else if wire < 86 then (hashRootPair group wire).1 + 2
  else externalBase group (5 + (wire - 86) / 16) - 80 + 5 * ((wire - 86) % 16)

def sboxInputNode (group wire : Nat) : Nat :=
  if wire < 64 then externalOutputNode group (wire / 16) (wire % 16)
  else if wire < 86 then
    if wire = 64 then externalOutputNode group 4 0
    else internalOutputNode group (wire - 65) 0
  else if wire - 86 < 16 then internalOutputNode group 21 ((wire - 86) % 16)
  else externalOutputNode group (4 + (wire - 86) / 16) ((wire - 86) % 16)

def internalInputNode (group round lane : Nat) : Nat :=
  if lane = 0 then sboxBase group (64 + round) + 4
  else if round = 0 then externalOutputNode group 4 lane
  else internalOutputNode group (round - 1) lane

def internalSumNode (group round index : Nat) : Nat :=
  if index = 0 then internalInputNode group round 0
  else (hashRootPair group (64 + round)).1 + 6 + index

def roundConstantNode (wire : Nat) : Nat := (hashRootPair 0 wire).1 - 2
def diagonalNode (lane : Nat) : Nat := 2996 + 3 * lane

def roundConstant (wire : Nat) : Nat :=
  if wire < 64 then
    (Poseidon2Width16Kernel.externalRoundConstantsInitial.getD (wire / 16) []).getD (wire % 16) 0
  else if wire < 86 then Poseidon2Width16Kernel.internalRoundConstants.getD (wire - 64) 0
  else (Poseidon2Width16Kernel.externalRoundConstantsTerminal.getD ((wire - 86) / 16) []).getD
    ((wire - 86) % 16) 0

def externalExpression (base : Nat) (input : Nat → Nat) (offset : Nat) : FieldExpression :=
  if offset < 28 then
    let q := offset / 7
    match offset % 7 with
    | 0 => orderedAdd (input (4*q)) (input (4*q+1))
    | 1 => orderedAdd (input (4*q+2)) (base+7*q)
    | 2 => orderedAdd (input (4*q+3)) (base+7*q+1)
    | c => orderedAdd (input (4*q+c-3)) (base+7*q+2)
  else
    let c := (offset-28)/11
    let a := base+28+11*c
    match (offset-28)%11 with
    | 0 => orderedAdd (base+3+c) (base+10+c)
    | 1 => orderedAdd (base+17+c) (base+24+c)
    | 2 => orderedAdd a (a+1)
    | 3 => orderedAdd (base+10+c) (a+2)
    | 4 => orderedAdd (base+24+c) (a+2)
    | 5 => orderedAdd (base+3+c) (base+3+c)
    | 6 => orderedAdd (a+4) (a+5)
    | 7 => orderedAdd (base+17+c) (base+17+c)
    | 8 => orderedAdd (a+3) (a+7)
    | 9 => orderedAdd a (a+3)
    | _ => orderedAdd (a+1) (a+4)

def externalQueries (group stage : Nat) : List Query :=
  (List.range 72).map (fun offset =>
    (externalBase group stage + offset,
      externalExpression (externalBase group stage) (externalInputNode group stage) offset))

def sboxQueries (group wire : Nat) : List Query :=
  let root := (hashRootPair group wire).1
  let constant := roundConstantNode wire
  let base := sboxBase group wire
  [(root-1, orderedAdd (sboxInputNode group wire) constant),
   (root+1, .sub (124 + hashRow group wire) constant),
   (base, orderedAdd constant (root+1)),
   (base+1, orderedMul base base),
   (base+2, orderedMul (base+1) (base+1)),
   (base+3, orderedMul (base+1) (base+2)),
   (base+4, orderedMul base (base+3))]

def internalQueries (group round : Nat) : List Query :=
  (List.range 15).map (fun i =>
    (internalSumNode group round (i+1),
      orderedAdd (internalInputNode group round (i+1)) (internalSumNode group round i))) ++
  (List.range 16).flatMap (fun i =>
    [(internalProductNode group round i,
       orderedMul (internalInputNode group round i) (diagonalNode i)),
     (internalOutputNode group round i,
       orderedAdd (internalSumNode group round 15) (internalProductNode group round i))])

def groupQueries (group : Nat) : List Query :=
  ((List.range 9).flatMap (externalQueries group) ++
    (List.range 150).flatMap (sboxQueries group)) ++
    (List.range 22).flatMap (internalQueries group)

def constantQueries : List Query :=
  (List.range 150).map (fun wire => (roundConstantNode wire, .constant (roundConstant wire))) ++
    (List.range 16).map (fun lane =>
      (diagonalNode lane, .constant (Poseidon2Width16Kernel.internalMatrixDiagonal.getD lane 0)))

def mergeQueriesFuel : Nat → List Query → List Query → List Query
  | 0, left, right => left ++ right
  | _+1, [], right => right
  | _+1, left, [] => left
  | fuel+1, a :: left, b :: right =>
      if a.1 ≤ b.1 then a :: mergeQueriesFuel fuel left (b :: right)
      else b :: mergeQueriesFuel fuel (a :: left) right

theorem mem_merge_queries_fuel {query : Query} (fuel : Nat) (left right : List Query) :
    query ∈ mergeQueriesFuel fuel left right ↔ query ∈ left ∨ query ∈ right := by
  induction fuel generalizing left right with
  | zero => simp [mergeQueriesFuel]
  | succ fuel ih =>
    cases left with
    | nil => simp [mergeQueriesFuel]
    | cons a left =>
      cases right with
      | nil => simp [mergeQueriesFuel]
      | cons b right =>
        by_cases order : a.1 ≤ b.1 <;> simp [mergeQueriesFuel, order, ih] <;> tauto

def mergeQueries (left right : List Query) : List Query :=
  mergeQueriesFuel (left.length+right.length) left right

theorem mem_merge_queries {query : Query} (left right : List Query) :
    query ∈ mergeQueries left right ↔ query ∈ left ∨ query ∈ right :=
  mem_merge_queries_fuel (left.length+right.length) left right

def sortQueriesFuel : Nat → List Query → List Query
  | 0, queries => queries
  | fuel+1, queries =>
      if queries.length ≤ 1 then queries
      else mergeQueries (sortQueriesFuel fuel (queries.take (queries.length/2)))
        (sortQueriesFuel fuel (queries.drop (queries.length/2)))

theorem mem_sort_queries_fuel {query : Query} (fuel : Nat) (queries : List Query) :
    query ∈ sortQueriesFuel fuel queries ↔ query ∈ queries := by
  induction fuel generalizing queries with
  | zero => rfl
  | succ fuel ih =>
    simp only [sortQueriesFuel]
    split
    · rfl
    · rw [mem_merge_queries, ih, ih, ← List.mem_append, List.take_append_drop]

def sortedQueries (queries : List Query) : List Query := sortQueriesFuel 13 queries

theorem mem_sorted_queries {query : Query} (queries : List Query) :
    query ∈ sortedQueries queries ↔ query ∈ queries := mem_sort_queries_fuel 13 queries

/-- A bounded partition changes checking cost, not which source queries must hold. -/
def queryBlock (queries : List Query) (block : Nat) : List Query :=
  (queries.drop (64 * block)).take 64

def queryBlockChecked (queries : List Query) (block : Nat) : Prop :=
  checkHashQueries 0 exactNonlinearExpressions (sortedQueries (queryBlock queries block)) = true

instance (queries : List Query) (block : Nat) : Decidable (queryBlockChecked queries block) := by
  unfold queryBlockChecked
  infer_instance

private theorem group_0_block_0_checked :
    queryBlockChecked (groupQueries 0) 0 := by
  decide +kernel

private theorem group_0_block_1_checked :
    queryBlockChecked (groupQueries 0) 1 := by
  decide +kernel

private theorem group_0_block_2_checked :
    queryBlockChecked (groupQueries 0) 2 := by
  decide +kernel

private theorem group_0_block_3_checked :
    queryBlockChecked (groupQueries 0) 3 := by
  decide +kernel

private theorem group_0_block_4_checked :
    queryBlockChecked (groupQueries 0) 4 := by
  decide +kernel

private theorem group_0_block_5_checked :
    queryBlockChecked (groupQueries 0) 5 := by
  decide +kernel

private theorem group_0_block_6_checked :
    queryBlockChecked (groupQueries 0) 6 := by
  decide +kernel

private theorem group_0_block_7_checked :
    queryBlockChecked (groupQueries 0) 7 := by
  decide +kernel

private theorem group_0_block_8_checked :
    queryBlockChecked (groupQueries 0) 8 := by
  decide +kernel

private theorem group_0_block_9_checked :
    queryBlockChecked (groupQueries 0) 9 := by
  decide +kernel

private theorem group_0_block_10_checked :
    queryBlockChecked (groupQueries 0) 10 := by
  decide +kernel

private theorem group_0_block_11_checked :
    queryBlockChecked (groupQueries 0) 11 := by
  decide +kernel

private theorem group_0_block_12_checked :
    queryBlockChecked (groupQueries 0) 12 := by
  decide +kernel

private theorem group_0_block_13_checked :
    queryBlockChecked (groupQueries 0) 13 := by
  decide +kernel

private theorem group_0_block_14_checked :
    queryBlockChecked (groupQueries 0) 14 := by
  decide +kernel

private theorem group_0_block_15_checked :
    queryBlockChecked (groupQueries 0) 15 := by
  decide +kernel

private theorem group_0_block_16_checked :
    queryBlockChecked (groupQueries 0) 16 := by
  decide +kernel

private theorem group_0_block_17_checked :
    queryBlockChecked (groupQueries 0) 17 := by
  decide +kernel

private theorem group_0_block_18_checked :
    queryBlockChecked (groupQueries 0) 18 := by
  decide +kernel

private theorem group_0_block_19_checked :
    queryBlockChecked (groupQueries 0) 19 := by
  decide +kernel

private theorem group_0_block_20_checked :
    queryBlockChecked (groupQueries 0) 20 := by
  decide +kernel

private theorem group_0_block_21_checked :
    queryBlockChecked (groupQueries 0) 21 := by
  decide +kernel

private theorem group_0_block_22_checked :
    queryBlockChecked (groupQueries 0) 22 := by
  decide +kernel

private theorem group_0_block_23_checked :
    queryBlockChecked (groupQueries 0) 23 := by
  decide +kernel

private theorem group_0_block_24_checked :
    queryBlockChecked (groupQueries 0) 24 := by
  decide +kernel

private theorem group_0_block_25_checked :
    queryBlockChecked (groupQueries 0) 25 := by
  decide +kernel

private theorem group_0_block_26_checked :
    queryBlockChecked (groupQueries 0) 26 := by
  decide +kernel

private theorem group_0_block_27_checked :
    queryBlockChecked (groupQueries 0) 27 := by
  decide +kernel

private theorem group_0_block_28_checked :
    queryBlockChecked (groupQueries 0) 28 := by
  decide +kernel

private theorem group_0_block_29_checked :
    queryBlockChecked (groupQueries 0) 29 := by
  decide +kernel

private theorem group_0_block_30_checked :
    queryBlockChecked (groupQueries 0) 30 := by
  decide +kernel

private theorem group_0_block_31_checked :
    queryBlockChecked (groupQueries 0) 31 := by
  decide +kernel

private theorem group_0_block_32_checked :
    queryBlockChecked (groupQueries 0) 32 := by
  decide +kernel

private theorem group_0_block_33_checked :
    queryBlockChecked (groupQueries 0) 33 := by
  decide +kernel

private theorem group_0_block_34_checked :
    queryBlockChecked (groupQueries 0) 34 := by
  decide +kernel

private theorem group_0_block_35_checked :
    queryBlockChecked (groupQueries 0) 35 := by
  decide +kernel

private theorem group_0_block_36_checked :
    queryBlockChecked (groupQueries 0) 36 := by
  decide +kernel

private theorem group_0_block_37_checked :
    queryBlockChecked (groupQueries 0) 37 := by
  decide +kernel

private theorem group_0_block_38_checked :
    queryBlockChecked (groupQueries 0) 38 := by
  decide +kernel

private theorem group_0_block_39_checked :
    queryBlockChecked (groupQueries 0) 39 := by
  decide +kernel

private theorem group_0_block_40_checked :
    queryBlockChecked (groupQueries 0) 40 := by
  decide +kernel

private theorem group_0_block_41_checked :
    queryBlockChecked (groupQueries 0) 41 := by
  decide +kernel

private theorem group_0_block_42_checked :
    queryBlockChecked (groupQueries 0) 42 := by
  decide +kernel

theorem group_zero_queries_checked (block : Nat) (bound : block < 43) :
    queryBlockChecked (groupQueries 0) block := by
  interval_cases block
  · exact group_0_block_0_checked
  · exact group_0_block_1_checked
  · exact group_0_block_2_checked
  · exact group_0_block_3_checked
  · exact group_0_block_4_checked
  · exact group_0_block_5_checked
  · exact group_0_block_6_checked
  · exact group_0_block_7_checked
  · exact group_0_block_8_checked
  · exact group_0_block_9_checked
  · exact group_0_block_10_checked
  · exact group_0_block_11_checked
  · exact group_0_block_12_checked
  · exact group_0_block_13_checked
  · exact group_0_block_14_checked
  · exact group_0_block_15_checked
  · exact group_0_block_16_checked
  · exact group_0_block_17_checked
  · exact group_0_block_18_checked
  · exact group_0_block_19_checked
  · exact group_0_block_20_checked
  · exact group_0_block_21_checked
  · exact group_0_block_22_checked
  · exact group_0_block_23_checked
  · exact group_0_block_24_checked
  · exact group_0_block_25_checked
  · exact group_0_block_26_checked
  · exact group_0_block_27_checked
  · exact group_0_block_28_checked
  · exact group_0_block_29_checked
  · exact group_0_block_30_checked
  · exact group_0_block_31_checked
  · exact group_0_block_32_checked
  · exact group_0_block_33_checked
  · exact group_0_block_34_checked
  · exact group_0_block_35_checked
  · exact group_0_block_36_checked
  · exact group_0_block_37_checked
  · exact group_0_block_38_checked
  · exact group_0_block_39_checked
  · exact group_0_block_40_checked
  · exact group_0_block_41_checked
  · exact group_0_block_42_checked

private theorem group_1_block_0_checked :
    queryBlockChecked (groupQueries 1) 0 := by
  decide +kernel

private theorem group_1_block_1_checked :
    queryBlockChecked (groupQueries 1) 1 := by
  decide +kernel

private theorem group_1_block_2_checked :
    queryBlockChecked (groupQueries 1) 2 := by
  decide +kernel

private theorem group_1_block_3_checked :
    queryBlockChecked (groupQueries 1) 3 := by
  decide +kernel

private theorem group_1_block_4_checked :
    queryBlockChecked (groupQueries 1) 4 := by
  decide +kernel

private theorem group_1_block_5_checked :
    queryBlockChecked (groupQueries 1) 5 := by
  decide +kernel

private theorem group_1_block_6_checked :
    queryBlockChecked (groupQueries 1) 6 := by
  decide +kernel

private theorem group_1_block_7_checked :
    queryBlockChecked (groupQueries 1) 7 := by
  decide +kernel

private theorem group_1_block_8_checked :
    queryBlockChecked (groupQueries 1) 8 := by
  decide +kernel

private theorem group_1_block_9_checked :
    queryBlockChecked (groupQueries 1) 9 := by
  decide +kernel

private theorem group_1_block_10_checked :
    queryBlockChecked (groupQueries 1) 10 := by
  decide +kernel

private theorem group_1_block_11_checked :
    queryBlockChecked (groupQueries 1) 11 := by
  decide +kernel

private theorem group_1_block_12_checked :
    queryBlockChecked (groupQueries 1) 12 := by
  decide +kernel

private theorem group_1_block_13_checked :
    queryBlockChecked (groupQueries 1) 13 := by
  decide +kernel

private theorem group_1_block_14_checked :
    queryBlockChecked (groupQueries 1) 14 := by
  decide +kernel

private theorem group_1_block_15_checked :
    queryBlockChecked (groupQueries 1) 15 := by
  decide +kernel

private theorem group_1_block_16_checked :
    queryBlockChecked (groupQueries 1) 16 := by
  decide +kernel

private theorem group_1_block_17_checked :
    queryBlockChecked (groupQueries 1) 17 := by
  decide +kernel

private theorem group_1_block_18_checked :
    queryBlockChecked (groupQueries 1) 18 := by
  decide +kernel

private theorem group_1_block_19_checked :
    queryBlockChecked (groupQueries 1) 19 := by
  decide +kernel

private theorem group_1_block_20_checked :
    queryBlockChecked (groupQueries 1) 20 := by
  decide +kernel

private theorem group_1_block_21_checked :
    queryBlockChecked (groupQueries 1) 21 := by
  decide +kernel

private theorem group_1_block_22_checked :
    queryBlockChecked (groupQueries 1) 22 := by
  decide +kernel

private theorem group_1_block_23_checked :
    queryBlockChecked (groupQueries 1) 23 := by
  decide +kernel

private theorem group_1_block_24_checked :
    queryBlockChecked (groupQueries 1) 24 := by
  decide +kernel

private theorem group_1_block_25_checked :
    queryBlockChecked (groupQueries 1) 25 := by
  decide +kernel

private theorem group_1_block_26_checked :
    queryBlockChecked (groupQueries 1) 26 := by
  decide +kernel

private theorem group_1_block_27_checked :
    queryBlockChecked (groupQueries 1) 27 := by
  decide +kernel

private theorem group_1_block_28_checked :
    queryBlockChecked (groupQueries 1) 28 := by
  decide +kernel

private theorem group_1_block_29_checked :
    queryBlockChecked (groupQueries 1) 29 := by
  decide +kernel

private theorem group_1_block_30_checked :
    queryBlockChecked (groupQueries 1) 30 := by
  decide +kernel

private theorem group_1_block_31_checked :
    queryBlockChecked (groupQueries 1) 31 := by
  decide +kernel

private theorem group_1_block_32_checked :
    queryBlockChecked (groupQueries 1) 32 := by
  decide +kernel

private theorem group_1_block_33_checked :
    queryBlockChecked (groupQueries 1) 33 := by
  decide +kernel

private theorem group_1_block_34_checked :
    queryBlockChecked (groupQueries 1) 34 := by
  decide +kernel

private theorem group_1_block_35_checked :
    queryBlockChecked (groupQueries 1) 35 := by
  decide +kernel

private theorem group_1_block_36_checked :
    queryBlockChecked (groupQueries 1) 36 := by
  decide +kernel

private theorem group_1_block_37_checked :
    queryBlockChecked (groupQueries 1) 37 := by
  decide +kernel

private theorem group_1_block_38_checked :
    queryBlockChecked (groupQueries 1) 38 := by
  decide +kernel

private theorem group_1_block_39_checked :
    queryBlockChecked (groupQueries 1) 39 := by
  decide +kernel

private theorem group_1_block_40_checked :
    queryBlockChecked (groupQueries 1) 40 := by
  decide +kernel

private theorem group_1_block_41_checked :
    queryBlockChecked (groupQueries 1) 41 := by
  decide +kernel

private theorem group_1_block_42_checked :
    queryBlockChecked (groupQueries 1) 42 := by
  decide +kernel

theorem group_one_queries_checked (block : Nat) (bound : block < 43) :
    queryBlockChecked (groupQueries 1) block := by
  interval_cases block
  · exact group_1_block_0_checked
  · exact group_1_block_1_checked
  · exact group_1_block_2_checked
  · exact group_1_block_3_checked
  · exact group_1_block_4_checked
  · exact group_1_block_5_checked
  · exact group_1_block_6_checked
  · exact group_1_block_7_checked
  · exact group_1_block_8_checked
  · exact group_1_block_9_checked
  · exact group_1_block_10_checked
  · exact group_1_block_11_checked
  · exact group_1_block_12_checked
  · exact group_1_block_13_checked
  · exact group_1_block_14_checked
  · exact group_1_block_15_checked
  · exact group_1_block_16_checked
  · exact group_1_block_17_checked
  · exact group_1_block_18_checked
  · exact group_1_block_19_checked
  · exact group_1_block_20_checked
  · exact group_1_block_21_checked
  · exact group_1_block_22_checked
  · exact group_1_block_23_checked
  · exact group_1_block_24_checked
  · exact group_1_block_25_checked
  · exact group_1_block_26_checked
  · exact group_1_block_27_checked
  · exact group_1_block_28_checked
  · exact group_1_block_29_checked
  · exact group_1_block_30_checked
  · exact group_1_block_31_checked
  · exact group_1_block_32_checked
  · exact group_1_block_33_checked
  · exact group_1_block_34_checked
  · exact group_1_block_35_checked
  · exact group_1_block_36_checked
  · exact group_1_block_37_checked
  · exact group_1_block_38_checked
  · exact group_1_block_39_checked
  · exact group_1_block_40_checked
  · exact group_1_block_41_checked
  · exact group_1_block_42_checked

private theorem constant_block_0_checked :
    queryBlockChecked constantQueries 0 := by
  decide +kernel

private theorem constant_block_1_checked :
    queryBlockChecked constantQueries 1 := by
  decide +kernel

private theorem constant_block_2_checked :
    queryBlockChecked constantQueries 2 := by
  decide +kernel

theorem constant_queries_checked (block : Nat) (bound : block < 3) :
    queryBlockChecked constantQueries block := by
  interval_cases block
  · exact constant_block_0_checked
  · exact constant_block_1_checked
  · exact constant_block_2_checked

theorem group_queries_length_bound {group : Nat} (bound : group < 2) :
    (groupQueries group).length ≤ 64 * 43 := by
  interval_cases group <;> decide +kernel

theorem constant_queries_length_bound : constantQueries.length ≤ 64 * 3 := by
  decide +kernel

theorem checked_sorted_query_source {queries : List Query}
    (checked : checkHashQueries 0 exactNonlinearExpressions (sortedQueries queries) = true)
    {query : Query} (member : query ∈ queries) :
    exactNonlinearExpressions[query.1]? = some query.2 := by
  have sortedMember : query ∈ sortedQueries queries := (mem_sorted_queries queries).mpr member
  simpa only [Nat.sub_zero] using
    (checked_hash_queries_sound 0 exactNonlinearExpressions (sortedQueries queries)
      checked query.1 query.2 sortedMember).2

theorem checked_block_query_source {queries : List Query} {blocks : Nat}
    (lengthBound : queries.length ≤ 64 * blocks)
    (checked : ∀ block, block < blocks → queryBlockChecked queries block)
    {query : Query} (member : query ∈ queries) :
    exactNonlinearExpressions[query.1]? = some query.2 := by
  obtain ⟨index, found⟩ := List.getElem?_of_mem member
  have indexBound := (List.getElem?_eq_some_iff.mp found).1
  have blockBound : index / 64 < blocks := by omega
  have inBlock : query ∈ queryBlock queries (index / 64) := by
    apply List.mem_of_getElem? (i := index % 64)
    unfold queryBlock
    rw [List.getElem?_take_of_lt (Nat.mod_lt _ (by decide)), List.getElem?_drop]
    have reconstruction : 64 * (index / 64) + index % 64 = index := by omega
    rw [reconstruction]
    exact found
  exact checked_sorted_query_source (checked (index / 64) blockBound) inBlock

theorem group_query_source {group : Nat} (bound : group < 2)
    {query : Query} (member : query ∈ groupQueries group) :
    exactNonlinearExpressions[query.1]? = some query.2 := by
  have alternatives : group = 0 ∨ group = 1 := by omega
  rcases alternatives with rfl | rfl
  · exact checked_block_query_source (group_queries_length_bound (by decide))
      group_zero_queries_checked member
  · exact checked_block_query_source (group_queries_length_bound (by decide))
      group_one_queries_checked member

theorem constant_query_source {query : Query} (member : query ∈ constantQueries) :
    exactNonlinearExpressions[query.1]? = some query.2 :=
  checked_block_query_source constant_queries_length_bound constant_queries_checked member

theorem external_query_source {group stage : Nat}
    (groupBound : group < 2) (stageBound : stage < 9)
    {query : Query} (member : query ∈ externalQueries group stage) :
    exactNonlinearExpressions[query.1]? = some query.2 := by
  apply group_query_source groupBound
  apply List.mem_append.mpr
  left
  apply List.mem_append.mpr
  left
  exact List.mem_flatMap.mpr ⟨stage, List.mem_range.mpr stageBound, member⟩

theorem sbox_query_source {group wire : Nat}
    (groupBound : group < 2) (wireBound : wire < 150)
    {query : Query} (member : query ∈ sboxQueries group wire) :
    exactNonlinearExpressions[query.1]? = some query.2 := by
  apply group_query_source groupBound
  apply List.mem_append.mpr
  left
  apply List.mem_append.mpr
  right
  exact List.mem_flatMap.mpr ⟨wire, List.mem_range.mpr wireBound, member⟩

theorem internal_query_source {group round : Nat}
    (groupBound : group < 2) (roundBound : round < 22)
    {query : Query} (member : query ∈ internalQueries group round) :
    exactNonlinearExpressions[query.1]? = some query.2 := by
  apply group_query_source groupBound
  apply List.mem_append.mpr
  right
  exact List.mem_flatMap.mpr ⟨round, List.mem_range.mpr roundBound, member⟩

theorem sbox_expected_node {group wire : Nat}
    (groupBound : group < 2) (wireBound : wire < 150) :
    (hashRootPair group wire).2 = (hashRootPair group wire).1 - 1 := by
  have checked : (List.range 2).all (fun g => (List.range 150).all (fun w =>
      decide ((hashRootPair g w).2 = (hashRootPair g w).1 - 1))) = true := by
    decide +kernel
  exact of_decide_eq_true (List.all_eq_true.mp
    (List.all_eq_true.mp checked group (List.mem_range.mpr groupBound)) wire
      (List.mem_range.mpr wireBound))

def InitialRoundSchedule (group round : Nat) : Prop :=
  ∀ lane : Fin 16,
    sboxInputNode group (16*round+lane.val) = externalOutputNode group round lane.val ∧
    sboxBase group (16*round+lane.val) + 4 = externalInputNode group (round+1) lane.val ∧
    roundConstant (16*round+lane.val) =
      (Poseidon2Width16Kernel.externalRoundConstantsInitial.getD round []).getD lane.val 0

def InternalRoundSchedule (group round : Nat) : Prop :=
  sboxInputNode group (64+round) =
    (if round = 0 then externalOutputNode group 4 0
      else internalOutputNode group (round-1) 0) ∧
  roundConstant (64+round) = Poseidon2Width16Kernel.internalRoundConstants.getD round 0

def TerminalRoundSchedule (group round : Nat) : Prop :=
  ∀ lane : Fin 16,
    sboxInputNode group (86+16*round+lane.val) =
      (if round = 0 then internalOutputNode group 21 lane.val
        else externalOutputNode group (4+round) lane.val) ∧
    sboxBase group (86+16*round+lane.val) + 4 =
      externalInputNode group (5+round) lane.val ∧
    roundConstant (86+16*round+lane.val) =
      (Poseidon2Width16Kernel.externalRoundConstantsTerminal.getD round []).getD lane.val 0

instance (group round : Nat) : Decidable (InitialRoundSchedule group round) := by
  unfold InitialRoundSchedule
  infer_instance

instance (group round : Nat) : Decidable (InternalRoundSchedule group round) := by
  unfold InternalRoundSchedule
  infer_instance

instance (group round : Nat) : Decidable (TerminalRoundSchedule group round) := by
  unfold TerminalRoundSchedule
  infer_instance

theorem initial_round_schedule {group round : Nat}
    (groupBound : group < 2) (roundBound : round < 4) : InitialRoundSchedule group round := by
  have checked : ∀ g : Fin 2, ∀ r : Fin 4, InitialRoundSchedule g.val r.val := by decide +kernel
  exact checked ⟨group, groupBound⟩ ⟨round, roundBound⟩

theorem internal_round_schedule {group round : Nat}
    (groupBound : group < 2) (roundBound : round < 22) : InternalRoundSchedule group round := by
  have checked : ∀ g : Fin 2, ∀ r : Fin 22, InternalRoundSchedule g.val r.val := by decide +kernel
  exact checked ⟨group, groupBound⟩ ⟨round, roundBound⟩

theorem terminal_round_schedule {group round : Nat}
    (groupBound : group < 2) (roundBound : round < 4) : TerminalRoundSchedule group round := by
  have checked : ∀ g : Fin 2, ∀ r : Fin 4, TerminalRoundSchedule g.val r.val := by decide +kernel
  exact checked ⟨group, groupBound⟩ ⟨round, roundBound⟩

theorem final_root_schedule {group lane : Nat}
    (groupBound : group < 2) (laneBound : lane < 16) :
    (hashRootPair group (150+lane)).2 = externalOutputNode group 8 lane := by
  have checked : ∀ g : Fin 2, ∀ i : Fin 16,
      (hashRootPair g.val (150+i.val)).2 = externalOutputNode g.val 8 i.val := by decide +kernel
  exact checked ⟨group, groupBound⟩ ⟨lane, laneBound⟩

noncomputable section

def nodeField (pub rows : Nat → F) (node : Nat) : F :=
  fieldAt exactNonlinearExpressions pub rows node

theorem expression_ordered_add (pub rows values : Nat → F) (a b : Nat) :
    expressionField pub rows values (orderedAdd a b) = values a + values b := by
  by_cases order : a ≤ b
  · simp only [orderedAdd, min_eq_left order, max_eq_right order, expressionField]
  · have reverse : b ≤ a := by omega
    simp only [orderedAdd, min_eq_right reverse, max_eq_left reverse,
      expressionField, add_comm]

theorem ordered_add_field (pub rows : Nat → F) {node a b : Nat}
    (found : exactNonlinearExpressions[node]? = some (orderedAdd a b)) :
    nodeField pub rows node = nodeField pub rows a + nodeField pub rows b := by
  have equation := actual_node_field_equation pub rows found
  by_cases order : a ≤ b
  · simpa only [orderedAdd, min_eq_left order, max_eq_right order,
      expressionField, nodeField] using equation
  · have reverse : b ≤ a := by omega
    simpa only [orderedAdd, min_eq_right reverse, max_eq_left reverse,
      expressionField, nodeField, add_comm] using equation

theorem ordered_mul_field (pub rows : Nat → F) {node a b : Nat}
    (found : exactNonlinearExpressions[node]? = some (orderedMul a b)) :
    nodeField pub rows node = nodeField pub rows a * nodeField pub rows b := by
  have equation := actual_node_field_equation pub rows found
  by_cases order : a ≤ b
  · simpa only [orderedMul, min_eq_left order, max_eq_right order,
      expressionField, nodeField] using equation
  · have reverse : b ≤ a := by omega
    simpa only [orderedMul, min_eq_right reverse, max_eq_left reverse,
      expressionField, nodeField, mul_comm] using equation

theorem constant_query_field (pub rows : Nat → F) {node value : Nat}
    (member : (node, FieldExpression.constant value) ∈ constantQueries) :
    nodeField pub rows node = (value : F) := by
  exact actual_node_field_equation pub rows
    (constant_query_source member)

theorem round_constant_field (pub rows : Nat → F) {wire : Nat} (bound : wire < 150) :
    nodeField pub rows (roundConstantNode wire) = (roundConstant wire : F) := by
  apply constant_query_field
  apply List.mem_append.mpr
  left
  exact List.mem_map.mpr ⟨wire, List.mem_range.mpr bound, rfl⟩

theorem diagonal_field (pub rows : Nat → F) {lane : Nat} (bound : lane < 16) :
    nodeField pub rows (diagonalNode lane) = diagonal lane := by
  apply constant_query_field
  apply List.mem_append.mpr
  right
  exact List.mem_map.mpr ⟨lane, List.mem_range.mpr bound, rfl⟩

theorem actual_witness_node_field (pub rows : Nat → F) {row : Nat} (bound : row < 686) :
    nodeField pub rows (124 + row) = rows row := by
  have member : (124 + row, FieldExpression.witnessRow row) ∈ hashQueries := by
    apply List.mem_append.mpr
    left
    exact List.mem_map.mpr ⟨row, List.mem_range.mpr bound, rfl⟩
  have source := (checked_hash_queries_sound 0 exactNonlinearExpressions hashQueries
    exact_hash_queries_checked _ _ member).2
  have found : exactNonlinearExpressions[124 + row]? = some (.witnessRow row) := by
    simpa only [Nat.sub_zero] using source
  exact actual_node_field_equation pub rows found

theorem external_offset_field (pub rows : Nat → F) {group stage : Nat}
    (groupBound : group < 2) (stageBound : stage < 9)
    (offset : Nat) (offsetBound : offset < 72) :
    nodeField pub rows (externalBase group stage + offset) =
      expressionField pub rows (nodeField pub rows)
        (externalExpression (externalBase group stage) (externalInputNode group stage) offset) := by
  exact actual_node_field_equation pub rows (external_query_source groupBound stageBound
    (List.mem_map.mpr ⟨offset, List.mem_range.mpr offsetBound, rfl⟩))

/-- Every external-layer gate comes from the actual expression list. -/
theorem source_external_template (pub rows : Nat → F) {group stage : Nat}
    (groupBound : group < 2) (stageBound : stage < 9) :
    External72 (fun i => nodeField pub rows (externalInputNode group stage i))
      (fun i => nodeField pub rows (externalBase group stage + i)) := by
  constructor
  · intro q bound
    have equation := external_offset_field pub rows groupBound stageBound (7*q) (by omega)
    interval_cases q <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro q bound
    have equation := external_offset_field pub rows groupBound stageBound (7*q+1) (by omega)
    interval_cases q <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro q bound
    have equation := external_offset_field pub rows groupBound stageBound (7*q+2) (by omega)
    interval_cases q <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro q qBound c cBound
    have equation := external_offset_field pub rows groupBound stageBound (7*q+3+c) (by omega)
    interval_cases q <;> interval_cases c <;>
      simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+1) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+2) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+3) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+4) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+5) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+6) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+7) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+8) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+9) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation
  · intro c bound
    have equation := external_offset_field pub rows groupBound stageBound (28+11*c+10) (by omega)
    interval_cases c <;> simpa [externalExpression, expression_ordered_add, Nat.add_assoc] using equation

theorem source_external_output (pub rows : Nat → F) {group stage : Nat}
    (groupBound : group < 2) (stageBound : stage < 9) (lane : Fin 16) :
    nodeField pub rows (externalOutputNode group stage lane.val) =
      externalField (fun i => nodeField pub rows (externalInputNode group stage i)) lane.val := by
  simpa only [externalOutputNode, Nat.add_assoc] using
    external72_computes_field _ _ (source_external_template pub rows groupBound stageBound) lane

/-- Acceptance fixes the recovered pre-S-box state, not just its later powers. -/
theorem source_sbox_template (pub rows : Nat → F) {group wire : Nat}
    (groupBound : group < 2) (wireBound : wire < 150)
    (recurrence : HashRecurrence group pub rows) :
    Sbox5 (nodeField pub rows (sboxInputNode group wire)) (roundConstant wire : F)
      (fun i => nodeField pub rows (sboxBase group wire + i)) := by
  have lookup := fun {query : Query} (member : query ∈ sboxQueries group wire) =>
    sbox_query_source groupBound wireBound member
  have preceding := ordered_add_field pub rows (lookup
    (show ((hashRootPair group wire).1-1,
      orderedAdd (sboxInputNode group wire) (roundConstantNode wire)) ∈ sboxQueries group wire by
        simp [sboxQueries]))
  have subtraction := actual_node_field_equation pub rows (lookup
    (show ((hashRootPair group wire).1+1,
      FieldExpression.sub (124+hashRow group wire) (roundConstantNode wire)) ∈
        sboxQueries group wire by simp [sboxQueries]))
  change nodeField pub rows ((hashRootPair group wire).1+1) =
    nodeField pub rows (124+hashRow group wire) - nodeField pub rows (roundConstantNode wire)
    at subtraction
  have row := recurrence wire (by omega)
  change rows (hashRow group wire) = nodeField pub rows (hashRootPair group wire).2 at row
  rw [sbox_expected_node groupBound wireBound, preceding] at row
  rw [actual_witness_node_field pub rows (by unfold hashRow; omega), row,
    add_sub_cancel_right] at subtraction
  constructor
  · have addition := ordered_add_field pub rows (lookup
      (show (sboxBase group wire,
        orderedAdd (roundConstantNode wire) ((hashRootPair group wire).1+1)) ∈
          sboxQueries group wire by simp [sboxQueries]))
    change nodeField pub rows (sboxBase group wire) =
      nodeField pub rows (sboxInputNode group wire) + (roundConstant wire : F)
    rw [subtraction, round_constant_field pub rows wireBound] at addition
    exact addition.trans (add_comm _ _)
  · exact ordered_mul_field pub rows (lookup
      (query := (sboxBase group wire+1, orderedMul (sboxBase group wire) (sboxBase group wire)))
      (by simp [sboxQueries]))
  · exact ordered_mul_field pub rows (lookup
      (query := (sboxBase group wire+2, orderedMul (sboxBase group wire+1) (sboxBase group wire+1)))
      (by simp [sboxQueries]))
  · exact ordered_mul_field pub rows (lookup
      (query := (sboxBase group wire+3, orderedMul (sboxBase group wire+1) (sboxBase group wire+2)))
      (by simp [sboxQueries]))
  · exact ordered_mul_field pub rows (lookup
      (query := (sboxBase group wire+4, orderedMul (sboxBase group wire) (sboxBase group wire+3)))
      (by simp [sboxQueries]))

theorem source_sbox_output (pub rows : Nat → F) {group wire : Nat}
    (groupBound : group < 2) (wireBound : wire < 150)
    (recurrence : HashRecurrence group pub rows) :
    nodeField pub rows (sboxBase group wire + 4) =
      (nodeField pub rows (sboxInputNode group wire) + (roundConstant wire : F))^7 := by
  exact sbox5_computes_power _ _ _ (source_sbox_template pub rows groupBound wireBound recurrence)

theorem source_internal_template (pub rows : Nat → F) {group round : Nat}
    (groupBound : group < 2) (roundBound : round < 22) :
    Internal47 (fun i => nodeField pub rows (internalInputNode group round i))
      (fun i => nodeField pub rows (internalSumNode group round i))
      (fun i => nodeField pub rows (internalProductNode group round i))
      (fun i => nodeField pub rows (internalOutputNode group round i)) := by
  have lookup := fun {query : Query} (member : query ∈ internalQueries group round) =>
    internal_query_source groupBound roundBound member
  constructor
  · rfl
  · intro i bound
    apply ordered_add_field pub rows
    apply lookup (query := (internalSumNode group round (i+1),
      orderedAdd (internalInputNode group round (i+1)) (internalSumNode group round i)))
    apply List.mem_append.mpr
    left
    exact List.mem_map.mpr ⟨i, List.mem_range.mpr bound, rfl⟩
  · intro i bound
    have equation := ordered_mul_field pub rows (lookup
      (show (internalProductNode group round i,
        orderedMul (internalInputNode group round i) (diagonalNode i)) ∈
          internalQueries group round from
        List.mem_append.mpr (Or.inr (List.mem_flatMap.mpr
          ⟨i, List.mem_range.mpr bound, by simp⟩))))
    simpa only [diagonal_field pub rows bound] using equation
  · intro i bound
    apply ordered_add_field pub rows
    apply lookup (query := (internalOutputNode group round i,
      orderedAdd (internalSumNode group round 15) (internalProductNode group round i)))
    apply List.mem_append.mpr
    right
    exact List.mem_flatMap.mpr ⟨i, List.mem_range.mpr bound, by simp⟩

theorem source_internal_output (pub rows : Nat → F) {group round : Nat}
    (groupBound : group < 2) (roundBound : round < 22) (lane : Fin 16) :
    nodeField pub rows (internalOutputNode group round lane.val) =
      internalField (fun i => nodeField pub rows (internalInputNode group round i)) lane.val := by
  exact internal47_computes_field _ _ _ _
    (source_internal_template pub rows groupBound roundBound) lane

def externalState (pub rows : Nat → F) (group stage lane : Nat) : F :=
  nodeField pub rows (externalOutputNode group stage lane)

def internalState (pub rows : Nat → F) (group stage lane : Nat) : F :=
  if stage = 0 then externalState pub rows group 4 lane
  else nodeField pub rows (internalOutputNode group (stage-1) lane)

def terminalState (pub rows : Nat → F) (group stage lane : Nat) : F :=
  if stage = 0 then nodeField pub rows (internalOutputNode group 21 lane)
  else externalState pub rows group (4+stage) lane

theorem source_initial_layer (pub rows : Nat → F) {group : Nat}
    (groupBound : group < 2) (lane : Fin 16) :
    externalState pub rows group 0 lane.val =
      externalField (fun i => rows (283+182*group+i)) lane.val := by
  rw [externalState, source_external_output pub rows groupBound (by decide) lane]
  apply externalField_congr
  intro i bound
  have rowBound : 283+182*group+i < 686 := by omega
  have indexEq : externalInputNode group 0 i = 124+(283+182*group+i) := by
    simp only [externalInputNode, ite_true]
    omega
  rw [indexEq, actual_witness_node_field pub rows rowBound]

theorem source_initial_round (pub rows : Nat → F) {group round : Nat}
    (groupBound : group < 2) (roundBound : round < 4)
    (recurrence : HashRecurrence group pub rows) (lane : Fin 16) :
    externalState pub rows group (round+1) lane.val =
      externalStep (externalState pub rows group round)
        (Poseidon2Width16Kernel.externalRoundConstantsInitial.getD round []) lane.val := by
  rw [externalState, source_external_output pub rows groupBound (by omega) lane]
  apply externalField_congr
  intro i bound
  obtain ⟨previous, next, constant⟩ := initial_round_schedule groupBound roundBound ⟨i,bound⟩
  rw [← next, source_sbox_output pub rows groupBound (by omega) recurrence, previous, constant]
  rfl

theorem source_internal_round (pub rows : Nat → F) {group round : Nat}
    (groupBound : group < 2) (roundBound : round < 22)
    (recurrence : HashRecurrence group pub rows) (lane : Fin 16) :
    internalState pub rows group (round+1) lane.val =
      internalStep (internalState pub rows group round)
        (Poseidon2Width16Kernel.internalRoundConstants.getD round 0) lane.val := by
  have stageEq : internalState pub rows group (round+1) lane.val =
      nodeField pub rows (internalOutputNode group round lane.val) := by
    simp only [internalState, Nat.add_eq_zero_iff, Nat.one_ne_zero, and_false,
      if_false, Nat.add_sub_cancel_right]
  rw [stageEq, source_internal_output pub rows groupBound roundBound lane]
  apply internalField_congr
  intro i bound
  by_cases zero : i = 0
  · subst i
    simp only [internalInputNode, replaceZero, ite_true]
    rw [source_sbox_output pub rows groupBound (by omega) recurrence]
    obtain ⟨previous, constant⟩ := internal_round_schedule groupBound roundBound
    rw [previous, constant]
    by_cases first : round = 0 <;> simp only [internalState, externalState, first, if_true, if_false]
  · simp only [internalInputNode, zero, if_false, replaceZero, internalState, externalState]
    by_cases first : round = 0 <;> simp only [first, if_true, if_false]

theorem source_terminal_round (pub rows : Nat → F) {group round : Nat}
    (groupBound : group < 2) (roundBound : round < 4)
    (recurrence : HashRecurrence group pub rows) (lane : Fin 16) :
    terminalState pub rows group (round+1) lane.val =
      externalStep (terminalState pub rows group round)
        (Poseidon2Width16Kernel.externalRoundConstantsTerminal.getD round []) lane.val := by
  have stageEq : terminalState pub rows group (round+1) lane.val =
      externalState pub rows group (5+round) lane.val := by
    have indexEq : 4+(round+1) = 5+round := by omega
    simp only [terminalState, Nat.add_eq_zero_iff, Nat.one_ne_zero, and_false, if_false, indexEq]
  rw [stageEq, externalState, source_external_output pub rows groupBound (by omega) lane]
  apply externalField_congr
  intro i bound
  obtain ⟨previous, next, constant⟩ := terminal_round_schedule groupBound roundBound ⟨i,bound⟩
  rw [← next, source_sbox_output pub rows groupBound (by omega) recurrence, previous, constant]
  by_cases first : round = 0 <;>
    simp only [terminalState, externalState, first, if_true, if_false]

theorem scheduled_external_rounds (rounds : List (List Nat))
    (states : Nat → Nat → F) (values : List Nat)
    (initial : StateMatches (states 0) values)
    (step : ∀ n, n < rounds.length → ∀ lane : Fin 16,
      states (n+1) lane.val = externalStep (states n) (rounds.getD n []) lane.val) :
    StateMatches (states rounds.length)
      (rounds.foldl Poseidon2Width16Kernel.externalRound values) := by
  induction rounds generalizing states values with
  | nil => exact initial
  | cons constants rounds ih =>
    simp only [List.length_cons, List.foldl_cons]
    have refined := external_step_refines (states 0) values constants initial
    have next : StateMatches (states 1) (Poseidon2Width16Kernel.externalRound values constants) := by
      constructor
      intro i bound
      have equation := step 0 (by simp) ⟨i,bound⟩
      simp only [Nat.zero_add, List.getD_cons_zero] at equation
      rw [equation]
      exact refined.lane i bound
    have remaining : ∀ n, n < rounds.length → ∀ lane : Fin 16,
        states ((n+1)+1) lane.val =
          externalStep (states (n+1)) (rounds.getD n []) lane.val := by
      intro n bound lane
      have equation := step (n+1) (by simp only [List.length_cons]; omega) lane
      simpa only [List.getD_cons_succ] using equation
    exact ih (fun n => states (n+1)) (Poseidon2Width16Kernel.externalRound values constants)
      next remaining

theorem scheduled_internal_rounds (rounds : List Nat)
    (states : Nat → Nat → F) (values : List Nat) (shape : values.length = 16)
    (initial : StateMatches (states 0) values)
    (step : ∀ n, n < rounds.length → ∀ lane : Fin 16,
      states (n+1) lane.val = internalStep (states n) (rounds.getD n 0) lane.val) :
    StateMatches (states rounds.length)
      (rounds.foldl Poseidon2Width16Kernel.internalRound values) := by
  induction rounds generalizing states values with
  | nil => exact initial
  | cons constant rounds ih =>
    simp only [List.length_cons, List.foldl_cons]
    have refined := internal_step_refines (states 0) values constant shape initial
    have next : StateMatches (states 1) (Poseidon2Width16Kernel.internalRound values constant) := by
      constructor
      intro i bound
      have equation := step 0 (by simp) ⟨i,bound⟩
      simp only [Nat.zero_add, List.getD_cons_zero] at equation
      rw [equation]
      exact refined.lane i bound
    have remaining : ∀ n, n < rounds.length → ∀ lane : Fin 16,
        states ((n+1)+1) lane.val =
          internalStep (states (n+1)) (rounds.getD n 0) lane.val := by
      intro n bound lane
      have equation := step (n+1) (by simp only [List.length_cons]; omega) lane
      simpa only [List.getD_cons_succ] using equation
    exact ih (fun n => states (n+1)) (Poseidon2Width16Kernel.internalRound values constant)
      (Poseidon2Width16Kernel.internal_round_length values constant)
      next remaining

/-- Initial state matching only names the supplied inputs. The full output
equality follows from the actual 332 accepted source recurrences. -/
theorem hash_recurrence_refines_kernel (pub rows : Nat → F) {group : Nat}
    (groupBound : group < 2) (recurrence : HashRecurrence group pub rows)
    (initialValues : List Nat)
    (initial : StateMatches (fun i => rows (283+182*group+i)) initialValues)
    (lane : Fin 16) :
    rows (449+182*group+lane.val) =
      (Poseidon2Width16Kernel.permutation initialValues |>.getD lane.val 0 : F) := by
  have linear : StateMatches (externalState pub rows group 0)
      (Poseidon2Width16Kernel.externalLinearLayer initialValues) := by
    constructor
    intro i bound
    change externalState pub rows group 0 i =
      (Poseidon2Width16Kernel.externalLinearLayer initialValues |>.getD i 0 : F)
    rw [source_initial_layer pub rows groupBound ⟨i,bound⟩,
      externalField_cast_kernel initialValues ⟨i,bound⟩]
    exact externalField_congr _ _ initial.lane ⟨i,bound⟩
  have first := scheduled_external_rounds Poseidon2Width16Kernel.externalRoundConstantsInitial
    (externalState pub rows group) (Poseidon2Width16Kernel.externalLinearLayer initialValues) linear
    (fun n bound i => source_initial_round pub rows groupBound (by simpa only
      [Poseidon2Width16Kernel.externalRoundConstantsInitial, List.length_cons, List.length_nil] using bound)
        recurrence i)
  have firstShape := external_rounds_length Poseidon2Width16Kernel.externalRoundConstantsInitial
    (Poseidon2Width16Kernel.externalLinearLayer initialValues)
      (Poseidon2Width16Kernel.external_linear_layer_length initialValues)
  have firstAsInternal : StateMatches (internalState pub rows group 0)
      (Poseidon2Width16Kernel.externalRoundConstantsInitial.foldl Poseidon2Width16Kernel.externalRound
        (Poseidon2Width16Kernel.externalLinearLayer initialValues)) := first
  have middle := scheduled_internal_rounds Poseidon2Width16Kernel.internalRoundConstants
    (internalState pub rows group)
    (Poseidon2Width16Kernel.externalRoundConstantsInitial.foldl Poseidon2Width16Kernel.externalRound
      (Poseidon2Width16Kernel.externalLinearLayer initialValues)) firstShape firstAsInternal
    (fun n bound i => source_internal_round pub rows groupBound (by simpa only
      [Poseidon2Width16Kernel.internalRoundConstants, List.length_cons, List.length_nil] using bound)
        recurrence i)
  have middleAsTerminal : StateMatches (terminalState pub rows group 0)
      (Poseidon2Width16Kernel.internalRoundConstants.foldl Poseidon2Width16Kernel.internalRound
        (Poseidon2Width16Kernel.externalRoundConstantsInitial.foldl Poseidon2Width16Kernel.externalRound
          (Poseidon2Width16Kernel.externalLinearLayer initialValues))) := middle
  have last := scheduled_external_rounds Poseidon2Width16Kernel.externalRoundConstantsTerminal
    (terminalState pub rows group)
    (Poseidon2Width16Kernel.internalRoundConstants.foldl Poseidon2Width16Kernel.internalRound
      (Poseidon2Width16Kernel.externalRoundConstantsInitial.foldl Poseidon2Width16Kernel.externalRound
        (Poseidon2Width16Kernel.externalLinearLayer initialValues))) middleAsTerminal
    (fun n bound i => source_terminal_round pub rows groupBound (by simpa only
      [Poseidon2Width16Kernel.externalRoundConstantsTerminal, List.length_cons, List.length_nil] using bound)
        recurrence i)
  change StateMatches (externalState pub rows group 8)
    (Poseidon2Width16Kernel.permutation initialValues) at last
  have rowEq : 449+182*group+lane.val = hashRow group (150+lane.val) := by
    unfold hashRow
    omega
  rw [rowEq, recurrence _ (by omega), final_root_schedule groupBound lane.isLt]
  exact last.lane lane.val lane.isLt

def packedInitialState (packed : List Nat) (call : Nat) : List Nat :=
  (List.range 16).map (fun i => HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord packed
    (Poseidon2V8DecoderRefinement.hashInitialIndex call i))

/-- No output-equality or honest-trace premise: acceptance determines each of
the 128 calls' final sixteen field words by the pinned kernel permutation. -/
theorem accepted_hash_call_final_refines_kernel {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {call limb : Nat} (callBound : call < 128) (limbBound : limb < 16) :
    (HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord packed
      (Poseidon2V8DecoderRefinement.hashFinalIndex call limb) : F) =
      (Poseidon2Width16Kernel.permutation (packedInitialState packed call) |>.getD limb 0 : F) := by
  have groupBound : call / 64 < 2 := by omega
  have laneBound : call % 64 < 64 := Nat.mod_lt _ (by decide)
  have initial : StateMatches
      (fun i => laneField packed (call%64) (283+182*(call/64)+i))
      (packedInitialState packed call) := by
    constructor
    intro i bound
    rw [laneField_eq_packedWord packed _ _ (by omega)]
    simp only [packedInitialState, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range bound, Option.map_some, Option.getD_some]
    congr 2
    simp [Poseidon2V8DecoderRefinement.hashInitialIndex,
      Poseidon2V8DecoderRefinement.hashRowStart, Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Poseidon2V8DecoderRefinement.packingFactor, Nat.mul_add, Nat.mul_comm, Nat.add_assoc]
  have final := hash_recurrence_refines_kernel (fun n => (publicWords.getD n 0 : F))
    (laneField packed (call%64)) groupBound
    (fun _ bound => accepted_hash_recurrence accepted groupBound bound laneBound)
    (packedInitialState packed call) initial ⟨limb,limbBound⟩
  rw [laneField_eq_packedWord packed _ _ (by omega)] at final
  have indexEq : (449+182*(call/64)+limb)*64+call%64 =
      Poseidon2V8DecoderRefinement.hashFinalIndex call limb := by
    simp [Poseidon2V8DecoderRefinement.hashFinalIndex,
      Poseidon2V8DecoderRefinement.hashRowStart, Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Poseidon2V8DecoderRefinement.hashFinalRowOffset, Poseidon2V8DecoderRefinement.packingFactor,
      Nat.mul_add, Nat.mul_comm, Nat.add_assoc]
    omega
  simpa only [indexEq] using final

theorem kernel_mds_word_canonical (input : List Nat) (lane : Fin 4) :
    (Poseidon2Width16Kernel.applyMds4 input).getD lane.val 0 <
      Poseidon2Width16Kernel.fieldModulus := by
  have additionBound (a b : Nat) : Poseidon2Width16Kernel.fieldAdd a b <
      Poseidon2Width16Kernel.fieldModulus := Nat.mod_lt _ (by decide)
  fin_cases lane <;>
    simp only [Poseidon2Width16Kernel.applyMds4, List.getD_cons_zero, List.getD_cons_succ] <;>
    exact additionBound _ _

theorem kernel_external_word_canonical (input : List Nat) (lane : Fin 16) :
    (Poseidon2Width16Kernel.externalLinearLayer input).getD lane.val 0 <
      Poseidon2Width16Kernel.fieldModulus := by
  simp only [Poseidon2Width16Kernel.externalLinearLayer, Poseidon2Width16Kernel.width,
    List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range lane.isLt,
    Option.map_some, Option.getD_some]
  exact kernel_mds_word_canonical _ ⟨lane.val/4, by omega⟩

theorem kernel_permutation_word_canonical (input : List Nat) (lane : Fin 16) :
    (Poseidon2Width16Kernel.permutation input).getD lane.val 0 <
      Poseidon2Width16Kernel.fieldModulus := by
  unfold Poseidon2Width16Kernel.permutation Poseidon2Width16Kernel.externalRoundConstantsTerminal
  simp only [List.foldl_cons, List.foldl_nil]
  exact kernel_external_word_canonical _ lane

/-- Canonical representatives strengthen the field theorem to exact natural
word equality, without a separate canonicality premise. -/
theorem accepted_hash_call_final_eq_kernel {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {call limb : Nat} (callBound : call < 128) (limbBound : limb < 16) :
    HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord packed
      (Poseidon2V8DecoderRefinement.hashFinalIndex call limb) =
      (Poseidon2Width16Kernel.permutation (packedInitialState packed call)).getD limb 0 := by
  have callGroup : call / 64 < 2 := by omega
  have callLane : call % 64 < 64 := Nat.mod_lt _ (by decide)
  have indexBound : Poseidon2V8DecoderRefinement.hashFinalIndex call limb <
      packedWitnessWordCount := by
    simp only [Poseidon2V8DecoderRefinement.hashFinalIndex,
      Poseidon2V8DecoderRefinement.hashRowStart, Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Poseidon2V8DecoderRefinement.hashFinalRowOffset, Poseidon2V8DecoderRefinement.packingFactor,
      packedWitnessWordCount]
    omega
  have packedBound := (HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange.canonical_packed_coordinate
    accepted.2.1 indexBound).2
  exact HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange.canonical_nat_cast_injective
    packedBound (kernel_permutation_word_canonical (packedInitialState packed call) ⟨limb,limbBound⟩)
    (accepted_hash_call_final_refines_kernel accepted callBound limbBound)

end
end HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
