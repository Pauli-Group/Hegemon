import HegemonCrypto.SmallWoodV8Smz9HashDependencyCertificate

namespace HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
  (fieldAt fieldAt_eq expressionField fieldAt_refines_source)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
  (actual_node_field_equation)

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

/-- A linear pass checks sorted named equations without repeated long-list indexing. -/
def checkHashQueries : Nat → List FieldExpression → List (Nat × FieldExpression) → Bool
  | _, _, [] => true
  | _, [], _ :: _ => false
  | start, actual :: program, (index, expected) :: queries =>
      if index = start then decide (actual = expected) &&
        checkHashQueries (start + 1) program queries
      else if start < index then
        checkHashQueries (start + 1) program ((index, expected) :: queries)
      else false

theorem cons_lookup_after {actual expected : FieldExpression}
    {program : List FieldExpression} {start index : Nat}
    (later : start + 1 ≤ index)
    (found : program[index - (start + 1)]? = some expected) :
    (actual :: program)[index - start]? = some expected := by
  have shifted : index - start = (index - (start + 1)) + 1 := by omega
  rw [shifted, List.getElem?_cons_succ]
  exact found

theorem checked_hash_queries_sound (start : Nat) (program : List FieldExpression)
    (queries : List (Nat × FieldExpression))
    (checked : checkHashQueries start program queries = true) :
    ∀ index expression, (index, expression) ∈ queries →
      start ≤ index ∧ program[index - start]? = some expression := by
  induction program generalizing start queries with
  | nil =>
      cases queries with
      | nil => simp
      | cons query tail => simp [checkHashQueries] at checked
  | cons actual program ih =>
      cases queries with
      | nil => simp
      | cons query queries =>
          rcases query with ⟨position, expected⟩
          by_cases same : position = start
          · subst position
            simp only [checkHashQueries, ite_true, Bool.and_eq_true,
              decide_eq_true_eq] at checked
            intro index expression member
            rcases List.mem_cons.mp member with head | tail
            · obtain ⟨rfl, rfl⟩ := Prod.mk.inj head
              exact ⟨Nat.le_refl _, by simpa only [Nat.sub_self,
                List.getElem?_cons_zero] using congrArg some checked.1⟩
            · obtain ⟨later, found⟩ := ih (start + 1) queries checked.2 index expression tail
              exact ⟨by omega, cons_lookup_after later found⟩
          · by_cases before : start < position
            · simp only [checkHashQueries, if_neg same, if_pos before] at checked
              intro index expression member
              obtain ⟨later, found⟩ := ih (start + 1) ((position, expected) :: queries)
                checked index expression member
              exact ⟨by omega, cons_lookup_after later found⟩
            · simp only [checkHashQueries, if_neg same, if_neg before,
                Bool.false_eq_true] at checked

def hashQueries : List (Nat × FieldExpression) :=
  (List.range 686).map (fun row => (124 + row, FieldExpression.witnessRow row)) ++
  (List.range 332).map (fun index =>
    let pair := hashRootPairs.getD index (0, 0)
    (pair.1, FieldExpression.sub (124 + hashRow (index / 166) (index % 166)) pair.2))

theorem exact_hash_queries_checked :
    checkHashQueries 0 exactNonlinearExpressions hashQueries = true := by
  decide +kernel

theorem exact_hash_root_pair_inventory :
    hashRootPairs.length = 332 ∧
      hashRootPairs.map Prod.fst = (exactNonlinearRoots.drop 471).take 332 := by
  decide +kernel

def HashRootSpanValid (group wire : Nat) : Prop :=
  283 + 182 * group ≤ (exactSpan (hashRootPair group wire).2).1 ∧
    (exactSpan (hashRootPair group wire).2).2 ≤ hashRow group wire

instance (group wire : Nat) : Decidable (HashRootSpanValid group wire) := by
  unfold HashRootSpanValid
  infer_instance

theorem exact_hash_root_spans {group wire : Nat}
    (groupBound : group < 2) (wireBound : wire < 166) : HashRootSpanValid group wire := by
  have checked : (List.range 2).all (fun group =>
      (List.range 166).all (fun wire => decide (HashRootSpanValid group wire))) = true := by
    decide +kernel
  have selected := List.all_eq_true.mp checked group (List.mem_range.mpr groupBound)
  exact of_decide_eq_true (List.all_eq_true.mp selected wire (List.mem_range.mpr wireBound))

theorem exact_hash_roots_valid {group wire : Nat}
    (groupBound : group < 2) (wireBound : wire < 166) : HashRootValid group wire := by
  have indexBound : 166 * group + wire < 332 := by omega
  have rowBound : hashRow group wire < 686 := by unfold hashRow; omega
  have groupEq : (166 * group + wire) / 166 = group := by omega
  have wireEq : (166 * group + wire) % 166 = wire := by omega
  have rootQuery : ((hashRootPair group wire).1,
      FieldExpression.sub (124 + hashRow group wire) (hashRootPair group wire).2) ∈
      hashQueries := by
    apply List.mem_append.mpr
    right
    apply List.mem_map.mpr
    refine ⟨166 * group + wire, List.mem_range.mpr indexBound, ?_⟩
    simp only [groupEq, wireEq, hashRootPair]
  have rowQuery : (124 + hashRow group wire, FieldExpression.witnessRow (hashRow group wire)) ∈
      hashQueries := by
    apply List.mem_append.mpr
    left
    exact List.mem_map.mpr ⟨hashRow group wire, List.mem_range.mpr rowBound, rfl⟩
  have rootEquation := (checked_hash_queries_sound 0 exactNonlinearExpressions hashQueries
    exact_hash_queries_checked _ _ rootQuery).2
  have rowEquation := (checked_hash_queries_sound 0 exactNonlinearExpressions hashQueries
    exact_hash_queries_checked _ _ rowQuery).2
  have pairBound : 166 * group + wire < hashRootPairs.length := by
    rw [exact_hash_root_pair_inventory.1]
    exact indexBound
  have pairMember : hashRootPair group wire ∈ hashRootPairs := by
    have found := List.getElem?_eq_getElem pairBound
    have member := List.mem_of_getElem? found
    simpa only [hashRootPair, List.getD_eq_getElem?_getD, found, Option.getD_some] using member
  have rootMember : (hashRootPair group wire).1 ∈ exactNonlinearRoots := by
    have mapped : (hashRootPair group wire).1 ∈ hashRootPairs.map Prod.fst :=
      List.mem_map.mpr ⟨hashRootPair group wire, pairMember, rfl⟩
    rw [exact_hash_root_pair_inventory.2] at mapped
    exact List.mem_of_mem_drop (List.mem_of_mem_take mapped)
  refine ⟨?_, ?_, rootMember, (exact_hash_root_spans groupBound wireBound).1,
    (exact_hash_root_spans groupBound wireBound).2⟩
  · simpa only [Nat.sub_zero] using rootEquation
  · simpa only [Nat.sub_zero] using rowEquation


end HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
