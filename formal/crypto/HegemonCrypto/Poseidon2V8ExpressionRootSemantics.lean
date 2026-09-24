import Hegemon.Transaction.Poseidon2V8RelationProgram

/-!
# Semantic consequence of expression-program acceptance

This small module exposes the pointwise meaning of `ExpressionProgram.Accepts` without
depending on any generated HGV8RP03 data.  It is intentionally reusable by the exact SMZ9
oracle-extraction proof: every root named by an accepted executable program has a concrete
interpreter trace and evaluates to zero.
-/

namespace HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics

open Hegemon.Transaction.Poseidon2V8RelationProgram

/-- Acceptance forces every named expression root to evaluate to zero in the interpreter. -/
theorem acceptance_makes_each_named_root_zero
    {program : ExpressionProgram}
    {publicWords rows : List Nat}
    (accepted : program.Accepts publicWords rows)
    {root : Nat}
    (rootMembership : root ∈ program.roots) :
    ∃ values,
      evalExpressionNodes publicWords rows program.expressions = some values ∧
        values[root]? = some 0 := by
  rcases accepted with ⟨values, evaluated, rootsZero⟩
  refine ⟨values, evaluated, ?_⟩
  have member :
      values[root]? ∈ program.roots.map (fun index => values[index]?) :=
    List.mem_map.mpr ⟨root, rootMembership, rfl⟩
  rw [rootsZero] at member
  simp at member
  exact member.2

end HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
