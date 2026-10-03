import SmzaRp05ExecutableAddressCompiler

/-! All-answer support of a fixed, constant executable suffix. A terminal
observer that repeats a previously included program adds no grouped keys.
These are ex-ante support statements, not Born-mass or selector stability. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableBindSupport

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableAddressCompiler (reachable groups)
open SmzaRp05GroupedSuffix (groupKeyOf)
open V8SmzaOracleParser (RawInput)
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

theorem reachable_subset_constant_bind {A B : Type}
    (firstProgram : Program A) (suffix : Program B) :
    reachable firstProgram ⊆ reachable (firstProgram.bind (fun _ => suffix)) := by
  induction firstProgram with
  | done result =>
      intro input member
      change input ∈ (∅ : Finset RawInput) at member
      simp at member
  | read raw next ih =>
      intro input member
      change input ∈ insert raw (Finset.univ.biUnion fun answer =>
        reachable (next answer)) at member
      change input ∈ insert raw (Finset.univ.biUnion fun answer =>
        reachable ((next answer).bind (fun _ => suffix)))
      rcases Finset.mem_insert.mp member with head | tail
      · exact Finset.mem_insert.mpr (Or.inl head)
      · rcases Finset.mem_biUnion.mp tail with ⟨answer, _, below⟩
        exact Finset.mem_insert_of_mem (Finset.mem_biUnion.mpr
          ⟨answer, Finset.mem_univ _, ih answer below⟩)

theorem reachable_constant_bind_subset_union {A B : Type}
    (firstProgram : Program A) (suffix : Program B) :
    reachable (firstProgram.bind (fun _ => suffix)) ⊆
      reachable firstProgram ∪ reachable suffix := by
  induction firstProgram with
  | done result =>
      cases result with
      | none =>
          intro input member
          change input ∈ (∅ : Finset RawInput) at member
          simp at member
      | some value =>
          intro input member
          exact Finset.mem_union.mpr (Or.inr member)
  | read raw next ih =>
      intro input member
      change input ∈ insert raw (Finset.univ.biUnion fun answer =>
        reachable ((next answer).bind (fun _ => suffix))) at member
      rcases Finset.mem_insert.mp member with head | tail
      · apply Finset.mem_union.mpr
        left
        change input ∈ insert raw (Finset.univ.biUnion fun answer =>
          reachable (next answer))
        exact Finset.mem_insert.mpr (Or.inl head)
      · rcases Finset.mem_biUnion.mp tail with ⟨answer, _, below⟩
        rcases Finset.mem_union.mp (ih answer below) with before | after
        · apply Finset.mem_union.mpr
          left
          change input ∈ insert raw (Finset.univ.biUnion fun answer =>
            reachable (next answer))
          exact Finset.mem_insert_of_mem (Finset.mem_biUnion.mpr
            ⟨answer, Finset.mem_univ _, before⟩)
        · exact Finset.mem_union.mpr (Or.inr after)

theorem groups_subset_constant_bind {A B : Type}
    (firstProgram : Program A) (suffix : Program B) :
    groups firstProgram ⊆ groups (firstProgram.bind (fun _ => suffix)) := by
  intro key member
  rcases Finset.mem_image.mp member with ⟨raw, rawMember, same⟩
  exact Finset.mem_image.mpr
    ⟨raw, reachable_subset_constant_bind firstProgram suffix rawMember, same⟩

theorem groups_constant_bind_subset_union {A B : Type}
    (firstProgram : Program A) (suffix : Program B) :
    groups (firstProgram.bind (fun _ => suffix)) ⊆ groups firstProgram ∪ groups suffix := by
  intro key member
  rcases Finset.mem_image.mp member with ⟨raw, rawMember, same⟩
  rcases Finset.mem_union.mp
      (reachable_constant_bind_subset_union firstProgram suffix rawMember) with before | after
  · exact Finset.mem_union.mpr (Or.inl (Finset.mem_image.mpr ⟨raw, before, same⟩))
  · exact Finset.mem_union.mpr (Or.inr (Finset.mem_image.mpr ⟨raw, after, same⟩))

/-- Repeating a static firstProgram already covered by the whole chronology does
not enlarge the universe, on any digest continuation, including aborts. -/
theorem groups_constant_bind_eq_of_suffix_subset {A B : Type}
    (firstProgram : Program A) (suffix : Program B)
    (included : groups suffix ⊆ groups firstProgram) :
    groups (firstProgram.bind (fun _ => suffix)) = groups firstProgram := by
  apply Finset.Subset.antisymm
  · intro key member
    rcases Finset.mem_union.mp
        (groups_constant_bind_subset_union firstProgram suffix member) with before | after
    · exact before
    · exact included after
  · exact groups_subset_constant_bind firstProgram suffix

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutableBindSupport
