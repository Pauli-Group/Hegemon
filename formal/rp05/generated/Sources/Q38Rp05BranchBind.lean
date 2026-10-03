import Q38Rp05CountedNonleaf

/-! Cost-exact composition for already checked arbitrary-answer branches. -/
namespace HegemonCrypto.SmallWood.Q38Rp05BranchBind
open V8Smz9HonestRequestSchedule Q38Rp05CountedNonleaf
set_option autoImplicit false
set_option Elab.async false

theorem read_branch_bind {Other A B : Type}
    {program : NonleafProgram Other A} {result : A} {used extra : Nat}
    (first : ReadBranch program result used) (next : A → NonleafProgram Other B)
    {output : B} (last : ReadBranch (next result) output extra) :
    ReadBranch (NonleafProgram.bind program next) output (used + extra) := by
  induction first with
  | done result => simpa only [NonleafProgram.bind, Nat.zero_add] using last
  | read input tail answer branch ih =>
      have joined := ReadBranch.read input
        (fun response => NonleafProgram.bind (tail response) next) answer (ih last)
      simpa only [NonleafProgram.bind, Nat.add_right_comm] using joined

theorem read_branch_map {Other A B : Type}
    {program : NonleafProgram Other A} {result : A} {used : Nat}
    (branch : ReadBranch program result used) (finish : A → B) :
    ReadBranch (NonleafProgram.bind program (fun value => .done (finish value)))
      (finish result) used := by
  induction branch with
  | done result => exact .done _
  | read input next answer tail ih => exact .read input _ answer ih

end HegemonCrypto.SmallWood.Q38Rp05BranchBind
