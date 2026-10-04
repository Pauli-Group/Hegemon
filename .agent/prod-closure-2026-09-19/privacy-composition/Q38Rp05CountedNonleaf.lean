import Q38MeasuredCmsNonleafCore

/-! Generic finite support and exact counted arbitrary-answer branches.
No current protocol algorithm is duplicated, and no all-result callback
bound or increased query allowance is assumed. -/
namespace HegemonCrypto.SmallWood.Q38Rp05CountedNonleaf
open V8Smz9HiddenLeafQrom V8Smz9HonestRequestSchedule Q38MeasuredCmsNonleaf
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

/-- Equality of all finite Nat-valued observations supplies an actual source
preimage. The indicator proof does not assume a distributional support lemma. -/
theorem preimage_of_kernel_sums {A B X : Type*} [Fintype A] [Fintype B]
    (source : A → X) (simulated : B → X)
    (same : ∀ observe : X → Nat,
      (∑ a, observe (source a)) = ∑ b, observe (simulated b)) (target : B) :
    ∃ origin, source origin = simulated target := by
  classical
  by_contra missing
  push Not at missing
  let indicator : X → Nat := fun output => if output = simulated target then 1 else 0
  have sourceZero : (∑ a, indicator (source a)) = 0 := by
    apply Finset.sum_eq_zero
    intro origin _
    exact if_neg (missing origin)
  have publicZero : (∑ b, indicator (simulated b)) = 0 :=
    (same indicator).symm.trans sourceZero
  have targetZero :=
    (Finset.sum_eq_zero_iff_of_nonneg (fun b _ => Nat.zero_le (indicator (simulated b)))).mp
      publicZero target (Finset.mem_univ target)
  simp [indicator] at targetZero

section CountedBranches
variable {Other Result : Type}

/-- Syntactic answer branches, deliberately allowing answers inconsistent
with repeated oracle keys, exactly as the worst-branch query counter does. -/
inductive ReadBranch : NonleafProgram Other Result → Result → Nat → Prop
  | done (result : Result) : ReadBranch (.done result) result 0
  | read (input : Other) (next : DigestRegister → NonleafProgram Other Result)
      (answer : DigestRegister) {result : Result} {used : Nat}
      (tail : ReadBranch (next answer) result used) :
      ReadBranch (.read input next) result (used + 1)

/-- Callback-sensitive read count: costs only callbacks present in the tree,
not all values of the possibly infinite Result type. -/
def weightedReadCount (score : Result → Nat) : NonleafProgram Other Result → Nat
  | .done result => score result
  | .read _ next => (Finset.univ.sup fun answer => weightedReadCount score (next answer)) + 1

theorem read_branch_score_le {program : NonleafProgram Other Result}
    {result : Result} {used : Nat} (branch : ReadBranch program result used)
    (score : Result → Nat) : used + score result ≤ weightedReadCount score program := by
  induction branch with
  | done result => simp [weightedReadCount]
  | @read input next answer result used tail ih =>
      have below := Finset.le_sup
        (f := fun output => weightedReadCount score (next output))
        (Finset.mem_univ answer)
      dsimp only [weightedReadCount]
      omega

theorem weighted_read_count_attained (program : NonleafProgram Other Result)
    (score : Result → Nat) :
    ∃ result used, ReadBranch program result used ∧
      weightedReadCount score program = used + score result := by
  induction program with
  | done result => exact ⟨result, 0, .done result, (Nat.zero_add _).symm⟩
  | read input next ih =>
      obtain ⟨answer, _, largest⟩ := Finset.exists_mem_eq_sup Finset.univ
        Finset.univ_nonempty (fun output => weightedReadCount score (next output))
      obtain ⟨result, used, branch, cost⟩ := ih answer
      refine ⟨result, used + 1, .read input next answer branch, ?_⟩
      dsimp only [weightedReadCount]
      rw [largest, cost]
      omega

theorem weighted_read_count_le_iff (program : NonleafProgram Other Result)
    (score : Result → Nat) (total : Nat) :
    weightedReadCount score program ≤ total ↔
      ∀ result used, ReadBranch program result used → used + score result ≤ total := by
  constructor
  · intro bounded result used branch
    exact (read_branch_score_le branch score).trans bounded
  · intro branches
    obtain ⟨result, used, branch, cost⟩ := weighted_read_count_attained program score
    rw [cost]
    exact branches result used branch

theorem weighted_read_count_zero (program : NonleafProgram Other Result) :
    weightedReadCount (fun _ => 0) program = NonleafProgram.readCount program := by
  induction program with
  | done result => rfl
  | read input next ih =>
      simp only [weightedReadCount, NonleafProgram.readCount, ih]

def traceReads : (fuel : Nat) → PublicTrace DigestRegister fuel → Nat
  | 0, _ => 0
  | _ + 1, none => 0
  | fuel + 1, some (_, tail) => traceReads fuel tail + 1

/-- Every actual answer branch has a canonical finite trace with exactly its
read cost. No fixed oracle or key-distinctness premise is involved. -/
theorem read_branch_has_counted_trace {program : NonleafProgram Other Result}
    {result : Result} {used : Nat} (branch : ReadBranch program result used)
    (fuel : Nat) (enough : used ≤ fuel) :
    ∃ trace : PublicTrace DigestRegister fuel,
      traceResult fuel program trace = some result ∧ traceReads fuel trace = used := by
  induction branch generalizing fuel with
  | done result =>
      cases fuel with
      | zero => exact ⟨(), rfl, rfl⟩
      | succ fuel => exact ⟨none, rfl, rfl⟩
  | @read input next answer result used tail ih =>
      cases fuel with
      | zero => omega
      | succ fuel =>
          obtain ⟨trace, decoded, counted⟩ := ih fuel (by omega)
          exact ⟨some (answer, trace), decoded, congrArg (fun n => n + 1) counted⟩

/-- Successful trace decoding has precisely the corresponding syntactic
branch, including its number of honest reads. Invalid padded traces supply
no branch and cannot create a callback budget premise. -/
theorem counted_trace_is_read_branch (fuel : Nat)
    (program : NonleafProgram Other Result) (trace : PublicTrace DigestRegister fuel)
    (result : Result) (decoded : traceResult fuel program trace = some result) :
    ReadBranch program result (traceReads fuel trace) := by
  induction fuel generalizing program with
  | zero =>
      cases program with
      | done returned =>
          have same : returned = result := Option.some.inj decoded
          subst result
          exact .done returned
      | read input next => simp [traceResult] at decoded
  | succ fuel ih =>
      cases program with
      | done returned =>
          cases trace with
          | none =>
              have same : returned = result := Option.some.inj decoded
              subst result
              exact .done returned
          | some tail => simp [traceResult] at decoded
      | read input next =>
          cases trace with
          | none => simp [traceResult] at decoded
          | some tail => exact .read input next tail.1 (ih (next tail.1) tail.2 decoded)

end CountedBranches

end
end HegemonCrypto.SmallWood.Q38Rp05CountedNonleaf
