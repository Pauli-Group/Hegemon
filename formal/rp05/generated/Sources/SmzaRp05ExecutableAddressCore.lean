import SmzaRp05ExecutableMerkleVerifier
import Q38Rp05RawInputPartition

/-!
# Import-light finite support and bounded byte compiler

SOURCE-ONLY, NOT COMPILED. These declarations retain their original
ExecutableAddressCompiler namespace and statements. The grouped-address
equations remain in that module; this core does not import GroupedSuffix.

Support includes every digest-dependent continuation, including aborts.
The derived bound is ex-ante for a FIXED program, not a uniform <=39162
protocol bound or permission to change universes between programs in one
quantum experiment. No key encoder or support certificate is an input.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableAddressCompiler

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open V8SmzaOracleParser (RawInput RawDigest)
open Q38Rp05RawInputPartition
open V8Smz9HonestFinalGame (RawTuple rawTupleBytes)
open scoped Classical

set_option autoImplicit false
noncomputable section

-- Prove union membership with an ABSTRACT answer type, before specializing
-- to the concrete 512-bit enum. Keep this constructor opaque at every
-- subsequent unfolding of the Program recursor.
private def readSupport {Answer : Type} [Fintype Answer]
    (raw : RawInput) (below : Answer → Finset RawInput) : Finset RawInput :=
  insert raw (Finset.univ.biUnion below)

private theorem read_support_head {Answer : Type} [Fintype Answer]
    (raw : RawInput) (below : Answer → Finset RawInput) : raw ∈ readSupport raw below :=
  Finset.mem_insert_self _ _

private theorem read_support_continuation {Answer : Type} [Fintype Answer]
    (raw : RawInput) (below : Answer → Finset RawInput) (answer : Answer)
    (key : RawInput) (member : key ∈ below answer) : key ∈ readSupport raw below :=
  Finset.mem_insert_of_mem (Finset.mem_biUnion.mpr
    ⟨answer, Finset.mem_univ _, member⟩)

attribute [local irreducible] readSupport

/-- Support of every branch of the fixed executable program, including
rejected branches and every answer-dependent continuation. -/
def reachable {Result : Type} : Program Result → Finset RawInput
  | .done _ => ∅
  | .read raw next => readSupport raw (fun answer => reachable (next answer))

def addressBound {Result : Type} (program : Program Result) : Nat :=
  (reachable program).sup List.length

abbrev RawKey {Result : Type} (program : Program Result) := ↥(reachable program)

theorem key_length_bounded {Result : Type} (program : Program Result) (key : RawKey program) :
    key.val.length ≤ addressBound program :=
  Finset.le_sup key.property

/-- Literal byte classifier, including the current 2511-byte leaf partition. -/
def compileRawKey {Result : Type} (program : Program Result) (key : RawKey program) :
    Rp05FullRawInput (addressBound program) :=
  rp05Classify (⟨⟨key.val.length, Nat.lt_succ_of_le (key_length_bounded program key)⟩,
    key.val.get⟩ : RawTuple (addressBound program))

theorem compiled_bytes {Result : Type} (program : Program Result) (key : RawKey program) :
    rp05RawBytes (compileRawKey program key) = key.val := by
  rw [compileRawKey, rp05_classify_preserves_bytes]
  exact List.ofFn_get key.val

theorem compile_raw_key_injective {Result : Type} (program : Program Result) :
    Function.Injective (compileRawKey program) := by
  intro left right equal
  apply Subtype.ext
  have same := congrArg rp05RawBytes equal
  simpa only [compiled_bytes] using same

private theorem reachable_read_head {Result : Type} (raw : RawInput)
    (next : RawDigest → Program Result) : raw ∈ reachable (.read raw next) := by
  rw [show reachable (.read raw next) =
    readSupport raw (fun answer => reachable (next answer)) from rfl]
  exact read_support_head raw (fun answer => reachable (next answer))

private theorem reachable_read_continuation {Result : Type} (raw : RawInput)
    (next : RawDigest → Program Result) (answer : RawDigest) (key : RawInput)
    (member : key ∈ reachable (next answer)) : key ∈ reachable (.read raw next) := by
  rw [show reachable (.read raw next) =
    readSupport raw (fun answer => reachable (next answer)) from rfl]
  exact read_support_continuation raw (fun value => reachable (next value)) answer key member

-- Splitting the log-membership disjunction must not normalize the target's
-- union over all 2^512 digests. Use the two one-layer structural lemmas
-- above while keeping that finite support opaque throughout the induction.
attribute [local irreducible] reachable

/-- No branch-support certificate is required to bound any actual query log. -/
theorem recorded_key_reachable {Result : Type} (oracle : Oracle) (program : Program Result)
    (call : RawInput × RawDigest) (member : call ∈ (program.record oracle).2) :
    call.1 ∈ reachable program := by
  induction program with
  | done result => simp only [Program.record, List.not_mem_nil] at member
  | read raw next ih =>
      simp only [Program.record, List.mem_cons] at member
      rcases member with equal | below
      · rw [equal]
        exact reachable_read_head raw next
      · exact reachable_read_continuation raw next (oracle raw) call.1
          (ih (oracle raw) below)

theorem recorded_key_bound {Result : Type} (oracle : Oracle) (program : Program Result)
    (call : RawInput × RawDigest) (member : call ∈ (program.record oracle).2) :
    call.1.length ≤ addressBound program :=
  key_length_bounded program ⟨call.1, recorded_key_reachable oracle program call member⟩

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutableAddressCompiler
