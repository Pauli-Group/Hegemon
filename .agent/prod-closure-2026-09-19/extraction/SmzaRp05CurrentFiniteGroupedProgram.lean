import SmzaRp05ExecutableAddressCompiler
import SmzaRp05PhysicalAcceptedReplayLite

/-! A finite, ex-ante universe of actual RP05 grouped CMS keys for one fixed
producer/verifier `Program`.  The support ranges over every raw-digest
continuation.  Unreachable raw inputs encode to a designated fallback key;
all calls on every answer branch retain their exact `GroupedSuffix` key. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteGroupedProgram

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableAddressCompiler (reachable groups)
open SmzaRp05GroupedSuffix (GroupKey groupKeyOf)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
open scoped Classical

/-- The finite key universe is the reachable groups plus one harmless
fallback, so it is nonempty even when the program performs no reads. -/
def Key {Result : Type} (program : Program Result) :=
  { key : GroupKey // key ∈ insert (groupKeyOf []) (groups program) }

noncomputable instance keyFintype {Result : Type} (program : Program Result) :
    Fintype (Key program) := by
  classical
  exact Fintype.ofFinset (insert (groupKeyOf []) (groups program)) (by
    intro key
    simp)

noncomputable instance keyDecidableEq {Result : Type} (program : Program Result) :
    DecidableEq (Key program) := Classical.decEq _

def included {Result : Type} (program : Program Result) : Key program → GroupKey :=
  Subtype.val

/-- Canonical total encoder: reachable addresses encode to their actual
group; inputs outside this fixed program's all-branch support use the
explicit fallback `groupKeyOf []`. -/
def encode {Result : Type} (program : Program Result) (raw : RawInput) : Key program :=
  if member : groupKeyOf raw ∈ insert (groupKeyOf []) (groups program) then
    ⟨groupKeyOf raw, member⟩
  else
    ⟨groupKeyOf [], Finset.mem_insert_self _ _⟩

private theorem group_key_reachable_member {Result : Type} (program : Program Result)
    (raw : RawInput) (member : raw ∈ reachable program) :
    groupKeyOf raw ∈ groups program := by
  unfold groups
  exact Finset.mem_image.mpr ⟨raw, member, rfl⟩

theorem included_encode_of_reachable {Result : Type} (program : Program Result)
    (raw : RawInput) (member : raw ∈ reachable program) :
    included program (encode program raw) = groupKeyOf raw := by
  have groupMember := group_key_reachable_member program raw member
  have inUniverse : groupKeyOf raw ∈ insert (groupKeyOf []) (groups program) :=
    Finset.mem_insert_of_mem groupMember
  simp [encode, included, inUniverse]

private theorem reachable_read_head {Result : Type} (raw : RawInput)
    (next : RawDigest → Program Result) :
    raw ∈ reachable (.read raw next) := by
  change raw ∈ insert raw
    (Finset.univ.biUnion fun digest : RawDigest => reachable (next digest))
  exact Finset.mem_insert_self _ _

private theorem reachable_read_continuation {Result : Type} (raw : RawInput)
    (next : RawDigest → Program Result) (answer : RawDigest) (input : RawInput)
    (member : input ∈ reachable (next answer)) :
    input ∈ reachable (.read raw next) := by
  change input ∈ insert raw
    (Finset.univ.biUnion fun digest : RawDigest => reachable (next digest))
  exact Finset.mem_insert_of_mem (Finset.mem_biUnion.mpr
    ⟨answer, Finset.mem_univ _, member⟩)

attribute [local irreducible]
  SmzaRp05ExecutableAddressCompiler.reachable

/-- Every address in an arbitrary answer branch lies in the executable
compiler's all-digest support for this same fixed program. -/
theorem answer_log_input_reachable {Result Output : Type}
    (decode : RawInput → Output → RawDigest) (program : Program Result)
    (branch : Branches decode program) (call : RawInput × Output)
    (member : call ∈ answerLog decode program branch) :
    call.1 ∈ reachable program := by
  induction program generalizing call with
  | done result => simp only [answerLog, List.not_mem_nil] at member
  | read raw next ih =>
      rcases branch with ⟨answer, tail⟩
      change call ∈
        (raw, answer) :: answerLog decode (next (decode raw answer)) tail at member
      rcases List.mem_cons.mp member with head | below
      · cases head
        exact reachable_read_head raw next
      · have tailReach := ih (decode raw answer) tail call below
        exact reachable_read_continuation raw next (decode raw answer) call.1 tailReach

/-- The exact finite-key representation premise required by grouped claim
retention, now derived for every branch without restricting to an observed
or accepted path. -/
theorem answer_log_group_keys_represented {Result : Type}
    {Output : Type} (decode : RawInput → Output → RawDigest)
    (program : Program Result) (branch : Branches decode program) :
    ∀ call ∈ answerLog decode program branch,
      included program (encode program call.1) = groupKeyOf call.1 := by
  intro call member
  exact included_encode_of_reachable program call.1
    (answer_log_input_reachable decode program branch call member)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteGroupedProgram
