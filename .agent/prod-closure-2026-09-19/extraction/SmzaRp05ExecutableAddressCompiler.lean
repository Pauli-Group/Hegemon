import SmzaRp05ExecutableAddressCore
import SmzaRp05GroupedSuffix

/-!
# Ex-ante finite address compiler for the executable read tree

SOURCE-ONLY, NOT COMPILED. `reachable` traverses ALL possible digest answers,
not only an accepted/observed path. Every fixed Program has a finite support
because its read continuation is indexed by the finite 512-bit output type.
`addressBound` is derived from that support; no key encoder, boundedness or
FiniteGroupPullback certificate is a caller input. Aborting branches count.

The finite raw key maps byte-injectively into Rp05FullRawInput addressBound;
its concrete group coordinate uses the existing exact groupAddress. The
finite grouped key universe is the image of this same ex-ante support, with
its inclusion injective by construction. Representatives satisfy the
existing counter-zero equation without assuming the queried counter zero.

BOUNDARY: this is a per-fixed-program compiler, not a uniform bound over all
proofs/adversaries and not a claim that addressBound <= 39162. Generic
Program.read accepts every List Byte, and standalone finish/rootInput and
fieldXof accept unbounded binding/role lists. The actual merkleProgram guards
binding/payload sizes before querying; a uniform protocol-wide bound still
requires that guarded constructor analysis and the missing complete verifier
composition. Likewise arbitrary adversary query addresses cannot be folded
into a uniform byte bound without an explicit machine/resource restriction.

The finite grouped universe below is selected before THIS program's answers,
not from accepted transcripts. It does not justify exchanging universes
between different proof-dependent programs inside a quantum experiment.
No oracle-state, physical retention, or complete execution refinement claim.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableAddressCompiler

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open V8SmzaOracleParser (RawInput RawDigest)
open Q38Rp05RawInputPartition
open SmzaRp05GroupedSuffix (GroupCounter groupAddress groupKeyOf groupCounterOf
  groupRepresentative groupZero group_address_injective group_representative_address)
open scoped Classical

set_option autoImplicit false
noncomputable section

def groups {Result : Type} (program : Program Result) : Finset SmzaRp05GroupedSuffix.GroupKey :=
  (reachable program).image groupKeyOf

abbrev GroupKey {Result : Type} (program : Program Result) := ↥(groups program)

def compileGroup {Result : Type} (program : Program Result) (key : RawKey program) :
    GroupKey program :=
  ⟨groupKeyOf key.val, Finset.mem_image.mpr ⟨key.val, key.property, rfl⟩⟩

def compileCoordinate {Result : Type} (program : Program Result) (key : RawKey program) :
    GroupKey program × GroupCounter :=
  (compileGroup program key, groupCounterOf key.val)

theorem compiled_group_counter {Result : Type} (program : Program Result)
    (key : RawKey program) :
    ((compileCoordinate program key).1.val, (compileCoordinate program key).2) =
      groupAddress (rp05RawBytes (compileRawKey program key)) := by
  rw [compiled_bytes]
  rfl

/-- The coordinate, not its group alone, is byte-injective. Different
counter queries in the same group are intentionally not conflated. -/
theorem compile_coordinate_injective {Result : Type} (program : Program Result) :
    Function.Injective (compileCoordinate program) := by
  intro left right equal
  apply Subtype.ext
  apply group_address_injective
  have same := congrArg (fun pair : GroupKey program × GroupCounter =>
    (pair.1.val, pair.2)) equal
  exact same

theorem group_inclusion_injective {Result : Type} (program : Program Result) :
    Function.Injective (fun key : GroupKey program => key.val) :=
  Subtype.val_injective

theorem every_reachable_group_covered {Result : Type} (program : Program Result)
    (raw : RawInput) (member : raw ∈ reachable program) :
    ∃ key : GroupKey program, key.val = groupKeyOf raw :=
  ⟨compileGroup program ⟨raw, member⟩, rfl⟩

def representative {Result : Type} (program : Program Result) (key : GroupKey program) :
    RawInput := groupRepresentative key.val

theorem representative_address {Result : Type} (program : Program Result)
    (key : GroupKey program) :
    groupAddress (representative program key) = (key.val, groupZero) :=
  group_representative_address key.val

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutableAddressCompiler
