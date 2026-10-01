import Q38Rp05AdaptiveScheduler
import Q38Rp05StoppedCore

/-! The stopped-prefix mass ledger keeps the original H-indexed family.
No branch is normalized and no second independent H is sampled. -/
namespace HegemonCrypto.SmallWood.Q38Rp05StoppedMass

open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05RecordedRequest
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 1000000

universe u
variable {Input Work : Type} {Job : Type u} [Fintype Input] [DecidableEq Input]
variable [Fintype Work]


section CurrentPrefix

variable {bound : Nat}
local notation "CurrentInput" => Rp05FullRawInput bound
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

def nonleafPrefix {Result : Type} :
    NonleafProgram (Rp05OtherRawInput bound) Result →
    (Result → Prefix CurrentInput Work Job) → Prefix CurrentInput Work Job
  | .done result, next => next result
  | .read input rest, next => .honestRead (.inr input)
      (fun answer => nonleafPrefix (rest answer) next)

/-- The false-game leaf instruction is the original uniform tape draw followed
by the actual current answer read, not a new independent digest label. -/
def realLeafPrefix : (count : Nat) → (Fin count → LeafIndex) → Statement → SaltBytes →
    (Fin count → Fin 1176 → Byte) →
    ((Fin count → LeafTape) → (Fin count → DigestRegister) →
      Prefix CurrentInput Work Job) → Prefix CurrentInput Work Job
  | 0, _, _, _, _, next => next Fin.elim0 Fin.elim0
  | count + 1, indices, statement, salt, data, next =>
    .random (uniformSource LeafTape) fun tape =>
    .honestRead (.inl (rp05SourceLeafInput statement salt (data 0) (indices 0) tape))
      fun answer => realLeafPrefix count (fun i => indices i.succ) statement salt
        (fun i => data i.succ) fun tapes labels =>
          next (Fin.cons tape tapes) (Fin.cons answer labels)

def realRequestPrefix (data : Request bound)
    (next : Bytes → Prefix CurrentInput Work Job) : Prefix CurrentInput Work Job :=
  .random rp05RemainingCoinsSource fun base =>
  .random rp05JointMasksSource fun masks =>
  realLeafPrefix 8388608 id data.statement data.salt
    (q38PhysicalSuffix (currentHeads data.witness base masks.1) base.2.2 masks.2)
    fun tapes labels =>
  nonleafPrefix (recordedPrefix data.largeEnough data.dsl data.statement
    data.witness data.salt data.widthBound base masks labels) fun record =>
  next (recordBytes data.dsl data.statement data.witness base masks.1 data.salt
    tapes record)

/-- The pending pivot carries the literal request data and already-compiled
public suffix. It cannot inspect an H-indexed family or normalize a branch. -/
abbrev Pivot (bound : Nat) (Work : Type) [Fintype Work] :=
  Request bound × (Bytes → V8Smz9MixedMaskCompiler.MixedProgram (Rp05FullRawInput bound) Work)

def stopBefore : {requests : Nat} → Nat → Schedule bound Work requests →
    Prefix CurrentInput Work (Pivot bound Work)
  | _, _, .finish event => .finish event
  | _, skip, .gate operation next => .gate operation (stopBefore skip next)
  | _, skip, .quantumQuery next => .quantumQuery (stopBefore skip next)
  | _, skip, .honestRead input next =>
      .honestRead input (fun answer => stopBefore skip (next answer))
  | _, skip, .instrument operation next =>
      .instrument operation (fun outcome => stopBefore skip (next outcome))
  | _, skip, .random source next =>
      .random source (fun coins => stopBefore skip (next coins))
  | _, 0, .request data next =>
      .pivot (data, fun bytes => hybrid 0 (next bytes))
  | _, skip + 1, .request data next =>
      realRequestPrefix data (fun bytes => stopBefore skip (next bytes))

/-- The actual full-schedule stopping condition, including early termination
and all real prior requests, inherits the mass ledger without a history factor. -/
theorem stopped_schedule_mass_le {requests : Nat}
    (schedule : Schedule bound Work requests) (skip : Nat)
    (family : Family CurrentInput Work) :
    arrivalMass (stopBefore skip schedule) family ≤ mass family :=
  stopped_mass_le _ _

end CurrentPrefix

end
end HegemonCrypto.SmallWood.Q38Rp05StoppedMass
