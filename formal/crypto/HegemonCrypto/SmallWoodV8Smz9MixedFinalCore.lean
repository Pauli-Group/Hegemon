import HegemonCrypto.SmallWoodV8Smz9MixedNonleaf
import HegemonCrypto.SmallWoodV8Smz9MixedLiteralWrites
import HegemonCrypto.SmallWoodV8Smz9PostFinalProgram

namespace HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame V8Smz9DynamicRequest
open V8Smz9HonestHybrid V8Smz9HonestOpeningSchedule
open V8Smz9DynamicTransport V8Smz9DynamicPhysicalTransport V8Smz9PostFinalProgram
open V8Smz9CurrentPublicContext V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution
open V8Smz9HonestWholeViewGames (GameState RandomSource)
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical ENNReal

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000

variable {Work : Type} [Fintype Work] {bound : Nat}

attribute [local irreducible] sourcePrefinal nonleafCompile sourcePostFinalBytesProgram
  sourcePublicPostFinalBytes actualLeafOverlay V8Smz9MixedMaskCompiler.actualLeafWrites

/-- Public source parameters and a fixed witness. This contains no oracle,
oracle-dependent state, sampled transcript, or endpoint-equality hypothesis. -/
structure RequestContext (bound : Nat) where
  largeEnough : 37434 ≤ bound
  statementBinding : List Nat
  bindingFits : 15704 + 8 * statementBinding.length ≤ bound
  statement : V8PublicStatement
  values : WitnessPackingValues Goldilocks
  salt : SaltBytes
  retainedRows : Nat
  rowBound : retainedRows ≤ 20605

abbrev ByteResult := Except String (List CanonicalBytes.Byte)

def uniformCoins (A : Type) [Fintype A] [Nonempty A] : RandomSource :=
  ⟨A, inferInstance, inferInstance⟩

def retainedPending (stage : PrefinalResult) : Bool :=
  sourcePendingFailure (sourcePendingFailure false stage.decsGamma) stage.piopGamma

/-- Recover Q and M only from the pre-final result retained by execution and
the full sampled T. In particular this does not re-read a post-update oracle. -/
def recoveredMasks (context : RequestContext bound) (base : SourceRemainingCoins Goldilocks)
    (stage : PrefinalResult) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) : JointMaskCoins Goldilocks :=
  jointMaskInverse (sourceDecodedDecsGamma stage.decsGamma)
    (currentJointHeads context.values base) base.2.2
    (currentJointUnmasked context.statement
      (fun _ => sourceDecodedPiopGamma context.retainedRows stage.piopGamma) context.values base)
    (response, transcript)

def transportedMasks (context : RequestContext bound)
    (oracle : OtherRawInput bound → DigestRegister) (labels : LeafIndex → DigestRegister)
    (base : SourceRemainingCoins Goldilocks) (output : JointMaskOutputs Goldilocks) :
    JointMaskCoins Goldilocks :=
  jointMaskInverse
    (sourcePublicDecsGamma bound (by have := context.largeEnough; omega)
      context.statementBinding context.bindingFits context.salt context.retainedRows context.rowBound oracle labels)
    (currentJointHeads context.values base) base.2.2
    (currentJointUnmasked context.statement
      (sourcePublicBatching bound (by have := context.largeEnough; omega)
        context.statementBinding context.bindingFits context.salt context.retainedRows context.rowBound oracle labels)
      context.values base) output

theorem recovered_masks_are_transport (context : RequestContext bound)
    (oracle : OtherRawInput bound → DigestRegister) (labels : LeafIndex → DigestRegister)
    (base : SourceRemainingCoins Goldilocks) (output : JointMaskOutputs Goldilocks) :
    recoveredMasks context base
      (sourcePublicPrefinal bound (by have := context.largeEnough; omega)
        context.statementBinding context.bindingFits context.salt context.retainedRows context.rowBound
        oracle labels output.1) output.1 output.2 =
      transportedMasks context oracle labels base output := by
  have gamma := source_prefinal_decs_gamma_independent bound (by have := context.largeEnough; omega)
    context.statementBinding context.bindingFits context.salt labels output.1 0
    context.retainedRows context.rowBound oracle
  unfold recoveredMasks transportedMasks sourcePublicDecsGamma
  simp only [sourcePublicPrefinal] at gamma ⊢
  rw [gamma]
  simp only [jointMaskInverse, currentJointUnmasked, sourcePublicBatching, sourcePublicPrefinal]

def postFinalBytes (context : RequestContext bound) (base : SourceRemainingCoins Goldilocks)
    (stage : PrefinalResult) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (tapes : LeafIndex → LeafTape) : NonleafProgram (OtherRawInput bound) ByteResult :=
  sourcePostFinalBytesProgram bound context.largeEnough
    (statementParameters context.statement (sourceDecodedPiopGamma context.retainedRows stage.piopGamma))
    (sourceDecodedDecsGamma stage.decsGamma) response transcript digest (retainedPending stage)
    context.values base context.salt stage.tree tapes

def oldByteContinuation (context : RequestContext bound) (base : SourceRemainingCoins Goldilocks)
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (tapes : LeafIndex → LeafTape) (_labels : LeafIndex → DigestRegister)
    (stage : PrefinalResult) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister) (_pending : Bool) :
    V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work :=
  NonleafProgram.compile (postFinalBytes context base stage response transcript digest tapes) next

/-- The event continuation first samples still-independent source base coins
and tapes, then performs every current leaf write and the real byte program.
Both game bits execute these writes; only the preceding final event is selected. -/
def randomPair (A B : Type) [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (next : A → B → MixedProgram (FullRawInput bound) Work) : MixedProgram (FullRawInput bound) Work :=
  .random (uniformCoins A) fun first => .random (uniformCoins B) (next first)

theorem random_pair_execution (A B : Type) [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (randomized : Bool) (next : A → B → MixedProgram (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run randomized (randomPair A B next) oracle state =
      uniformAverage (fun first : A => uniformAverage (fun second : B =>
        V8Smz9MixedMaskCompiler.run randomized (next first second) oracle state)) := rfl

theorem written_nonleaf_fixed_execution (randomized : Bool)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister)
    (program : NonleafProgram (OtherRawInput bound) ByteResult)
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run randomized
      (V8Smz9MixedMaskCompiler.actualLeafWrites values base masks salt tapes labels
        (nonleafCompile program (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))))
      oracle state =
    V8Smz9HonestWholeViewGames.run true (NonleafProgram.compile program next)
      (actualLeafOverlay oracle values base masks salt tapes labels) state := by
  rw [V8Smz9MixedMaskCompiler.actual_leaf_writes_execution, nonleaf_compile_fixed_program,
    V8Smz9MixedMaskCompiler.fixed_program_execution]

theorem random_pair_mass (A B : Type) [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (cap : ℝ≥0∞) (next : A → B → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ first second, V8Smz9MixedMaskCompiler.InputMassAtMost cap (next first second)) :
    V8Smz9MixedMaskCompiler.InputMassAtMost cap (randomPair A B next) := remaining

theorem random_pair_program_bound (A B : Type) [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (next : A → B → MixedProgram (FullRawInput bound) Work) (programs : Nat)
    (remaining : ∀ first second, V8Smz9MixedMaskCompiler.programmingCount (next first second) ≤ programs) :
    V8Smz9MixedMaskCompiler.programmingCount (randomPair A B next) ≤ programs := by
  exact Finset.sup_le fun first _ => Finset.sup_le fun second _ => remaining first second

def afterFinal (context : RequestContext bound) (labels : LeafIndex → DigestRegister)
    (stage : PrefinalResult) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (next : ByteResult → MixedProgram (FullRawInput bound) Work) : MixedProgram (FullRawInput bound) Work :=
  randomPair (SourceRemainingCoins Goldilocks) (LeafIndex → LeafTape) fun base tapes =>
      V8Smz9MixedMaskCompiler.actualLeafWrites context.values base
        (recoveredMasks context base stage response transcript) context.salt tapes labels
        (nonleafCompile (postFinalBytes context base stage response transcript digest tapes) next)



end
end HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational
