import HegemonCrypto.SmallWoodV8Smz9AdjacentComposition
import HegemonCrypto.SmallWoodV8Smz9HonestLeafBatch

/-! Chronological source request prefix with actually computed responses.
The DECS response is formed only after its actual challenge read. The PIOP
transcript is formed only after its actual batching challenge read. The final
digest is then an ordinary read at that exact transcript input. This gives a
leaf-only honest/randomized program on one persistent oracle.

This is the atomic prefix through h_piop. Fallible post-final opening and proof
serialization remain continuations; this does not assert a complete endpoint. -/

namespace HegemonCrypto.SmallWood.V8Smz9DynamicRequest

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9RuntimeRandomness V8Smz9JointAlgebraicLaw V8Smz9HonestHybrid
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9SingleProofPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9CurrentPublicContext V8Smz9CurrentProgramPiop V8Smz9ZeroKnowledge
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestLeafBatch
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler
open V8Smz9PrivacyGameComposition V8Smz9RuntimeDistribution
open V8Smz9WholeViewObservation
open V8Smz9RawCounterCompiler
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

/-- Actual chunks_exact(140) allocation of the 700 DECS field words,
including the source poison output when its XOF rejects. -/
def sourceDecodedDecsGamma (result : Option (List FieldWord)) : DecsGamma Goldilocks :=
  fun polynomial row => ((sourceReturnedWords 700 result).getD (polynomial.val * 140 + row.val) 0).val

/-- Actual chunks_exact(max(830, retainedRows)) PIOP allocation. The source
shares this matrix across nonlinear and retained linear constraints. -/
def sourceDecodedPiopGamma (retainedRows : Nat) (result : Option (List FieldWord)) :
    Fin 5 → Nat → Goldilocks :=
  fun polynomial row => ((sourceReturnedWords (sourceGammaWordRequest retainedRows) result).getD
    (polynomial.val * max 830 retainedRows + row) 0).val

def sourceDynamicPrefinal (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks) (retainedLinearRows : Nat)
    (rowBound : retainedLinearRows ≤ 20605) :
    NonleafProgram (OtherRawInput bound) (PrefinalResult × DecsFullCoefficients Goldilocks) :=
  let rootWords := fun root => sourceSaltWords salt ++ sourceDigestWords root ++ statementBinding
  let rootKey := fun root => sourceCounterKey bound SmallWoodTranscript.merkleRootDomain (rootWords root)
    (by simp only [rootWords, sourceSaltWords, List.length_append, List.length_ofFn,
      source_digest_word_count]; have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
        rw [role]; omega)
    (by simp only [rootWords, sourceSaltWords, List.length_append, List.length_ofFn,
      source_digest_word_count]; have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
        rw [role]; omega) ⟨0, by norm_num⟩
  NonleafProgram.bind (allSourceMerkleLevels bound (by omega) labels) fun built =>
    .read (rootKey built.1) fun firstHashMt =>
      NonleafProgram.bind
        (sourceFieldXof bound SmallWoodTranscript.decsCoefficientDomain (sourceDigestWords firstHashMt)
          (by rw [source_digest_word_count]; have role : SmallWoodTranscript.decsCoefficientDomain.length = 41 := by decide
              rw [role]; omega)
          (by rw [source_digest_word_count]; decide) 700 (by norm_num)) fun decsGamma =>
        let response := respond decsGamma
        .read (rootKey built.1) fun hashMt =>
          let piopInputWords := sourceDigestWords hashMt ++ sourceResponseWords response ++ statementBinding
          let inputKey := sourceCounterKey bound SmallWoodTranscript.piopInputDomain piopInputWords
            (by simp only [piopInputWords, List.length_append, source_digest_word_count,
              source_response_word_count]; have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
                rw [role]; omega)
            (by simp only [piopInputWords, List.length_append, source_digest_word_count,
              source_response_word_count]; have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
                rw [role]; omega) ⟨0, by norm_num⟩
          .read inputKey fun hashFpp =>
            NonleafProgram.bind
              (sourceFieldXof bound SmallWoodTranscript.piopCoefficientDomain (sourceDigestWords hashFpp)
                (by rw [source_digest_word_count]; have role : SmallWoodTranscript.piopCoefficientDomain.length = 41 := by decide
                    rw [role]; omega)
                (by rw [source_digest_word_count]; decide)
                (sourceGammaWordRequest retainedLinearRows)
                (by unfold sourceGammaWordRequest; omega)) fun piopGamma =>
              .done (⟨built.2, hashMt, decsGamma, hashFpp, piopGamma⟩, response)


/-- The source forms D=C(gamma,heads,tails)+M, not a caller-supplied public
response. gamma is obtained from the just-executed commitment hash schedule. -/
def sourceComputedDecsResponse (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (sampled : Option (List FieldWord)) : DecsFullCoefficients Goldilocks :=
  exactDecsResponse (sourceDecodedDecsGamma sampled)
    (currentJointHeads values base masks.1) base.2.2 masks.2

/-- T is the current-program PIOP response at the original source masks and
the actual decoded batching words, not a fresh response substituted in advance. -/
def sourceComputedPiopTranscript (statement : V8PublicStatement)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (retainedRows : Nat)
    (sampled : Option (List FieldWord)) : PiopCoefficients Goldilocks :=
  currentResponseCoefficients (statementParameters statement (sourceDecodedPiopGamma retainedRows sampled))
    (sourceWitnessPolynomials values base.1) masks.1

theorem source_computed_response_is_joint_coordinate
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (sampled : Option (List FieldWord)) :
    sourceComputedDecsResponse values base masks sampled =
      exactDecsUnmaskedCoefficients (sourceDecodedDecsGamma sampled)
        (currentJointHeads values base masks.1) base.2.2 + masks.2 := rfl

theorem source_computed_transcript_is_affine_coordinate
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (retainedRows : Nat) (sampled : Option (List FieldWord)) :
    sourceComputedPiopTranscript statement values base masks retainedRows sampled =
      currentResponseCoefficients (statementParameters statement (sourceDecodedPiopGamma retainedRows sampled))
        (sourceWitnessPolynomials values base.1) 0 + masks.1 :=
  current_response_is_affine_mask_map _ _ _

variable {Work : Type} [Fintype Work]

def sourceComputedPrefix (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work) : Program (FullRawInput bound) Work :=
  NonleafProgram.compile
    (sourceDynamicPrefinal bound largeEnough statementBinding bindingFits salt labels
      (sourceComputedDecsResponse values base masks) retainedRows rowBound) fun computed =>
        let transcript := sourceComputedPiopTranscript statement values base masks retainedRows computed.1.piopGamma
        .honestRead (sourceFinalKey bound largeEnough (sourceDigestPrefix computed.1.hashFpp) transcript) fun digest =>
          next computed.1 computed.2 transcript digest
            (sourcePendingFailure (sourcePendingFailure false computed.1.decsGamma) computed.1.piopGamma)

attribute [local irreducible] V8Smz9HonestWholeViewGames.run InputMassAtMost sourceDynamicPrefinal

/-- Every raw source nonleaf call is a charged honest-read instruction. The
same table reaches the exact final digest read and then the arbitrary suffix. -/
theorem source_computed_prefix_execution (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (randomized : Bool) (oracle : FullRawInput bound → DigestRegister)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    run randomized (sourceComputedPrefix bound largeEnough statementBinding bindingFits statement values
      base masks salt labels retainedRows rowBound next) oracle initial =
      let computed := NonleafProgram.interpret (fun input => oracle (Sum.inr input))
        (sourceDynamicPrefinal bound largeEnough statementBinding bindingFits salt labels
          (sourceComputedDecsResponse values base masks) retainedRows rowBound)
      let transcript := sourceComputedPiopTranscript statement values base masks retainedRows computed.1.piopGamma
      run randomized (next computed.1 computed.2 transcript
        (oracle (sourceFinalKey bound largeEnough (sourceDigestPrefix computed.1.hashFpp) transcript))
        (sourcePendingFailure (sourcePendingFailure false computed.1.decsGamma) computed.1.piopGamma))
        oracle initial := by
  unfold sourceComputedPrefix
  rw [NonleafProgram.compiled_execution]
  simp only [V8Smz9HonestWholeViewGames.run]

theorem source_computed_prefix_preserves_mass (cap : ℝ≥0∞)
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (remaining : ∀ stageResult response transcript digest pending,
      InputMassAtMost cap (next stageResult response transcript digest pending)) :
    InputMassAtMost cap (sourceComputedPrefix bound largeEnough statementBinding bindingFits statement
      values base masks salt labels retainedRows rowBound next) := by
  apply NonleafProgram.compile_preserves_mass
  intro computed
  simp only [InputMassAtMost]
  intro digest
  exact remaining _ _ _ _ _

/-- Full actual source leaf inputs precede the dynamic source response
schedule. The callback retains the source tape vector for later selected leaf
openings. No leaf table is reset on a later public error. -/
def sourceAllLeavesThenComputedPrefix (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work) : Program (FullRawInput bound) Work :=
  allCurrentSourceLeaves values base masks salt fun tapes labels =>
    sourceComputedPrefix bound largeEnough statementBinding bindingFits statement values base masks salt labels
      retainedRows rowBound (next tapes labels)

theorem source_all_leaves_computed_prefix_mass (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (remaining : ∀ tapes labels stageResult response transcript digest pending,
      InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next tapes labels stageResult response transcript digest pending)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
      (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits statement
        values base masks salt retainedRows rowBound next) := by
  apply source_leaf_batch_mass
  intro tapes labels
  exact source_computed_prefix_preserves_mass _ bound largeEnough statementBinding bindingFits statement
    values base masks salt labels retainedRows rowBound (next tapes labels) (remaining tapes labels)

/-- Actual leaf-only reprogramming comparison for the full computed prefix.
The continuation is included in every syntactic query/program/mass bound.
The external premise is the universal adaptive-reprogramming theorem only. -/
theorem source_all_leaves_computed_prefix_reprogramming_bound
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (remaining : ∀ tapes labels stageResult response transcript digest pending,
      InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next tapes labels stageResult response transcript digest pending))
    (initial : GameState (Input := FullRawInput bound) (Work := Work))
    (queries leaves : Nat) (normalized : ‖initial‖ = 1)
    (queryBound : queryCount (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding
      bindingFits statement values base masks salt retainedRows rowBound next) ≤ queries)
    (leafBound : programmingCount (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding
      bindingFits statement values base masks salt retainedRows rowBound next) ≤ leaves) :
    |acceptance true (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits
        statement values base masks salt retainedRows rowBound next) initial -
      acceptance false (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits
        statement values base masks salt retainedRows rowBound next) initial| ≤
      (leaves : ℝ) * (Real.sqrt ((queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) +
        (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) :=
  measured_adaptive_leaf_game_bound ghhm _ initial queries leaves normalized queryBound leafBound
    (source_all_leaves_computed_prefix_mass bound largeEnough statementBinding bindingFits statement
      values base masks salt retainedRows rowBound next remaining)

end
end HegemonCrypto.SmallWood.V8Smz9DynamicRequest
