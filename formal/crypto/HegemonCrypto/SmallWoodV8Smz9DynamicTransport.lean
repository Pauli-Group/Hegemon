import HegemonCrypto.SmallWoodV8Smz9DynamicRequest

/-! Same-oracle transport for the actually computed source responses.
All public challenge functions below are interpretations of the existing
source programs against one fixed nonleaf table. The dynamic response is
proved to be the triangular Q/M forward map before the finite coin transport
is applied. Arbitrary observations retain old masks and the whole oracle.
-/

namespace HegemonCrypto.SmallWood.V8Smz9DynamicTransport

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9RuntimeRandomness V8Smz9HonestHybrid V8Smz9EagerPrivacy
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9SingleProofPrivacy V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9CurrentPublicContext V8Smz9CurrentProgramPiop V8Smz9ZeroKnowledge
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestLeafBatch
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule V8Smz9DynamicRequest
open V8Smz9RuntimeDistribution V8Smz9WholeViewObservation V8Smz9RawCounterCompiler
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

attribute [local irreducible] allSourceMerkleLevels sourceFieldXof

structure PrefinalShape (Other : Type) where
  build : NonleafProgram Other (DigestRegister × List (List DigestRegister))
  rootKey : DigestRegister → Other
  decs : DigestRegister → NonleafProgram Other (Option (List FieldWord))
  piopKey : DigestRegister → DecsFullCoefficients Goldilocks → Other
  piop : DigestRegister → NonleafProgram Other (Option (List FieldWord))

def PrefinalShape.fixed {Other : Type} (shape : PrefinalShape Other)
    (response : DecsFullCoefficients Goldilocks) : NonleafProgram Other PrefinalResult :=
  NonleafProgram.bind shape.build fun built =>
    .read (shape.rootKey built.1) fun firstHash =>
      NonleafProgram.bind (shape.decs firstHash) fun gamma =>
        .read (shape.rootKey built.1) fun hashMt =>
          .read (shape.piopKey hashMt response) fun hashFpp =>
            NonleafProgram.bind (shape.piop hashFpp) fun batching =>
              .done ⟨built.2, hashMt, gamma, hashFpp, batching⟩

def PrefinalShape.dynamic {Other : Type} (shape : PrefinalShape Other)
    (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks) :
    NonleafProgram Other (PrefinalResult × DecsFullCoefficients Goldilocks) :=
  NonleafProgram.bind shape.build fun built =>
    .read (shape.rootKey built.1) fun firstHash =>
      NonleafProgram.bind (shape.decs firstHash) fun gamma =>
        .read (shape.rootKey built.1) fun hashMt =>
          .read (shape.piopKey hashMt (respond gamma)) fun hashFpp =>
            NonleafProgram.bind (shape.piop hashFpp) fun batching =>
              .done (⟨built.2, hashMt, gamma, hashFpp, batching⟩, respond gamma)

theorem PrefinalShape.gamma_independent {Other : Type} (shape : PrefinalShape Other)
    (oracle : Other → DigestRegister) (left right : DecsFullCoefficients Goldilocks) :
    (NonleafProgram.interpret oracle (shape.fixed left)).decsGamma =
      (NonleafProgram.interpret oracle (shape.fixed right)).decsGamma := by
  simp only [PrefinalShape.fixed, NonleafProgram.interpret_bind, NonleafProgram.interpret]

theorem PrefinalShape.dynamic_exact {Other : Type} (shape : PrefinalShape Other)
    (oracle : Other → DigestRegister) (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks) :
    NonleafProgram.interpret oracle (shape.dynamic respond) =
      let response := respond (NonleafProgram.interpret oracle (shape.fixed 0)).decsGamma
      (NonleafProgram.interpret oracle (shape.fixed response), response) := by
  simp only [PrefinalShape.fixed, PrefinalShape.dynamic,
    NonleafProgram.interpret_bind, NonleafProgram.interpret]

def sourcePrefinalShape (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605) : PrefinalShape (OtherRawInput bound) where
  build := allSourceMerkleLevels bound (by omega) labels
  rootKey := fun root =>
    let words := sourceSaltWords salt ++ sourceDigestWords root ++ statementBinding
    sourceCounterKey bound SmallWoodTranscript.merkleRootDomain words
      (by simp only [words, sourceSaltWords, List.length_append, List.length_ofFn, source_digest_word_count]
          have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
          rw [role]; omega)
      (by simp only [words, sourceSaltWords, List.length_append, List.length_ofFn, source_digest_word_count]
          have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
          rw [role]; omega) ⟨0, by norm_num⟩
  decs := fun digest => sourceFieldXof bound SmallWoodTranscript.decsCoefficientDomain (sourceDigestWords digest)
    (by rw [source_digest_word_count]
        have role : SmallWoodTranscript.decsCoefficientDomain.length = 41 := by decide
        rw [role]; omega)
    (by rw [source_digest_word_count]; decide) 700 (by norm_num)
  piopKey := fun digest response =>
    let words := sourceDigestWords digest ++ sourceResponseWords response ++ statementBinding
    sourceCounterKey bound SmallWoodTranscript.piopInputDomain words
      (by simp only [words, List.length_append, source_digest_word_count, source_response_word_count]
          have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
          rw [role]; omega)
      (by simp only [words, List.length_append, source_digest_word_count, source_response_word_count]
          have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
          rw [role]; omega) ⟨0, by norm_num⟩
  piop := fun digest => sourceFieldXof bound SmallWoodTranscript.piopCoefficientDomain (sourceDigestWords digest)
    (by rw [source_digest_word_count]
        have role : SmallWoodTranscript.piopCoefficientDomain.length = 41 := by decide
        rw [role]; omega)
    (by rw [source_digest_word_count]; decide)
    (sourceGammaWordRequest retainedRows) (by unfold sourceGammaWordRequest; omega)

theorem source_prefinal_is_shape (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605) :
    sourcePrefinal bound largeEnough statementBinding bindingFits salt labels response retainedRows rowBound =
      (sourcePrefinalShape bound largeEnough statementBinding bindingFits salt labels retainedRows rowBound).fixed response := rfl

theorem source_dynamic_prefinal_is_shape (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605) :
    sourceDynamicPrefinal bound largeEnough statementBinding bindingFits salt labels respond retainedRows rowBound =
      (sourcePrefinalShape bound largeEnough statementBinding bindingFits salt labels retainedRows rowBound).dynamic respond := rfl

/-- The DECS challenge does not depend on the later response D. The apparent
use of a zero-response reference here projects only the earlier sampled words;
it does not add any reads to the executed source program. -/
theorem source_prefinal_decs_gamma_independent
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (left right : DecsFullCoefficients Goldilocks) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) :
    (NonleafProgram.interpret oracle
      (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels left retainedRows rowBound)).decsGamma =
    (NonleafProgram.interpret oracle
      (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels right retainedRows rowBound)).decsGamma := by
  simp only [source_prefinal_is_shape]
  exact PrefinalShape.gamma_independent _ oracle left right

/-- Reading gamma, computing D, and continuing is exactly the fixed-D source
schedule at the computed D. Both failure flags and every digest are retained. -/
theorem source_dynamic_prefinal_exact_execution
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
      (sourceDynamicPrefinal bound largeEnough statementBinding bindingFits salt labels respond retainedRows rowBound) =
      let gammaWords := (NonleafProgram.interpret oracle
        (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels 0 retainedRows rowBound)).decsGamma
      let response := respond gammaWords
      (NonleafProgram.interpret oracle
        (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels response retainedRows rowBound), response) := by
  simp only [source_dynamic_prefinal_is_shape, source_prefinal_is_shape]
  exact PrefinalShape.dynamic_exact _ oracle respond

def sourcePublicPrefinal (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister)
    (labels : LeafIndex → DigestRegister) (response : DecsFullCoefficients Goldilocks) : PrefinalResult :=
  NonleafProgram.interpret oracle
    (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels response retainedRows rowBound)

def sourcePublicDecsGamma (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) (labels : LeafIndex → DigestRegister) : DecsGamma Goldilocks :=
  sourceDecodedDecsGamma
    (sourcePublicPrefinal bound largeEnough statementBinding bindingFits salt retainedRows rowBound oracle labels 0).decsGamma

def sourcePublicBatching (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) : Fin 5 → Nat → Goldilocks :=
  sourceDecodedPiopGamma retainedRows
    (sourcePublicPrefinal bound largeEnough statementBinding bindingFits salt retainedRows rowBound oracle labels response).piopGamma

def sourceDynamicOutputs (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (labels : LeafIndex → DigestRegister) : JointMaskOutputs Goldilocks :=
  let computed := NonleafProgram.interpret oracle
    (sourceDynamicPrefinal bound largeEnough statementBinding bindingFits salt labels
      (sourceComputedDecsResponse values base masks) retainedRows rowBound)
  (computed.2, sourceComputedPiopTranscript statement values base masks retainedRows computed.1.piopGamma)

/-- The forward map is the actually executed dynamic source response, with
both gamma functions read from the same fixed raw nonleaf table. -/
theorem source_dynamic_outputs_are_joint_forward
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (labels : LeafIndex → DigestRegister) :
    sourceDynamicOutputs bound largeEnough statementBinding bindingFits statement values salt retainedRows rowBound
      oracle base masks labels =
    jointMaskForward
      (sourcePublicDecsGamma bound largeEnough statementBinding bindingFits salt retainedRows rowBound oracle labels)
      (currentJointHeads values base) base.2.2
      (currentJointUnmasked statement
        (sourcePublicBatching bound largeEnough statementBinding bindingFits salt retainedRows rowBound oracle labels)
        values base) masks := by
  unfold sourceDynamicOutputs
  rw [source_dynamic_prefinal_exact_execution]
  apply Prod.ext
  · rfl
  · exact current_response_is_affine_mask_map _ _ _

/-- Exact chronological Q/M transport for the computed public hash history.
The observer retains the full original masks, so this equality preserves the
actual hidden leaf inputs and any complete physical future using their table. -/
theorem chronological_dynamic_source_transport
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister)
    (observe : SourceRemainingCoins Goldilocks → (LeafIndex → DigestRegister) →
      JointMaskCoins Goldilocks → JointMaskOutputs Goldilocks → ℝ) :
    uniformAverage (fun base => uniformAverage (fun masks => uniformAverage (fun labels =>
      observe base labels masks (sourceDynamicOutputs bound largeEnough statementBinding bindingFits
        statement values salt retainedRows rowBound oracle base masks labels)))) =
    uniformAverage (fun labels => uniformAverage (fun output => uniformAverage (fun base =>
      observe base labels
        (jointMaskInverse
          (sourcePublicDecsGamma bound largeEnough statementBinding bindingFits salt retainedRows rowBound oracle labels)
          (currentJointHeads values base) base.2.2
          (currentJointUnmasked statement
            (sourcePublicBatching bound largeEnough statementBinding bindingFits salt retainedRows rowBound oracle labels)
            values base) output) output))) := by
  simp_rw [source_dynamic_outputs_are_joint_forward]
  exact chronological_joint_mask_real_transport
    (sourcePublicDecsGamma bound largeEnough statementBinding bindingFits salt retainedRows rowBound oracle)
    (currentJointHeads values) (fun base => base.2.2)
    (fun base labels => currentJointUnmasked statement
      (sourcePublicBatching bound largeEnough statementBinding bindingFits salt retainedRows rowBound oracle labels)
      values base) observe

end
end HegemonCrypto.SmallWood.V8Smz9DynamicTransport
