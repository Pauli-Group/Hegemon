import Q38Rp05OpeningSchedule
import Q38Rp05PostFinalPure

/-!
# Post-final request on current SMZA physical inputs

Only the pure q38 field/serializer definitions are reused from the prior
compiler. Every oracle read here uses the corrected current raw complement
and the SMZA profile. This is a source construction, not a checked full
privacy or accepted-execution endpoint.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9WholeViewObservation
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped Classical

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

def currentOpeningKey (bound : Nat) (largeEnough : 39162 ≤ bound)
    (digest : DigestRegister) (heads : PublicCombinationHeads Goldilocks)
    (tails : Earlier Goldilocks) : Rp05OtherRawInput bound :=
  rp05SourceCounterKey bound SmallWoodTranscript.decsOpeningDomain
    (openingWords digest heads tails)
    (by rw [opening_word_count]
        have role : SmallWoodTranscript.decsOpeningDomain.length = 37 := by decide
        rw [role]
        omega)
    (by rw [opening_word_count]
        have role : SmallWoodTranscript.decsOpeningDomain.length = 37 := by decide
        rw [role]
        decide) ⟨0, by norm_num⟩

def currentFixedIndexKey (bound : Nat) (largeEnough : 39162 ≤ bound)
    (digest : DigestRegister) (counter : Fin (2 ^ 64)) : Rp05OtherRawInput bound :=
  rp05SourceCounterKey bound SmallWoodTranscript.decsFixedSamplingDomain
    (sourceDigestWords digest)
    (by rw [source_digest_word_count]
        have role : SmallWoodTranscript.decsFixedSamplingDomain.length = 44 := by decide
        rw [role]
        omega)
    (by rw [source_digest_word_count]
        have role : SmallWoodTranscript.decsFixedSamplingDomain.length = 44 := by decide
        rw [role]
        decide) counter

def currentFixedIndexXof (bound : Nat) (largeEnough : 39162 ≤ bound)
    (digest : DigestRegister) :
    NonleafProgram (Rp05OtherRawInput bound) (Option (List FieldWord)) :=
  sourceFieldReadLoop 50 [] (List.ofFn fun index : Fin 11 =>
    currentFixedIndexKey bound largeEnough digest ⟨index.val, by omega⟩)

def currentSelectIndices (bound : Nat) (largeEnough : 39162 ≤ bound)
    (points : Fin 6 → Goldilocks) (pointsDistinct : Function.Injective points)
    (digest : DigestRegister) (heads : PublicCombinationHeads Goldilocks)
    (tails : Earlier Goldilocks) (pending : Bool) :
    NonleafProgram (Rp05OtherRawInput bound) (SelectionResult points) :=
  .read (currentOpeningKey bound largeEnough digest heads tails) fun challenge =>
    NonleafProgram.bind (currentFixedIndexXof bound largeEnough challenge) fun sampled =>
      .done ⟨challenge, sampled,
        sampledTargets points pointsDistinct (sourceReturnedWords 50 sampled),
      sourcePendingFailure pending sampled⟩

/-- Physical continuation view for the current post-final request.  Keep this
small compiler helper local so this leaf does not depend on
`Q38Rp05SelectedContinuation`, whose complete-request import would create a
cycle through `Q38Rp05CurrentCompleteRequest`. -/
def currentSelectedPhysicalView
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (reply : D)
    {points : Fin 6 → Goldilocks}
    (job : SelectionResult points) : PartialView Goldilocks :=
  (sourceWitnessOpenings values points base.1,
   sourcePcsFullView points (pcsBase points q reply) base.2.1,
   earlier points base.2.2,
   job.targets.map fun targets =>
     fullSubset (currentHeads values base q) base.2.2
       (indexedPoints targets.val))

def currentHonestSelectedProgram
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable) :
    NonleafProgram (Rp05OtherRawInput bound) (Except String (List Byte)) :=
  let witness := sourceWitnessOpenings values opening.points base.1
  let pcs := sourcePcsFullView opening.points
    (pcsBase opening.points q reply) base.2.1
  NonleafProgram.bind
    (currentSelectIndices bound largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points transcript witness pcs)
      (earlier opening.points base.2.2) opening.pendingFailure)
    fun result => .done (selectedBytes dsl statement parameters opening gamma
      reply transcript digest salt tree tapes
      (currentSelectedPhysicalView values base q reply result) result)

def currentHonestPostFinalProgram
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable) :
    NonleafProgram (Rp05OtherRawInput bound) (Except String (List Byte)) :=
  NonleafProgram.bind (rp05ChooseOpening bound (by omega) digest pending)
    fun nonceResult =>
      match certifyOpening nonceResult with
      | none => .done (.error "smallwood opening nonce trial limit exhausted")
      | some opening => currentHonestSelectedProgram bound largeEnough dsl statement
          parameters opening values base q gamma reply transcript digest salt tree tapes

/-- Literal complete post-final execution at one physical oracle, including
both nonce and index exhaustion, with no oracle-aware view supplied externally. -/
theorem current_post_final_executes
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
      (currentHonestPostFinalProgram bound largeEnough dsl statement parameters
        values base q gamma reply transcript digest pending salt tree tapes) =
      match certifyOpening (NonleafProgram.interpret oracle
        (rp05ChooseOpening bound (by omega) digest pending)) with
      | none => .error "smallwood opening nonce trial limit exhausted"
      | some opening =>
          let result := NonleafProgram.interpret oracle
            (currentSelectIndices bound largeEnough opening.points
              (computed_opening_points_distinct opening) digest
              (combinationHeads dsl statement parameters opening.points transcript
                (sourceWitnessOpenings values opening.points base.1)
                (sourcePcsFullView opening.points
                  (pcsBase opening.points q reply) base.2.1))
              (earlier opening.points base.2.2) opening.pendingFailure)
          selectedBytes dsl statement parameters opening gamma reply transcript
            digest salt tree tapes (currentSelectedPhysicalView values base q reply result) result := by
  simp only [currentHonestPostFinalProgram, NonleafProgram.interpret_bind]
  cases certifyOpening (NonleafProgram.interpret oracle
    (rp05ChooseOpening bound (by omega) digest pending)) with
  | none => rfl
  | some opening =>
      simp only [currentHonestSelectedProgram, NonleafProgram.interpret_bind,
        NonleafProgram.interpret]

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
