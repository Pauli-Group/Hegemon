import Q38Rp05AdaptiveOpening
import Q38Rp05OpenedOverlay
import HegemonCrypto.SmallWoodV8Smz9DynamicRequest
import HegemonCrypto.SmallWoodV8Smz9SourceLifetime
import HegemonCrypto.SmallWoodV8Smz9EagerOracleGame

/-!
# RP05 request algebra model: physical-key transport still open

This is a new compiler, not a coercion of the 1,407-byte RP04 program.  Its
leaf calls use the 2,511-byte strict-v2 namespace.  The reusable non-leaf
grammar currently emits historical SMZ9-profile Merkle/counter-XOF keys,
not the live SMZA-profile keys. Its imported `OtherRawInput` also excludes
length 1407 instead of the current leaf length 2511. Consequently this sum
type does not yet give an injective physical-oracle address model. See
`Q38Rp05RawInputPartition` for the corrected partition and an explicit
counterexample to the legacy partition. The algebra model serializes the
current five-by-406 DECS answer and requests exactly five times the RP05 DSL
width for the PIOP batching stream.
No theorem here establishes live RP05 execution until both key transports
are supplied. The historical helpers must not be globally relabelled SMZA.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05RequestCompiler

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestFinalGame
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestHybrid
open HegemonCrypto.SmallWood.V8Smz9WholeViewObservation
open HegemonCrypto.SmallWood.V8Smz9DynamicRequest
open HegemonCrypto.SmallWood.V8Smz9SourceLifetime
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaSelectionFeedback
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05LeafNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped BigOperators Classical ENNReal

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

abbrev Other (bound : Nat) := OtherRawInput bound
abbrev Input (bound : Nat) := Rp05LeafInput ⊕ Other bound

/-- The two independent finite q38 sources.  In particular the tail has 38
coordinates and the DECS mask has 406, not the earlier q20 dimensions. -/
def rp05RemainingCoinsSource : RandomSource :=
  ⟨RemainingCoins Goldilocks, inferInstance, inferInstance⟩

def rp05JointMasksSource : RandomSource :=
  ⟨Q × D, inferInstance, inferInstance⟩

/-- The old compiler was hardwired to `LeafInput`.  This structurally
identical fold embeds only non-leaf keys and therefore applies to RP05. -/
def compileNonleaf {bound : Nat} {Result Work : Type} [Fintype Work] :
    NonleafProgram (Other bound) Result →
      (Result → Program (Input bound) Work) → Program (Input bound) Work
  | .done result, next => next result
  | .read input rest, next =>
      .honestRead (Sum.inr input) (fun output => compileNonleaf (rest output) next)

theorem compile_nonleaf_execution {bound : Nat} {Result Work : Type}
    [Fintype Work] (randomized : Bool)
    (program : NonleafProgram (Other bound) Result)
    (next : Result → Program (Input bound) Work)
    (oracle : Input bound → DigestRegister)
    (state : GameState (Input := Input bound) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run randomized
        (compileNonleaf program next) oracle state =
      V8Smz9HonestWholeViewGames.run randomized
        (next (NonleafProgram.interpret
          (fun input => oracle (Sum.inr input)) program)) oracle state := by
  induction program with
  | done result => rfl
  | read input rest ih => exact ih _

def statementWords (statement : Statement) : List Nat :=
  List.ofFn fun word : Fin 138 => decodeLE (List.ofFn fun byte : Fin 8 =>
    statement ⟨8 * word.val + byte.val, by
      have := word.isLt
      have := byte.isLt
      simp only [preambleBytes]
      omega⟩)

theorem statement_word_count (statement : Statement) :
    (statementWords statement).length = 138 := by
  simp only [statementWords, List.length_ofFn]

def responseWords (response : D) : List Nat :=
  (List.ofFn fun polynomial : Fin 5 =>
    List.ofFn fun coefficient : Fin 406 =>
      fromGoldilocks (response polynomial coefficient)).flatten

theorem response_word_count (response : D) :
    (responseWords response).length = 2030 := by
  simp only [responseWords, List.length_flatten, List.map_ofFn, Function.comp_def,
    List.length_ofFn, List.sum_ofFn, Finset.sum_const, Finset.card_univ,
    Fintype.card_fin, smul_eq_mul]

def decodedParameters (dsl : RelationDsl) (statement : Statement)
    (sampled : Option (List V8Smz9WholeViewObservation.FieldWord)) :
    Parameters dsl statement :=
  fun polynomial coordinate =>
    ((sourceReturnedWords (5 * dsl.width statement) sampled).getD
      (polynomial.val * dsl.width statement + coordinate.val) 0).val

/-- The first answer is computed at the just-read 700-word DECS challenge.
It is the current q38 5x406 coordinate, not the historical 5x388 carrier. -/
def decsReply (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks)
    (masks : Q × D)
    (sampled : Option (List V8Smz9WholeViewObservation.FieldWord)) : D :=
  V8SmzaMathPrivacy.response (decodedQ38DecsGamma sampled)
    (currentHeads values base masks.1) base.2.2 masks.2

def transcript (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks)
    (masks : Q × D) (sampled : Option
      (List V8Smz9WholeViewObservation.FieldWord)) : Q :=
  Q38Rp05ChronologicalAlgebra.response dsl statement
    (decodedParameters dsl statement sampled)
    (sourceWitnessPolynomials values base.1) masks.1

/-- Current response-indexed non-leaf schedule.  Both sampler failures remain
in `PrefinalResult`; no failure branch resets or replaces the database. -/
def rp05Prefinal (bound : Nat) (largeEnough : 25029 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks)
    (masks : Q × D)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24) :
    NonleafProgram (Other bound) (PrefinalResult × D) :=
  let binding := statementWords statement
  let rootWords := fun root => sourceSaltWords salt ++ sourceDigestWords root ++ binding
  let rootKey := fun root => sourceCounterKey bound
    SmallWoodTranscript.merkleRootDomain (rootWords root)
      (by simp only [rootWords, binding, sourceSaltWords, List.length_append,
        List.length_ofFn, source_digest_word_count, statement_word_count]
          have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
          rw [role]
          omega)
      (by simp only [rootWords, binding, sourceSaltWords, List.length_append,
        List.length_ofFn, source_digest_word_count, statement_word_count]
          have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
          rw [role]
          omega) ⟨0, by norm_num⟩
  NonleafProgram.bind (allSourceMerkleLevels bound (by omega) labels) fun built =>
    .read (rootKey built.1) fun firstHash =>
      NonleafProgram.bind
        (sourceFieldXof bound SmallWoodTranscript.decsCoefficientDomain
          (sourceDigestWords firstHash)
          (by rw [source_digest_word_count]
              have role : SmallWoodTranscript.decsCoefficientDomain.length = 41 := by decide
              rw [role]
              omega)
          (by rw [source_digest_word_count]; decide) 700 (by norm_num)) fun decsGamma =>
        let reply := decsReply values base masks decsGamma
        .read (rootKey built.1) fun hashMt =>
          let piopWords := sourceDigestWords hashMt ++ responseWords reply ++ binding
          let inputKey := sourceCounterKey bound SmallWoodTranscript.piopInputDomain
            piopWords
            (by simp only [piopWords, binding, List.length_append, source_digest_word_count,
              response_word_count, statement_word_count]
                have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
                rw [role]
                omega)
            (by simp only [piopWords, binding, List.length_append, source_digest_word_count,
              response_word_count, statement_word_count]
                have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
                rw [role]
                omega) ⟨0, by norm_num⟩
          .read inputKey fun hashFpp =>
            NonleafProgram.bind
              (sourceFieldXof bound SmallWoodTranscript.piopCoefficientDomain
                (sourceDigestWords hashFpp)
                (by rw [source_digest_word_count]
                    have role : SmallWoodTranscript.piopCoefficientDomain.length = 41 := by decide
                    rw [role]
                    omega)
                (by rw [source_digest_word_count]; decide)
                (5 * dsl.width statement) widthBound) fun piopGamma =>
              .done (⟨built.2, hashMt, decsGamma, hashFpp, piopGamma⟩, reply)

/-- The same literal RP05 non-leaf program exposed in the measured chronology
shape.  This is used to retain the complete answer-conditioned PIOP trace in
the privacy kernel instead of projecting it to a detached field list. -/
def rp05PrefinalShape (bound : Nat) (largeEnough : 25029 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24) :
    Q38PrefinalShape (Other bound) :=
  let binding := statementWords statement
  let rootWords := fun root => sourceSaltWords salt ++ sourceDigestWords root ++ binding
  let rootKey := fun root => sourceCounterKey bound
    SmallWoodTranscript.merkleRootDomain (rootWords root)
      (by simp only [rootWords, binding, sourceSaltWords, List.length_append,
        List.length_ofFn, source_digest_word_count, statement_word_count]
          have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
          rw [role]
          omega)
      (by simp only [rootWords, binding, sourceSaltWords, List.length_append,
        List.length_ofFn, source_digest_word_count, statement_word_count]
          have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
          rw [role]
          omega) ⟨0, by norm_num⟩
  {
    build := allSourceMerkleLevels bound (by omega) labels
    rootKey := rootKey
    decs := fun firstHash =>
      sourceFieldXof bound SmallWoodTranscript.decsCoefficientDomain
        (sourceDigestWords firstHash)
        (by rw [source_digest_word_count]
            have role : SmallWoodTranscript.decsCoefficientDomain.length = 41 := by decide
            rw [role]
            omega)
        (by rw [source_digest_word_count]; decide) 700 (by norm_num)
    piopKey := fun hashMt reply =>
      let piopWords := sourceDigestWords hashMt ++ responseWords reply ++ binding
      sourceCounterKey bound SmallWoodTranscript.piopInputDomain piopWords
        (by simp only [piopWords, binding, List.length_append, source_digest_word_count,
          response_word_count, statement_word_count]
            have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
            rw [role]
            omega)
        (by simp only [piopWords, binding, List.length_append, source_digest_word_count,
          response_word_count, statement_word_count]
            have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
            rw [role]
            omega) ⟨0, by norm_num⟩
    piop := fun hashFpp =>
      sourceFieldXof bound SmallWoodTranscript.piopCoefficientDomain
        (sourceDigestWords hashFpp)
        (by rw [source_digest_word_count]
            have role : SmallWoodTranscript.piopCoefficientDomain.length = 41 := by decide
            rw [role]
            omega)
        (by rw [source_digest_word_count]; decide)
        (5 * dsl.width statement) widthBound
  }

theorem rp05_prefinal_is_measured_dynamic (bound : Nat)
    (largeEnough : 25029 ≤ bound) (dsl : RelationDsl) (statement : Statement)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24) :
    rp05Prefinal bound largeEnough dsl statement salt labels values base masks widthBound =
      (rp05PrefinalShape bound largeEnough dsl statement salt labels widthBound).dynamic
        (decsReply values base masks) := by
  rfl

structure RequestResult where
  tapes : LeafIndex → LeafTape
  labels : LeafIndex → DigestRegister
  stage : PrefinalResult
  decs : D
  piop : Q
  digest : DigestRegister
  failed : Bool

/-- Full successor request prefix through the final transcript hash.  All
leaves, non-leaf reads and the arbitrary later continuation execute against
one persistent oracle.  Witness data enters only the honest leaf/response
formulas; the continuation receives the public request result. -/
def requestPrefix {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 25029 ≤ bound) (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : RequestResult → Program (Input bound) Work) :
    Program (Input bound) Work :=
  .random rp05RemainingCoinsSource fun base =>
    .random rp05JointMasksSource fun masks =>
      rp05LeafBatch 8388608 id statement salt
        (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
        fun tapes labels =>
          compileNonleaf
            (rp05Prefinal bound largeEnough dsl statement salt labels values base masks widthBound)
            fun computed =>
              let piop := transcript dsl statement values base masks computed.1.piopGamma
              .honestRead (Sum.inr (sourceFinalOtherKey bound largeEnough
                (sourceDigestPrefix computed.1.hashFpp) piop)) fun digest =>
                  next ⟨tapes, labels, computed.1, computed.2, piop, digest,
                    sourcePendingFailure
                      (sourcePendingFailure false computed.1.decsGamma)
                      computed.1.piopGamma⟩

/-- The non-leaf portion is executable, so its observed result is exactly the
interpretation of the literal counter-key program on the current oracle. -/
theorem request_nonleaf_execution {bound : Nat} {Work : Type} [Fintype Work]
    (randomized : Bool) (largeEnough : 25029 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : (PrefinalResult × D) → Program (Input bound) Work)
    (oracle : Input bound → DigestRegister)
    (state : GameState (Input := Input bound) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run randomized
        (compileNonleaf
          (rp05Prefinal bound largeEnough dsl statement salt labels values base masks widthBound)
          next) oracle state =
      V8Smz9HonestWholeViewGames.run randomized
        (next (NonleafProgram.interpret (fun input => oracle (Sum.inr input))
          (rp05Prefinal bound largeEnough dsl statement salt labels values base masks widthBound)))
        oracle state :=
  compile_nonleaf_execution randomized _ next oracle state

structure PublicResult where
  stage : PrefinalResult
  decs : D
  piop : Q
  digest : DigestRegister
  failed : Bool

/-- Literal post-leaf continuation used by the adaptive game.  It recomputes
the Merkle root from the retained public labels, samples the current-width
RP05 challenges, and reads the final transcript key before continuing. -/
def requestContinuation {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 25029 ≤ bound) (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : PublicResult → Program (Input bound) Work) : Program (Input bound) Work :=
  compileNonleaf
    (rp05Prefinal bound largeEnough dsl statement salt labels values base masks widthBound)
    fun computed =>
      let piop := transcript dsl statement values base masks computed.1.piopGamma
      .honestRead (Sum.inr (sourceFinalOtherKey bound largeEnough
        (sourceDigestPrefix computed.1.hashFpp) piop)) fun digest =>
          next ⟨computed.1, computed.2, piop, digest,
            sourcePendingFailure
              (sourcePendingFailure false computed.1.decsGamma)
              computed.1.piopGamma⟩

/-- End-to-end RP05 adaptive leaf-erasure endpoint for the executable request
continuation.  It specializes the two-stage theorem to the actual physical
leaf serializer and current relation compiler; no privacy probability or
per-request indistinguishability statement is supplied as a hypothesis. -/
theorem request_adaptive_opening_bound {bound : Nat} {Work Job : Type}
    [Fintype Work] [Fintype Job]
    (randomized : Bool) (largeEnough : 25029 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (selecPrefix : Selection (Input bound) Work Job)
    (selected : Job → Fin 38 → LeafIndex)
    (distinct : ∀ job, Function.Injective (selected job))
    (next : (job : Job) →
      (Opened (q38Unopened (selected job)) → LeafTape) →
        PublicResult → Program (Input bound) Work)
    (queries : Nat)
    (bounded : ∀ job visible,
      queryCount (requestContinuation largeEnough dsl statement values base masks
        salt labels widthBound (next job visible)) ≤ queries)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other bound → DigestRegister)
    (state : GameState (Input := Input bound) (Work := Work))
    (normalized : ‖state‖ = 1) :
    |fullGame randomized selecPrefix (fun job => q38Unopened (selected job))
        (fun job visible => requestContinuation largeEnough dsl statement values
          base masks salt labels widthBound (next job visible))
        old other labels statement salt
        (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2) state -
      publicGame randomized selecPrefix (fun job => q38Unopened (selected job))
        (fun job visible => requestContinuation largeEnough dsl statement values
          base masks salt labels widthBound (next job visible))
        old other labels statement salt
        (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2) state| ≤
      4 * ((exposures selecPrefix : ℝ) + queries) / (2 ^ 256 : ℝ) :=
  Q38Rp05AdaptiveOpening.q38_adaptive_opening_bound
    (Other := Other bound) (Work := Work) (Job := Job)
    randomized selecPrefix selected distinct
    (fun job visible => requestContinuation largeEnough dsl statement values
      base masks salt labels widthBound (next job visible))
    old other labels statement salt
    (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
    queries bounded state normalized

end
end HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
