import Q38Rp05WholePrivacy
import Q38OpenedRows
import Q38Rp05PostFinalPure
import Q38Rp05RequestCompiler
import Q38MeasuredCmsNonleaf
import Q38Rp05LeafSupport
import Q38JointSimulatorR2
import Q38RemainingAlgebra
import Q38OpenedTapeConditioningR5
import HegemonCrypto.SmallWoodV8Smz9PostFinalProgram
import HegemonCrypto.SmallWoodV8Smz9HonestFinalGame
import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule
import HegemonCrypto.SmallWoodV8Smz9PrivacyGameComposition

/-!
# Literal RP05 q38 post-final compiler

This file deliberately does not reuse the q20 `IndexedTargets`, field carrier,
or `SMZ9` serializer.  It implements the profile-9 fixed fifty-candidate
selector, the 38-tail DECS transcript, the public q38 row reconstruction and
the `SMZA` byte order.  Both bounded samplers remain in the executable
`NonleafProgram`; no successful draw is conditioned into the definition.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler

open HegemonCrypto.CanonicalBytes HegemonCrypto.SmallWoodProofWire
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9WholeViewObservation
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestFinalGame
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9SourceIndexSampler
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram
open HegemonCrypto.SmallWood.V8Smz9PostFinalSerializer
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding
open HegemonCrypto.SmallWood.V8Smz9PiopOpeningRecovery
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaOpenedRows
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.V8SmzaSelectionFeedback
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "FieldWord" => HegemonCrypto.SmallWood.V8Smz9WholeViewObservation.FieldWord

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

def openingKey (bound : Nat) (largeEnough : 39162 ≤ bound)
    (digest : DigestRegister) (heads : Fin 12 → Fin 368 → Goldilocks)
    (tails : Earlier Goldilocks) : OtherRawInput bound :=
  sourceCounterKey bound SmallWoodTranscript.decsOpeningDomain
    (openingWords digest heads tails)
    (by rw [opening_word_count]
        have role : SmallWoodTranscript.decsOpeningDomain.length = 37 := by decide
        rw [role]
        omega)
    (by rw [opening_word_count]; decide) ⟨0, by norm_num⟩

def fixedIndexKey (bound : Nat) (largeEnough : 39162 ≤ bound)
    (digest : DigestRegister) (counter : Fin (2 ^ 64)) : OtherRawInput bound :=
  sourceCounterKey bound SmallWoodTranscript.decsFixedSamplingDomain
    (sourceDigestWords digest)
    (by rw [source_digest_word_count]
        have role : SmallWoodTranscript.decsFixedSamplingDomain.length = 44 := by decide
        rw [role]
        omega)
    (by rw [source_digest_word_count]; decide) counter

def fixedIndexXof (bound : Nat) (largeEnough : 39162 ≤ bound)
    (digest : DigestRegister) :
    NonleafProgram (OtherRawInput bound) (Option (List FieldWord)) :=
  sourceFieldReadLoop 50 [] (List.ofFn fun index : Fin 11 =>
    fixedIndexKey bound largeEnough digest ⟨index.val, by omega⟩)

/-- Exact embedding of a non-leaf source read schedule as the selection
grammar used by the retained-opening theorem.  No oracle answer or branch
state is projected away. -/
def asSelection {Other Work Result : Type} [Fintype Other] [Fintype Work] :
    NonleafProgram Other Result → Selection (Rp05LeafInput ⊕ Other) Work Result
  | .done result => .reveal result
  | .read input next => .honestRead (Sum.inr input) fun answer =>
      asSelection (next answer)

theorem execute_as_selection {Other Work Result : Type}
    [Fintype Other] [DecidableEq Other] [Fintype Work]
    (program : NonleafProgram Other Result)
    (kernel : PhysicalKernel (Input := Rp05LeafInput ⊕ Other) (Work := Work) Result)
    (oracle : Rp05LeafInput ⊕ Other → DigestRegister)
    (state : GameState (Input := Rp05LeafInput ⊕ Other) (Work := Work)) :
    execute (asSelection program) kernel.observe oracle state =
      kernel.observe (NonleafProgram.interpret (fun input => oracle (Sum.inr input)) program)
        state := by
  induction program generalizing state with
  | done result => rfl
  | read input next ih => exact ih (oracle (Sum.inr input)) state

def selectIndices (bound : Nat) (largeEnough : 39162 ≤ bound)
    (points : Fin 6 → Goldilocks) (pointsDistinct : Function.Injective points)
    (digest : DigestRegister) (heads : Fin 12 → Fin 368 → Goldilocks)
    (tails : Earlier Goldilocks) (pending : Bool) :
    NonleafProgram (OtherRawInput bound) (SelectionResult points) :=
  .read (openingKey bound largeEnough digest heads tails) fun challenge =>
    NonleafProgram.bind (fixedIndexXof bound largeEnough challenge) fun sampled =>
      .done ⟨challenge, sampled,
        sampledTargets points pointsDistinct (sourceReturnedWords 50 sampled),
        sourcePendingFailure pending sampled⟩

def defaultIndices : Fin 38 → LeafIndex :=
  fun index => ⟨index.val, index.isLt.trans (by decide)⟩

theorem default_indices_injective : Function.Injective defaultIndices := by
  intro left right same
  exact Fin.ext (congrArg (fun index : LeafIndex => index.val) same)

def selectedIndices {points : Fin 6 → Goldilocks}
    (result : SelectionResult points) : Fin 38 → LeafIndex :=
  match result.targets with
  | none => defaultIndices
  | some targets => targets.val

theorem selected_indices_injective {points : Fin 6 → Goldilocks}
    (result : SelectionResult points) : Function.Injective (selectedIndices result) := by
  cases chosen : result.targets with
  | none => simpa [selectedIndices, chosen] using default_indices_injective
  | some targets => simpa [selectedIndices, chosen] using targets.property.1

/-- P8/P9 instantiated with the literal q38 hash/XOF selector.  Exhaustion is
represented by the selector job and uses a fixed distinct dummy set only to
type the common error continuation; successful jobs use exactly the sampled
38 indices. -/
theorem select_indices_opening_bound
    {bound : Nat} {Work : Type} [Fintype Work]
    (randomized : Bool) (largeEnough : 39162 ≤ bound)
    (points : Fin 6 → Goldilocks) (pointsDistinct : Function.Injective points)
    (digest : DigestRegister) (heads : PublicCombinationHeads Goldilocks)
    (early : Earlier Goldilocks) (pending : Bool)
    (program : (job : SelectionResult points) →
      (Opened (q38Unopened (selectedIndices job)) → LeafTape) →
        Program (Rp05LeafInput ⊕ OtherRawInput bound) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : OtherRawInput bound → DigestRegister)
    (labels : LeafIndex → DigestRegister)
    (preamble : Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (queries : Nat) (bounded : ∀ job visible,
      queryCount (program job visible) ≤ queries)
    (state : GameState (Input := Rp05LeafInput ⊕ OtherRawInput bound) (Work := Work))
    (normalized : ‖state‖ = 1) :
    |fullGame randomized
        (asSelection (Other := OtherRawInput bound) (Work := Work)
          (Result := SelectionResult points)
          (selectIndices bound largeEnough points pointsDistinct digest heads early pending))
        (fun job => q38Unopened (selectedIndices job)) program old other labels
        preamble salt data state -
      publicGame randomized
        (asSelection (Other := OtherRawInput bound) (Work := Work)
          (Result := SelectionResult points)
          (selectIndices bound largeEnough points pointsDistinct digest heads early pending))
        (fun job => q38Unopened (selectedIndices job)) program old other labels
        preamble salt data state| ≤
      4 * ((exposures
        (asSelection (Other := OtherRawInput bound) (Work := Work)
          (Result := SelectionResult points)
          (selectIndices bound largeEnough points pointsDistinct digest heads early pending)) : ℝ) +
          queries) / (2 ^ 256 : ℝ) := by
  exact q38_adaptive_opening_bound randomized
    (asSelection (Other := OtherRawInput bound) (Work := Work)
      (Result := SelectionResult points)
      (selectIndices bound largeEnough points pointsDistinct digest heads early pending))
    selectedIndices selected_indices_injective program old other labels preamble salt data
    queries bounded state normalized

def chooseTargets (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (parameters : Parameters dsl statement)
    (opening : ComputedOpening) (transcript : Q) (digest : DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister) :
    WitnessOpeningView Goldilocks → SourcePcsView Goldilocks → Earlier Goldilocks →
      Option (Targets opening.points) :=
  fun witness pcs early =>
    ((NonleafProgram.interpret oracle
      (selectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points transcript witness pcs)
        early opening.pendingFailure)).targets).map targetValues

-- These are executable programs whose concrete read/XOF expansion is not
-- needed to type the state-kernel transport. Keep them symbolic at dependent
-- `Targets points` boundaries instead of normalizing the 50-candidate source
-- sampler during elaboration.
attribute [local irreducible] sourceComputedOpening chooseTargets fixedIndexXof

/-- Keep the selected/fallback point vector and its dependent chooser in one
pattern match. Splitting these into separate local matches makes Lean compare
`Targets (match selected with ...)` against `Targets opening.points` by
normalizing the executable nonce program. -/
def selectedPostFinalPoints (abortPoints : Fin 6 → Goldilocks) :
    Option ComputedOpening → Fin 6 → Goldilocks
  | none => abortPoints
  | some opening => opening.points

def selectedPostFinalChooser (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (abortPoints : Fin 6 → Goldilocks)
    (selected : Option ComputedOpening) (transcript : Q)
    (digest : DigestRegister) (oracle : OtherRawInput bound → DigestRegister) :
    WitnessOpeningView Goldilocks → SourcePcsView Goldilocks → Earlier Goldilocks →
      Option (Targets (selectedPostFinalPoints abortPoints selected)) :=
  match selected with
  | none => fun _ _ _ => none
  | some opening => chooseTargets bound largeEnough dsl statement parameters
      opening transcript digest oracle

attribute [local irreducible] selectedPostFinalPoints selectedPostFinalChooser

def selectedProgram (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (parameters : Parameters dsl statement)
    (opening : ComputedOpening) (gamma : Gamma Goldilocks) (reply : D)
    (transcript : Q) (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (view : PartialView Goldilocks) :
    NonleafProgram (OtherRawInput bound) (Except String (List Byte)) :=
  NonleafProgram.bind
    (selectIndices bound largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points transcript view.1 view.2.1)
      view.2.2.1 opening.pendingFailure)
    fun result => .done
      (selectedBytes dsl statement parameters opening gamma reply transcript digest
        salt tree tapes view result)

def postFinalProgram (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (view : PartialView Goldilocks) :
    NonleafProgram (OtherRawInput bound) (Except String (List Byte)) :=
  NonleafProgram.bind (sourceChooseOpening bound (by omega) digest pending) fun result =>
    match certifyOpening result with
    | none => .done (.error "smallwood opening nonce trial limit exhausted")
    | some opening => selectedProgram bound largeEnough dsl statement parameters opening gamma
        reply transcript digest salt tree tapes view

-- Preserve the literal bounded nonce and selector programs as opaque
-- computations at their type boundary. Their branch results are supplied by
-- `certify_actual_opening`; reducing the source XOF loops is not needed to
-- elaborate the dependent view or the state-kernel identity.
attribute [local irreducible] postFinalProgram selectIndices
  sourceChooseOpening sourceChooseOpeningLoop sourceOpeningXof sourceOpeningValid

/-- Literal execution factorization.  This is the actual bounded nonce
program followed by the actual q38 challenge and serializer, so the nonce
abort precedes index exhaustion and the field-XOF latch is checked only after
the selected public bytes have been constructed. -/
theorem post_final_program_executes (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (view : PartialView Goldilocks) (oracle : OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
      (postFinalProgram bound largeEnough dsl statement parameters gamma reply transcript
        digest pending salt tree tapes view) =
    match sourceComputedOpening bound (by omega) digest pending oracle with
    | none => .error "smallwood opening nonce trial limit exhausted"
    | some opening =>
        let result := NonleafProgram.interpret oracle
          (selectIndices bound largeEnough opening.points
            (computed_opening_points_distinct opening) digest
            (combinationHeads dsl statement parameters opening.points transcript view.1 view.2.1)
            view.2.2.1 opening.pendingFailure)
        selectedBytes dsl statement parameters opening gamma reply transcript digest
          salt tree tapes view result := by
  simp only [postFinalProgram, NonleafProgram.interpret_bind,
    certify_actual_opening]
  cases opened : sourceComputedOpening bound (by omega) digest pending oracle with
  | none => rfl
  | some opening =>
      simp only [selectedProgram, NonleafProgram.interpret_bind,
        NonleafProgram.interpret]

/-- Concrete specialization of the state-kernel identity.  The continuation
is the interpretation of `selectedProgram` itself; no `kernelMatches`, desired
distribution, or per-request privacy premise is supplied. -/
theorem selected_program_is_public_state_kernel
    {Value : Type*} [AddCommMonoid Value]
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (parameters : Parameters dsl statement)
    (opening : ComputedOpening) (gamma : Gamma Goldilocks)
    (values : WitnessPackingValues Goldilocks) (digest : DigestRegister)
    (salt : SaltBytes) (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister)
    (observe : D → Q → Except String (List Byte) → Value) :
    (∑ base : RemainingCoins Goldilocks, ∑ q, ∑ m,
      let reply := V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m
      let publicTranscript := Q38Rp05ChronologicalAlgebra.response dsl statement parameters
        (sourceWitnessPolynomials values base.1) q
      let view := partialChronologicalView values opening.points
        (fun _ => pcsBase opening.points q reply)
        (fun witness pcs => physicalHeads (sourceWitnessPolynomials values witness) q pcs)
        (chooseTargets bound largeEnough dsl statement parameters opening publicTranscript
          digest oracle) base
      observe reply publicTranscript
        (NonleafProgram.interpret oracle
          (selectedProgram bound largeEnough dsl statement parameters opening gamma reply
            publicTranscript digest salt tree tapes view))) =
    ∑ reply, ∑ publicTranscript, ∑ view : RemainingView Goldilocks,
      let partialView := abortProjection
        (chooseTargets bound largeEnough dsl statement parameters opening publicTranscript
          digest oracle) view
      observe reply publicTranscript
        (NonleafProgram.interpret oracle
          (selectedProgram bound largeEnough dsl statement parameters opening gamma reply
            publicTranscript digest salt tree tapes partialView)) := by
  have transported := request_public_opening_state_kernel_sum
      (PublicBranch := Unit) (Value := Value) dsl statement gamma values
      (fun _reply _branch => parameters)
      (fun _reply _branch _transcript => opening.points)
      (fun _reply _branch _transcript => computed_opening_interpolation_admissible opening)
      (fun _reply _branch _transcript => computed_opening_points_nonzero opening)
      (fun _reply _branch _transcript =>
        ⟨indexedPoints (fun index : Fin 38 => ⟨index.val, index.isLt.trans (by decide)⟩),
          indexed_targets_admissible opening.points
            (computed_opening_points_distinct opening)
            (fun index : Fin 38 => ⟨index.val, index.isLt.trans (by decide)⟩)
            (by intro left right same
                exact Fin.ext (congrArg (fun index : LeafIndex => index.val) same))⟩)
      (fun _reply _branch transcript =>
        chooseTargets bound largeEnough dsl statement parameters opening transcript
          digest oracle)
      (fun reply _branch transcript view =>
        observe reply transcript
          (NonleafProgram.interpret oracle
            (selectedProgram bound largeEnough dsl statement parameters opening gamma reply
              transcript digest salt tree tapes view)))
  simpa using transported

/-- Actual D -> measured trace -> T -> opening -> post-final state-kernel
factorization.  The complete trace is the branch index and may carry its
answer-conditioned CMS/GameState in `observe`.  Nonce exhaustion is not
conditioned away: `postFinalProgram` is interpreted in the kernel on both
sides, and the abort branch uses an arbitrary fixed admissible coordinate
only to totalize the algebraic change of variables. -/
theorem measured_trace_post_final_state_kernel
    {Other : Type} {Value : Type*} [AddCommMonoid Value]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ opening, abortPoints opening ≠ 0)
    (abortTargets : Targets abortPoints)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister)
    (observe : D → PublicTrace DigestRegister fuel → Q →
      Except String (List Byte) → Value) :
    (∑ base : RemainingCoins Goldilocks, ∑ q, ∑ m,
      ∑ trace : PublicTrace DigestRegister fuel,
      let reply := V8SmzaMathPrivacy.response
        (decodedQ38DecsGamma stage.decsGamma)
        (currentHeads values base q) base.2.2 m
      let parameters := decodedParameters dsl statement
        (tracedPiopSample fuel shape stage reply trace)
      let publicTranscript := Q38Rp05ChronologicalAlgebra.response dsl statement
        parameters (sourceWitnessPolynomials values base.1) q
      let selected := sourceComputedOpening bound (by omega) digest pending oracle
      let points := selectedPostFinalPoints abortPoints selected
      let choose : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
          Earlier Goldilocks → Option (Targets points) :=
        selectedPostFinalChooser bound largeEnough dsl statement parameters
          abortPoints selected publicTranscript digest oracle
      let view := partialChronologicalView values points
        (fun _ => pcsBase points q reply)
        (fun witness pcs => physicalHeads (sourceWitnessPolynomials values witness) q pcs)
        choose base
      observe reply trace publicTranscript
        (NonleafProgram.interpret oracle
          (postFinalProgram bound largeEnough dsl statement parameters
            (decodedQ38DecsGamma stage.decsGamma) reply publicTranscript digest
            pending salt tree tapes view))) =
    ∑ reply, ∑ trace : PublicTrace DigestRegister fuel, ∑ publicTranscript,
      ∑ publicView : RemainingView Goldilocks,
      let parameters := decodedParameters dsl statement
        (tracedPiopSample fuel shape stage reply trace)
      let selected := sourceComputedOpening bound (by omega) digest pending oracle
      let points := selectedPostFinalPoints abortPoints selected
      let choose : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
          Earlier Goldilocks → Option (Targets points) :=
        selectedPostFinalChooser bound largeEnough dsl statement parameters
          abortPoints selected publicTranscript digest oracle
      let view := abortProjection choose publicView
      observe reply trace publicTranscript
        (NonleafProgram.interpret oracle
          (postFinalProgram bound largeEnough dsl statement parameters
            (decodedQ38DecsGamma stage.decsGamma) reply publicTranscript digest
            pending salt tree tapes view)) := by
  let selected := sourceComputedOpening bound (by omega) digest pending oracle
  let points : D → PublicTrace DigestRegister fuel → Q → Fin 6 → Goldilocks :=
    fun _ _ _ => selectedPostFinalPoints abortPoints selected
  let choose : ∀ reply trace transcript,
      WitnessOpeningView Goldilocks → SourcePcsView Goldilocks → Earlier Goldilocks →
        Option (Targets (points reply trace transcript)) :=
    fun reply trace transcript => selectedPostFinalChooser bound largeEnough
      dsl statement (decodedParameters dsl statement
        (tracedPiopSample fuel shape stage reply trace)) abortPoints selected
      transcript digest oracle
  let fallback : ∀ reply trace transcript, Targets (points reply trace transcript) :=
    fun _ _ _ => match chosen : selected with
      | none => by
          simpa only [points, chosen, selectedPostFinalPoints] using abortTargets
      | some opening => by
          let indices : Fin 38 → LeafIndex :=
            fun index => ⟨index.val, index.isLt.trans (by decide)⟩
          have distinct : Function.Injective indices := by
            intro left right same
            exact Fin.ext (congrArg (fun index : LeafIndex => index.val) same)
          simpa only [points, chosen, selectedPostFinalPoints] using
            (⟨indexedPoints indices, indexed_targets_admissible opening.points
              (computed_opening_points_distinct opening) indices distinct⟩
              : Targets opening.points)
  have transported := request_public_opening_state_kernel_sum
    (PublicBranch := PublicTrace DigestRegister fuel) (Value := Value)
    dsl statement (decodedQ38DecsGamma stage.decsGamma) values
    (fun reply trace => decodedParameters dsl statement
      (tracedPiopSample fuel shape stage reply trace)) points
    (fun _ _ _ => by
      cases chosen : selected with
      | none =>
          simpa only [points, chosen, selectedPostFinalPoints] using abortAdmissible
      | some opening =>
          simpa only [points, chosen, selectedPostFinalPoints] using
            computed_opening_interpolation_admissible opening)
    (fun _ _ _ index => by
      cases chosen : selected with
      | none =>
          simpa only [points, chosen, selectedPostFinalPoints] using abortNonzero index
      | some opening =>
          simpa only [points, chosen, selectedPostFinalPoints] using
            computed_opening_points_nonzero opening index)
    fallback choose
    (fun reply trace transcript view =>
      observe reply trace transcript
        (NonleafProgram.interpret oracle
          (postFinalProgram bound largeEnough dsl statement
            (decodedParameters dsl statement
              (tracedPiopSample fuel shape stage reply trace))
            (decodedQ38DecsGamma stage.decsGamma) reply transcript digest
            pending salt tree tapes view)))
  simpa only [points, choose] using transported

/-- The literal source-side probability/state mass of one RP05 request after
the measured prefinal trace.  This is a definition of the executable
post-final branch, not an abstract kernel supplied by a caller. -/
def measuredPostFinalSource
    {Other : Type} {Value : Type*} [AddCommMonoid Value]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (abortPoints : Fin 6 → Goldilocks)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister)
    (observe : D → PublicTrace DigestRegister fuel → Q →
      Except String (List Byte) → Value) : Value :=
  ∑ base : RemainingCoins Goldilocks, ∑ q, ∑ m,
    ∑ trace : PublicTrace DigestRegister fuel,
      let reply := V8SmzaMathPrivacy.response
        (decodedQ38DecsGamma stage.decsGamma)
        (currentHeads values base q) base.2.2 m
      let parameters := decodedParameters dsl statement
        (tracedPiopSample fuel shape stage reply trace)
      let publicTranscript := Q38Rp05ChronologicalAlgebra.response dsl statement
        parameters (sourceWitnessPolynomials values base.1) q
      let selected := sourceComputedOpening bound (by omega) digest pending oracle
      let points := selectedPostFinalPoints abortPoints selected
      let choose : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
          Earlier Goldilocks → Option (Targets points) :=
        selectedPostFinalChooser bound largeEnough dsl statement parameters
          abortPoints selected publicTranscript digest oracle
      let view := partialChronologicalView values points
        (fun _ => pcsBase points q reply)
        (fun witness pcs => physicalHeads
          (sourceWitnessPolynomials values witness) q pcs)
        choose base
      observe reply trace publicTranscript
        (NonleafProgram.interpret oracle
          (postFinalProgram bound largeEnough dsl statement parameters
            (decodedQ38DecsGamma stage.decsGamma) reply publicTranscript digest
            pending salt tree tapes view))

/-- Public middle experiment for `measuredPostFinalSource`.  Every summation
coordinate and every literal post-final read is public; in particular this
definition contains neither witness values nor a witness-dependent
continuation.  The latched sampler-failure branch remains present. -/
def measuredPostFinalPublic
    {Other : Type} {Value : Type*} [AddCommMonoid Value]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (abortPoints : Fin 6 → Goldilocks)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister)
    (observe : D → PublicTrace DigestRegister fuel → Q →
      Except String (List Byte) → Value) : Value :=
  ∑ reply, ∑ trace : PublicTrace DigestRegister fuel, ∑ publicTranscript,
    ∑ publicView : RemainingView Goldilocks,
      let parameters := decodedParameters dsl statement
        (tracedPiopSample fuel shape stage reply trace)
      let selected := sourceComputedOpening bound (by omega) digest pending oracle
      let points := selectedPostFinalPoints abortPoints selected
      let choose : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
          Earlier Goldilocks → Option (Targets points) :=
        selectedPostFinalChooser bound largeEnough dsl statement parameters
          abortPoints selected publicTranscript digest oracle
      let view := abortProjection choose publicView
      observe reply trace publicTranscript
        (NonleafProgram.interpret oracle
          (postFinalProgram bound largeEnough dsl statement parameters
            (decodedQ38DecsGamma stage.decsGamma) reply publicTranscript digest
            pending salt tree tapes view))

/-- Exact literal RP05 request factorization through a witness-free public
middle experiment. -/
theorem measured_post_final_source_eq_public
    {Other : Type} {Value : Type*} [AddCommMonoid Value]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ opening, abortPoints opening ≠ 0)
    (abortTargets : Targets abortPoints)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister)
    (observe : D → PublicTrace DigestRegister fuel → Q →
      Except String (List Byte) → Value) :
    measuredPostFinalSource fuel shape stage bound largeEnough dsl statement
        values abortPoints digest pending salt tree tapes oracle observe =
      measuredPostFinalPublic fuel shape stage bound largeEnough dsl statement
        abortPoints digest pending salt tree tapes oracle observe := by
  exact measured_trace_post_final_state_kernel fuel shape stage bound largeEnough
    dsl statement values abortPoints abortAdmissible abortNonzero abortTargets
    digest pending salt tree tapes oracle observe

/-- Concrete two-witness equality for the complete measured trace and literal
post-final compiler.  The common middle is `measuredPostFinalPublic`; hence
the continuation cannot recover either witness through the retained state. -/
theorem measured_post_final_two_witness
    {Other : Type} {Value : Type*} [AddCommMonoid Value]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (left right : WitnessPackingValues Goldilocks)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ opening, abortPoints opening ≠ 0)
    (abortTargets : Targets abortPoints)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : OtherRawInput bound → DigestRegister)
    (observe : D → PublicTrace DigestRegister fuel → Q →
      Except String (List Byte) → Value) :
    measuredPostFinalSource fuel shape stage bound largeEnough dsl statement
        left abortPoints digest pending salt tree tapes oracle observe =
      measuredPostFinalSource fuel shape stage bound largeEnough dsl statement
        right abortPoints digest pending salt tree tapes oracle observe := by
  calc
    _ = measuredPostFinalPublic fuel shape stage bound largeEnough dsl statement
          abortPoints digest pending salt tree tapes oracle observe :=
      measured_post_final_source_eq_public fuel shape stage bound largeEnough
        dsl statement left abortPoints abortAdmissible abortNonzero abortTargets
        digest pending salt tree tapes oracle observe
    _ = _ := (measured_post_final_source_eq_public fuel shape stage bound largeEnough
      dsl statement right abortPoints abortAdmissible abortNonzero abortTargets
      digest pending salt tree tapes oracle observe).symm

end
end HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
