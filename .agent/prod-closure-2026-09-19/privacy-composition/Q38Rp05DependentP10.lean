import Q38Rp05RecordedRequest

/-! Current dependent D -> PIOP -> S -> final -> nonce -> index P10.
The physical oracle below is fixed only in the denotational finite-sum
identity. No oracle measurement or table-dependent operation is added.
This source is uncompiled and is not the complete adaptive game theorem. -/
namespace HegemonCrypto.SmallWood.Q38Rp05DependentP10

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05CurrentP10
open HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05RecordedRequest
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram (certifyOpening)
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

/-- These fields are the public information available immediately after
the D-indexed PIOP prefix. They have no source-witness argument. -/
structure DynamicStage (dsl : RelationDsl) (statement : Statement) where
  parameters : Parameters dsl statement
  gamma : Gamma Goldilocks
  hashFpp : DigestRegister
  pending : Bool
  tree : List (List DigestRegister)

def dynamicStage
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (oracle : Rp05OtherRawInput bound → DigestRegister) (reply : D) :
    DynamicStage dsl statement :=
  let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement
    salt labels widthBound
  let stage := NonleafProgram.interpret oracle (decsPrefix shape)
  let result := NonleafProgram.interpret oracle (piopSuffix shape stage reply)
  ⟨decodedParameters dsl statement result.piopGamma,
   decodedQ38DecsGamma result.decsGamma, result.hashFpp,
   sourcePendingFailure (sourcePendingFailure false result.decsGamma)
     result.piopGamma, result.tree⟩

def dynamicDigest
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    {dsl : RelationDsl} {statement : Statement}
    (stage : DynamicStage dsl statement)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (transcript : Q) : DigestRegister :=
  oracle (currentFinalKey bound (by omega) stage.hashFpp transcript)

def dynamicOpening
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    {dsl : RelationDsl} {statement : Statement}
    (stage : DynamicStage dsl statement)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (transcript : Q) : Option ComputedOpening :=
  certifyOpening (NonleafProgram.interpret oracle
    (rp05ChooseOpening bound (by omega)
      (dynamicDigest largeEnough stage oracle transcript) stage.pending))

def dynamicPoints (abortPoints : Fin 6 → Goldilocks)
    (opening : Option ComputedOpening) : Fin 6 → Goldilocks :=
  match opening with
  | none => abortPoints
  | some result => result.points

def dynamicChooseCore
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (abortPoints : Fin 6 → Goldilocks)
    (stage : DynamicStage dsl statement)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (transcript : Q) (digest : DigestRegister)
    (opening : Option ComputedOpening) :
    WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      Earlier Goldilocks → Option (Targets
        (dynamicPoints abortPoints opening)) :=
  match opening with
  | none => fun _ _ _ => none
  | some result => currentChooseTargets bound largeEnough dsl statement stage.parameters
      result transcript digest oracle

def dynamicChoose
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (abortPoints : Fin 6 → Goldilocks)
    (stage : DynamicStage dsl statement)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (transcript : Q) :
    WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      Earlier Goldilocks → Option (Targets
        (dynamicPoints abortPoints
          (dynamicOpening largeEnough stage oracle transcript))) :=
  dynamicChooseCore largeEnough dsl statement abortPoints stage oracle transcript
    (dynamicDigest largeEnough stage oracle transcript)
    (dynamicOpening largeEnough stage oracle transcript)

/-- The actual nonce and index outcomes are consumed once by both bytes and
oracle reconstruction. `observe` can run any subsequent oracle program on
`currentPublicOpenedOracleFromRecorded` using precisely this record/view. -/
def dynamicKernel
    {bound : Nat} {Value : Type*} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (tapes : TapeTable) (stage : DynamicStage dsl statement)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (reply : D) (transcript : Q) (view : PartialView Goldilocks)
    (observe : RequestRecord dsl statement → PartialView Goldilocks →
      Except String (List Byte) → Value) : Value :=
  let digest := dynamicDigest largeEnough stage oracle transcript
  match dynamicOpening largeEnough stage oracle transcript with
  | none => observe
      ⟨stage.parameters, stage.gamma, reply, transcript, digest,
        stage.tree, .nonceAbort⟩ view
      (.error "smallwood opening nonce trial limit exhausted")
  | some opening =>
    let selected := NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement stage.parameters opening.points
          transcript view.1 view.2.1) view.2.2.1 opening.pendingFailure)
    observe ⟨stage.parameters, stage.gamma, reply, transcript, digest,
        stage.tree, .opened opening selected⟩ view
      (selectedBytes dsl statement stage.parameters opening stage.gamma
        reply transcript digest salt stage.tree tapes view selected)

/-- The concrete observer used at the physical-game join. It consumes the
recorded selector outcome, reconstructs its 38 public leaf writes, and runs
the actual arbitrary successor program on the original old-H fiber state.
It performs no selector/nonce reads and introduces no replacement state. -/
def dynamicContinuationObservation
    {bound : Nat} {Work : Type} [Fintype Work]
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (record : RequestRecord dsl statement) (view : PartialView Goldilocks)
    (bytes : Except String (List Byte)) : ℝ :=
  run true (next bytes)
    (currentPublicOpenedOracleFromRecorded bound dsl statement
      record.parameters record.gamma record.reply record.coefficients salt
      tapes labels view record.postFinal oldOracle) state

/-- Exact normalized P10 with actual D-dependent PIOP parameters and
S-dependent final/nonce reads on the current partition. The source RHS is
witness-free; abort points are mathematical padding only, and the actual
nonce-abort kernel ignores that padding. This does not supply the remaining
physical-family/recorded-prefix equivalence as an assumption. -/
theorem current_dependent_p10_normalized
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (values : WitnessPackingValues Goldilocks)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0)
    (abortTargets : Targets abortPoints)
    (tapes : TapeTable) (oracle : Rp05OtherRawInput bound → DigestRegister)
    (observe : RequestRecord dsl statement → PartialView Goldilocks →
      Except String (List Byte) → ℝ) :
    let stages := dynamicStage largeEnough dsl statement salt labels widthBound oracle
    let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement salt
      labels widthBound
    let gamma := decodedQ38DecsGamma
      (NonleafProgram.interpret oracle (decsPrefix shape)).decsGamma
    let parameters := fun reply (_ : Unit) => (stages reply).parameters
    let points := fun reply (_ : Unit) transcript =>
      dynamicPoints abortPoints
        (dynamicOpening largeEnough (stages reply) oracle transcript)
    let choose := fun reply (_ : Unit) transcript =>
      dynamicChoose largeEnough dsl statement abortPoints (stages reply) oracle transcript
    let kernel := fun reply (_ : Unit) transcript view =>
      dynamicKernel largeEnough dsl statement salt tapes (stages reply)
        oracle reply transcript view observe
    sourceRequestAverage dsl statement gamma values parameters points choose kernel =
      publicRequestAverage points choose kernel := by
  dsimp only
  apply source_request_average_eq_public_request_average
  · intro reply branch transcript
    cases h : dynamicOpening largeEnough
      (dynamicStage largeEnough dsl statement salt labels widthBound oracle reply)
      oracle transcript with
    | none => exact abortAdmissible
    | some opening => exact computed_opening_interpolation_admissible opening
  · intro reply branch transcript index
    cases h : dynamicOpening largeEnough
      (dynamicStage largeEnough dsl statement salt labels widthBound oracle reply)
      oracle transcript with
    | none => exact abortNonzero index
    | some opening => exact computed_opening_points_nonzero opening index
  · intro reply branch transcript
    cases h : dynamicOpening largeEnough
      (dynamicStage largeEnough dsl statement salt labels widthBound oracle reply)
      oracle transcript with
    | none => exact abortTargets
    | some opening =>
      exact ⟨HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler.indexedPoints
          (fun index : Fin 38 => ⟨index.val, by omega⟩),
        indexed_targets_admissible opening.points
          (computed_opening_points_distinct opening)
          (fun index : Fin 38 => ⟨index.val, by omega⟩)
          (by intro left right same
              exact Fin.ext (congrArg (fun index : LeafIndex => index.val) same))⟩

end
end HegemonCrypto.SmallWood.Q38Rp05DependentP10
