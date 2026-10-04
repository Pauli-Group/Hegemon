import SmzaRp05CurrentMerklePublic
import HegemonCrypto.SmallWoodV8Smz9NoteSpongeFold

/-! Exact current RP05 output-note capacity/padding cells. Absorbed words
are reconstructed by the decoder; none is assumed zero. These 60 source
cells are a subset of the 75 emitted output-note family23 rows. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputFrame

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex rawIndex)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05CurrentMerklePublic
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation

set_option autoImplicit false

def noteCall (input : Fin 2) : Nat := if input.val = 0 then 75 else 78

abbrev NoteCell := Fin 2 × Fin 3 × Fin 16

def boundCell (cell : NoteCell) : Prop :=
  if cell.2.1.val < 2 then 8 ≤ cell.2.2.val else 2 ≤ cell.2.2.val

instance (cell : NoteCell) : Decidable (boundCell cell) := by
  unfold boundCell
  infer_instance

def localIndex (cell : NoteCell) : Nat :=
  let block := cell.2.1.val
  let lane := cell.2.2.val
  if cell.1.val = 0 then
    if block = 0 then lane - 6 else if block = 1 then lane + 7 else 23 + lane
  else 39 +
    if block = 0 then lane - 6 else if block = 1 then lane + 4 else 20 + lane

def sourceIndex (_cell : NoteCell) : Option Nat := none

def expectedTerms (cell : NoteCell) : List (Nat × Nat) :=
  let call := noteCall cell.1 + cell.2.1.val
  let lane := cell.2.2.val
  [(hashInitialIndex call lane, 1)] ++
    (if cell.2.1.val = 0 then [] else
      [(hashFinalIndex (call - 1) lane, 160)]) ++
    (sourceIndex cell).toList.map fun index => (index, 160)

def noteConstant (block lane : Nat) : Nat :=
  if block = 0 then
    if lane = 8 then 1 else if lane = 9 then 18
    else if lane = 10 then poseidon2V8SpongeModeMarker
    else if lane = 15 then poseidon2V8SuiteMarker else 0
  else if block = 2 ∧ lane = 11 then 1 else 0

def expectedConstant (cell : NoteCell) : Nat :=
  noteConstant cell.2.1.val cell.2.2.val

def expectedTarget (cell : NoteCell) : Nat :=
  let block := cell.2.1.val
  let lane := cell.2.2.val
  if block = 0 then
    if lane = 8 then 1 else if lane = 9 then 409
    else if lane = 10 then 540 else if lane = 15 then 541 else 0
  else if block = 2 ∧ lane = 11 then 1 else 0

/-- Every field is finite syntax of the current CSR. No field states a
witness-quantified sponge or commitment equality. -/
structure Certificate (components : RelationProgramComponents) where
  canonical : ({ expressions := components.csrExpressions, roots := [] } :
    ExpressionProgram).Canonical true
  one : Realizes components.csrExpressions 1 (.constant 1)
  negative : Realizes components.csrExpressions 160
    (.sub (.constant 0) (.constant 1))
  target : ∀ cell, Realizes components.csrExpressions
    (expectedTarget cell) (.constant (expectedConstant cell))
  attempt : ∀ cell : NoteCell, boundCell cell → CsrExecutableAttempt
  member : ∀ cell bound, attempt cell bound ∈ components.csrAttempts
  exactTerms : ∀ cell bound,
    (attempt cell bound).terms = expectedTerms cell
  exactTarget : ∀ cell bound,
    (attempt cell bound).targetRoot = expectedTarget cell

/-- The capacity cells per output, in their exact fixture emission order. -/
def boundedCells : List NoteCell :=
  (List.range 2).flatMap fun input =>
    (List.range 3).flatMap fun block =>
      (List.range 16).filterMap fun lane =>
        if h : input < 2 ∧ block < 3 ∧ lane < 16 then
          let cell : NoteCell :=
            (⟨input, h.1⟩, ⟨block, h.2.1⟩, ⟨lane, h.2.2⟩)
          if boundCell cell then some cell else none
        else none

/-- This exact attempt's `globalIndex` equals 18337 plus the fixture-local
offset. It is emitted with family23 and emission0. -/
def exactAttempt (cell : NoteCell) : CsrExecutableAttempt where
  globalIndex := 18337 + localIndex cell
  family := 23
  localIndex := localIndex cell
  emission := 0
  terms := expectedTerms cell
  targetRoot := expectedTarget cell

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputFrame
