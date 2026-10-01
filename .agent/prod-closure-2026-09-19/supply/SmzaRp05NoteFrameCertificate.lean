import SmzaRp05MerkleCallStep
import HegemonCrypto.SmallWoodV8Smz9NoteSpongeFold

/-!
# Exact RP05 input-note sponge frame

The 18 absorbed words are always the decoder's source words. Eleven are
private and have no CSR source-copy attempt: word0/1 and words10..12,14..17
are copied from specified raw/authorization rows, while words2..9 and13
are recovered from the first initial-state lane or later initial-minus-final
difference. The latter are *not* zero. Each of the 39 CSR attempts per input
below checks only an actually emitted source, padding, or capacity cell.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate

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

def noteCall (input : Fin 2) : Nat := if input.val = 0 then 1 else 38

abbrev NoteCell := Fin 2 × Fin 3 × Fin 16

def boundCell (cell : NoteCell) : Prop :=
  let block := cell.2.1.val
  let lane := cell.2.2.val
  if block = 0 then lane < 2 ∨ 8 ≤ lane
  else if block = 1 then lane = 2 ∨ lane = 3 ∨ lane = 4 ∨
    lane = 6 ∨ lane = 7 ∨ 8 ≤ lane
  else True

instance (cell : NoteCell) : Decidable (boundCell cell) := by
  unfold boundCell
  infer_instance

def localIndex (cell : NoteCell) : Nat :=
  let block := cell.2.1.val
  let lane := cell.2.2.val
  39 * cell.1.val +
    if block = 0 then if lane < 2 then lane else lane - 6
    else if block = 1 then if lane < 5 then lane + 8 else lane + 7
    else 23 + lane

def sourceIndex (cell : NoteCell) : Option Nat :=
  let input := cell.1.val
  let block := cell.2.1.val
  let lane := cell.2.2.val
  if block = 0 then
    if lane = 0 then some (rawIndex (34 * input))
    else if lane = 1 then some (rawIndex (34 * input + 1))
    else none
  else if block = 1 then
    if lane = 2 ∨ lane = 3 ∨ lane = 4 then
      some ((95 + input) * 64 + lane + 2)
    else if lane = 6 ∨ lane = 7 then
      some ((95 + input) * 64 + lane - 6)
    else none
  else if lane < 2 then some ((95 + input) * 64 + lane + 2)
  else none

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

/-- The 39 cells per input, in their exact fixture emission order. -/
def boundedCells : List NoteCell :=
  (List.range 2).flatMap fun input =>
    (List.range 3).flatMap fun block =>
      (List.range 16).filterMap fun lane =>
        if h : input < 2 ∧ block < 3 ∧ lane < 16 then
          let cell : NoteCell :=
            (⟨input, h.1⟩, ⟨block, h.2.1⟩, ⟨lane, h.2.2⟩)
          if boundCell cell then some cell else none
        else none

/-- This exact attempt's `globalIndex` equals 15759 plus the fixture-local
offset. It is emitted with family14 and emission0. -/
def exactAttempt (cell : NoteCell) : CsrExecutableAttempt where
  globalIndex := 15759 + localIndex cell
  family := 14
  localIndex := localIndex cell
  emission := 0
  terms := expectedTerms cell
  targetRoot := expectedTarget cell

end HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate
