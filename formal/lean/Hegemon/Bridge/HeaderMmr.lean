namespace Hegemon
namespace Bridge
namespace HeaderMmr

inductive Reject where
  | headerMmrMismatch
  | leafOutOfRange
  | openingMismatch
  | peakMismatch
deriving DecidableEq, Repr

structure ShapeInput where
  contextMatches : Bool
  leafIndex : Nat
  leafCount : Nat
  siblingCount : Nat
  peakCount : Nat
deriving DecidableEq, Repr

structure OpeningShape where
  peakIndex : Nat
  peakStart : Nat
  peakSize : Nat
  expectedSiblings : Nat
  localIndex : Nat
  currentIsLeft : List Bool
deriving DecidableEq, Repr

def largestPowerOfTwoLeFrom (current n fuel : Nat) : Nat :=
  match fuel with
  | 0 => current
  | fuel' + 1 =>
      let next := current * 2
      if next ≤ n then
        largestPowerOfTwoLeFrom next n fuel'
      else
        current

def largestPowerOfTwoLe (n : Nat) : Nat :=
  if n = 0 then 0 else largestPowerOfTwoLeFrom 1 n n

def peakRangesAux (remaining start fuel : Nat) : List (Nat × Nat) :=
  match fuel with
  | 0 => []
  | fuel' + 1 =>
      if remaining = 0 then
        []
      else
        let size := largestPowerOfTwoLe remaining
        (start, size) :: peakRangesAux (remaining - size) (start + size) fuel'

def peakRanges (leafCount : Nat) : List (Nat × Nat) :=
  peakRangesAux leafCount 0 leafCount

def findPeakAux (leafIndex : Nat) (ranges : List (Nat × Nat)) (index : Nat) :
    Option (Nat × Nat × Nat) :=
  match ranges with
  | [] => none
  | (start, size) :: rest =>
      if leafIndex ≥ start && leafIndex < start + size then
        some (index, start, size)
      else
        findPeakAux leafIndex rest (index + 1)

def findPeak (leafIndex : Nat) (ranges : List (Nat × Nat)) :
    Option (Nat × Nat × Nat) :=
  findPeakAux leafIndex ranges 0

def log2PowerOfTwoAux (value acc fuel : Nat) : Nat :=
  match fuel with
  | 0 => acc
  | fuel' + 1 =>
      if value ≤ 1 then
        acc
      else
        log2PowerOfTwoAux (value / 2) (acc + 1) fuel'

def log2PowerOfTwo (value : Nat) : Nat :=
  log2PowerOfTwoAux value 0 value

def orientationBitsAux (localIndex remaining : Nat) : List Bool :=
  match remaining with
  | 0 => []
  | remaining' + 1 =>
      ((localIndex % 2) = 0) :: orientationBitsAux (localIndex / 2) remaining'

def evaluateShape (input : ShapeInput) : Except Reject OpeningShape :=
  if input.contextMatches = false then
    Except.error Reject.headerMmrMismatch
  else if input.leafIndex ≥ input.leafCount then
    Except.error Reject.leafOutOfRange
  else
    let ranges := peakRanges input.leafCount
    if ranges.length ≠ input.peakCount then
      Except.error Reject.peakMismatch
    else
      match findPeak input.leafIndex ranges with
      | none => Except.error Reject.leafOutOfRange
      | some (peakIndex, peakStart, peakSize) =>
          let expectedSiblings := log2PowerOfTwo peakSize
          if input.siblingCount ≠ expectedSiblings then
            Except.error Reject.openingMismatch
          else
            let localIndex := input.leafIndex - peakStart
            Except.ok {
              peakIndex := peakIndex,
              peakStart := peakStart,
              peakSize := peakSize,
              expectedSiblings := expectedSiblings,
              localIndex := localIndex,
              currentIsLeft := orientationBitsAux localIndex expectedSiblings
            }

def acceptedShape (input : ShapeInput) : Option OpeningShape :=
  match evaluateShape input with
  | Except.ok shape => some shape
  | Except.error _ => none

def rejection (input : ShapeInput) : Option Reject :=
  match evaluateShape input with
  | Except.ok _ => none
  | Except.error reject => some reject

def validShape : ShapeInput :=
  {
    contextMatches := true,
    leafIndex := 5,
    leafCount := 6,
    siblingCount := 1,
    peakCount := 2
  }

def singletonShape : ShapeInput :=
  {
    contextMatches := true,
    leafIndex := 0,
    leafCount := 1,
    siblingCount := 0,
    peakCount := 1
  }

def fourLeafLeftShape : ShapeInput :=
  {
    contextMatches := true,
    leafIndex := 2,
    leafCount := 4,
    siblingCount := 2,
    peakCount := 1
  }

def fourLeafRightShape : ShapeInput :=
  {
    contextMatches := true,
    leafIndex := 3,
    leafCount := 4,
    siblingCount := 2,
    peakCount := 1
  }

theorem peak_ranges_six :
    peakRanges 6 = [(0, 4), (4, 2)] := by
  decide

theorem valid_shape_accepts :
    acceptedShape validShape =
      some {
        peakIndex := 1,
        peakStart := 4,
        peakSize := 2,
        expectedSiblings := 1,
        localIndex := 1,
        currentIsLeft := [false]
      } := by
  decide

theorem singleton_shape_accepts :
    acceptedShape singletonShape =
      some {
        peakIndex := 0,
        peakStart := 0,
        peakSize := 1,
        expectedSiblings := 0,
        localIndex := 0,
        currentIsLeft := []
      } := by
  decide

theorem four_leaf_left_orientation :
    acceptedShape fourLeafLeftShape =
      some {
        peakIndex := 0,
        peakStart := 0,
        peakSize := 4,
        expectedSiblings := 2,
        localIndex := 2,
        currentIsLeft := [true, false]
      } := by
  decide

theorem four_leaf_right_orientation :
    acceptedShape fourLeafRightShape =
      some {
        peakIndex := 0,
        peakStart := 0,
        peakSize := 4,
        expectedSiblings := 2,
        localIndex := 3,
        currentIsLeft := [false, false]
      } := by
  decide

theorem rejects_context_mismatch :
    rejection { validShape with contextMatches := false } =
      some Reject.headerMmrMismatch := by
  decide

theorem rejects_leaf_out_of_range :
    rejection { validShape with leafIndex := 6 } =
      some Reject.leafOutOfRange := by
  decide

theorem rejects_empty_leaf_set :
    rejection { singletonShape with leafCount := 0, peakCount := 0 } =
      some Reject.leafOutOfRange := by
  decide

theorem rejects_peak_count_mismatch :
    rejection { validShape with peakCount := 1 } =
      some Reject.peakMismatch := by
  decide

theorem rejects_sibling_count_mismatch :
    rejection { validShape with siblingCount := 2 } =
      some Reject.openingMismatch := by
  decide

end HeaderMmr
end Bridge
end Hegemon
