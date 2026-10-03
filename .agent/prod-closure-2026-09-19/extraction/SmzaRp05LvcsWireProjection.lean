import SmzaRp05PcsWireProjection

/-!
# RP05 LVCS row reconstruction from the PCS wire fields

SOURCE-ONLY, NOT COMPILED. This file models `lvcs_recompute_rows` (Rust
`smallwood_engine.rs:11319`) without adding proof fields. `heads` must be the
output of `reconstructedHeadsForRow` for all opening evaluations; `tails` and
`subsetEvals` are decoded from the existing `PcsProof`. The coefficient
matrices and evaluation points are derived verifier data.

The Rust routine first forms each extended combination `[head | tail]`, rotates
left by `nb_lvcs_cols`, evaluates it at each DECS point, splits coefficient
columns at `fullrank_cols`, solves the opened columns with the inverse of the
square first-part matrix, and fills the remaining columns from subset_evals.
The inversion below is computed by deterministic Gauss-Jordan elimination
with the same first-nonzero pivot rule and rejects singular matrices. A theorem
equating every row operation with Rust `mat_inv` and a proof that the fixed
RP05 challenge construction always yields an invertible matrix remain open.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05LvcsWireProjection

open HegemonCrypto.SmallWood.SmzaRp05PcsWireProjection
open SmzaRp05ExecutableChallengeStage (FieldWord)
open scoped BigOperators

set_option autoImplicit false

abbrev F := Goldilocks
abbrev FMatrix := List (List F)

/-- Rust `rotate_left_words`, with its configured nonzero row width. -/
def rotateLeft (values : List F) (amount : Nat) : List F :=
  let shift := amount % values.length
  values.drop shift ++ values.take shift

/-- Lagrange basis for the values at consecutive integer points. -/
def consecutiveBasis (count index : Nat) (point : F) : F :=
  ∏ j ∈ Finset.range count, if index = j then 1
    else (point - (j : F)) * (((index : F) - (j : F))⁻¹)

/-- `evaluate_consecutive_values`: interpolate the supplied evaluations at
`0..n-1` and evaluate that unique polynomial at the challenge point. -/
def evaluateConsecutive (values : List F) (point : F) : F :=
  ∑ i ∈ Finset.range values.length,
    values.getD i 0 * consecutiveBasis values.length i point

/-- Finite-field inner product used by Rust `mat_vec_mul_owned`. -/
def dot (left right : List F) : F :=
  ∑ i ∈ Finset.range left.length, left.getD i 0 * right.getD i 0

/-- Matrix-vector product with Rust's row-major accumulation order. -/
def matVec (matrix : FMatrix) (vector : List F) : List F :=
  matrix.map fun row => dot row vector

/-- Exact local residual guard mirrored by the native and recursive Rust
verifiers after solving the opened coordinates. -/
def residualCheckPassed (matrix : FMatrix) (residual rhs : List F) : Bool :=
  decide (rhs.length = residual.length) &&
    (decide (matrix.length = rhs.length) &&
      (!(matrix.any fun row => decide (row.length ≠ residual.length)) &&
        decide (matVec matrix residual = rhs)))

theorem residualCheckPassed_implies_equation (matrix : FMatrix)
    (residual rhs : List F)
    (passed : residualCheckPassed matrix residual rhs = true) :
    matVec matrix residual = rhs := by
  simp only [residualCheckPassed, Bool.and_eq_true] at passed
  exact of_decide_eq_true passed.2.2.2

/-- Partition one coefficient row into selected columns, in `fullrank_cols`
order, and complementary positions in original row order. -/
def splitCoefficientRow (fullrankCols : List Nat) (row : List F) : List F × List F :=
  (fullrankCols.map fun k => row.getD k 0,
   (List.range row.length).filterMap fun k =>
     let previous := (fullrankCols.filter fun selected => decide (selected < k)).length
     if fullrankCols[previous]? = some k then none else row[k]?)

def splitCoefficientMatrix (fullrankCols : List Nat) (coeffs : FMatrix) :
    FMatrix × FMatrix :=
  (coeffs.map fun row => (splitCoefficientRow fullrankCols row).1,
   coeffs.map fun row => (splitCoefficientRow fullrankCols row).2)

def setAt {α : Type} : List α → Nat → α → List α
  | [], _, _ => []
  | _ :: rest, 0, value => value :: rest
  | first :: rest, index + 1, value => first :: setAt rest index value

def swapAt {α : Type} (values : List α) (left right : Nat) : List α :=
  match values[left]?, values[right]? with
  | some a, some b => setAt (setAt values left b) right a
  | _, _ => values

/-- Return the first nonzero pivot at or below `start`. -/
def findPivot (matrix : FMatrix) (start column : Nat) : Option Nat := Id.run do
  for row in List.range matrix.length do
    if decide (row ≥ start) && decide ((matrix.getD row []).getD column 0 ≠ 0) then
      return some row
  return none

def normalizeRow (row : List F) (pivot : F) : List F :=
  row.map fun value => value * pivot⁻¹

def eliminateRow (row pivotRow : List F) (factor : F) : List F :=
  (List.range row.length).map fun j =>
    row.getD j 0 - factor * pivotRow.getD j 0

def eliminateColumn (matrix : FMatrix) (pivotRow column : Nat) : FMatrix := Id.run do
  let pivot := matrix.getD pivotRow []
  let mut result := matrix
  for row in List.range matrix.length do
    if row ≠ pivotRow then
      let factor := (result.getD row []).getD column 0
      result := setAt result row (eliminateRow (result.getD row []) pivot factor)
  return result

/-- Apply the same elementary row operation to both augmented halves.
The multiplier is always read from the left half, as in Rust `mat_inv`;
computing it independently from the right half does not compute an inverse. -/
def eliminateAugmentedColumn (left right : FMatrix) (pivotRow column : Nat) :
    FMatrix × FMatrix := Id.run do
  let leftPivot := left.getD pivotRow []
  let rightPivot := right.getD pivotRow []
  let mut leftResult := left
  let mut rightResult := right
  for row in List.range left.length do
    if row ≠ pivotRow then
      let factor := (leftResult.getD row []).getD column 0
      leftResult := setAt leftResult row
        (eliminateRow (leftResult.getD row []) leftPivot factor)
      rightResult := setAt rightResult row
        (eliminateRow (rightResult.getD row []) rightPivot factor)
  return (leftResult, rightResult)

/-- Deterministic Gauss-Jordan inverse. Row pivoting follows the first-nonzero
rule used by Rust `mat_inv`; a missing pivot rejects a singular matrix. -/
def gaussInverse (n : Nat) (matrix : FMatrix) : Option FMatrix := do
  if decide (matrix.length ≠ n) ||
      matrix.any (fun row => decide (row.length ≠ n)) then failure
  let mut left := matrix
  let mut right := List.range n |>.map fun i =>
    List.range n |>.map fun j => if i = j then (1 : F) else 0
  for column in List.range n do
    let pivot? := findPivot left column column
    if pivot?.isNone then failure
    let pivot := pivot?.getD 0
    left := swapAt left column pivot
    right := swapAt right column pivot
    let pivotValue := (left.getD column []).getD column 0
    left := setAt left column (normalizeRow (left.getD column []) pivotValue)
    right := setAt right column (normalizeRow (right.getD column []) pivotValue)
    let eliminated := eliminateAugmentedColumn left right column column
    left := eliminated.1
    right := eliminated.2
  return right

/-- Deterministic row-major product for square verifier coefficient matrices. -/
def matrixProduct (n : Nat) (left right : FMatrix) : FMatrix :=
  left.map fun row => (List.range n).map fun column =>
    ∑ index ∈ Finset.range n,
      row.getD index 0 * (right.getD index []).getD column 0

def identityMatrix (n : Nat) : FMatrix :=
  (List.range n).map fun row =>
    (List.range n).map fun column => if row = column then 1 else 0

def hasMatrixShape (matrix : FMatrix) (rows columns : Nat) : Bool :=
  decide (matrix.length = rows) &&
    !(matrix.any fun row => decide (row.length ≠ columns))

/-- Acceptance guard mirroring the verifier's local `A * computedInverse = I`
check. Dimensions are explicit, so the product is only relied on for square
matrices of the configured rank. -/
def inverseCheckPassed (rank : Nat) (matrix inverse : FMatrix) : Bool :=
  hasMatrixShape matrix rank rank &&
    (hasMatrixShape inverse rank rank &&
      decide (matrixProduct rank matrix inverse = identityMatrix rank))

theorem inverseCheckPassed_implies_product_identity (rank : Nat)
    (matrix inverse : FMatrix)
    (passed : inverseCheckPassed rank matrix inverse = true) :
    matrixProduct rank matrix inverse = identityMatrix rank := by
  simp only [inverseCheckPassed, Bool.and_eq_true] at passed
  exact of_decide_eq_true passed.2.2

/-- Strict reconstruction of one row. `inverse` is the matrix returned by
Rust `mat_inv(coeffs_part1)` on its success path. Shape inconsistencies reject. -/
def reconstructOne (fullrank totalRows lvcsCols tailCount : Nat)
    (fullrankCols : List Nat) (coeffsPart1 coeffsPart2 inverse : FMatrix)
    (heads tails : FMatrix) (subset : List F) (point : F) : Option (List F) := do
  if lvcsCols = 0 ∨ fullrankCols.length ≠ fullrank ∨
      heads.length ≠ fullrank ∨ tails.length ≠ fullrank ∨
      heads.any (fun row => decide (row.length ≠ lvcsCols)) ∨
      tails.any (fun row => decide (row.length ≠ tailCount)) then failure
  if coeffsPart1.length ≠ fullrank ∨ coeffsPart2.length ≠ fullrank ∨
      inverse.length ≠ fullrank ∨
      inverse.any (fun row => decide (row.length ≠ fullrank)) ∨
      coeffsPart1.any (fun row => decide (row.length ≠ fullrank)) ∨
      coeffsPart2.any (fun row => decide (row.length ≠ subset.length)) ∨
      totalRows ≠ fullrank + subset.length
    then failure
  let q := List.range fullrank |>.map fun k =>
    evaluateConsecutive
      (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) lvcsCols) point
  let tmp := matVec coeffsPart2 subset
  let rhs := List.range fullrank |>.map fun k => q.getD k 0 - tmp.getD k 0
  let res := matVec inverse rhs
  if res.length ≠ fullrank then failure
  if !residualCheckPassed coeffsPart1 res rhs then failure
  let values := List.range totalRows |>.map fun k =>
    let openedBefore := (fullrankCols.filter fun selected => decide (selected < k)).length
    if fullrankCols[openedBefore]? = some k then res.getD openedBefore 0
    else subset.getD (k - openedBefore) 0
  pure values

private theorem list_getD_map {α β : Type} (xs : List α) (f : α → β)
    (i : Nat) (fallback : β) :
    (xs.map f).getD i fallback = ((xs[i]?).map f).getD fallback := by
  induction xs generalizing i with
  | nil => simp
  | cons head tail ih =>
      cases i with
      | zero => rfl
      | succ i => exact ih i

/-- A successful row reconstruction exposes the exact local residual vector
and solved vector used by the implementation. The `residualCheckPassed`
guard on that same `coeffsPart1`, `res`, and `rhs` implies the checked linear
equation; no inverse-correctness or matrix nonsingularity theorem is assumed. -/
theorem reconstructOne_success_extracts_residual_equation
    (fullrank totalRows lvcsCols tailCount : Nat)
    (fullrankCols : List Nat) (coeffsPart1 coeffsPart2 inverse : FMatrix)
    (heads tails : FMatrix) (subset : List F) (point : F)
    (values : List F)
    (success : reconstructOne fullrank totalRows lvcsCols tailCount
      fullrankCols coeffsPart1 coeffsPart2 inverse heads tails subset point =
        some values) :
    ∃ res rhs,
      res = matVec inverse rhs ∧
      rhs = (List.range fullrank).map (fun k =>
        (List.range fullrank |>.map (fun j =>
          evaluateConsecutive
            (rotateLeft ((heads.getD j []) ++ (tails.getD j [])) lvcsCols)
            point)).getD k 0 -
          (matVec coeffsPart2 subset).getD k 0) ∧
      matVec coeffsPart1 res = rhs := by
  let q := List.range fullrank |>.map fun k =>
    evaluateConsecutive
      (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) lvcsCols) point
  let tmp := matVec coeffsPart2 subset
  let rhs := List.range fullrank |>.map fun k => q.getD k 0 - tmp.getD k 0
  let res := matVec inverse rhs
  have unfoldedSuccess := success
  simp [reconstructOne] at unfoldedSuccess
  have extracted := unfoldedSuccess.2.2.2.1
  have passed : residualCheckPassed coeffsPart1 res rhs = true := by
    simpa [q, tmp, rhs, res, list_getD_map] using extracted
  refine ⟨res, rhs, rfl, ?_, ?_⟩
  · rfl
  · exact residualCheckPassed_implies_equation coeffsPart1 res rhs passed

/-- The same successful reconstruction satisfies the unsplit opened-row
equation at every actual row index: the opened-coordinate product plus the
complementary-coordinate product equals that row's interpolated target. -/
theorem reconstructOne_success_coordinate_equation
    (fullrank totalRows lvcsCols tailCount : Nat)
    (fullrankCols : List Nat) (coeffsPart1 coeffsPart2 inverse : FMatrix)
    (heads tails : FMatrix) (subset : List F) (point : F)
    (values : List F)
    (success : reconstructOne fullrank totalRows lvcsCols tailCount
      fullrankCols coeffsPart1 coeffsPart2 inverse heads tails subset point =
        some values) :
    ∃ res rhs,
      res = matVec inverse rhs ∧
      ∀ k, k < fullrank →
        (matVec coeffsPart1 res).getD k 0 +
          (matVec coeffsPart2 subset).getD k 0 =
        evaluateConsecutive
          (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) lvcsCols)
          point := by
  obtain ⟨res, rhs, res_eq, rhs_eq, linear_eq⟩ :=
    reconstructOne_success_extracts_residual_equation
      fullrank totalRows lvcsCols tailCount fullrankCols coeffsPart1
      coeffsPart2 inverse heads tails subset point values success
  refine ⟨res, rhs, res_eq, ?_⟩
  intro k hk
  have linear_at := congrArg (fun xs : List F => xs.getD k 0) linear_eq
  have rhs_at : rhs.getD k 0 =
      evaluateConsecutive
        (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) lvcsCols)
        point - (matVec coeffsPart2 subset).getD k 0 := by
    rw [rhs_eq]
    simp [hk]
  calc
    (matVec coeffsPart1 res).getD k 0 +
        (matVec coeffsPart2 subset).getD k 0 =
      rhs.getD k 0 + (matVec coeffsPart2 subset).getD k 0 := by
        rw [linear_at]
    _ = evaluateConsecutive
        (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) lvcsCols)
        point := by rw [rhs_at]; ring

/-- Appending one successful result on each pass through a list loop has the
same source order as a monadic map. This is the control-flow fact needed to
read a DECS row back at its original sampled index. -/
private theorem forIn_append_eq_mapM {α β : Type} (xs : List α)
    (initial : List β) (f : α → Option β) :
    (forIn xs initial (fun x acc => do
      let value ← f x
      pure (.yield (acc ++ [value])))) =
      (xs.mapM f).map (fun values => initial ++ values) := by
  induction xs generalizing initial with
  | nil => simp
  | cons x rest ih =>
      rw [List.forIn_cons, List.mapM_cons]
      cases hx : f x with
      | none => simp
      | some value =>
          simp
          simpa [Option.map_eq_bind, List.append_assoc] using
            ih (initial ++ [value])

/-- A successful monadic map has exactly one output per source element, in
the same index order. -/
private theorem mapM_success_getD {α β : Type}
    (xs : List α) (f : α → Option β) (values : List β)
    (sourceFallback : α) (valueFallback : β)
    (success : xs.mapM f = some values) :
    values.length = xs.length ∧
      ∀ index, index < xs.length →
        f (xs.getD index sourceFallback) =
          some (values.getD index valueFallback) := by
  induction xs generalizing values with
  | nil =>
      simp at success
      subst values
      simp
  | cons x rest ih =>
      cases hx : f x with
      | none => simp [List.mapM_cons, hx] at success
      | some value =>
          cases hrest : rest.mapM f with
          | none => simp [List.mapM_cons, hx, hrest] at success
          | some tail =>
              simp [List.mapM_cons, hx, hrest] at success
              subst values
              obtain ⟨length_eq, entry_eq⟩ := ih tail hrest
              constructor
              · simp [length_eq]
              · intro index hindex
                cases index with
                | zero => simpa using hx
                | succ index =>
                    have htail : index < rest.length := by
                      simpa using hindex
                    simpa using entry_eq index htail

/-- On success, the exact append loop used by `reconstructRows` yields one row
per DECS point, in point order, and every row has its checked coordinate
equation. The matrix arguments are precisely those fixed before the loop. -/
theorem reconstructRows_loop_success_coordinate_equation
    (fullrank totalRows lvcsCols tailCount : Nat)
    (fullrankCols : List Nat) (coeffsPart1 coeffsPart2 inverse : FMatrix)
    (heads tails subsets : FMatrix) (points : List F) (rows : FMatrix)
    (success :
      (forIn (List.range points.length) ([] : FMatrix) (fun j acc => do
        let row ← reconstructOne fullrank totalRows lvcsCols tailCount
          fullrankCols coeffsPart1 coeffsPart2 inverse heads tails
          (subsets.getD j []) (points.getD j 0)
        pure (.yield (acc ++ [row])))) = some rows) :
    rows.length = points.length ∧
      ∀ j, j < points.length →
        ∃ res rhs,
          res = matVec inverse rhs ∧
          ∀ k, k < fullrank →
            (matVec coeffsPart1 res).getD k 0 +
              (matVec coeffsPart2 (subsets.getD j [])).getD k 0 =
            evaluateConsecutive
              (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) lvcsCols)
              (points.getD j 0) := by
  let rowAt : Nat → Option (List F) := fun j =>
    reconstructOne fullrank totalRows lvcsCols tailCount
      fullrankCols coeffsPart1 coeffsPart2 inverse heads tails
      (subsets.getD j []) (points.getD j 0)
  have loop_eq := forIn_append_eq_mapM
    (List.range points.length) ([] : FMatrix) rowAt
  have mapped : (List.range points.length).mapM rowAt = some rows := by
    change (forIn (List.range points.length) ([] : FMatrix)
      (fun j acc => do
        let row ← rowAt j
        pure (.yield (acc ++ [row])))) = some rows at success
    rw [loop_eq] at success
    simpa using success
  obtain ⟨length_eq, per_index⟩ :=
    mapM_success_getD (List.range points.length) rowAt rows 0 [] mapped
  constructor
  · simpa using length_eq
  · intro j hj
    have indexed := per_index j (by simpa using hj)
    have indexed' : rowAt j = some (rows.getD j []) := by
      simpa [List.getD_eq_getElem?_getD, List.getElem?_range hj] using indexed
    dsimp [rowAt] at indexed'
    exact reconstructOne_success_coordinate_equation
      fullrank totalRows lvcsCols tailCount fullrankCols coeffsPart1
      coeffsPart2 inverse heads tails (subsets.getD j [])
      (points.getD j 0) (rows.getD j []) indexed'

/-- Private arithmetic kernel. The public verifier entry below derives every
argument from config, challenges, and decoded proof bytes before calling it. -/
private def reconstructRows (totalRows lvcsCols tailCount : Nat)
    (fullrankCols : List Nat) (coeffs : FMatrix)
    (heads tails subsets : FMatrix) (points : List F) : Option FMatrix := do
  let fullrank := fullrankCols.length
  if fullrankCols.any (fun column => decide (column ≥ totalRows)) then failure
  let (coeffsPart1, coeffsPart2) := splitCoefficientMatrix fullrankCols coeffs
  let inverse ← gaussInverse fullrank coeffsPart1
  if !inverseCheckPassed fullrank coeffsPart1 inverse then failure
  if heads.length ≠ fullrank ∨ tails.length ≠ fullrank then failure
  if subsets.length ≠ points.length then failure
  let mut rows := []
  for j in List.range points.length do
    let row ← reconstructOne fullrank totalRows
      lvcsCols tailCount fullrankCols coeffsPart1 coeffsPart2 inverse heads tails
      (subsets.getD j []) (points.getD j 0)
    rows := rows ++ [row]
  pure rows

/-- Success of the private reconstruction kernel exposes the exact inverse
selected by Gauss-Jordan and the coordinate equation for every returned row.
The row at index `j` belongs to DECS point `j`. -/
theorem reconstructRows_success_coordinate_equation
    (totalRows lvcsCols tailCount : Nat)
    (fullrankCols : List Nat) (coeffs : FMatrix)
    (heads tails subsets : FMatrix) (points : List F) (rows : FMatrix)
    (success : reconstructRows totalRows lvcsCols tailCount fullrankCols
      coeffs heads tails subsets points = some rows) :
    ∃ inverse,
      gaussInverse fullrankCols.length
        (splitCoefficientMatrix fullrankCols coeffs).1 = some inverse ∧
      rows.length = points.length ∧
      ∀ j, j < points.length →
        ∃ res rhs,
          res = matVec inverse rhs ∧
          ∀ k, k < fullrankCols.length →
            (matVec (splitCoefficientMatrix fullrankCols coeffs).1 res).getD k 0 +
              (matVec (splitCoefficientMatrix fullrankCols coeffs).2
                (subsets.getD j [])).getD k 0 =
            evaluateConsecutive
              (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) lvcsCols)
              (points.getD j 0) := by
  cases hsplit : splitCoefficientMatrix fullrankCols coeffs with
  | mk part1 part2 =>
      cases hcolumns : fullrankCols.any
          (fun column => decide (column ≥ totalRows)) with
      | true =>
          simp [reconstructRows, hcolumns] at success
      | false =>
          cases hinverse : gaussInverse fullrankCols.length part1 with
          | none =>
              simp [reconstructRows, hsplit, hcolumns, hinverse] at success
          | some inverse =>
              cases hchecked : inverseCheckPassed fullrankCols.length
                  part1 inverse with
              | false =>
                  simp [reconstructRows, hsplit, hcolumns, hinverse,
                    hchecked] at success
              | true =>
                  by_cases hheads :
                      heads.length ≠ fullrankCols.length ∨
                        tails.length ≠ fullrankCols.length
                  · simp [reconstructRows, hsplit, hcolumns, hinverse,
                      hheads] at success
                  · by_cases hsubsets : subsets.length ≠ points.length
                    · simp [reconstructRows, hsplit, hcolumns, hinverse,
                        hheads, hsubsets] at success
                    · have loop_success :
                        (forIn (List.range points.length) ([] : FMatrix)
                          (fun j acc => do
                            let row ← reconstructOne fullrankCols.length
                              totalRows lvcsCols tailCount fullrankCols
                              part1 part2 inverse heads tails
                              (subsets.getD j []) (points.getD j 0)
                            pure (.yield (acc ++ [row])))) = some rows := by
                          simpa [reconstructRows, hsplit, hcolumns, hinverse,
                            hchecked, hheads, hsubsets] using success
                      obtain ⟨length_eq, equations⟩ :=
                        reconstructRows_loop_success_coordinate_equation
                          fullrankCols.length totalRows lvcsCols tailCount
                          fullrankCols part1 part2 inverse heads tails
                          subsets points rows loop_success
                      refine ⟨inverse, ?_, length_eq, ?_⟩
                      · rfl
                      · simpa [hsplit] using equations

/-- Concatenate source-order beta-head blocks for every opening evaluation.
The heads are computed from the proof's decoded `partial_evals` and the
existing opened row scalars by `reconstructedHeadsForRow`; they are not inputs. -/
def reconstructAllHeads (fields : DecodedPcsFields)
    (evalPoints : List F) (rowScalars : List (List FieldWord))
    (packingFactor : Nat) (widths deltas : List Nat) (beta lvcsCols : Nat) :
    Option FMatrix := do
  let mut heads : FMatrix := []
  for j in List.range evalPoints.length do
    let rowHeads ← reconstructedHeadsForRow fields evalPoints rowScalars j
      packingFactor widths deltas beta lvcsCols
    heads := heads ++ rowHeads
  pure heads

/-- Literal `pcs_build_coefficients`: beta rows per opening point, each row
contains powers 1,r,...,r^(packingFactor+numberOfOpenPoints-1) in its source
block, with zeros elsewhere. -/
def pcsBuildCoefficients (evalPoints : List F) (beta packingFactor totalRows : Nat) : FMatrix :=
  let block := packingFactor + evalPoints.length
  (List.range (beta * evalPoints.length)).map fun rowIndex =>
    let openingIndex := rowIndex / beta
    let betaIndex := rowIndex % beta
    let point := evalPoints.getD openingIndex 0
    (List.range totalRows).map fun column =>
      if column ≥ block * betaIndex && column < block * (betaIndex + 1) then
        point ^ (column - block * betaIndex)
      else 0

/-- The configured `fullrank_cols` arithmetic from `SmallwoodConfig::new`. -/
def configuredFullrankCols (beta packingFactor openingCount : Nat) : List Nat :=
  (List.range beta).flatMap fun i =>
    (List.range openingCount).map fun j => i * (packingFactor + openingCount) + j

/-- Wire-connected LVCS reconstruction: combination heads come from decoded
partial_evals plus opened row scalars; tails/subsets come from the existing
proof fields. Coefficients and the inverse are computed from verifier inputs. -/
def reconstructRowsFromPcsFields (fields : DecodedPcsFields)
    (evalPoints decsPoints : List F) (rowScalars : List (List FieldWord))
    (packingFactor : Nat) (widths deltas : List Nat) (beta lvcsCols : Nat)
    (totalRows tailCount : Nat) : Option FMatrix := do
  if beta = 0 ∨ lvcsCols = 0 then failure
  if totalRows ≠ beta * (packingFactor + evalPoints.length) then failure
  let heads ← reconstructAllHeads fields evalPoints rowScalars packingFactor
    widths deltas beta lvcsCols
  let tails := fields.rcombiTails.map fieldWordsToGoldilocks
  let subsets := fields.subsetEvals.map fieldWordsToGoldilocks
  let fullrankCols := configuredFullrankCols beta packingFactor evalPoints.length
  let coeffs := pcsBuildCoefficients evalPoints beta packingFactor totalRows
  reconstructRows totalRows lvcsCols tailCount fullrankCols coeffs
    heads tails subsets decsPoints

/-- A successful public PCS-field reconstruction has exactly one LVCS row per
DECS point. Each returned row satisfies the residual equation at that same
point, using only the heads derived from the decoded proof and the coefficient
matrix derived from the verifier's configuration. -/
theorem reconstructRowsFromPcsFields_success_coordinate_equation
    (fields : DecodedPcsFields)
    (evalPoints decsPoints : List F) (rowScalars : List (List FieldWord))
    (packingFactor : Nat) (widths deltas : List Nat) (beta lvcsCols : Nat)
    (totalRows tailCount : Nat) (rows : FMatrix)
    (success : reconstructRowsFromPcsFields fields evalPoints decsPoints
      rowScalars packingFactor widths deltas beta lvcsCols totalRows tailCount =
        some rows) :
    ∃ heads inverse,
      reconstructAllHeads fields evalPoints rowScalars packingFactor
        widths deltas beta lvcsCols = some heads ∧
      gaussInverse (configuredFullrankCols beta packingFactor evalPoints.length).length
        (splitCoefficientMatrix
          (configuredFullrankCols beta packingFactor evalPoints.length)
          (pcsBuildCoefficients evalPoints beta packingFactor totalRows)).1 =
        some inverse ∧
      rows.length = decsPoints.length ∧
      ∀ j, j < decsPoints.length →
        ∃ res rhs,
          res = matVec inverse rhs ∧
          ∀ k, k < (configuredFullrankCols beta packingFactor
              evalPoints.length).length →
            (matVec (splitCoefficientMatrix
              (configuredFullrankCols beta packingFactor evalPoints.length)
              (pcsBuildCoefficients evalPoints beta packingFactor totalRows)).1
              res).getD k 0 +
            (matVec (splitCoefficientMatrix
              (configuredFullrankCols beta packingFactor evalPoints.length)
              (pcsBuildCoefficients evalPoints beta packingFactor totalRows)).2
              ((fields.subsetEvals.map fieldWordsToGoldilocks).getD j [])).getD
                k 0 =
            evaluateConsecutive
              (rotateLeft ((heads.getD k []) ++
                ((fields.rcombiTails.map fieldWordsToGoldilocks).getD k []))
                lvcsCols) (decsPoints.getD j 0) := by
  by_cases hentry : beta = 0 ∨ lvcsCols = 0
  · simp [reconstructRowsFromPcsFields, hentry] at success
  · by_cases hsize : totalRows ≠ beta * (packingFactor + evalPoints.length)
    · simp [reconstructRowsFromPcsFields, hentry, hsize] at success
    · cases hheads : reconstructAllHeads fields evalPoints rowScalars
        packingFactor widths deltas beta lvcsCols with
      | none =>
          simp [reconstructRowsFromPcsFields, hentry, hsize, hheads] at success
      | some heads =>
          have kernel_success :
              reconstructRows totalRows lvcsCols tailCount
                (configuredFullrankCols beta packingFactor evalPoints.length)
                (pcsBuildCoefficients evalPoints beta packingFactor totalRows)
                heads (fields.rcombiTails.map fieldWordsToGoldilocks)
                (fields.subsetEvals.map fieldWordsToGoldilocks)
                decsPoints = some rows := by
            simpa [reconstructRowsFromPcsFields, hentry, hsize, hheads] using
              success
          obtain ⟨inverse, hinverse, length_eq, equations⟩ :=
            reconstructRows_success_coordinate_equation totalRows lvcsCols
              tailCount
              (configuredFullrankCols beta packingFactor evalPoints.length)
              (pcsBuildCoefficients evalPoints beta packingFactor totalRows)
              heads (fields.rcombiTails.map fieldWordsToGoldilocks)
              (fields.subsetEvals.map fieldWordsToGoldilocks) decsPoints rows
              kernel_success
          exact ⟨heads, inverse, rfl, hinverse, length_eq, equations⟩

end HegemonCrypto.SmallWood.SmzaRp05LvcsWireProjection
