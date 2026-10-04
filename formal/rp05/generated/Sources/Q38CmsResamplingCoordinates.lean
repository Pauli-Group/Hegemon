import Q38CmsControlledSwap
import Q38ControlledFreshSwapCore

/-! Coordinate-level identification of the initialized CMS basis with the
controlled-fresh-swap basis.  The permutation retains input and phase in the
fresh-swap workspace; it does not reset or discard them.
-/
namespace HegemonCrypto.SmallWood.Q38CmsResamplingCoordinates
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaFreshSwapFiber
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

variable {Input Output Phase Work Index Branch : Type}
variable [Fintype Input] [DecidableEq Input] [Fintype Output] [DecidableEq Output]
variable [AddCommGroup Output] [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work] [Fintype Index] [DecidableEq Index]
variable [Fintype Branch] [DecidableEq Branch]

abbrev CmsBasis (Input Output Phase Work Index Branch : Type) :=
  HegemonCrypto.CmsCompressedOracle.Basis Input Output Phase ((Index → Output) × (Branch × Work))
abbrev FreshBasis (Input Output Phase Work Index Branch : Type) :=
  V8SmzaControlledFreshSwap.Basis Input Index Branch
    (Input × Phase × Work) Output

local notation "CB" => CmsBasis Input Output Phase Work Index Branch
local notation "FB" => FreshBasis Input Output Phase Work Index Branch

theorem cmsBasis_ext {left right : CB}
    (input : left.input = right.input)
    (phase : left.phase = right.phase)
    (workspace : left.workspace = right.workspace)
    (database : left.database = right.database) : left = right := by
  cases left
  cases right
  simp_all

def basisPermutation : CB ≃ FB where
  toFun b :=
    (b.workspace.2.1, b.database, b.workspace.1,
      (b.input, b.phase, b.workspace.2.2))
  invFun b :=
    { input := b.2.2.2.1
      phase := b.2.2.2.2.1
      workspace := (b.2.2.1, b.1, b.2.2.2.2.2)
      database := b.2.1 }
  left_inv b := by cases b; rfl
  right_inv b := by cases b; rfl

def J (ψ : CB → ℂ) :
    V8SmzaControlledFreshSwap.Space (Key := Input) (Index := Index)
      (Branch := Branch) (Work := Input × Phase × Work) (Output := Output) :=
  WithLp.toLp 2 (fun b => ψ ((basisPermutation).symm b))

def JInv (ψ : FB → ℂ) : CB → ℂ :=
  fun b => ψ (basisPermutation b)

theorem J_coordinate (ψ : CB → ℂ) (b : FB) :
    J ψ b = ψ ((basisPermutation).symm b) := rfl

theorem J_inverse (ψ : CB → ℂ) : JInv (fun b => J ψ b) = ψ := by
  funext b
  change J ψ (basisPermutation b) = ψ b
  rw [J_coordinate]
  simp

theorem J_normSquared (ψ : CB → ℂ) :
    ∑ b : FB, Complex.normSq (J ψ b) =
      ∑ b : CB, Complex.normSq (ψ b) := by
  change ∑ b : FB, Complex.normSq (ψ ((basisPermutation).symm b)) = _
  exact (basisPermutation.symm.sum_comp (fun b => Complex.normSq (ψ b)))

theorem J_isometry (ψ φ : CB → ℂ) :
    ∑ b : FB, Complex.normSq (J ψ b - J φ b) =
      ∑ b : CB, Complex.normSq (ψ b - φ b) := by
  change ∑ b : FB,
      Complex.normSq ((ψ - φ) ((basisPermutation).symm b)) = _
  exact (basisPermutation.symm.sum_comp (fun b => Complex.normSq ((ψ - φ) b)))

theorem basisPermutation_actual_coordinates (b : CB) :
    let fresh := basisPermutation b
    fresh.1 = b.workspace.2.1 ∧
    fresh.2.1 = b.database ∧
    fresh.2.2.1 = b.workspace.1 ∧
    fresh.2.2.2.1 = b.input ∧
    fresh.2.2.2.2.1 = b.phase ∧
    fresh.2.2.2.2.2 = b.workspace.2.2 := by
  simp [basisPermutation]

/- The CMS basis representative of one isolated fresh-swap cell. -/
def cmsCell (keys : Branch → Index → Input) (index : Index)
    (rest : V8SmzaControlledFreshSwap.Rest
      (Work := Input × Phase × Work) (Output := Output) keys index)
    (cell : Option Output × Output) : CB :=
  (basisPermutation).symm
    ((V8SmzaControlledFreshSwap.isolate keys index).symm ⟨rest, cell⟩)

theorem cmsCell_selected_database
    (keys : Branch → Index → Input) (index : Index)
    (rest : V8SmzaControlledFreshSwap.Rest
      (Work := Input × Phase × Work) (Output := Output) keys index)
    (cell : Option Output × Output) :
    (cmsCell keys index rest cell).database (keys rest.1 index) = cell.1 := by
  simp [cmsCell, basisPermutation, V8SmzaControlledFreshSwap.isolate]

theorem cmsCell_selected_label
    (keys : Branch → Index → Input) (index : Index)
    (rest : V8SmzaControlledFreshSwap.Rest
      (Work := Input × Phase × Work) (Output := Output) keys index)
    (cell : Option Output × Output) :
    (cmsCell keys index rest cell).workspace.1 index = cell.2 := by
  simp [cmsCell, basisPermutation, V8SmzaControlledFreshSwap.isolate]

theorem cmsCell_retains_complement
    (keys : Branch → Index → Input) (index : Index)
    (rest : V8SmzaControlledFreshSwap.Rest
      (Work := Input × Phase × Work) (Output := Output) keys index)
    (cell : Option Output × Output) :
    (cmsCell keys index rest cell).workspace.2.1 = rest.1 ∧
    (cmsCell keys index rest cell).input = rest.2.2.2.1 ∧
    (cmsCell keys index rest cell).phase = rest.2.2.2.2.1 ∧
    (cmsCell keys index rest cell).workspace.2.2 = rest.2.2.2.2.2 := by
  simp [cmsCell, basisPermutation, V8SmzaControlledFreshSwap.isolate]

theorem cmsCell_replace_database (keys : Branch → Index → Input) (index : Index)
    (rest : Rest (Work := Input × Phase × Work) (Output := Output) keys index)
    (cell : Option Output × Output) (slot : Option Output) :
    { input := (cmsCell keys index rest cell).input
      phase := (cmsCell keys index rest cell).phase
      workspace := (cmsCell keys index rest cell).workspace
      database := setDatabaseCoordinate (cmsCell keys index rest cell).database
        (keys rest.1 index) slot } =
      cmsCell keys index rest (slot, cell.2) := by
  have database :
      setDatabaseCoordinate (cmsCell keys index rest cell).database (keys rest.1 index) slot =
        (cmsCell keys index rest (slot, cell.2)).database := by
    funext key
    by_cases selected : key = keys rest.1 index <;>
      simp [setDatabaseCoordinate, cmsCell, basisPermutation, isolate, selected]
  apply cmsBasis_ext
  · rfl
  · rfl
  · rfl
  · exact database

/-- The actual CMS reflection has exactly the fresh-swap fiber kernel. -/
theorem fiber_decompress (keys : Branch → Index → Input) (index : Index)
    (rest : Rest (Work := Input × Phase × Work) (Output := Output) keys index)
    (ψ : CB → ℂ) :
    fiber keys index (J (decompressAt (keys rest.1 index) ψ)) rest =
      decompressJoint (fiber keys index (J ψ) rest) := by
  ext cell
  change decompressAt (keys rest.1 index) ψ (cmsCell keys index rest cell) =
    HegemonCrypto.CmsCompressedOracleUnitary.decompressFiber
      (WithLp.toLp 2 (fun slot => ψ (cmsCell keys index rest (slot, cell.2)))) cell.1
  rw [decompress_at_eq_sum_kernel, decompress_fiber_eq_sum_basis,
    cmsCell_selected_database]
  apply Finset.sum_congr rfl
  intro slot _
  rw [cmsCell_replace_database]

/-- Raw exchange acts on precisely the isolated cell and fresh label. -/
theorem cmsCell_indexed_raw (keys : Branch → Index → Input) (index : Index)
    (rest : Rest (Work := Input × Phase × Work) (Output := Output) keys index)
    (ψ : CB → ℂ) (cell : Option Output × Output) :
    indexedRawSwap (keys rest.1 index) index ψ (cmsCell keys index rest cell) =
      ψ (cmsCell keys index rest (rawExchange cell)) := by
  rcases cell with ⟨slot, label⟩
  cases slot with
  | none =>
      apply congrArg ψ
      apply cmsBasis_ext
      · simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
          cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
          Equiv.piSplitAt, setDatabaseCoordinate]
      · simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
          cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
          Equiv.piSplitAt, setDatabaseCoordinate]
      · apply Prod.ext
        · funext site
          by_cases same : site = index <;>
            simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
              cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
              Equiv.piSplitAt, setDatabaseCoordinate, same]
        · simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
            cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
            Equiv.piSplitAt, setDatabaseCoordinate]
      · funext key
        by_cases same : key = keys rest.1 index <;>
          simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
            cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
            Equiv.piSplitAt, setDatabaseCoordinate, same]
  | some answer =>
      apply congrArg ψ
      apply cmsBasis_ext
      · simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
          cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
          Equiv.piSplitAt, setDatabaseCoordinate]
      · simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
          cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
          Equiv.piSplitAt, setDatabaseCoordinate]
      · apply Prod.ext
        · funext site
          by_cases same : site = index <;>
            simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
              cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
              Equiv.piSplitAt, setDatabaseCoordinate, same]
        · simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
            cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
            Equiv.piSplitAt, setDatabaseCoordinate]
      · funext key
        by_cases same : key = keys rest.1 index <;>
          simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
            cmsCell, basisPermutation, isolate, rawExchange, Equiv.funSplitAt,
            Equiv.piSplitAt, setDatabaseCoordinate, same]

theorem fiber_raw (keys : Branch → Index → Input) (index : Index)
    (rest : Rest (Work := Input × Phase × Work) (Output := Output) keys index)
    (ψ : CB → ℂ) :
    fiber keys index (J (indexedRawSwap (keys rest.1 index) index ψ)) rest =
      exchange (fiber keys index (J ψ) rest) := by
  ext cell
  exact cmsCell_indexed_raw keys index rest ψ cell

theorem fiber_compressed (keys : Branch → Index → Input) (index : Index)
    (rest : Rest (Work := Input × Phase × Work) (Output := Output) keys index)
    (ψ : CB → ℂ) :
    fiber keys index (J (indexedCompressedSwap (keys rest.1 index) index ψ)) rest =
      compressedExchange (fiber keys index (J ψ) rest) := by
  rw [indexedCompressedSwap, fiber_decompress, fiber_raw, fiber_decompress]
  rfl

theorem slice_indexed_raw (branch : Branch) (key : Input) (index : Index)
    (ψ : CB → ℂ) :
    slice branch (indexedRawSwap key index ψ) = indexedRawSwap key index (slice branch ψ) := by
  funext basis
  cases selected : basis.database key <;>
    simp [slice, indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
      selected, Equiv.funSplitAt, Equiv.piSplitAt]

theorem slice_indexed_compressed (branch : Branch) (key : Input) (index : Index)
    (ψ : CB → ℂ) :
    slice branch (indexedCompressedSwap key index ψ) =
      indexedCompressedSwap key index (slice branch ψ) := by
  rw [indexedCompressedSwap, slice_decompress_at, slice_indexed_raw,
    slice_decompress_at]
  rfl

theorem controlled_single_coordinate (keys : Branch → Index → Input) (index : Index)
    (ψ : CB → ℂ) (basis : CB) :
    controlledCompressed keys [index] ψ basis =
      indexedCompressedSwap (keys basis.workspace.2.1 index) index ψ basis := by
  have sliced := congrArg
    (fun state => state
      { input := basis.input
        phase := basis.phase
        workspace := (basis.workspace.1, basis.workspace.2.2)
        database := basis.database })
    (slice_indexed_compressed basis.workspace.2.1
      (keys basis.workspace.2.1 index) index ψ)
  exact sliced.symm

/-- Exact singleton identity, including database, branch, labels, query
registers and arbitrary workspace. No state-transport equality is assumed. -/
theorem J_controlled_single (keys : Branch → Index → Input) (index : Index)
    (ψ : CB → ℂ) :
    J (controlledCompressed keys [index] ψ) = exchangeAt keys index (J ψ) := by
  ext basis
  rw [exchange_at_apply]
  let rest := ((isolate keys index) basis).1
  let cell := ((isolate keys index) basis).2
  have fiberEquality :=
    congrArg (fun state => state cell) (fiber_compressed keys index rest ψ)
  have branchEquality :=
    (controlled_single_coordinate keys index ψ (cmsCell keys index rest cell)).trans
      fiberEquality
  dsimp [rest, cell] at branchEquality
  have reconstructed :
      cmsCell keys index ((isolate keys index basis).1)
          ((isolate keys index basis).2) =
        (basisPermutation).symm basis := by
    unfold cmsCell
    rw [Prod.eta, Equiv.symm_apply_apply]
  rw [reconstructed] at branchEquality
  simpa [fiber, J, cmsCell] using branchEquality

theorem controlled_cons (keys : Branch → Index → Input) (index : Index)
    (tail : List Index) (ψ : CB → ℂ) :
    controlledCompressed keys (index :: tail) ψ =
      controlledCompressed keys tail (controlledCompressed keys [index] ψ) := by
  funext basis
  simp only [controlledCompressed, compressedSwapList, slice_controlled_compressed]

/-- Complete operator identification for every list of adaptively selected
keys. The same full state is retained; this is not a probability-only bridge. -/
theorem J_controlled_many (keys : Branch → Index → Input) (indices : List Index)
    (ψ : CB → ℂ) :
    J (controlledCompressed keys indices ψ) = exchangeMany keys indices (J ψ) := by
  induction indices generalizing ψ with
  | nil => rfl
  | cons index tail ih =>
    rw [controlled_cons, ih, J_controlled_single]
    rfl

end
end HegemonCrypto.SmallWood.Q38CmsResamplingCoordinates
