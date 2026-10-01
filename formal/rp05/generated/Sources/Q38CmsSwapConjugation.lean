import HegemonCrypto.CmsOracleDatabaseBridge

/-! Exact oracle/label swap conjugation through the existing CMS whole-table
decompression. The raw operation swaps a selected database entry with a
retained fresh-label register. Other database coordinates commute with it. -/
namespace HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Input Output Phase Work : Type}
variable [Fintype Input] [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase] [Fintype Work] [DecidableEq Work]

abbrev SwapBasis := Basis Input Output Phase (Output × Work)
abbrev SwapState := State Input Output Phase (Output × Work)

def swapBasis (selected : Input) (basis : SwapBasis (Input := Input) (Output := Output) (Phase := Phase) (Work := Work)) :=
  match basis.database selected with
  | none => basis
  | some answer => { basis with
      database := setDatabaseCoordinate basis.database selected (some basis.workspace.1)
      workspace := (answer, basis.workspace.2) }

def rawSwap (selected : Input) (state : SwapState (Input := Input) (Output := Output) (Phase := Phase) (Work := Work)) :
    SwapState (Input := Input) (Output := Output) (Phase := Phase) (Work := Work) :=
  fun basis => state (swapBasis selected basis)

omit [Fintype Phase] [DecidableEq Phase] [Fintype Work] [DecidableEq Work] in
theorem swap_preserves_other (selected other : Input) (different : other ≠ selected)
    (basis : SwapBasis (Input := Input) (Output := Output) (Phase := Phase) (Work := Work)) :
    (swapBasis selected basis).database other = basis.database other := by
  cases value : basis.database selected <;> simp [swapBasis, value, set_database_coordinate_other _ different]

omit [Fintype Phase] [DecidableEq Phase] [Fintype Work] [DecidableEq Work] in
theorem swap_replacement_commutes (selected other : Input) (different : other ≠ selected)
    (basis : SwapBasis (Input := Input) (Output := Output) (Phase := Phase) (Work := Work))
    (value : Option Output) :
    swapBasis selected { basis with database := setDatabaseCoordinate basis.database other value } =
      { swapBasis selected basis with database := setDatabaseCoordinate (swapBasis selected basis).database other value } := by
  have otherRead : setDatabaseCoordinate basis.database other value selected = basis.database selected :=
    set_database_coordinate_other _ (Ne.symm different) _
  cases answer : basis.database selected with
  | none => simp only [swapBasis, otherRead, answer]
  | some answer =>
    simp only [swapBasis, otherRead, answer]
    rw [set_database_coordinate_commutes basis.database other selected different]

theorem raw_swap_decompression_commutes (selected other : Input) (different : other ≠ selected)
    (state : SwapState (Input := Input) (Output := Output) (Phase := Phase) (Work := Work)) :
    rawSwap selected (decompressAt other state) = decompressAt other (rawSwap selected state) := by
  funext basis
  change decompressAt other state (swapBasis selected basis) = _
  rw [decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel]
  rw [swap_preserves_other selected other different]
  apply Finset.sum_congr rfl
  intro value _
  unfold rawSwap
  have commutes := swap_replacement_commutes selected other different basis value
  exact congrArg (fun target => state target * decompressKernel value (basis.database other)) commutes.symm

theorem raw_swap_decompression_list_commutes (selected : Input) (inputs : List Input)
    (different : ∀ input ∈ inputs, input ≠ selected)
    (state : SwapState (Input := Input) (Output := Output) (Phase := Phase) (Work := Work)) :
    rawSwap selected (decompressList inputs state) = decompressList inputs (rawSwap selected state) := by
  induction inputs with
  | nil => rfl
  | cons input tail ih =>
    rw [decompress_list_cons, raw_swap_decompression_commutes selected input (different input (List.mem_cons_self)),
      ih (fun other member => different other (List.mem_cons_of_mem input member))]
    rfl

theorem raw_swap_decompression_except_commutes (selected : Input)
    (state : SwapState (Input := Input) (Output := Output) (Phase := Phase) (Work := Work)) :
    rawSwap selected (decompressExcept selected state) = decompressExcept selected (rawSwap selected state) := by
  apply raw_swap_decompression_list_commutes
  intro input member
  exact (Finset.mem_erase.mp (Finset.mem_toList.mp member)).1

/-- Conjugating the actual raw oracle/label exchange by full CMS
decompression equals its one-coordinate D·swap·D implementation exactly. -/
theorem global_swap_conjugation (selected : Input)
    (state : SwapState (Input := Input) (Output := Output) (Phase := Phase) (Work := Work)) :
    globalDecompress (rawSwap selected (globalDecompress state)) =
      decompressAt selected (rawSwap selected (decompressAt selected state)) := by
  rw [global_decompress_eq_selected_first selected,
    global_decompress_eq_selected_last selected state,
    raw_swap_decompression_except_commutes]
  unfold decompressExcept
  rw [decompress_list_involutive]

end
end HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
