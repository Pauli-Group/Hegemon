import Q38CmsSwapConjugation

/-! Lift the exact CMS raw-swap conjugation to distinct fresh-label
coordinates, preserving all other label registers and workspace. -/
namespace HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge V8SmzaCmsSwapConjugation
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Input Output Phase Work OtherWork Index : Type}
variable [Fintype Input] [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase] [Fintype Work] [DecidableEq Work]
variable [Fintype OtherWork] [DecidableEq OtherWork] [Fintype Index] [DecidableEq Index]

def transportWorkspace (equivalence : Work ≃ OtherWork) (state : State Input Output Phase Work) :
    State Input Output Phase OtherWork :=
  fun basis => state
    { input := basis.input
      phase := basis.phase
      workspace := (Equiv.symm equivalence) basis.workspace
      database := basis.database }

omit [Fintype Input] [DecidableEq Input] [Fintype Output] [DecidableEq Output]
  [AddCommGroup Output] [Fintype Phase] [DecidableEq Phase] [Fintype Work]
  [DecidableEq Work] [Fintype OtherWork] [DecidableEq OtherWork] in
theorem transport_workspace_roundtrip (equivalence : Work ≃ OtherWork) (state : State Input Output Phase Work) :
    transportWorkspace equivalence.symm (transportWorkspace equivalence state) = state := by
  funext basis
  simp [transportWorkspace]

omit [Fintype Input] [AddCommGroup Output] [Fintype Phase] [DecidableEq Phase]
  [Fintype Work] [DecidableEq Work] [Fintype OtherWork] [DecidableEq OtherWork] in
theorem transport_decompress_at (equivalence : Work ≃ OtherWork) (key : Input)
    (state : State Input Output Phase Work) :
    transportWorkspace equivalence (decompressAt key state) =
      decompressAt key (transportWorkspace equivalence state) := by
  rfl

omit [Fintype OtherWork] [DecidableEq OtherWork] in
theorem transport_decompress_list (equivalence : Work ≃ OtherWork) (keys : List Input)
    (state : State Input Output Phase Work) :
    transportWorkspace equivalence (decompressList keys state) =
      decompressList keys (transportWorkspace equivalence state) := by
  induction keys with
  | nil => rfl
  | cons key tail ih => rw [decompress_list_cons, transport_decompress_at, ih]; rfl

omit [Fintype OtherWork] [DecidableEq OtherWork] in
theorem transport_global_decompress (equivalence : Work ≃ OtherWork)
    (state : State Input Output Phase Work) :
    transportWorkspace equivalence (globalDecompress state) =
      globalDecompress (transportWorkspace equivalence state) :=
  transport_decompress_list equivalence _ state

def labelSplit (index : Index) : ((Index → Output) × Work) ≃
    (Output × (({ site : Index // site ≠ index } → Output) × Work)) :=
  ((Equiv.funSplitAt index Output).prodCongr (Equiv.refl Work)).trans (Equiv.prodAssoc _ _ _)

def indexedRawSwap (key : Input) (index : Index)
    (state : State Input Output Phase ((Index → Output) × Work)) :
    State Input Output Phase ((Index → Output) × Work) :=
  transportWorkspace (labelSplit (Output := Output) (Work := Work) index).symm
    (rawSwap key (transportWorkspace (labelSplit index) state))

def indexedCompressedSwap (key : Input) (index : Index)
    (state : State Input Output Phase ((Index → Output) × Work)) :
    State Input Output Phase ((Index → Output) × Work) :=
  decompressAt key (indexedRawSwap key index (decompressAt key state))

/-- Each fresh label has its own register. The other labels are carried
through the same exact global/local conjugation, with no reset or discard. -/
theorem global_indexed_swap_conjugation (key : Input) (index : Index)
    (state : State Input Output Phase ((Index → Output) × Work)) :
    globalDecompress (indexedRawSwap key index (globalDecompress state)) =
      indexedCompressedSwap key index state := by
  simp only [indexedCompressedSwap, indexedRawSwap]
  rw [transport_global_decompress]
  have hswap := global_swap_conjugation key
    (transportWorkspace (labelSplit (Output := Output) (Work := Work) index) state)
  rw [← transport_global_decompress]
  rw [hswap]
  simp only [transport_decompress_at]

theorem global_indexed_swap_intertwining (key : Input) (index : Index)
    (state : State Input Output Phase ((Index → Output) × Work)) :
    globalDecompress (indexedCompressedSwap key index state) =
      indexedRawSwap key index (globalDecompress state) := by
  rw [← global_indexed_swap_conjugation, global_decompress_involutive]

def rawSwapList (keys : Index → Input) : List Index →
    State Input Output Phase ((Index → Output) × Work) → State Input Output Phase ((Index → Output) × Work)
  | [], state => state
  | index :: tail, state => rawSwapList keys tail (indexedRawSwap (keys index) index state)

def compressedSwapList (keys : Index → Input) : List Index →
    State Input Output Phase ((Index → Output) × Work) → State Input Output Phase ((Index → Output) × Work)
  | [], state => state
  | index :: tail, state => compressedSwapList keys tail (indexedCompressedSwap (keys index) index state)

theorem global_swap_list_intertwining (keys : Index → Input) (indices : List Index)
    (state : State Input Output Phase ((Index → Output) × Work)) :
    globalDecompress (compressedSwapList keys indices state) =
      rawSwapList keys indices (globalDecompress state) := by
  induction indices generalizing state with
  | nil => rfl
  | cons index tail ih =>
    rw [compressedSwapList, ih, global_indexed_swap_intertwining]
    rfl

end
end HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
