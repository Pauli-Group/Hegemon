import Q38CmsIndexedSwap

/-! Branch-controlled all-leaf oracle/label exchange in the existing CMS
state representation. Each unnormalized measured branch chooses its own
payload-dependent key map; global decompression preserves that branch. -/
namespace HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open V8SmzaCmsIndexedSwap
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Input Output Phase Work Index Branch : Type}
variable [Fintype Input] [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase] [Fintype Work] [DecidableEq Work]
variable [Fintype Index] [DecidableEq Index] [Fintype Branch] [DecidableEq Branch]

def slice (branch : Branch) (state : State Input Output Phase ((Index → Output) × (Branch × Work))) :
    State Input Output Phase ((Index → Output) × Work) :=
  fun basis => state
    { input := basis.input
      phase := basis.phase
      workspace := (basis.workspace.1, branch, basis.workspace.2)
      database := basis.database }

omit [Fintype Input] [AddCommGroup Output] [Fintype Phase] [DecidableEq Phase]
  [Fintype Work] [DecidableEq Work] [Fintype Index] [DecidableEq Index]
  [Fintype Branch] [DecidableEq Branch] in
theorem slice_decompress_at (branch : Branch) (key : Input)
    (state : State Input Output Phase ((Index → Output) × (Branch × Work))) :
    slice branch (decompressAt key state) = decompressAt key (slice branch state) := rfl

theorem slice_decompress_list (branch : Branch) (keys : List Input)
    (state : State Input Output Phase ((Index → Output) × (Branch × Work))) :
    slice branch (decompressList keys state) = decompressList keys (slice branch state) := by
  induction keys with
  | nil => rfl
  | cons key tail ih => rw [decompress_list_cons, slice_decompress_at, ih]; rfl

theorem slice_global_decompress (branch : Branch)
    (state : State Input Output Phase ((Index → Output) × (Branch × Work))) :
    slice branch (globalDecompress state) = globalDecompress (slice branch state) :=
  slice_decompress_list branch _ state

def controlledRaw (keys : Branch → Index → Input) (indices : List Index)
    (state : State Input Output Phase ((Index → Output) × (Branch × Work))) :
    State Input Output Phase ((Index → Output) × (Branch × Work)) :=
  fun basis => rawSwapList (keys basis.workspace.2.1) indices (slice basis.workspace.2.1 state)
    { input := basis.input
      phase := basis.phase
      workspace := (basis.workspace.1, basis.workspace.2.2)
      database := basis.database }

def controlledCompressed (keys : Branch → Index → Input) (indices : List Index)
    (state : State Input Output Phase ((Index → Output) × (Branch × Work))) :
    State Input Output Phase ((Index → Output) × (Branch × Work)) :=
  fun basis => compressedSwapList (keys basis.workspace.2.1) indices (slice basis.workspace.2.1 state)
    { input := basis.input
      phase := basis.phase
      workspace := (basis.workspace.1, basis.workspace.2.2)
      database := basis.database }

omit [Fintype Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase] [Fintype Work] [DecidableEq Work]
  [Fintype Index] [Fintype Branch] [DecidableEq Branch] in
theorem slice_controlled_raw (branch : Branch) (keys : Branch → Index → Input) (indices : List Index)
    (state : State Input Output Phase ((Index → Output) × (Branch × Work))) :
    slice branch (controlledRaw keys indices state) = rawSwapList (keys branch) indices (slice branch state) := rfl

omit [Fintype Input] [AddCommGroup Output] [Fintype Phase] [DecidableEq Phase]
  [Fintype Work] [DecidableEq Work] [Fintype Index] [Fintype Branch] [DecidableEq Branch] in
theorem slice_controlled_compressed (branch : Branch) (keys : Branch → Index → Input) (indices : List Index)
    (state : State Input Output Phase ((Index → Output) × (Branch × Work))) :
    slice branch (controlledCompressed keys indices state) = compressedSwapList (keys branch) indices (slice branch state) := rfl

/-- Exact adaptive experiment identification at the full quantum state level.
There is no branch-probability equality premise and no discarded measurement
outcome: branch-controlled compressed resampling is the raw oracle/label swap
after the existing whole-domain CMS decompression. -/
theorem global_controlled_swap_intertwining (keys : Branch → Index → Input) (indices : List Index)
    (state : State Input Output Phase ((Index → Output) × (Branch × Work))) :
    globalDecompress (controlledCompressed keys indices state) =
      controlledRaw keys indices (globalDecompress state) := by
  funext basis
  have sliced := congrArg
    (fun current : State Input Output Phase ((Index → Output) × Work) =>
      current
        { input := basis.input
          phase := basis.phase
          workspace := (basis.workspace.1, basis.workspace.2.2)
          database := basis.database })
    (slice_global_decompress basis.workspace.2.1 (controlledCompressed keys indices state))
  rw [slice_controlled_compressed, global_swap_list_intertwining, ← slice_global_decompress] at sliced
  exact sliced

end
end HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
