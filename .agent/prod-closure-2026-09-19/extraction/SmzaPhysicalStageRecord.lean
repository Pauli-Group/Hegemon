import SmzaInitializedStageRouting

/-! Record/Split on the exact physical basis used by initialized routing.
The two record kernels are defined independently by their selected register
slots. The intertwining law is proved, not supplied as an execution premise.
Instantiating the local gate, accepted readout and common complete execution
remains separate; this module does not assert those constructions exist. -/
namespace HegemonCrypto.SmallWood.SmzaPhysicalStageRecord

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open V8Smz9CoherentMerklePartition V8Smz9CoherentVectorMerkle
open SmzaRecordSplitR3 SmzaStageControlledSplit SmzaStageGlobalSplit

noncomputable section
set_option autoImplicit false

variable {Key Counter Target Label Cell Private : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Target] [Fintype Label] [Fintype Cell] [Fintype Private]

local notation "SB" => StageBasis Key Counter Target Label Cell Private
local notation "DB" => Database Key (VectorOutput Counter)

/-- One local record operation, controlled on the raw query key. It preserves
the VC database, query key and private workspace and acts on the phase/answer
register and exactly one record cell. -/
def physicalRecordKernel (selector : DB → Target → Option Label)
    (queryTarget : Key → Target)
    (gate : Key → (VectorOutput Counter × Cell) → (VectorOutput Counter × Cell) → ℂ)
    (source target : SB) : ℂ :=
  if target.input = source.input ∧ target.database = source.database ∧
      target.workspace.1 = source.workspace.1 then
    localRecordKernel
      (queryTarget source.input, selector source.database (queryTarget source.input))
      (gate source.input) (source.phase, source.workspace.2)
      (target.phase, target.workspace.2)
  else 0

omit [DecidableEq Counter] [Fintype Target] [Fintype Label] [Fintype Cell]
  [Fintype Private] in
theorem physical_record_kernel_conjugation
    (value : DB → Target → Label) (queryTarget : Key → Target)
    (gate : Key → (VectorOutput Counter × Cell) → (VectorOutput Counter × Cell) → ℂ)
    (source target : SB) :
    physicalRecordKernel (fun _ _ => none) queryTarget gate
        (fullSplit value source) (fullSplit value target) =
      physicalRecordKernel (fun database target => some (value database target))
        queryTarget gate source target := by
  unfold physicalRecordKernel
  change (if target.input = source.input ∧ target.database = source.database ∧
      target.workspace.1 = source.workspace.1 then
    localRecordKernel (queryTarget source.input, none) (gate source.input)
      (source.phase, splitRegisters (value source.database) source.workspace.2)
      (target.phase, splitRegisters (value target.database) target.workspace.2)
    else 0) = _
  split_ifs with same
  · rw [same.2.1]
    exact record_split_kernel_conjugation (value source.database)
      (queryTarget source.input) (gate source.input)
      (source.phase, source.workspace.2) (target.phase, target.workspace.2)
  · rfl

omit [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
  [Fintype Target] [Fintype Label] [Fintype Cell] [Fintype Private] in
theorem physical_full_split_involutive (value : DB → Target → Label) :
    Function.Involutive (fullSplit (Cell := Cell) (Private := Private) value) := by
  intro basis
  rcases basis with ⟨input, phase, ⟨privateState, registers⟩, database⟩
  exact congrArg
    (fun registers => (Basis.mk input phase (privateState, registers) database : SB))
    (split_registers_involutive (value database) registers)

/-- The exact premise required by initialized selected-stage routing, now
derived for the concrete independently defined physical record kernels. -/
theorem physical_record_intertwines
    (value : DB → Target → Label) (queryTarget : Key → Target)
    (gate : Key → (VectorOutput Counter × Cell) → (VectorOutput Counter × Cell) → ℂ)
    (state : SB → ℂ) :
    permute (fullSplit value)
        (applyKernel (physicalRecordKernel (fun _ _ => none) queryTarget gate) state) =
      applyKernel
        (physicalRecordKernel (fun database target => some (value database target))
          queryTarget gate) (permute (fullSplit value) state) := by
  have reverse : ∀ left right : SB,
      physicalRecordKernel (fun database target => some (value database target))
          queryTarget gate (fullSplit value left) (fullSplit value right) =
        physicalRecordKernel (fun _ _ => none) queryTarget gate left right := by
    intro left right
    have hleft : fullSplit value (fullSplit value left) = left :=
      physical_full_split_involutive value left
    have hright : fullSplit value (fullSplit value right) = right :=
      physical_full_split_involutive value right
    simpa only [hleft, hright] using
      (physical_record_kernel_conjugation value queryTarget gate
        (fullSplit value left) (fullSplit value right)).symm
  exact (kernel_intertwining _ _ (fullSplit value) reverse state).symm

end
end HegemonCrypto.SmallWood.SmzaPhysicalStageRecord
