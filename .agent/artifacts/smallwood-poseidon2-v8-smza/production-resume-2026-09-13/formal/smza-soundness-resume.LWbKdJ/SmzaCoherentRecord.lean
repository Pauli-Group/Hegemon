import SmzaRecordSplitR3

/-! The Record/Split conjugation on the JOINT physical database, query target,
answer and record-register Hilbert space. Neither database nor query target
is measured. This is finite oracle algebra, not a security-success assertion. -/
namespace HegemonCrypto.SmallWood.SmzaCoherentRecord

open SmzaRecordSplitR3 V8Smz9CoherentMerklePartition
open scoped BigOperators Classical
noncomputable section

variable {Database Target Label Answer Cell : Type*}
variable [DecidableEq Label]

abbrev JointBasis (Database Target Label Answer Cell : Type*) :=
  Database × Target × Answer × Registers Target Label Cell

def coherentSplit (extract : Database → Target → Label) :
    JointBasis Database Target Label Answer Cell ≃ JointBasis Database Target Label Answer Cell :=
  Equiv.prodCongrRight fun database =>
    Equiv.prodCongr (Equiv.refl Target) (splitAnswerRegisters (extract database))

theorem coherent_split_involutive (extract : Database → Target → Label) :
    Function.Involutive (coherentSplit (Answer := Answer) (Cell := Cell) extract) := by
  rintro ⟨database, target, answer, registers⟩
  exact Prod.ext rfl (Prod.ext rfl (Prod.ext rfl
    (split_registers_involutive (extract database) registers)))

/-- A record-oracle call is controlled on the target register, preserves the
VC database, and applies any complex local kernel to answer and selected cell.
The selector is none for the ordinary record oracle and some(extract D target)
for the extraction-indexed record oracle. -/
def jointRecordKernel (selector : Database → Target → Option Label)
    (gate : Target → (Answer × Cell) → (Answer × Cell) → ℂ)
    (source target : JointBasis Database Target Label Answer Cell) : ℂ :=
  if target.1 = source.1 ∧ target.2.1 = source.2.1 then
    localRecordKernel (source.2.1, selector source.1 source.2.1)
      (gate source.2.1) source.2.2 target.2.2
  else 0

/-- Every matrix entry of the coherent oracle satisfies the conjugation,
including entries between arbitrary database and target basis values. -/
theorem coherent_record_kernel_conjugation (extract : Database → Target → Label)
    (gate : Target → (Answer × Cell) → (Answer × Cell) → ℂ)
    (source target : JointBasis Database Target Label Answer Cell) :
    jointRecordKernel (fun _ _ => none) gate
        (coherentSplit extract source) (coherentSplit extract target) =
      jointRecordKernel (fun database target => some (extract database target)) gate source target := by
  unfold jointRecordKernel
  change (if target.1 = source.1 ∧ target.2.1 = source.2.1 then
      localRecordKernel (source.2.1, none) (gate source.2.1)
        (splitAnswerRegisters (extract source.1) source.2.2)
        (splitAnswerRegisters (extract target.1) target.2.2) else 0) = _
  split_ifs with same
  · rw [same.1]
    exact record_split_kernel_conjugation (extract source.1) source.2.1
      (gate source.2.1) source.2.2 target.2.2
  · rfl

variable [Fintype Database] [Fintype Target] [Fintype Label] [Fintype Answer] [Fintype Cell]

/-- Exact operator identity on arbitrary jointly entangled states. The
extraction-indexed oracle is independently defined by its selected record cell,
not defined tautologically as a conjugation of the ordinary oracle. -/
theorem coherent_record_operator_intertwining (extract : Database → Target → Label)
    (gate : Target → (Answer × Cell) → (Answer × Cell) → ℂ)
    (state : JointBasis Database Target Label Answer Cell → ℂ) :
    applyKernel (jointRecordKernel (fun _ _ => none) gate)
        (permute (coherentSplit extract) state) =
      permute (coherentSplit extract)
        (applyKernel
          (jointRecordKernel (fun database target => some (extract database target)) gate) state) :=
  kernel_intertwining _ _ _ (coherent_record_kernel_conjugation extract gate) state

theorem coherent_split_preserves_mass (extract : Database → Target → Label)
    (state : JointBasis Database Target Label Answer Cell → ℂ) :
    mass (permute (coherentSplit extract) state) = mass state :=
  permute_mass _ _

end
end HegemonCrypto.SmallWood.SmzaCoherentRecord
