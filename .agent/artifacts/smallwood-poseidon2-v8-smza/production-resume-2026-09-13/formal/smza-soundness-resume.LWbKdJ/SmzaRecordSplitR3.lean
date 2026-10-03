import HegemonCrypto.SmallWoodV8Smz9CoherentMerklePartition

/-! Exact finite Record/Split algebra for arbitrary local complex kernels.
Labels are computed from the physical database, never supplied as a successful
extraction record. Source parser, active-slot support and the CMS commutator
instantiation remain separate obligations. No security probability is assumed.
-/
namespace HegemonCrypto.SmallWood.SmzaRecordSplitR3

open V8Smz9CoherentMerklePartition
open scoped BigOperators Classical
noncomputable section

variable {Target Label Cell Answer Database : Type*}
variable [DecidableEq Label]

abbrev Slot (Target Label : Type*) := Target × Option Label
abbrev Registers (Target Label Cell : Type*) := Slot Target Label → Cell

/-- For each target, exchange the original record cell with the cell indexed
by its actual extracted label. Different targets have disjoint cells. -/
def slotSplit (label : Target → Label) : Slot Target Label ≃ Slot Target Label :=
  Equiv.prodCongrRight fun target => Equiv.swap none (some (label target))

@[simp] theorem slot_split_plain (label : Target → Label) (target : Target) :
    slotSplit label (target, none) = (target, some (label target)) := by
  simp [slotSplit]

@[simp] theorem slot_split_labeled (label : Target → Label) (target : Target) :
    slotSplit label (target, some (label target)) = (target, none) := by
  simp [slotSplit]

theorem slot_split_involutive (label : Target → Label) :
    Function.Involutive (slotSplit label) := by
  intro slot
  rcases slot with ⟨target, cell⟩
  simp [slotSplit]

/-- A register permutation, with an explicit inverse; not a copy or measurement
of the adversary's query input. -/
def reindex (equivalence : Slot Target Label ≃ Slot Target Label) :
    Registers Target Label Cell ≃ Registers Target Label Cell where
  toFun registers := fun slot => registers (equivalence slot)
  invFun registers := fun slot => registers (equivalence.symm slot)
  left_inv registers := by funext slot; simp
  right_inv registers := by funext slot; simp

def splitRegisters (label : Target → Label) :
    Registers Target Label Cell ≃ Registers Target Label Cell :=
  reindex (slotSplit label)

theorem split_registers_involutive (label : Target → Label) :
    Function.Involutive (splitRegisters (Cell := Cell) label) := by
  intro registers
  funext slot
  exact congrArg registers (slot_split_involutive label slot)

/-- Splitting is controlled by the physical database and leaves it untouched. -/
def splitDatabase (extract : Database → Target → Label) :
    (Database × Registers Target Label Cell) ≃
      (Database × Registers Target Label Cell) :=
  Equiv.prodCongrRight fun database => splitRegisters (extract database)

@[simp] theorem split_database_preserves_database
    (extract : Database → Target → Label)
    (state : Database × Registers Target Label Cell) :
    (splitDatabase extract state).1 = state.1 := rfl

theorem split_database_involutive (extract : Database → Target → Label) :
    Function.Involutive (splitDatabase (Cell := Cell) extract) := by
  intro state
  rcases state with ⟨database, registers⟩
  exact Prod.ext rfl (split_registers_involutive (extract database) registers)

/-- Slots untouched by a local record operation must agree between basis
vectors. This formulation permits an arbitrary complex local operator. -/
def agreeOutside (slot : Slot Target Label)
    (left right : Registers Target Label Cell) : Prop :=
  ∀ other, other ≠ slot → left other = right other

omit [DecidableEq Label] in
theorem agree_outside_reindex
    (equivalence : Slot Target Label ≃ Slot Target Label)
    (slot : Slot Target Label) (left right : Registers Target Label Cell) :
    agreeOutside slot (reindex equivalence left) (reindex equivalence right) ↔
      agreeOutside (equivalence slot) left right := by
  constructor
  · intro same other different
    have different' : equivalence.symm other ≠ slot := by
      intro equal
      apply different
      simpa using congrArg equivalence equal
    simpa [reindex] using same (equivalence.symm other) different'
  · intro same other different
    apply same (equivalence other)
    exact fun equal => different (equivalence.injective equal)

/-- Matrix coefficients of any operator on (answer, chosen record cell),
tensored with identity on every other record cell. -/
def localRecordKernel (slot : Slot Target Label)
    (gate : (Answer × Cell) → (Answer × Cell) → ℂ)
    (source target : Answer × Registers Target Label Cell) : ℂ :=
  if agreeOutside slot source.2 target.2 then
    gate (source.1, source.2 slot) (target.1, target.2 slot)
  else 0

def splitAnswerRegisters (label : Target → Label) :
    (Answer × Registers Target Label Cell) ≃
      (Answer × Registers Target Label Cell) :=
  Equiv.prodCongr (Equiv.refl Answer) (splitRegisters label)

/-- Exact Record conjugation at every matrix coefficient. Gate may be any
complex kernel, not merely a classical reversible gate. Uniformity in target
allows the final oracle to control this equation on a superposed target. -/
theorem record_split_kernel_conjugation
    (label : Target → Label) (target : Target)
    (gate : (Answer × Cell) → (Answer × Cell) → ℂ)
    (left right : Answer × Registers Target Label Cell) :
    localRecordKernel (target, none) gate
        (splitAnswerRegisters label left) (splitAnswerRegisters label right) =
      localRecordKernel (target, some (label target)) gate left right := by
  unfold localRecordKernel
  have agreement := agree_outside_reindex (slotSplit label) (target, none) left.2 right.2
  simp only [slot_split_plain] at agreement
  change (if agreeOutside (target, none)
      (reindex (slotSplit label) left.2) (reindex (slotSplit label) right.2) then
      gate (left.1, left.2 (slotSplit label (target, none)))
        (right.1, right.2 (slotSplit label (target, none))) else 0) = _
  rw [agreement, slot_split_plain]

section FiniteOperators

variable {Basis : Type*} [Fintype Basis]

/-- Kernel conjugation is exact operator intertwining, with no basis-state or
classical-input restriction on the input state. -/
theorem kernel_intertwining
    (original indexed : Basis → Basis → ℂ) (split : Basis ≃ Basis)
    (conjugates : ∀ left right, original (split left) (split right) = indexed left right)
    (state : Basis → ℂ) :
    applyKernel original (permute split state) =
      permute split (applyKernel indexed state) := by
  funext target
  unfold applyKernel permute
  dsimp only [Function.comp_def]
  rw [← split.sum_comp (fun source => state (split.symm source) * original source target)]
  apply Finset.sum_congr rfl
  intro source _
  rw [split.symm_apply_apply]
  have same := conjugates source (split.symm target)
  rw [split.apply_symm_apply] at same
  rw [same]

variable [Fintype Target] [Fintype Label] [Fintype Cell] [Fintype Answer]

/-- Exact coherent Record/Split relation for arbitrary superpositions of answer
and all record-register values. This is a change of basis, not a new log. -/
theorem record_split_operator_intertwining
    (label : Target → Label) (target : Target)
    (gate : (Answer × Cell) → (Answer × Cell) → ℂ)
    (state : (Answer × Registers Target Label Cell) → ℂ) :
    applyKernel (localRecordKernel (target, none) gate)
        (permute (splitAnswerRegisters label) state) =
      permute (splitAnswerRegisters label)
        (applyKernel (localRecordKernel (target, some (label target)) gate) state) :=
  kernel_intertwining _ _ _ (record_split_kernel_conjugation label target gate) state

end FiniteOperators

end
end HegemonCrypto.SmallWood.SmzaRecordSplitR3
