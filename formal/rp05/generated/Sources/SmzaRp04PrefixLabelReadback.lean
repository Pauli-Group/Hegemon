import SmzaRp04PrefixLabels

/-! Small readback lemmas which do not construct dependent role labels in a
theorem statement. -/

namespace HegemonCrypto.SmallWood.SmzaRp04CompleteRawRoleCells

open SmzaRp04RoleBadCells SmzaRp04PublicContext SmzaRp04ChronologicalAlgebra
open SmzaRp04ActualProgram SmzaRp04CalculatedExtraction
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction
open V8Smz9PiopSoundness

set_option autoImplicit false
set_option maxRecDepth 10000

theorem matrix_label_ext {publicWords : List Nat}
    (left right : PiopMatrixLabel publicWords)
    (candidateEq : left.candidate = right.candidate) : left = right := by
  cases left with
  | mk leftCandidate leftInvalid =>
      cases right with
      | mk rightCandidate rightInvalid =>
          cases candidateEq
          rfl

/-- The successful branch of an optional dependent guard preserves the
builder's actual proof-carrying result. No RP04 candidate type occurs in this
statement; the concrete prefix instantiates it only inside its consumer. -/
theorem guarded_option_some {α β : Type*}
    (choice : Option α) (allowed : α → Prop) [DecidablePred allowed]
    (build : (x : α) → allowed x → β)
    (x : α) (read : choice = some x) (ok : allowed x) :
    (match choice with
      | none => none
      | some y => if hy : allowed y then some (build y hy) else none) =
        some (build x ok) := by
  cases choice with
  | none => cases read
  | some y =>
      cases read
      simp [ok]

theorem guarded_optional_event {α β γ : Type*}
    (choice : Option α) (allowed : α → Prop) [DecidablePred allowed]
    (build : (x : α) → allowed x → β) (event : β → γ → Prop)
    (output : γ) (x : α) (read : choice = some x) (ok : allowed x)
    (bad : event (build x ok) output) :
    ∃ label,
      (match choice with
        | none => none
        | some y => if hy : allowed y then some (build y hy) else none) =
          some label ∧ event label output := by
  cases choice with
  | none => cases read
  | some y =>
      cases read
      refine ⟨build x ok, ?_, bad⟩
      simp only [dif_pos ok]

/-- Readback of a dependent `Option` match is independent of the equality
proof chosen for its successful branch. -/
theorem dependent_option_some {α β : Type*} (r : Option α)
    (f : (x : α) → r = some x → β) (x : α) (present : r = some x) :
    (match r with
      | none => none
      | some value => some (f value rfl)) = some (f x present) := by
  cases r with
  | none => cases present
  | some value =>
      cases present
      rfl

theorem optional_event_of_eq_some {β γ : Type*} (stored : Option β)
    (event : β → γ → Prop) (output : γ) (label : β)
    (present : stored = some label) (bad : event label output) :
    ∃ selected, stored = some selected ∧ event selected output := by
  exact ⟨label, present, bad⟩

end HegemonCrypto.SmallWood.SmzaRp04CompleteRawRoleCells
