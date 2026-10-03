import SmzaRp05ExecutableProgramEquality

/-! Finite summation reindexing along genuine type/program equalities. -/
namespace HegemonCrypto.SmallWood.SmzaRp05FiniteSumEqualityTransport

open scoped BigOperators
open SmzaRp05PhysicalAcceptedReplayLite (Branches)
open SmzaRp05ExecutableProgramEquality (castProgramBranch)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

theorem sum_cast_type_eq {Left Right : Type}
    [leftFinite : Fintype Left] [rightFinite : Fintype Right]
    (same : Left = Right) (mass : Right → ℝ) :
    (∑ value : Left, mass (cast same value)) = ∑ value : Right, mass value := by
  cases same
  have finiteSame : leftFinite = rightFinite := Subsingleton.elim _ _
  cases finiteSame
  rfl

theorem sum_cast_program_eq {Result Output : Type}
    (decode : RawInput → Output → RawDigest)
    (left right : Program Result) (same : left = right)
    [Fintype (Branches decode left)] [Fintype (Branches decode right)]
    (mass : Branches decode right → ℝ) :
    (∑ branch : Branches decode left,
      mass (castProgramBranch decode left right same branch)) =
      ∑ branch : Branches decode right, mass branch := by
  exact sum_cast_type_eq (congrArg (Branches decode) same) mass

end
end HegemonCrypto.SmallWood.SmzaRp05FiniteSumEqualityTransport
