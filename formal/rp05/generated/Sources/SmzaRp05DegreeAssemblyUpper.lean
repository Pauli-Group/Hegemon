import SmzaRp05DegreeGroup8Fast
import SmzaRp05DegreeGroup9Fast
import SmzaRp05DegreeGroup10Fast
import SmzaRp05DegreeGroup11Fast
import SmzaRp05DegreeGroup12Fast
import SmzaRp05DegreeGroup13Fast
import SmzaRp05DegreeGroup14Fast
import SmzaRp05DegreeGroup15Fast
import SmzaRp05DegreeGroupTail
import Lean.Elab.Tactic.Omega

/-! Remaining eight already checked RP05 degree groups and 21-node tail. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9ProgramPolynomials
open SmzaRp05Components

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem upper_group_sound (check : Nat → Bool) (group node : Nat)
    (checked : (List.range 4).all (fun j =>
      (List.range 128).all (fun i => check ((4 * group + j) * 128 + i))) = true)
    (lower : group * 512 ≤ node) (upper : node < (group + 1) * 512) :
    check node = true := by
  let j : Nat := (node - group * 512) / 128
  let i : Nat := (node - group * 512) % 128
  have jBound : j < 4 := by dsimp [j]; omega
  have iBound : i < 128 := by dsimp [i]; omega
  have outer := (List.all_eq_true.mp checked) j (List.mem_range.mpr jBound)
  have inner := (List.all_eq_true.mp outer) i (List.mem_range.mpr iBound)
  have same : (4 * group + j) * 128 + i = node := by
    dsimp [j, i]
    omega
  simpa only [same] using inner

theorem degreeCheck_upper (node : Nat) (lower : 4096 ≤ node)
    (bound : node < 8213) : degreeCheck node = true := by
  by_cases upper_8 : node < 4608
  · exact upper_group_sound degreeCheck 8 node degree_group_8
      (by omega) (by omega)
  by_cases upper_9 : node < 5120
  · exact upper_group_sound degreeCheck 9 node degree_group_9
      (by omega) (by omega)
  by_cases upper_10 : node < 5632
  · exact upper_group_sound degreeCheck 10 node degree_group_10
      (by omega) (by omega)
  by_cases upper_11 : node < 6144
  · exact upper_group_sound degreeCheck 11 node degree_group_11
      (by omega) (by omega)
  by_cases upper_12 : node < 6656
  · exact upper_group_sound degreeCheck 12 node degree_group_12
      (by omega) (by omega)
  by_cases upper_13 : node < 7168
  · exact upper_group_sound degreeCheck 13 node degree_group_13
      (by omega) (by omega)
  by_cases upper_14 : node < 7680
  · exact upper_group_sound degreeCheck 14 node degree_group_14
      (by omega) (by omega)
  by_cases upper_15 : node < 8192
  · exact upper_group_sound degreeCheck 15 node degree_group_15
      (by omega) (by omega)
  have tailMember : node - 8192 ∈ List.range 21 :=
    List.mem_range.mpr (by omega)
  have one := (List.all_eq_true.mp degree_group_tail) (node - 8192) tailMember
  have same : 8192 + (node - 8192) = node := by omega
  simpa only [same] using one

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
