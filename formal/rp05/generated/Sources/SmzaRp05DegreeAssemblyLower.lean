import SmzaRp05DegreeGroup0
import SmzaRp05DegreeGroup1
import SmzaRp05DegreeGroup2Fast
import SmzaRp05DegreeGroup3Fast
import SmzaRp05DegreeGroup4Fast
import SmzaRp05DegreeGroup5Fast
import SmzaRp05DegreeGroup6Fast
import SmzaRp05DegreeGroup7Fast
import Lean.Elab.Tactic.Omega

/-! First eight already checked RP05 degree groups. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9ProgramPolynomials
open SmzaRp05Components

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem lower_group_sound (check : Nat → Bool) (group node : Nat)
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

theorem degreeCheck_lower (node : Nat) (bound : node < 4096) :
    degreeCheck node = true := by
  by_cases upper_0 : node < 512
  · exact lower_group_sound degreeCheck 0 node degree_group_0
      (by omega) (by omega)
  by_cases upper_1 : node < 1024
  · exact lower_group_sound degreeCheck 1 node degree_group_1
      (by omega) (by omega)
  by_cases upper_2 : node < 1536
  · exact lower_group_sound degreeCheck 2 node degree_group_2
      (by omega) (by omega)
  by_cases upper_3 : node < 2048
  · exact lower_group_sound degreeCheck 3 node degree_group_3
      (by omega) (by omega)
  by_cases upper_4 : node < 2560
  · exact lower_group_sound degreeCheck 4 node degree_group_4
      (by omega) (by omega)
  by_cases upper_5 : node < 3072
  · exact lower_group_sound degreeCheck 5 node degree_group_5
      (by omega) (by omega)
  by_cases upper_6 : node < 3584
  · exact lower_group_sound degreeCheck 6 node degree_group_6
      (by omega) (by omega)
  exact lower_group_sound degreeCheck 7 node degree_group_7
    (by omega) (by omega)

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
