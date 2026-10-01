import SmzaRp05DegreeRoots
import Lean.Elab.Tactic.Omega

/-! Join the seven cached exact root-degree blocks. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9ProgramPolynomials
open SmzaRp05Components

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem block_sound (check : Nat → Bool) (offset count node : Nat)
    (checked : (List.range count).all (fun i => check (offset + i)) = true)
    (lower : offset ≤ node) (upper : node < offset + count) :
    check node = true := by
  have one := (List.all_eq_true.mp checked) (node - offset)
    (List.mem_range.mpr (by omega))
  have same : offset + (node - offset) = node := by omega
  simpa [same] using one

theorem rootDegreeCheck_all (node : Nat) (bound : node < 818) :
    rootDegreeCheck node = true := by
  by_cases upper_0 : node < 128
  · exact block_sound rootDegreeCheck 0 128 node root_block_0
      (by omega) (by omega)
  by_cases upper_128 : node < 256
  · exact block_sound rootDegreeCheck 128 128 node root_block_128
      (by omega) (by omega)
  by_cases upper_256 : node < 384
  · exact block_sound rootDegreeCheck 256 128 node root_block_256
      (by omega) (by omega)
  by_cases upper_384 : node < 512
  · exact block_sound rootDegreeCheck 384 128 node root_block_384
      (by omega) (by omega)
  by_cases upper_512 : node < 640
  · exact block_sound rootDegreeCheck 512 128 node root_block_512
      (by omega) (by omega)
  by_cases upper_640 : node < 768
  · exact block_sound rootDegreeCheck 640 128 node root_block_640
      (by omega) (by omega)
  by_cases upper_768 : node < 818
  · exact block_sound rootDegreeCheck 768 50 node root_block_768
      (by omega) (by omega)
  omega

theorem rootsExact : exactNonlinearRoots = List.ofFn nonlinearRoot := by
  decide

theorem rootDegree (slot : Fin 818) : nodeDegree (nonlinearRoot slot) ≤ 8 := by
  have checked := rootDegreeCheck_all slot.val slot.isLt
  cases found : exactNonlinearRoots[slot.val]? with
  | none => simp [rootDegreeCheck, found] at checked
  | some root =>
      simpa [rootDegreeCheck, nonlinearRoot, List.getD_eq_getElem?_getD, found]
        using checked

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
