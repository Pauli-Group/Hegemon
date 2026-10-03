import SmzaRp05DegreeAssemblyLower
import SmzaRp05DegreeAssemblyUpper
import SmzaRp05DegreeFastExpression
import Lean.Elab.Tactic.Omega

/-! Join the two cached source-pinned degree halves. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9ProgramPolynomials
open SmzaRp05Components

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem degreeCheck_all (node : Nat) (bound : node < 8213) :
    degreeCheck node = true := by
  by_cases lower : node < 4096
  · exact degreeCheck_lower node lower
  · exact degreeCheck_upper node (by omega) bound

theorem degreeCertificate :
    DegreeCertificate exactNonlinearExpressions nodeDegree := by
  intro node expression found
  have bound : node < exactNonlinearExpressions.length :=
    (List.getElem?_eq_some_iff.mp found).1
  have numericBound : node < 8213 := by
    simpa only [sourceLength] using bound
  have checked := degreeCheck_all node numericBound
  simpa [degreeCheck, found] using checked

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
