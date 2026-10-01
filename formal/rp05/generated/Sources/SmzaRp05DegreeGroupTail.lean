import SmzaRp05DegreeFastExpression

/-! Isolated final 21-node finite degree check for RP05 DAG nodes 8192 through 8212. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem degree_group_tail :
    (List.range 21).all (fun i => degreeCheck (8192 + i)) = true := by
  have fastTail :
      (List.range 21).all (fun i => fastDegreeCheck (8192 + i)) = true := by
    decide
  apply List.all_eq_true.mpr
  intro i iMember
  have checked := (List.all_eq_true.mp fastTail) i iMember
  simpa only [fastDegreeCheck_eq_degreeCheck] using checked

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
