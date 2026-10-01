import SmzaRp05DegreeCertificateData

/-! Bounded four-block pilot for RP05 DAG node degrees 0 through 511. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem degree_group_0 :
    (List.range 4).all (fun j =>
      (List.range 128).all (fun i => degreeCheck ((4 * 0 + j) * 128 + i))) = true := by
  decide

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
