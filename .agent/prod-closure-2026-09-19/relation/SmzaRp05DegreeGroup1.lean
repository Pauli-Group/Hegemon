import SmzaRp05DegreeCertificateData

/-! Isolated four-block finite degree check for RP05 DAG nodes 512 through 1023. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem degree_group_1 :
    (List.range 4).all (fun j =>
      (List.range 128).all (fun i => degreeCheck ((4 * 1 + j) * 128 + i))) = true := by
  decide

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData

