import SmzaRp05DegreeCertificateData

/-! Isolated finite root checks over the exact SHA-pinned RP05 DAG. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem root_block_0 :
    (List.range 128).all (fun i => rootDegreeCheck (0 + i)) = true := by
  decide

theorem root_block_128 :
    (List.range 128).all (fun i => rootDegreeCheck (128 + i)) = true := by
  decide

theorem root_block_256 :
    (List.range 128).all (fun i => rootDegreeCheck (256 + i)) = true := by
  decide

theorem root_block_384 :
    (List.range 128).all (fun i => rootDegreeCheck (384 + i)) = true := by
  decide

theorem root_block_512 :
    (List.range 128).all (fun i => rootDegreeCheck (512 + i)) = true := by
  decide

theorem root_block_640 :
    (List.range 128).all (fun i => rootDegreeCheck (640 + i)) = true := by
  decide

theorem root_block_768 :
    (List.range 50).all (fun i => rootDegreeCheck (768 + i)) = true := by
  decide

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
