import SmzaRp05DegreeFastExpression

/-! Four-block RP05 degree check for nodes 6144 through 6655 using the
    source-equivalent chunked expression accessor. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem degree_group_12_fast :
    (List.range 4).all (fun j =>
      (List.range 128).all (fun i => fastDegreeCheck ((4 * 12 + j) * 128 + i))) = true := by
  decide

theorem degree_group_12 :
    (List.range 4).all (fun j =>
      (List.range 128).all (fun i => degreeCheck ((4 * 12 + j) * 128 + i))) = true := by
  apply List.all_eq_true.mpr
  intro j jMember
  apply List.all_eq_true.mpr
  intro i iMember
  have outer := (List.all_eq_true.mp degree_group_12_fast) j jMember
  have inner := (List.all_eq_true.mp outer) i iMember
  simpa only [fastDegreeCheck_eq_degreeCheck] using inner

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData

