import HegemonCrypto.SmallWoodV8Smz9SourceStableStateCoefficients

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableOutputCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableStateCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_stable_root_target (pub : Nat → F) (which : Fin 2) (lane : Fin 7) :
    actualCsrCoefficients pub (362+5*lane.val+which.val) =
      if which.val=0 then
        (1-liveEnabled pub)*(pub (95+lane.val)-pub (102+lane.val))+pub (95+lane.val)*liveEnabled pub
      else pub (102+lane.val)*liveEnabled pub := by
  have before := actual_public_coefficient pub ⟨95+lane.val,by omega⟩
  have after := actual_public_coefficient pub ⟨102+lane.val,by omega⟩
  have beforeAddress : 4+(95+lane.val)=99+lane.val := by omega
  have afterAddress : 4+(102+lane.val)=106+lane.val := by omega
  simp only [beforeAddress] at before
  simp only [afterAddress] at after
  have gap := actual_csr_node_field_equation pub
    (show exactCsrExpressions[359+5*lane.val]? = some (.sub (99+lane.val) (106+lane.val)) by fin_cases lane <;> decide)
  have dormant := actual_csr_node_field_equation pub
    (show exactCsrExpressions[360+5*lane.val]? = some (.mul 307 (359+5*lane.val)) by fin_cases lane <;> decide)
  have active := actual_csr_node_field_equation pub
    (show exactCsrExpressions[361+5*lane.val]? = some (.mul (99+lane.val) 306) by fin_cases lane <;> decide)
  have beforeTarget := actual_csr_node_field_equation pub
    (show exactCsrExpressions[362+5*lane.val]? = some (.add (360+5*lane.val) (361+5*lane.val)) by fin_cases lane <;> decide)
  have afterTarget := actual_csr_node_field_equation pub
    (show exactCsrExpressions[363+5*lane.val]? = some (.mul (106+lane.val) 306) by fin_cases lane <;> decide)
  simp only [expressionField] at gap dormant active beforeTarget afterTarget
  rw [before,after] at gap
  rw [live_coefficient_307,gap] at dormant
  rw [before,live_coefficient_306] at active
  rw [dormant,active] at beforeTarget
  rw [after,live_coefficient_306] at afterTarget
  fin_cases which
  · simpa only [Nat.add_zero,if_true] using beforeTarget
  · simpa only [show 362+5*lane.val+1=363+5*lane.val by omega,
      Nat.one_ne_zero,if_false] using afterTarget

theorem actual_stable_issuer_auth_target (pub : Nat → F) (lane : Fin 7) :
    actualCsrCoefficients pub (394+lane.val) = pub (113+lane.val)*liveMint pub := by
  have publicWord := actual_public_coefficient pub ⟨113+lane.val,by omega⟩
  have address : 4+(113+lane.val)=117+lane.val := by omega
  simp only [address] at publicWord
  have target := actual_csr_node_field_equation pub
    (show exactCsrExpressions[394+lane.val]? = some (.mul (117+lane.val) 304) by fin_cases lane <;> decide)
  simp only [expressionField,publicWord,live_coefficient_304] at target
  exact target

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableOutputCoefficients
