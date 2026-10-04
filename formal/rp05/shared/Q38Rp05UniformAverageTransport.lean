import HegemonCrypto.SmallWoodV8Smz9CurrentPrivacyGame

namespace HegemonCrypto.SmallWood.Q38Rp05UniformAverageTransport

open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame

set_option autoImplicit false

/-- Pointwise transport does not compare concrete finite enumerations by
conversion. Both dictionaries enumerate the same finite type and hence give
the same uniform law; the equality follows from Fintype's subsingleton proof. -/
theorem uniform_average_congr_instances {A : Type}
    (leftFinite rightFinite : Fintype A)
    (leftNonempty rightNonempty : Nonempty A) (left right : A → ℝ)
    (pointwise : ∀ value, left value = right value) :
    @uniformAverage A leftFinite leftNonempty left =
      @uniformAverage A rightFinite rightNonempty right := by
  have finiteEq : leftFinite = rightFinite := Subsingleton.elim _ _
  subst rightFinite
  have functionEq : left = right := funext pointwise
  subst right
  rfl

end HegemonCrypto.SmallWood.Q38Rp05UniformAverageTransport
