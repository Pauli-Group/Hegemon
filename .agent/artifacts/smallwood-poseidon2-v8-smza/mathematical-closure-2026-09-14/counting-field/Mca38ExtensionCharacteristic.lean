import Mca38ConcreteExtensionR6
import Mathlib.Algebra.CharP.Algebra

namespace HegemonCrypto.SmallWood.Mca38ExtensionCharacteristic
open Mca38ConcreteExtension
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
noncomputable section
set_option autoImplicit false

instance extensionCharP : CharP Extension5 18446744069414584321 :=
  charP_of_injective_algebraMap (algebraMap Goldilocks Extension5).injective _

theorem extension_characteristic : ringChar Extension5 = 18446744069414584321 :=
  ringChar.eq _ _

end
end HegemonCrypto.SmallWood.Mca38ExtensionCharacteristic
