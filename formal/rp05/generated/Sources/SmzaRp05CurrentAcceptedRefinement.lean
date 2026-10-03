import SmzaRp05GeneratedCertificates
import SmzaRp05RelationRefinement
import SmzaRp05AcceptedRelationInterface

/-! Concrete, premise-free RP05 specialization of the generic relation model
and accepted-extraction refinement. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRefinement

open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates
open HegemonCrypto.SmallWood.SmzaRp05AcceptedExtraction
open HegemonCrypto.SmallWood.SmzaRp05TracePrefixes

set_option autoImplicit false
set_option maxRecDepth 10000

noncomputable def currentModel : RelationModel :=
  relationModel currentDsl certificates

noncomputable def currentRefinement :
    SmzaRp05AcceptedExtraction.RelationRefinement currentModel :=
  relationRefinement currentDsl certificates

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRefinement
