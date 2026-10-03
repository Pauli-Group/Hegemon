import SmzaRp05DegreeCertificateAssembly
import SmzaRp05NonlinearCanonical
import SmzaRp05CsrFinite
import SmzaRp05CsrNormalization

/-!
Concrete current-RP05 `GeneratedCertificates` assembly. This declaration is
source-only until every imported finite node, root, canonicality, and CSR
module compiles against the SHA-512-pinned current fixture.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates

open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.SmzaRp05CsrNormalization

set_option autoImplicit false

def currentDsl : RelationDsl :=
  normalizedDsl program nonlinearRoot nodeDegree

theorem certificates : GeneratedCertificates currentDsl :=
  { nonlinear :=
      { nonlinearCountExact := rfl
        programCanonical := SmzaRp05NonlinearCanonical.canonical
        rootsExact := SmzaRp05DegreeCertificateData.rootsExact
        degreeCertificate := SmzaRp05DegreeCertificateData.degreeCertificate
        rootDegree := SmzaRp05DegreeCertificateData.rootDegree }
    csr := csrCertificate program nonlinearRoot nodeDegree
      SmzaRp05CsrFiniteData.csrProgramCanonical
      SmzaRp05CsrFiniteData.csrAttemptCoordinates
      SmzaRp05CsrFiniteData.zeroAttempt
      SmzaRp05CsrFiniteData.zeroAttemptMember
      SmzaRp05CsrFiniteData.zeroAttemptTerms
      SmzaRp05CsrFiniteData.zeroAttemptTarget
      SmzaRp05CsrFiniteData.zeroNode
      SmzaRp05CsrFiniteData.oneNode }

end HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates
