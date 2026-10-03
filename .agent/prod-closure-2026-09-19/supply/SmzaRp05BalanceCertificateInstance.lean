import SmzaRp05BalancePrefixCertificate
import SmzaRp05BalanceCore
import SmzaRp05NonlinearCanonical
import SmzaRp05CsrFinite

/-! Concrete finite balance certificate for the selected RP05 program.
Each field reuses an exact checked provider for that same program. -/

namespace HegemonCrypto.SmallWood.SmzaRp05BalanceCertificateInstance

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05BalanceCore
open HegemonCrypto.SmallWood.SmzaRp05BalancePrefixCertificate

instance currentProgram : BalanceCertificate program where
  nonlinearCanonical := HegemonCrypto.SmallWood.SmzaRp05NonlinearCanonical.canonical
  csrCanonical := by
    have canonicalFalse :
        ({ expressions := program.csrExpressions, roots := [] } :
          ExpressionProgram).Canonical false := by
      simpa [program] using
        HegemonCrypto.SmallWood.SmzaRp05CsrFiniteData.csrProgramCanonical
    constructor
    · intro node expression found
      exact HegemonCrypto.SmallWood.V8Smz9SemanticBinding.canonical_without_rows_allows_rows
        (canonicalFalse.1 node expression found)
    · simp
  nonlinearPrefix :=
    HegemonCrypto.SmallWood.SmzaRp05BalancePrefixCertificate.nonlinearPrefix
  baseRoots := HegemonCrypto.SmallWood.SmzaRp05BalancePrefixCertificate.baseRoots
  csrPrefix := HegemonCrypto.SmallWood.SmzaRp05BalancePrefixCertificate.csrPrefix
  noteBridges := HegemonCrypto.SmallWood.SmzaRp05BalancePrefixCertificate.noteBridges
  denseReconstructions :=
    HegemonCrypto.SmallWood.SmzaRp05BalancePrefixCertificate.denseReconstructions

end HegemonCrypto.SmallWood.SmzaRp05BalanceCertificateInstance
