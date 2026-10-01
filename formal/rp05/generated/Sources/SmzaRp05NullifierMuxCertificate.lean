import SmzaRp05NullifierBinding
import SmzaRp05LocalCertificate

/-! Exact RP05 two-input nullifier-key mux root certificate. No digest claim. -/
namespace HegemonCrypto.SmallWood.SmzaRp05NullifierMuxCertificate

open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.SmzaRp05Components

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

def rootFor (input : Fin 2) : Nat := if input.val = 0 then 1367 else 1377

private theorem realizes_zero :
    Realizes exactNonlinearExpressions (rootFor 0) (nullifierKeyMuxTerm 0) := by
  change Realizes exactNonlinearExpressions 1367
    (.sub (.witness 97)
      (.add (.mul (.witness 92) (.witness 227))
        (.mul (.witness 228) (.add (.witness 93) (.witness 94)))))
  exact Realizes.sub (leftNode := 221) (rightNode := 1366)
    (by decide) (by decide) (by decide)
    (Realizes.witness (by decide))
    (Realizes.add (leftNode := 1364) (rightNode := 1365)
      (by decide) (by decide) (by decide)
      (Realizes.mul (leftNode := 216) (rightNode := 351)
        (by decide) (by decide) (by decide)
        (Realizes.witness (by decide)) (Realizes.witness (by decide)))
      (Realizes.mul (leftNode := 352) (rightNode := 1234)
        (by decide) (by decide) (by decide)
        (Realizes.witness (by decide))
        (Realizes.add (leftNode := 217) (rightNode := 218)
          (by decide) (by decide) (by decide)
          (Realizes.witness (by decide)) (Realizes.witness (by decide)))))

private theorem realizes_one :
    Realizes exactNonlinearExpressions (rootFor 1) (nullifierKeyMuxTerm 1) := by
  change Realizes exactNonlinearExpressions 1377
    (.sub (.witness 98)
      (.add (.mul (.witness 94) (.witness 228))
        (.mul (.witness 227) (.add (.witness 92) (.witness 93)))))
  exact Realizes.sub (leftNode := 222) (rightNode := 1376)
    (by decide) (by decide) (by decide)
    (Realizes.witness (by decide))
    (Realizes.add (leftNode := 1374) (rightNode := 1375)
      (by decide) (by decide) (by decide)
      (Realizes.mul (leftNode := 218) (rightNode := 352)
        (by decide) (by decide) (by decide)
        (Realizes.witness (by decide)) (Realizes.witness (by decide)))
      (Realizes.mul (leftNode := 351) (rightNode := 1241)
        (by decide) (by decide) (by decide)
        (Realizes.witness (by decide))
        (Realizes.add (leftNode := 216) (rightNode := 217)
          (by decide) (by decide) (by decide)
          (Realizes.witness (by decide)) (Realizes.witness (by decide)))))

def certificate : CurrentNullifierMuxCertificate program :=
  { canonical := SmzaRp05LocalCertificate.certificate.canonical
    rootFor := rootFor
    member := by
      intro input
      fin_cases input <;> decide
    realizes := by
      intro input
      fin_cases input
      · exact realizes_zero
      · exact realizes_one }

end HegemonCrypto.SmallWood.SmzaRp05NullifierMuxCertificate
