import SmzaRp05SingleKeyPrfSourceData
import SmzaRp05SingleKeyPrfSourceMembers0
import SmzaRp05SingleKeyPrfSourceMembers1
import SmzaRp05SingleKeyPrfSourceMembers2
import SmzaRp05SingleKeyPrfSourceMembers3
import SmzaRp05SingleKeyPrfSourceCanonical
import SmzaRp05TypedRelation

/-! Checked aggregate of the split exact current-RP05 attempt memberships. -/
namespace HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCertificate

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceData

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

structure Certificate (components : RelationProgramComponents) where
  canonical : ({ expressions := components.csrExpressions, roots := [] } :
    ExpressionProgram).Canonical true
  zeroRealizes : Realizes components.csrExpressions 0 (.constant 0)
  oneRealizes : Realizes components.csrExpressions 1 (.constant 1)
  literalMinusOneRealizes : Realizes components.csrExpressions 3
    (.constant 18446744069414584320)
  derivedMinusOneRealizes : Realizes components.csrExpressions 160
    (.sub (.constant 0) (.constant 1))
  initialTargetRealizes : ∀ lane : Fin 16,
    Realizes components.csrExpressions (initialTarget lane)
      (.constant (initialExpected lane))
  initialMember : ∀ lane : Fin 16,
    initialAttempt lane ∈ components.csrAttempts
  legacyMember : ∀ limb : Fin 7,
    legacyAttempt limb ∈ components.csrAttempts

private theorem initial_member : ∀ lane : Fin 16,
    initialAttempt lane ∈ program.csrAttempts := by
  intro lane
  fin_cases lane
  all_goals first
    | exact HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers0.initial ⟨0, by decide⟩
    | exact HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers0.initial ⟨1, by decide⟩
    | exact HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers0.initial ⟨2, by decide⟩
    | exact HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers0.initial ⟨3, by decide⟩
    | exact HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers0.initial ⟨4, by decide⟩
    | exact HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers0.initial ⟨5, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers1.initial ⟨0, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers1.initial ⟨1, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers1.initial ⟨2, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers1.initial ⟨3, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers1.initial ⟨4, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers1.initial ⟨5, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers2.initial ⟨0, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers2.initial ⟨1, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers2.initial ⟨2, by decide⟩
    | simpa [initialAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers2.initial ⟨3, by decide⟩

private theorem legacy_member : ∀ limb : Fin 7,
    legacyAttempt limb ∈ program.csrAttempts := by
  intro limb
  fin_cases limb
  all_goals first
    | exact HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers2.legacyFirstTwo ⟨0, by decide⟩
    | exact HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers2.legacyFirstTwo ⟨1, by decide⟩
    | simpa [legacyAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers3.legacyLastFive ⟨0, by decide⟩
    | simpa [legacyAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers3.legacyLastFive ⟨1, by decide⟩
    | simpa [legacyAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers3.legacyLastFive ⟨2, by decide⟩
    | simpa [legacyAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers3.legacyLastFive ⟨3, by decide⟩
    | simpa [legacyAttempt] using
        HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers3.legacyLastFive ⟨4, by decide⟩

private theorem initial_target_realizes (lane : Fin 16) :
    Realizes program.csrExpressions (initialTarget lane)
      (.constant (initialExpected lane)) := by
  fin_cases lane <;> exact Realizes.constant (by decide)

theorem certificate : Certificate program :=
  { canonical := HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCanonical.csrCanonical
    zeroRealizes := Realizes.constant (by decide)
    oneRealizes := Realizes.constant (by decide)
    literalMinusOneRealizes := Realizes.constant (by decide)
    derivedMinusOneRealizes := Realizes.sub
      (leftNode := 0) (rightNode := 1)
      (by decide) (by decide) (by decide)
      (Realizes.constant (by decide)) (Realizes.constant (by decide))
    initialTargetRealizes := by
      intro lane
      exact initial_target_realizes lane
    initialMember := initial_member
    legacyMember := legacy_member }

end HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCertificate
