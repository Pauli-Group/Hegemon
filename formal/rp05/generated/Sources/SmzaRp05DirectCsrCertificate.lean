import SmzaRp05AuthSourceBridge
import SmzaRp05Components
import SmzaRp05SupplyClosureCsrChunks
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality

/-!
Source-exact HGV8RP05 direct AUTH copies. The 49 entries below are only the
seven digest families consumed by `CurrentDigestProjection`; absorbed intent,
policy and accumulator words remain in `CurrentAbsorbCertificate`.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05DirectCsrCertificate

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05AuthSourceBridge
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def attemptIndex : CurrentDirectWord → Nat
  | .intentDigest limb => 18670 + limb.val
  | .policyRaw limb => 18773 + 3 * limb.val
  | .policyHash limb => 18774 + 3 * limb.val
  | .nextAccumulatorDigest limb => 19123 + 4 * limb.val
  | .valueLockDigest limb => 19124 + 4 * limb.val
  | .boundCurrent limb => 19109 + 2 * limb.val
  | .boundSecondary limb => 19110 + 2 * limb.val

def attemptFamily : CurrentDirectWord → Nat
  | .intentDigest _ => 27
  | .policyRaw _ | .policyHash _ => 29
  | .nextAccumulatorDigest _ | .valueLockDigest _ => 41
  | .boundCurrent _ | .boundSecondary _ => 40

def attemptLocal : CurrentDirectWord → Nat
  | .intentDigest limb => limb.val
  | .policyRaw limb => 3 * limb.val
  | .policyHash limb => 3 * limb.val + 1
  | .nextAccumulatorDigest limb => 4 * limb.val
  | .valueLockDigest limb => 4 * limb.val + 1
  | .boundCurrent limb => 2 * limb.val
  | .boundSecondary limb => 2 * limb.val + 1

def exactAttempt (word : CurrentDirectWord) : CsrExecutableAttempt :=
  { globalIndex := attemptIndex word
    family := attemptFamily word
    localIndex := attemptLocal word
    emission := 0
    terms := [(word.sourceIndex, 1),
      (word.targetIndex, word.minusOneNode 3 160)]
    targetRoot := 0 }

private theorem csr_canonical :
    ({ expressions := program.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical true := by
  apply (checkExpressionProgram_eq_true _ _).mp
  decide

private theorem attempt_member (word : CurrentDirectWord) :
    exactAttempt word ∈ program.csrAttempts := by
  have indexBound : attemptIndex word / 32 < 644 := by
    apply (Nat.div_lt_iff_lt_mul (by decide : 0 < 32)).2
    cases word with
    | intentDigest limb => fin_cases limb <;> decide
    | policyRaw limb => fin_cases limb <;> decide
    | policyHash limb => fin_cases limb <;> decide
    | nextAccumulatorDigest limb => fin_cases limb <;> decide
    | valueLockDigest limb => fin_cases limb <;> decide
    | boundCurrent limb => fin_cases limb <;> decide
    | boundSecondary limb => fin_cases limb <;> decide
  apply SmzaRp05SupplyClosureCsrChunks.chunk_member
    (chunk := attemptIndex word / 32) indexBound
  cases word with
  | intentDigest limb => fin_cases limb <;> decide +revert
  | policyRaw limb => fin_cases limb <;> decide +revert
  | policyHash limb => fin_cases limb <;> decide +revert
  | nextAccumulatorDigest limb => fin_cases limb <;> decide +revert
  | valueLockDigest limb => fin_cases limb <;> decide +revert
  | boundCurrent limb => fin_cases limb <;> decide +revert
  | boundSecondary limb => fin_cases limb <;> decide +revert

def certificate : CurrentDirectCertificate program :=
  { csrCanonicalWithRows := csr_canonical
    zeroNode := 0
    oneNode := 1
    literalMinusOneNode := 3
    derivedMinusOneNode := 160
    zeroRealizes := Realizes.constant (by decide)
    oneRealizes := Realizes.constant (by decide)
    literalMinusOneRealizes := Realizes.constant (by decide)
    derivedMinusOneRealizes := Realizes.sub
      (leftNode := 0) (rightNode := 1)
      (by decide) (by decide) (by decide)
      (Realizes.constant (by decide)) (Realizes.constant (by decide))
    attempt := exactAttempt
    attemptMember := attempt_member
    attemptTerms := by intro word; rfl
    attemptTarget := by intro word; rfl }

end HegemonCrypto.SmallWood.SmzaRp05DirectCsrCertificate
