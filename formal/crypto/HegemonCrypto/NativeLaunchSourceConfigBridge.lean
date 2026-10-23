import HegemonCrypto.NativeLaunchPublicViewRoundtrip

set_option autoImplicit false
set_option maxHeartbeats 1000000
set_option maxRecDepth 10000
namespace HegemonCrypto.NativeLaunchSourceConfigBridge
open NativeLaunchPublicProofView NativeLaunchPublicViewRoundtrip
open SmallWood.NativeLaunchRelationModelResponse (Branch queryCount)

def rp06Config : Config := ⟨488,132,140,12,368,736,696⟩
def htlcConfig (R : Nat) : Config := ⟨74,132,140,12,(R+21)/2,R+20,R+10⟩

def rp06Literal : Fin 8 → Nat × Nat
  | 0 => (5,483) | 1 => (5,126) | 2 => (12,38) | 3 => (38,128)
  | 4 => (6,40) | 5 => (38,5) | 6 => (5,368) | 7 => (6,696)
def htlcLiteral (R : Nat) : Fin 8 → Nat × Nat
  | 0 => (5,69) | 1 => (5,126) | 2 => (12,58) | 3 => (58,128)
  | 4 => (6,10) | 5 => (58,5) | 6 => (5,(R+21)/2) | 7 => (6,R+10)

theorem rp06_dims : dims .rp06 rp06Config = rp06Literal := by
  funext i; fin_cases i <;> rfl

theorem htlc_dims (b : Branch) (R : Nat) (native : b ≠ .rp06) :
    dims b (htlcConfig R) = htlcLiteral R := by
  funext i
  cases b <;> try contradiction
  all_goals fin_cases i <;> simp [dims, htlcConfig, htlcLiteral, queryCount]

theorem rp06_shape : ShapeGuard .rp06 rp06Config := by
  refine ⟨by decide, by decide, by decide, by decide, ?_⟩
  intro i; fin_cases i <;> decide

theorem htlc_shape (b : Branch) (R : Nat) (native : b ≠ .rp06)
    (wireBound : R+10 < 65536) : ShapeGuard b (htlcConfig R) := by
  refine ⟨by simp [htlcConfig], by simp [htlcConfig], by simp [htlcConfig],
    by simp [htlcConfig], ?_⟩
  intro i
  rw [htlc_dims b R native]
  fin_cases i <;> simp [htlcLiteral] <;> omega

theorem htlc_ceiling (R : Nat) : (R+20+1)/2 = (htlcConfig R).lvcsCols := by
  simp [htlcConfig, Nat.add_assoc]

theorem rp06_length (v : View .rp06 rp06Config) :
    (encode v).length = 121105 + 64 * (pathNodes v.paths).length := by
  rw [complete_length]
  simp [matrixTotal, matrix, matrix_length, dims, rp06Config, queryCount]
  omega

theorem htlc_length (b : Branch) (R : Nat) (native : b ≠ .rp06)
    (v : View b (htlcConfig R)) :
    (encode v).length = 79957 + 48*R + 40*((R+21)/2) + 64*(pathNodes v.paths).length := by
  rw [complete_length]
  have q : queryCount b = 58 := by cases b <;> simp_all [queryCount]
  simp [matrixTotal, matrix, matrix_length, htlc_dims b R native, htlcLiteral, q]
  omega

theorem rp06_cap (v : View .rp06 rp06Config)
    (compactNodes : (pathNodes v.paths).length ≤ 672) :
    (encode v).length ≤ NativeLaunchPublicProofParser.maximumBytes .rp06 := by
  rw [rp06_length]
  change 121105 + 64*(pathNodes v.paths).length ≤ 164113
  omega

theorem rp06_configured_roundtrip (v : View .rp06 rp06Config)
    (compactNodes : (pathNodes v.paths).length ≤ 672) :
    NativeLaunchPublicProofParser.decodeExact .rp06 rp06Config (encode v) = some (rawWire v) :=
  typed_view_exact_roundtrip v (rp06_cap v compactNodes)

theorem htlc_configured_roundtrip (b : Branch) (R : Nat) (native : b ≠ .rp06)
    (v : View b (htlcConfig R))
    (formulaCap : 79957+48*R+40*((R+21)/2)+64*(pathNodes v.paths).length ≤ 2097152) :
    NativeLaunchPublicProofParser.decodeExact b (htlcConfig R) (encode v) = some (rawWire v) := by
  apply typed_view_exact_roundtrip
  rw [htlc_length b R native v]
  have cap : NativeLaunchPublicProofParser.maximumBytes b = 2097152 := by
    cases b <;> simp_all [NativeLaunchPublicProofParser.maximumBytes]
  rw [cap]
  exact formulaCap

end HegemonCrypto.NativeLaunchSourceConfigBridge
