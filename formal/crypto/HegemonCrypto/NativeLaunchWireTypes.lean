import HegemonCrypto.CanonicalBytes
import Mathlib.Tactic.DeriveFintype

/-! Shared wire types, preserving the existing declaration namespaces. -/
namespace HegemonCrypto.SmallWood.NativeLaunchRelationModelResponse

inductive Branch where
  | rp06 | htlcLock | htlcClaim | htlcRefund
  deriving DecidableEq, Fintype

def queryCount : Branch → Nat
  | .rp06 => 38
  | _ => 58

end HegemonCrypto.SmallWood.NativeLaunchRelationModelResponse

namespace HegemonCrypto.NativeLaunchRelationModelStatement

abbrev FieldWord := Fin 18446744069414584321

end HegemonCrypto.NativeLaunchRelationModelStatement
