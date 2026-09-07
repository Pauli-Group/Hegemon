import HegemonCrypto.SmallWoodV8Smz9SemanticDenseRange

/-! Exact node-431 lookup for the enabled sequence equation. -/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled

open Hegemon.Transaction.Poseidon2V8RelationProgram (evalFieldExpression fieldSub)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem stable_enabled_sequence_node431_value {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (node430 : values[430]? = some (fieldSub (publicWords.getD 112 0) 1)) :
    values[431]? = some (fieldSub 0 (fieldSub (publicWords.getD 112 0) 1)) := by
  have constants := csr_trace_zero_one_values equations
  simpa [evalFieldExpression, constants.1, node430] using
    equations 431 (.sub 0 430) (by decide)

end HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
