import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6282 through 6297. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6282_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6282 + i)) = true := by
  decide

theorem edge_subblock_6282 (node : Nat) (lower : 6282 ≤ node)
    (upper : node < 6298) : directedEdgeCheck node = true :=
  block_sound 6282 16 node edge_part_6282_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part05
