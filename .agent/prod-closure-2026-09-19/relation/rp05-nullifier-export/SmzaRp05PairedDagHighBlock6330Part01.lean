import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6346 through 6361. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6346_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6346 + i)) = true := by
  decide

theorem edge_subblock_6346 (node : Nat) (lower : 6346 ≤ node)
    (upper : node < 6362) : directedEdgeCheck node = true :=
  block_sound 6346 16 node edge_part_6346_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part01
