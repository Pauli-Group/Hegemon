import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6202 through 6217. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6202_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6202 + i)) = true := by
  decide

theorem edge_subblock_6202 (node : Nat) (lower : 6202 ≤ node)
    (upper : node < 6218) : directedEdgeCheck node = true :=
  block_sound 6202 16 node edge_part_6202_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part00
