import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6234 through 6249. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6234_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6234 + i)) = true := by
  decide

theorem edge_subblock_6234 (node : Nat) (lower : 6234 ≤ node)
    (upper : node < 6250) : directedEdgeCheck node = true :=
  block_sound 6234 16 node edge_part_6234_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part02
