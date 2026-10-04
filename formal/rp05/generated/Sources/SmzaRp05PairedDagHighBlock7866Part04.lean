import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7930 through 7945. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7930_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7930 + i)) = true := by
  decide

theorem edge_subblock_7930 (node : Nat) (lower : 7930 ≤ node)
    (upper : node < 7946) : directedEdgeCheck node = true :=
  block_sound 7930 16 node edge_part_7930_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part04
