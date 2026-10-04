import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7642 through 7657. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7642_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7642 + i)) = true := by
  decide

theorem edge_subblock_7642 (node : Nat) (lower : 7642 ≤ node)
    (upper : node < 7658) : directedEdgeCheck node = true :=
  block_sound 7642 16 node edge_part_7642_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part02
