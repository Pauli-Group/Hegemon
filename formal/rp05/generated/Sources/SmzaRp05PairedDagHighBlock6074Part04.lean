import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6138 through 6153. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6138_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6138 + i)) = true := by
  decide

theorem edge_subblock_6138 (node : Nat) (lower : 6138 ≤ node)
    (upper : node < 6154) : directedEdgeCheck node = true :=
  block_sound 6138 16 node edge_part_6138_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part04
