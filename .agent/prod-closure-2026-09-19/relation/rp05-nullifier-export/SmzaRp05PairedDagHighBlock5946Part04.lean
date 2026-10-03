import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6010 through 6025. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6010_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6010 + i)) = true := by
  decide

theorem edge_subblock_6010 (node : Nat) (lower : 6010 ≤ node)
    (upper : node < 6026) : directedEdgeCheck node = true :=
  block_sound 6010 16 node edge_part_6010_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part04
