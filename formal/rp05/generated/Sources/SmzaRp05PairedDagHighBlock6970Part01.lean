import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6986 through 7001. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6986_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6986 + i)) = true := by
  decide

theorem edge_subblock_6986 (node : Nat) (lower : 6986 ≤ node)
    (upper : node < 7002) : directedEdgeCheck node = true :=
  block_sound 6986 16 node edge_part_6986_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part01
