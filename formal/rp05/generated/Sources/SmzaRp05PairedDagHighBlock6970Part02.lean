import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7002 through 7017. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7002_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7002 + i)) = true := by
  decide

theorem edge_subblock_7002 (node : Nat) (lower : 7002 ≤ node)
    (upper : node < 7018) : directedEdgeCheck node = true :=
  block_sound 7002 16 node edge_part_7002_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part02
