import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7178 through 7193. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7178_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7178 + i)) = true := by
  decide

theorem edge_subblock_7178 (node : Nat) (lower : 7178 ≤ node)
    (upper : node < 7194) : directedEdgeCheck node = true :=
  block_sound 7178 16 node edge_part_7178_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part05
