import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7242 through 7257. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7242_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7242 + i)) = true := by
  decide

theorem edge_subblock_7242 (node : Nat) (lower : 7242 ≤ node)
    (upper : node < 7258) : directedEdgeCheck node = true :=
  block_sound 7242 16 node edge_part_7242_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part01
