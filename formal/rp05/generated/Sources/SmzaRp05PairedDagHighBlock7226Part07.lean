import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7338 through 7353. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7338_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7338 + i)) = true := by
  decide

theorem edge_subblock_7338 (node : Nat) (lower : 7338 ≤ node)
    (upper : node < 7354) : directedEdgeCheck node = true :=
  block_sound 7338 16 node edge_part_7338_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part07
