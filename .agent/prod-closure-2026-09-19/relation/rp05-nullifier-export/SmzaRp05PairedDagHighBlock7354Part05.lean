import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7434 through 7449. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7434_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7434 + i)) = true := by
  decide

theorem edge_subblock_7434 (node : Nat) (lower : 7434 ≤ node)
    (upper : node < 7450) : directedEdgeCheck node = true :=
  block_sound 7434 16 node edge_part_7434_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part05
