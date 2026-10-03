import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7418 through 7433. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7418_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7418 + i)) = true := by
  decide

theorem edge_subblock_7418 (node : Nat) (lower : 7418 ≤ node)
    (upper : node < 7434) : directedEdgeCheck node = true :=
  block_sound 7418 16 node edge_part_7418_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part04
