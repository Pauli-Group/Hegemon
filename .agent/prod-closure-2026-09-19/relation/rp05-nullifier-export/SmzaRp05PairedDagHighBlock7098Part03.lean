import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7146 through 7161. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7146_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7146 + i)) = true := by
  decide

theorem edge_subblock_7146 (node : Nat) (lower : 7146 ≤ node)
    (upper : node < 7162) : directedEdgeCheck node = true :=
  block_sound 7146 16 node edge_part_7146_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part03
