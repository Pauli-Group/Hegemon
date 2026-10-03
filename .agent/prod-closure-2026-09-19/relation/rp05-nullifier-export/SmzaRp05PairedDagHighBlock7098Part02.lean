import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7130 through 7145. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7130_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7130 + i)) = true := by
  decide

theorem edge_subblock_7130 (node : Nat) (lower : 7130 ≤ node)
    (upper : node < 7146) : directedEdgeCheck node = true :=
  block_sound 7130 16 node edge_part_7130_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part02
