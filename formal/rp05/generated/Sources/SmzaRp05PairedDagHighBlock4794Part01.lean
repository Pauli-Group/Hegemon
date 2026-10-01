import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4810 through 4825. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4810_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4810 + i)) = true := by
  decide

theorem edge_subblock_4810 (node : Nat) (lower : 4810 ≤ node)
    (upper : node < 4826) : directedEdgeCheck node = true :=
  block_sound 4810 16 node edge_part_4810_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part01
