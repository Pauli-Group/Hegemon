import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4794 through 4809. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4794_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4794 + i)) = true := by
  decide

theorem edge_subblock_4794 (node : Nat) (lower : 4794 ≤ node)
    (upper : node < 4810) : directedEdgeCheck node = true :=
  block_sound 4794 16 node edge_part_4794_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part00
