import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4778 through 4793. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4778_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4778 + i)) = true := by
  decide

theorem edge_subblock_4778 (node : Nat) (lower : 4778 ≤ node)
    (upper : node < 4794) : directedEdgeCheck node = true :=
  block_sound 4778 16 node edge_part_4778_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part07
