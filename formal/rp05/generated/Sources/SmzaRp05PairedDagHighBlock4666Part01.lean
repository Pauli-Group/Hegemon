import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4682 through 4697. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4682_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4682 + i)) = true := by
  decide

theorem edge_subblock_4682 (node : Nat) (lower : 4682 ≤ node)
    (upper : node < 4698) : directedEdgeCheck node = true :=
  block_sound 4682 16 node edge_part_4682_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part01
