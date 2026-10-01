import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6890 through 6905. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6890_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6890 + i)) = true := by
  decide

theorem edge_subblock_6890 (node : Nat) (lower : 6890 ≤ node)
    (upper : node < 6906) : directedEdgeCheck node = true :=
  block_sound 6890 16 node edge_part_6890_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part03
