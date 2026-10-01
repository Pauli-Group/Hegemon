import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7082 through 7097. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7082_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7082 + i)) = true := by
  decide

theorem edge_subblock_7082 (node : Nat) (lower : 7082 ≤ node)
    (upper : node < 7098) : directedEdgeCheck node = true :=
  block_sound 7082 16 node edge_part_7082_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part07
