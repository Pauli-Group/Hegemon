import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6714 through 6729. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6714_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6714 + i)) = true := by
  decide

theorem edge_subblock_6714 (node : Nat) (lower : 6714 ≤ node)
    (upper : node < 6730) : directedEdgeCheck node = true :=
  block_sound 6714 16 node edge_part_6714_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part00
