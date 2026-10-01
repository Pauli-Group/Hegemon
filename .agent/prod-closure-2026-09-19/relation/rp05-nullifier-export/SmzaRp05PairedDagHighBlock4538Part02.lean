import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4570 through 4585. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4570_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4570 + i)) = true := by
  decide

theorem edge_subblock_4570 (node : Nat) (lower : 4570 ≤ node)
    (upper : node < 4586) : directedEdgeCheck node = true :=
  block_sound 4570 16 node edge_part_4570_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part02
