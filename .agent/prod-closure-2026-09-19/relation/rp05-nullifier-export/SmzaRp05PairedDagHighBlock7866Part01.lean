import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7882 through 7897. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7882_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7882 + i)) = true := by
  decide

theorem edge_subblock_7882 (node : Nat) (lower : 7882 ≤ node)
    (upper : node < 7898) : directedEdgeCheck node = true :=
  block_sound 7882 16 node edge_part_7882_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part01
