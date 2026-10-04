import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7370 through 7385. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7370_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7370 + i)) = true := by
  decide

theorem edge_subblock_7370 (node : Nat) (lower : 7370 ≤ node)
    (upper : node < 7386) : directedEdgeCheck node = true :=
  block_sound 7370 16 node edge_part_7370_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part01
