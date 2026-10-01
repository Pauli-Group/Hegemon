import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7354 through 7369. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7354_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7354 + i)) = true := by
  decide

theorem edge_subblock_7354 (node : Nat) (lower : 7354 ≤ node)
    (upper : node < 7370) : directedEdgeCheck node = true :=
  block_sound 7354 16 node edge_part_7354_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part00
