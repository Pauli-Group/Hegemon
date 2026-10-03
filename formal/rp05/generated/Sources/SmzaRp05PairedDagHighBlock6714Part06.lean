import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6810 through 6825. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6810_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6810 + i)) = true := by
  decide

theorem edge_subblock_6810 (node : Nat) (lower : 6810 ≤ node)
    (upper : node < 6826) : directedEdgeCheck node = true :=
  block_sound 6810 16 node edge_part_6810_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part06
