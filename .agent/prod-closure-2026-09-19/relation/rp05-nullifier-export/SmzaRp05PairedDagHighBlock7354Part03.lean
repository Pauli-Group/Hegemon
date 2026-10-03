import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7402 through 7417. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7402_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7402 + i)) = true := by
  decide

theorem edge_subblock_7402 (node : Nat) (lower : 7402 ≤ node)
    (upper : node < 7418) : directedEdgeCheck node = true :=
  block_sound 7402 16 node edge_part_7402_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part03
