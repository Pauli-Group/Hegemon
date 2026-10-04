import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4394 through 4409. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4394_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4394 + i)) = true := by
  decide

theorem edge_subblock_4394 (node : Nat) (lower : 4394 ≤ node)
    (upper : node < 4410) : directedEdgeCheck node = true :=
  block_sound 4394 16 node edge_part_4394_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part07
