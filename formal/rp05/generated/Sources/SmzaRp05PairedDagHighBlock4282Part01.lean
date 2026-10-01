import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4298 through 4313. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4298_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4298 + i)) = true := by
  decide

theorem edge_subblock_4298 (node : Nat) (lower : 4298 ≤ node)
    (upper : node < 4314) : directedEdgeCheck node = true :=
  block_sound 4298 16 node edge_part_4298_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part01
