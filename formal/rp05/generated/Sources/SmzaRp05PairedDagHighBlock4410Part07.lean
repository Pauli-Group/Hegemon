import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4522 through 4537. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4522_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4522 + i)) = true := by
  decide

theorem edge_subblock_4522 (node : Nat) (lower : 4522 ≤ node)
    (upper : node < 4538) : directedEdgeCheck node = true :=
  block_sound 4522 16 node edge_part_4522_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part07
