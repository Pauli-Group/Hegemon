import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4538 through 4553. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4538_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4538 + i)) = true := by
  decide

theorem edge_subblock_4538 (node : Nat) (lower : 4538 ≤ node)
    (upper : node < 4554) : directedEdgeCheck node = true :=
  block_sound 4538 16 node edge_part_4538_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part00
