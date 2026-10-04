import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4410 through 4425. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4410_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4410 + i)) = true := by
  decide

theorem edge_subblock_4410 (node : Nat) (lower : 4410 ≤ node)
    (upper : node < 4426) : directedEdgeCheck node = true :=
  block_sound 4410 16 node edge_part_4410_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part00
