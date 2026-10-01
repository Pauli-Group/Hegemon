import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4506 through 4521. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4506_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4506 + i)) = true := by
  decide

theorem edge_subblock_4506 (node : Nat) (lower : 4506 ≤ node)
    (upper : node < 4522) : directedEdgeCheck node = true :=
  block_sound 4506 16 node edge_part_4506_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4410Part06
