import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4250 through 4265. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4250_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4250 + i)) = true := by
  decide

theorem edge_subblock_4250 (node : Nat) (lower : 4250 ≤ node)
    (upper : node < 4266) : directedEdgeCheck node = true :=
  block_sound 4250 16 node edge_part_4250_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part06
