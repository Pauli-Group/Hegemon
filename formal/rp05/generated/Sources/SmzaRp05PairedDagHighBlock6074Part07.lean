import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6186 through 6201. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6186_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6186 + i)) = true := by
  decide

theorem edge_subblock_6186 (node : Nat) (lower : 6186 ≤ node)
    (upper : node < 6202) : directedEdgeCheck node = true :=
  block_sound 6186 16 node edge_part_6186_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part07
