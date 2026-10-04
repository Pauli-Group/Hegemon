import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6682 through 6697. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6682_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6682 + i)) = true := by
  decide

theorem edge_subblock_6682 (node : Nat) (lower : 6682 ≤ node)
    (upper : node < 6698) : directedEdgeCheck node = true :=
  block_sound 6682 16 node edge_part_6682_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part06
