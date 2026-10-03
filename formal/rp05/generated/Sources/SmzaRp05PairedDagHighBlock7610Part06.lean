import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7706 through 7721. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7706_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7706 + i)) = true := by
  decide

theorem edge_subblock_7706 (node : Nat) (lower : 7706 ≤ node)
    (upper : node < 7722) : directedEdgeCheck node = true :=
  block_sound 7706 16 node edge_part_7706_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part06
