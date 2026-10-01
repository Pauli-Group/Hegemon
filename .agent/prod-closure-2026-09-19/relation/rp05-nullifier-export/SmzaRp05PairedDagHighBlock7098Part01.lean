import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7114 through 7129. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7114_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7114 + i)) = true := by
  decide

theorem edge_subblock_7114 (node : Nat) (lower : 7114 ≤ node)
    (upper : node < 7130) : directedEdgeCheck node = true :=
  block_sound 7114 16 node edge_part_7114_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part01
