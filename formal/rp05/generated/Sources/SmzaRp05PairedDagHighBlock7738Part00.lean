import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7738 through 7753. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7738_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7738 + i)) = true := by
  decide

theorem edge_subblock_7738 (node : Nat) (lower : 7738 ≤ node)
    (upper : node < 7754) : directedEdgeCheck node = true :=
  block_sound 7738 16 node edge_part_7738_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part00
