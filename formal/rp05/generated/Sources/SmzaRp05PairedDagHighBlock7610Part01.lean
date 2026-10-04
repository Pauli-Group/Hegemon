import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7626 through 7641. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7626_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7626 + i)) = true := by
  decide

theorem edge_subblock_7626 (node : Nat) (lower : 7626 ≤ node)
    (upper : node < 7642) : directedEdgeCheck node = true :=
  block_sound 7626 16 node edge_part_7626_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part01
