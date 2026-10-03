import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4186 through 4201. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4186_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4186 + i)) = true := by
  decide

theorem edge_subblock_4186 (node : Nat) (lower : 4186 ≤ node)
    (upper : node < 4202) : directedEdgeCheck node = true :=
  block_sound 4186 16 node edge_part_4186_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part02
