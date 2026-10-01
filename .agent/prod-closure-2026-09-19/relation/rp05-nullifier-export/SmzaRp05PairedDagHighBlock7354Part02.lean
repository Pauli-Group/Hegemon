import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7386 through 7401. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7386_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7386 + i)) = true := by
  decide

theorem edge_subblock_7386 (node : Nat) (lower : 7386 ≤ node)
    (upper : node < 7402) : directedEdgeCheck node = true :=
  block_sound 7386 16 node edge_part_7386_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7354Part02
