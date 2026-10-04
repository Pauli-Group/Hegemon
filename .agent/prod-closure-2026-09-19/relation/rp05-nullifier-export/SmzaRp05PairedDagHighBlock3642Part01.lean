import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3658 through 3673. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3658_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3658 + i)) = true := by
  decide

theorem edge_subblock_3658 (node : Nat) (lower : 3658 ≤ node)
    (upper : node < 3674) : directedEdgeCheck node = true :=
  block_sound 3658 16 node edge_part_3658_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part01
