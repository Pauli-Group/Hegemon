import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6618 through 6633. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6618_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6618 + i)) = true := by
  decide

theorem edge_subblock_6618 (node : Nat) (lower : 6618 ≤ node)
    (upper : node < 6634) : directedEdgeCheck node = true :=
  block_sound 6618 16 node edge_part_6618_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part02
