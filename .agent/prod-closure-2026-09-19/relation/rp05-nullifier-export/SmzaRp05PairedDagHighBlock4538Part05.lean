import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4618 through 4633. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4618_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4618 + i)) = true := by
  decide

theorem edge_subblock_4618 (node : Nat) (lower : 4618 ≤ node)
    (upper : node < 4634) : directedEdgeCheck node = true :=
  block_sound 4618 16 node edge_part_4618_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part05
