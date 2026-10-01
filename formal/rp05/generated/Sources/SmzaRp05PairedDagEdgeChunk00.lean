import SmzaRp05PairedHashDagData

/-! Finite directed-edge checks for paired Poseidon DAG nodes 0 through 127. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_chunk00_checked :
    (List.range 128).all directedEdgeCheck = true := by
  decide

/-- Every directed-edge correspondence check in the first 128 paired-DAG
    nodes succeeds against the exact current and reference expression arrays. -/
theorem directed_edge_check (node : Nat) (bound : node < 128) :
    directedEdgeCheck node = true := by
  exact (List.all_eq_true.mp edge_chunk00_checked) node
    (List.mem_range.mpr bound)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk00
