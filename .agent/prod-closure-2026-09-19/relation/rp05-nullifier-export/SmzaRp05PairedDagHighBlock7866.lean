import SmzaRp05PairedDagHighBlock7866Part00
import SmzaRp05PairedDagHighBlock7866Part01
import SmzaRp05PairedDagHighBlock7866Part02
import SmzaRp05PairedDagHighBlock7866Part03
import SmzaRp05PairedDagHighBlock7866Part04
import SmzaRp05PairedDagHighBlock7866Part05

/-! Bounded dispatcher for the exact directed-edge interval 7866 through 7950. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_7866 (node : Nat) (lower : 7866 ≤ node)
    (upper : node < 7951) : directedEdgeCheck node = true := by
  by_cases h7882 : node < 7882
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part00.edge_subblock_7866 node lower h7882
  · by_cases h7898 : node < 7898
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part01.edge_subblock_7882 node (Nat.le_of_not_gt h7882) (h7898)
    · by_cases h7914 : node < 7914
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part02.edge_subblock_7898 node (Nat.le_of_not_gt h7898) (h7914)
      · by_cases h7930 : node < 7930
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part03.edge_subblock_7914 node (Nat.le_of_not_gt h7914) (h7930)
        · by_cases h7946 : node < 7946
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part04.edge_subblock_7930 node (Nat.le_of_not_gt h7930) (h7946)
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part05.edge_subblock_7946 node (Nat.le_of_not_gt h7946) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866
