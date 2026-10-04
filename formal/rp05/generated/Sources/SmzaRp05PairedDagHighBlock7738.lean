import SmzaRp05PairedDagHighBlock7738Part00
import SmzaRp05PairedDagHighBlock7738Part01
import SmzaRp05PairedDagHighBlock7738Part02
import SmzaRp05PairedDagHighBlock7738Part03
import SmzaRp05PairedDagHighBlock7738Part04
import SmzaRp05PairedDagHighBlock7738Part05
import SmzaRp05PairedDagHighBlock7738Part06
import SmzaRp05PairedDagHighBlock7738Part07

/-! Bounded dispatcher for the exact directed-edge interval 7738 through 7865. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_7738 (node : Nat) (lower : 7738 ≤ node)
    (upper : node < 7866) : directedEdgeCheck node = true := by
  by_cases h7754 : node < 7754
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part00.edge_subblock_7738 node lower h7754
  · by_cases h7770 : node < 7770
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part01.edge_subblock_7754 node (Nat.le_of_not_gt h7754) (h7770)
    · by_cases h7786 : node < 7786
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part02.edge_subblock_7770 node (Nat.le_of_not_gt h7770) (h7786)
      · by_cases h7802 : node < 7802
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part03.edge_subblock_7786 node (Nat.le_of_not_gt h7786) (h7802)
        · by_cases h7818 : node < 7818
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part04.edge_subblock_7802 node (Nat.le_of_not_gt h7802) (h7818)
          · by_cases h7834 : node < 7834
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part05.edge_subblock_7818 node (Nat.le_of_not_gt h7818) (h7834)
            · by_cases h7850 : node < 7850
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part06.edge_subblock_7834 node (Nat.le_of_not_gt h7834) (h7850)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part07.edge_subblock_7850 node (Nat.le_of_not_gt h7850) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738
