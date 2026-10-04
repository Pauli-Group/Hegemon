import SmzaRp05PairedDagHighBlock7610Part00
import SmzaRp05PairedDagHighBlock7610Part01
import SmzaRp05PairedDagHighBlock7610Part02
import SmzaRp05PairedDagHighBlock7610Part03
import SmzaRp05PairedDagHighBlock7610Part04
import SmzaRp05PairedDagHighBlock7610Part05
import SmzaRp05PairedDagHighBlock7610Part06
import SmzaRp05PairedDagHighBlock7610Part07

/-! Bounded dispatcher for the exact directed-edge interval 7610 through 7737. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_7610 (node : Nat) (lower : 7610 ≤ node)
    (upper : node < 7738) : directedEdgeCheck node = true := by
  by_cases h7626 : node < 7626
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part00.edge_subblock_7610 node lower h7626
  · by_cases h7642 : node < 7642
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part01.edge_subblock_7626 node (Nat.le_of_not_gt h7626) (h7642)
    · by_cases h7658 : node < 7658
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part02.edge_subblock_7642 node (Nat.le_of_not_gt h7642) (h7658)
      · by_cases h7674 : node < 7674
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part03.edge_subblock_7658 node (Nat.le_of_not_gt h7658) (h7674)
        · by_cases h7690 : node < 7690
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part04.edge_subblock_7674 node (Nat.le_of_not_gt h7674) (h7690)
          · by_cases h7706 : node < 7706
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part05.edge_subblock_7690 node (Nat.le_of_not_gt h7690) (h7706)
            · by_cases h7722 : node < 7722
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part06.edge_subblock_7706 node (Nat.le_of_not_gt h7706) (h7722)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part07.edge_subblock_7722 node (Nat.le_of_not_gt h7722) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610
