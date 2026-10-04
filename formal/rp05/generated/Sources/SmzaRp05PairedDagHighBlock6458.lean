import SmzaRp05PairedDagHighBlock6458Part00
import SmzaRp05PairedDagHighBlock6458Part01
import SmzaRp05PairedDagHighBlock6458Part02
import SmzaRp05PairedDagHighBlock6458Part03
import SmzaRp05PairedDagHighBlock6458Part04
import SmzaRp05PairedDagHighBlock6458Part05
import SmzaRp05PairedDagHighBlock6458Part06
import SmzaRp05PairedDagHighBlock6458Part07

/-! Bounded dispatcher for the exact directed-edge interval 6458 through 6585. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_6458 (node : Nat) (lower : 6458 ≤ node)
    (upper : node < 6586) : directedEdgeCheck node = true := by
  by_cases h6474 : node < 6474
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part00.edge_subblock_6458 node lower h6474
  · by_cases h6490 : node < 6490
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part01.edge_subblock_6474 node (Nat.le_of_not_gt h6474) (h6490)
    · by_cases h6506 : node < 6506
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part02.edge_subblock_6490 node (Nat.le_of_not_gt h6490) (h6506)
      · by_cases h6522 : node < 6522
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part03.edge_subblock_6506 node (Nat.le_of_not_gt h6506) (h6522)
        · by_cases h6538 : node < 6538
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part04.edge_subblock_6522 node (Nat.le_of_not_gt h6522) (h6538)
          · by_cases h6554 : node < 6554
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part05.edge_subblock_6538 node (Nat.le_of_not_gt h6538) (h6554)
            · by_cases h6570 : node < 6570
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part06.edge_subblock_6554 node (Nat.le_of_not_gt h6554) (h6570)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part07.edge_subblock_6570 node (Nat.le_of_not_gt h6570) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458
