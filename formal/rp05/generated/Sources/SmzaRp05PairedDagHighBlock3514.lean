import SmzaRp05PairedDagHighBlock3514Part00
import SmzaRp05PairedDagHighBlock3514Part01
import SmzaRp05PairedDagHighBlock3514Part02
import SmzaRp05PairedDagHighBlock3514Part03
import SmzaRp05PairedDagHighBlock3514Part04
import SmzaRp05PairedDagHighBlock3514Part05
import SmzaRp05PairedDagHighBlock3514Part06
import SmzaRp05PairedDagHighBlock3514Part07

/-! Bounded dispatcher for the exact directed-edge interval 3514 through 3641. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_3514 (node : Nat) (lower : 3514 ≤ node)
    (upper : node < 3642) : directedEdgeCheck node = true := by
  by_cases h3530 : node < 3530
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part00.edge_subblock_3514 node lower h3530
  · by_cases h3546 : node < 3546
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part01.edge_subblock_3530 node (Nat.le_of_not_gt h3530) (h3546)
    · by_cases h3562 : node < 3562
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part02.edge_subblock_3546 node (Nat.le_of_not_gt h3546) (h3562)
      · by_cases h3578 : node < 3578
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part03.edge_subblock_3562 node (Nat.le_of_not_gt h3562) (h3578)
        · by_cases h3594 : node < 3594
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part04.edge_subblock_3578 node (Nat.le_of_not_gt h3578) (h3594)
          · by_cases h3610 : node < 3610
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part05.edge_subblock_3594 node (Nat.le_of_not_gt h3594) (h3610)
            · by_cases h3626 : node < 3626
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part06.edge_subblock_3610 node (Nat.le_of_not_gt h3610) (h3626)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part07.edge_subblock_3626 node (Nat.le_of_not_gt h3626) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514
