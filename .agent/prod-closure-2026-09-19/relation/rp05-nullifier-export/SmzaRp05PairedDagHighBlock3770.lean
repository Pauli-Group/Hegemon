import SmzaRp05PairedDagHighBlock3770Part00
import SmzaRp05PairedDagHighBlock3770Part01
import SmzaRp05PairedDagHighBlock3770Part02
import SmzaRp05PairedDagHighBlock3770Part03
import SmzaRp05PairedDagHighBlock3770Part04
import SmzaRp05PairedDagHighBlock3770Part05
import SmzaRp05PairedDagHighBlock3770Part06
import SmzaRp05PairedDagHighBlock3770Part07

/-! Bounded dispatcher for the exact directed-edge interval 3770 through 3897. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_3770 (node : Nat) (lower : 3770 ≤ node)
    (upper : node < 3898) : directedEdgeCheck node = true := by
  by_cases h3786 : node < 3786
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part00.edge_subblock_3770 node lower h3786
  · by_cases h3802 : node < 3802
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part01.edge_subblock_3786 node (Nat.le_of_not_gt h3786) (h3802)
    · by_cases h3818 : node < 3818
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part02.edge_subblock_3802 node (Nat.le_of_not_gt h3802) (h3818)
      · by_cases h3834 : node < 3834
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part03.edge_subblock_3818 node (Nat.le_of_not_gt h3818) (h3834)
        · by_cases h3850 : node < 3850
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part04.edge_subblock_3834 node (Nat.le_of_not_gt h3834) (h3850)
          · by_cases h3866 : node < 3866
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part05.edge_subblock_3850 node (Nat.le_of_not_gt h3850) (h3866)
            · by_cases h3882 : node < 3882
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part06.edge_subblock_3866 node (Nat.le_of_not_gt h3866) (h3882)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part07.edge_subblock_3882 node (Nat.le_of_not_gt h3882) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770
