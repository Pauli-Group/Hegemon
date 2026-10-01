import SmzaRp05PairedDagHighBlock3642Part00
import SmzaRp05PairedDagHighBlock3642Part01
import SmzaRp05PairedDagHighBlock3642Part02
import SmzaRp05PairedDagHighBlock3642Part03
import SmzaRp05PairedDagHighBlock3642Part04
import SmzaRp05PairedDagHighBlock3642Part05
import SmzaRp05PairedDagHighBlock3642Part06
import SmzaRp05PairedDagHighBlock3642Part07

/-! Bounded dispatcher for the exact directed-edge interval 3642 through 3769. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_3642 (node : Nat) (lower : 3642 ≤ node)
    (upper : node < 3770) : directedEdgeCheck node = true := by
  by_cases h3658 : node < 3658
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part00.edge_subblock_3642 node lower h3658
  · by_cases h3674 : node < 3674
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part01.edge_subblock_3658 node (Nat.le_of_not_gt h3658) (h3674)
    · by_cases h3690 : node < 3690
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part02.edge_subblock_3674 node (Nat.le_of_not_gt h3674) (h3690)
      · by_cases h3706 : node < 3706
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part03.edge_subblock_3690 node (Nat.le_of_not_gt h3690) (h3706)
        · by_cases h3722 : node < 3722
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part04.edge_subblock_3706 node (Nat.le_of_not_gt h3706) (h3722)
          · by_cases h3738 : node < 3738
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part05.edge_subblock_3722 node (Nat.le_of_not_gt h3722) (h3738)
            · by_cases h3754 : node < 3754
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part06.edge_subblock_3738 node (Nat.le_of_not_gt h3738) (h3754)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part07.edge_subblock_3754 node (Nat.le_of_not_gt h3754) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642
