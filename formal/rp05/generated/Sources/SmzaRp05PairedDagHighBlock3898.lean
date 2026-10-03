import SmzaRp05PairedDagHighBlock3898Part00
import SmzaRp05PairedDagHighBlock3898Part01
import SmzaRp05PairedDagHighBlock3898Part02
import SmzaRp05PairedDagHighBlock3898Part03
import SmzaRp05PairedDagHighBlock3898Part04
import SmzaRp05PairedDagHighBlock3898Part05
import SmzaRp05PairedDagHighBlock3898Part06
import SmzaRp05PairedDagHighBlock3898Part07

/-! Bounded dispatcher for the exact directed-edge interval 3898 through 4025. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_3898 (node : Nat) (lower : 3898 ≤ node)
    (upper : node < 4026) : directedEdgeCheck node = true := by
  by_cases h3914 : node < 3914
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part00.edge_subblock_3898 node lower h3914
  · by_cases h3930 : node < 3930
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part01.edge_subblock_3914 node (Nat.le_of_not_gt h3914) (h3930)
    · by_cases h3946 : node < 3946
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part02.edge_subblock_3930 node (Nat.le_of_not_gt h3930) (h3946)
      · by_cases h3962 : node < 3962
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part03.edge_subblock_3946 node (Nat.le_of_not_gt h3946) (h3962)
        · by_cases h3978 : node < 3978
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part04.edge_subblock_3962 node (Nat.le_of_not_gt h3962) (h3978)
          · by_cases h3994 : node < 3994
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part05.edge_subblock_3978 node (Nat.le_of_not_gt h3978) (h3994)
            · by_cases h4010 : node < 4010
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part06.edge_subblock_3994 node (Nat.le_of_not_gt h3994) (h4010)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part07.edge_subblock_4010 node (Nat.le_of_not_gt h4010) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898
