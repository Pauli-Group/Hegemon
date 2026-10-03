import SmzaRp05PairedDagHighBlock3130Part00
import SmzaRp05PairedDagHighBlock3130Part01
import SmzaRp05PairedDagHighBlock3130Part02
import SmzaRp05PairedDagHighBlock3130Part03
import SmzaRp05PairedDagHighBlock3130Part04
import SmzaRp05PairedDagHighBlock3130Part05
import SmzaRp05PairedDagHighBlock3130Part06
import SmzaRp05PairedDagHighBlock3130Part07

/-! Bounded dispatcher for the exact 128-node interval 3130 through 3257. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_3130 (node : Nat) (lower : 3130 ≤ node)
    (upper : node < 3258) : directedEdgeCheck node = true := by
  by_cases h3146 : node < 3146
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part00.edge_subblock_3130 node lower h3146
  · by_cases h3162 : node < 3162
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part01.edge_subblock_3146 node (Nat.le_of_not_gt h3146) h3162
    · by_cases h3178 : node < 3178
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part02.edge_subblock_3162 node (Nat.le_of_not_gt h3162) h3178
      · by_cases h3194 : node < 3194
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part03.edge_subblock_3178 node (Nat.le_of_not_gt h3178) h3194
        · by_cases h3210 : node < 3210
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part04.edge_subblock_3194 node (Nat.le_of_not_gt h3194) h3210
          · by_cases h3226 : node < 3226
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part05.edge_subblock_3210 node (Nat.le_of_not_gt h3210) h3226
            · by_cases h3242 : node < 3242
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part06.edge_subblock_3226 node (Nat.le_of_not_gt h3226) h3242
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part07.edge_subblock_3242 node (Nat.le_of_not_gt h3242) upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130
