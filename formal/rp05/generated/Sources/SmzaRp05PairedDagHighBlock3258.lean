import SmzaRp05PairedDagHighBlock3258Part00
import SmzaRp05PairedDagHighBlock3258Part01
import SmzaRp05PairedDagHighBlock3258Part02
import SmzaRp05PairedDagHighBlock3258Part03
import SmzaRp05PairedDagHighBlock3258Part04
import SmzaRp05PairedDagHighBlock3258Part05
import SmzaRp05PairedDagHighBlock3258Part06
import SmzaRp05PairedDagHighBlock3258Part07

/-! Bounded dispatcher for the exact directed-edge interval 3258 through 3385. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_3258 (node : Nat) (lower : 3258 ≤ node)
    (upper : node < 3386) : directedEdgeCheck node = true := by
  by_cases h3274 : node < 3274
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part00.edge_subblock_3258 node lower h3274
  · by_cases h3290 : node < 3290
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part01.edge_subblock_3274 node (Nat.le_of_not_gt h3274) (h3290)
    · by_cases h3306 : node < 3306
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part02.edge_subblock_3290 node (Nat.le_of_not_gt h3290) (h3306)
      · by_cases h3322 : node < 3322
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part03.edge_subblock_3306 node (Nat.le_of_not_gt h3306) (h3322)
        · by_cases h3338 : node < 3338
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part04.edge_subblock_3322 node (Nat.le_of_not_gt h3322) (h3338)
          · by_cases h3354 : node < 3354
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part05.edge_subblock_3338 node (Nat.le_of_not_gt h3338) (h3354)
            · by_cases h3370 : node < 3370
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part06.edge_subblock_3354 node (Nat.le_of_not_gt h3354) (h3370)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part07.edge_subblock_3370 node (Nat.le_of_not_gt h3370) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258
