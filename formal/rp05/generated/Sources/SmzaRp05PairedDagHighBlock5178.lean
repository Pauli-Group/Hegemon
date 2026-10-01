import SmzaRp05PairedDagHighBlock5178Part00
import SmzaRp05PairedDagHighBlock5178Part01
import SmzaRp05PairedDagHighBlock5178Part02
import SmzaRp05PairedDagHighBlock5178Part03
import SmzaRp05PairedDagHighBlock5178Part04
import SmzaRp05PairedDagHighBlock5178Part05
import SmzaRp05PairedDagHighBlock5178Part06
import SmzaRp05PairedDagHighBlock5178Part07

/-! Bounded dispatcher for the exact directed-edge interval 5178 through 5305. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_5178 (node : Nat) (lower : 5178 ≤ node)
    (upper : node < 5306) : directedEdgeCheck node = true := by
  by_cases h5194 : node < 5194
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part00.edge_subblock_5178 node lower h5194
  · by_cases h5210 : node < 5210
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part01.edge_subblock_5194 node (Nat.le_of_not_gt h5194) (h5210)
    · by_cases h5226 : node < 5226
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part02.edge_subblock_5210 node (Nat.le_of_not_gt h5210) (h5226)
      · by_cases h5242 : node < 5242
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part03.edge_subblock_5226 node (Nat.le_of_not_gt h5226) (h5242)
        · by_cases h5258 : node < 5258
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part04.edge_subblock_5242 node (Nat.le_of_not_gt h5242) (h5258)
          · by_cases h5274 : node < 5274
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part05.edge_subblock_5258 node (Nat.le_of_not_gt h5258) (h5274)
            · by_cases h5290 : node < 5290
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part06.edge_subblock_5274 node (Nat.le_of_not_gt h5274) (h5290)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part07.edge_subblock_5290 node (Nat.le_of_not_gt h5290) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178
