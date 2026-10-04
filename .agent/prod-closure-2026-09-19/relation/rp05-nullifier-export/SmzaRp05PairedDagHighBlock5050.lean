import SmzaRp05PairedDagHighBlock5050Part00
import SmzaRp05PairedDagHighBlock5050Part01
import SmzaRp05PairedDagHighBlock5050Part02
import SmzaRp05PairedDagHighBlock5050Part03
import SmzaRp05PairedDagHighBlock5050Part04
import SmzaRp05PairedDagHighBlock5050Part05
import SmzaRp05PairedDagHighBlock5050Part06
import SmzaRp05PairedDagHighBlock5050Part07

/-! Bounded dispatcher for the exact directed-edge interval 5050 through 5177. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_5050 (node : Nat) (lower : 5050 ≤ node)
    (upper : node < 5178) : directedEdgeCheck node = true := by
  by_cases h5066 : node < 5066
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part00.edge_subblock_5050 node lower h5066
  · by_cases h5082 : node < 5082
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part01.edge_subblock_5066 node (Nat.le_of_not_gt h5066) (h5082)
    · by_cases h5098 : node < 5098
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part02.edge_subblock_5082 node (Nat.le_of_not_gt h5082) (h5098)
      · by_cases h5114 : node < 5114
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part03.edge_subblock_5098 node (Nat.le_of_not_gt h5098) (h5114)
        · by_cases h5130 : node < 5130
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part04.edge_subblock_5114 node (Nat.le_of_not_gt h5114) (h5130)
          · by_cases h5146 : node < 5146
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part05.edge_subblock_5130 node (Nat.le_of_not_gt h5130) (h5146)
            · by_cases h5162 : node < 5162
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part06.edge_subblock_5146 node (Nat.le_of_not_gt h5146) (h5162)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part07.edge_subblock_5162 node (Nat.le_of_not_gt h5162) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050
