import SmzaRp05PairedDagHighBlock5946Part00
import SmzaRp05PairedDagHighBlock5946Part01
import SmzaRp05PairedDagHighBlock5946Part02
import SmzaRp05PairedDagHighBlock5946Part03
import SmzaRp05PairedDagHighBlock5946Part04
import SmzaRp05PairedDagHighBlock5946Part05
import SmzaRp05PairedDagHighBlock5946Part06
import SmzaRp05PairedDagHighBlock5946Part07

/-! Bounded dispatcher for the exact directed-edge interval 5946 through 6073. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_5946 (node : Nat) (lower : 5946 ≤ node)
    (upper : node < 6074) : directedEdgeCheck node = true := by
  by_cases h5962 : node < 5962
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part00.edge_subblock_5946 node lower h5962
  · by_cases h5978 : node < 5978
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part01.edge_subblock_5962 node (Nat.le_of_not_gt h5962) (h5978)
    · by_cases h5994 : node < 5994
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part02.edge_subblock_5978 node (Nat.le_of_not_gt h5978) (h5994)
      · by_cases h6010 : node < 6010
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part03.edge_subblock_5994 node (Nat.le_of_not_gt h5994) (h6010)
        · by_cases h6026 : node < 6026
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part04.edge_subblock_6010 node (Nat.le_of_not_gt h6010) (h6026)
          · by_cases h6042 : node < 6042
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part05.edge_subblock_6026 node (Nat.le_of_not_gt h6026) (h6042)
            · by_cases h6058 : node < 6058
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part06.edge_subblock_6042 node (Nat.le_of_not_gt h6042) (h6058)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part07.edge_subblock_6058 node (Nat.le_of_not_gt h6058) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946
