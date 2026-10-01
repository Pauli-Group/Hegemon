import SmzaRp05PairedDagHighBlock6074Part00
import SmzaRp05PairedDagHighBlock6074Part01
import SmzaRp05PairedDagHighBlock6074Part02
import SmzaRp05PairedDagHighBlock6074Part03
import SmzaRp05PairedDagHighBlock6074Part04
import SmzaRp05PairedDagHighBlock6074Part05
import SmzaRp05PairedDagHighBlock6074Part06
import SmzaRp05PairedDagHighBlock6074Part07

/-! Bounded dispatcher for the exact directed-edge interval 6074 through 6201. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_6074 (node : Nat) (lower : 6074 ≤ node)
    (upper : node < 6202) : directedEdgeCheck node = true := by
  by_cases h6090 : node < 6090
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part00.edge_subblock_6074 node lower h6090
  · by_cases h6106 : node < 6106
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part01.edge_subblock_6090 node (Nat.le_of_not_gt h6090) (h6106)
    · by_cases h6122 : node < 6122
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part02.edge_subblock_6106 node (Nat.le_of_not_gt h6106) (h6122)
      · by_cases h6138 : node < 6138
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part03.edge_subblock_6122 node (Nat.le_of_not_gt h6122) (h6138)
        · by_cases h6154 : node < 6154
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part04.edge_subblock_6138 node (Nat.le_of_not_gt h6138) (h6154)
          · by_cases h6170 : node < 6170
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part05.edge_subblock_6154 node (Nat.le_of_not_gt h6154) (h6170)
            · by_cases h6186 : node < 6186
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part06.edge_subblock_6170 node (Nat.le_of_not_gt h6170) (h6186)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part07.edge_subblock_6186 node (Nat.le_of_not_gt h6186) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074
