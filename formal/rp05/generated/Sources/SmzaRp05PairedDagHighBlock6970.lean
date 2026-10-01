import SmzaRp05PairedDagHighBlock6970Part00
import SmzaRp05PairedDagHighBlock6970Part01
import SmzaRp05PairedDagHighBlock6970Part02
import SmzaRp05PairedDagHighBlock6970Part03
import SmzaRp05PairedDagHighBlock6970Part04
import SmzaRp05PairedDagHighBlock6970Part05
import SmzaRp05PairedDagHighBlock6970Part06
import SmzaRp05PairedDagHighBlock6970Part07

/-! Bounded dispatcher for the exact directed-edge interval 6970 through 7097. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_6970 (node : Nat) (lower : 6970 ≤ node)
    (upper : node < 7098) : directedEdgeCheck node = true := by
  by_cases h6986 : node < 6986
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part00.edge_subblock_6970 node lower h6986
  · by_cases h7002 : node < 7002
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part01.edge_subblock_6986 node (Nat.le_of_not_gt h6986) (h7002)
    · by_cases h7018 : node < 7018
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part02.edge_subblock_7002 node (Nat.le_of_not_gt h7002) (h7018)
      · by_cases h7034 : node < 7034
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part03.edge_subblock_7018 node (Nat.le_of_not_gt h7018) (h7034)
        · by_cases h7050 : node < 7050
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part04.edge_subblock_7034 node (Nat.le_of_not_gt h7034) (h7050)
          · by_cases h7066 : node < 7066
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part05.edge_subblock_7050 node (Nat.le_of_not_gt h7050) (h7066)
            · by_cases h7082 : node < 7082
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part06.edge_subblock_7066 node (Nat.le_of_not_gt h7066) (h7082)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part07.edge_subblock_7082 node (Nat.le_of_not_gt h7082) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970
