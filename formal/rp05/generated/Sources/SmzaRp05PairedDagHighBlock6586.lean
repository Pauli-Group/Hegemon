import SmzaRp05PairedDagHighBlock6586Part00
import SmzaRp05PairedDagHighBlock6586Part01
import SmzaRp05PairedDagHighBlock6586Part02
import SmzaRp05PairedDagHighBlock6586Part03
import SmzaRp05PairedDagHighBlock6586Part04
import SmzaRp05PairedDagHighBlock6586Part05
import SmzaRp05PairedDagHighBlock6586Part06
import SmzaRp05PairedDagHighBlock6586Part07

/-! Bounded dispatcher for the exact directed-edge interval 6586 through 6713. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_6586 (node : Nat) (lower : 6586 ≤ node)
    (upper : node < 6714) : directedEdgeCheck node = true := by
  by_cases h6602 : node < 6602
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part00.edge_subblock_6586 node lower h6602
  · by_cases h6618 : node < 6618
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part01.edge_subblock_6602 node (Nat.le_of_not_gt h6602) (h6618)
    · by_cases h6634 : node < 6634
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part02.edge_subblock_6618 node (Nat.le_of_not_gt h6618) (h6634)
      · by_cases h6650 : node < 6650
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part03.edge_subblock_6634 node (Nat.le_of_not_gt h6634) (h6650)
        · by_cases h6666 : node < 6666
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part04.edge_subblock_6650 node (Nat.le_of_not_gt h6650) (h6666)
          · by_cases h6682 : node < 6682
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part05.edge_subblock_6666 node (Nat.le_of_not_gt h6666) (h6682)
            · by_cases h6698 : node < 6698
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part06.edge_subblock_6682 node (Nat.le_of_not_gt h6682) (h6698)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part07.edge_subblock_6698 node (Nat.le_of_not_gt h6698) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586
