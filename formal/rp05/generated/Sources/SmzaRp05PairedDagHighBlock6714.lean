import SmzaRp05PairedDagHighBlock6714Part00
import SmzaRp05PairedDagHighBlock6714Part01
import SmzaRp05PairedDagHighBlock6714Part02
import SmzaRp05PairedDagHighBlock6714Part03
import SmzaRp05PairedDagHighBlock6714Part04
import SmzaRp05PairedDagHighBlock6714Part05
import SmzaRp05PairedDagHighBlock6714Part06
import SmzaRp05PairedDagHighBlock6714Part07

/-! Bounded dispatcher for the exact directed-edge interval 6714 through 6841. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_6714 (node : Nat) (lower : 6714 ≤ node)
    (upper : node < 6842) : directedEdgeCheck node = true := by
  by_cases h6730 : node < 6730
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part00.edge_subblock_6714 node lower h6730
  · by_cases h6746 : node < 6746
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part01.edge_subblock_6730 node (Nat.le_of_not_gt h6730) (h6746)
    · by_cases h6762 : node < 6762
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part02.edge_subblock_6746 node (Nat.le_of_not_gt h6746) (h6762)
      · by_cases h6778 : node < 6778
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part03.edge_subblock_6762 node (Nat.le_of_not_gt h6762) (h6778)
        · by_cases h6794 : node < 6794
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part04.edge_subblock_6778 node (Nat.le_of_not_gt h6778) (h6794)
          · by_cases h6810 : node < 6810
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part05.edge_subblock_6794 node (Nat.le_of_not_gt h6794) (h6810)
            · by_cases h6826 : node < 6826
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part06.edge_subblock_6810 node (Nat.le_of_not_gt h6810) (h6826)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part07.edge_subblock_6826 node (Nat.le_of_not_gt h6826) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714
