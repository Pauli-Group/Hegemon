import SmzaRp05PairedDagHighBlock4666Part00
import SmzaRp05PairedDagHighBlock4666Part01
import SmzaRp05PairedDagHighBlock4666Part02
import SmzaRp05PairedDagHighBlock4666Part03
import SmzaRp05PairedDagHighBlock4666Part04
import SmzaRp05PairedDagHighBlock4666Part05
import SmzaRp05PairedDagHighBlock4666Part06
import SmzaRp05PairedDagHighBlock4666Part07

/-! Bounded dispatcher for the exact directed-edge interval 4666 through 4793. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_4666 (node : Nat) (lower : 4666 ≤ node)
    (upper : node < 4794) : directedEdgeCheck node = true := by
  by_cases h4682 : node < 4682
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part00.edge_subblock_4666 node lower h4682
  · by_cases h4698 : node < 4698
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part01.edge_subblock_4682 node (Nat.le_of_not_gt h4682) (h4698)
    · by_cases h4714 : node < 4714
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part02.edge_subblock_4698 node (Nat.le_of_not_gt h4698) (h4714)
      · by_cases h4730 : node < 4730
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part03.edge_subblock_4714 node (Nat.le_of_not_gt h4714) (h4730)
        · by_cases h4746 : node < 4746
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part04.edge_subblock_4730 node (Nat.le_of_not_gt h4730) (h4746)
          · by_cases h4762 : node < 4762
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part05.edge_subblock_4746 node (Nat.le_of_not_gt h4746) (h4762)
            · by_cases h4778 : node < 4778
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part06.edge_subblock_4762 node (Nat.le_of_not_gt h4762) (h4778)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part07.edge_subblock_4778 node (Nat.le_of_not_gt h4778) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666
