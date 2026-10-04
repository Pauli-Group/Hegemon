import SmzaRp05PairedDagHighBlock4538Part00
import SmzaRp05PairedDagHighBlock4538Part01
import SmzaRp05PairedDagHighBlock4538Part02
import SmzaRp05PairedDagHighBlock4538Part03
import SmzaRp05PairedDagHighBlock4538Part04
import SmzaRp05PairedDagHighBlock4538Part05
import SmzaRp05PairedDagHighBlock4538Part06
import SmzaRp05PairedDagHighBlock4538Part07

/-! Bounded dispatcher for the exact directed-edge interval 4538 through 4665. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem edge_block_4538 (node : Nat) (lower : 4538 ≤ node)
    (upper : node < 4666) : directedEdgeCheck node = true := by
  by_cases h4554 : node < 4554
  · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part00.edge_subblock_4538 node lower h4554
  · by_cases h4570 : node < 4570
    · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part01.edge_subblock_4554 node (Nat.le_of_not_gt h4554) (h4570)
    · by_cases h4586 : node < 4586
      · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part02.edge_subblock_4570 node (Nat.le_of_not_gt h4570) (h4586)
      · by_cases h4602 : node < 4602
        · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part03.edge_subblock_4586 node (Nat.le_of_not_gt h4586) (h4602)
        · by_cases h4618 : node < 4618
          · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part04.edge_subblock_4602 node (Nat.le_of_not_gt h4602) (h4618)
          · by_cases h4634 : node < 4634
            · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part05.edge_subblock_4618 node (Nat.le_of_not_gt h4618) (h4634)
            · by_cases h4650 : node < 4650
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part06.edge_subblock_4634 node (Nat.le_of_not_gt h4634) (h4650)
              · exact HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part07.edge_subblock_4650 node (Nat.le_of_not_gt h4650) (upper)

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538
