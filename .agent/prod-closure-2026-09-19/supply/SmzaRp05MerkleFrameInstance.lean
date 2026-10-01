import SmzaRp05MerkleFrameCertificate
import SmzaRp05Components
import SmzaRp05DirectCsrCertificate
import SmzaRp05LocalCertificate
import SmzaRp05SupplyClosureCsrChunks

/-!
# Selected RP05 fixture Merkle-frame certificate candidate

This instantiates the finite source certificate against the generated
`SmzaRp05Components.program`, whose source artifact is SHA-512 pinned in that
module. The exact membership/realization checks below are intentionally
kernel `decide` goals. This file is source-only until the serial Lean runner
checks it and retains a receipt; it is not yet production evidence.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05MerkleFrameInstance

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05MerkleFrameCertificate
open HegemonCrypto.SmallWood.SmzaRp05CurrentMerklePublic
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05Components
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashFinalIndex)

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

private theorem lift496 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0496) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 496) (by decide)) member

private theorem lift497 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0497) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 497) (by decide)) member

private theorem lift498 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0498) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 498) (by decide)) member

private theorem lift499 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0499) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 499) (by decide)) member

private theorem lift500 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0500) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 500) (by decide)) member

private theorem lift501 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0501) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 501) (by decide)) member

private theorem lift502 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0502) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 502) (by decide)) member

private theorem lift503 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0503) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 503) (by decide)) member

private theorem lift504 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0504) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 504) (by decide)) member

private theorem lift505 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0505) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 505) (by decide)) member

private theorem lift506 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0506) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 506) (by decide)) member

private theorem lift507 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0507) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 507) (by decide)) member

private theorem lift508 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0508) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 508) (by decide)) member

private theorem lift509 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0509) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 509) (by decide)) member

private theorem lift510 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0510) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 510) (by decide)) member

private theorem lift511 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0511) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 511) (by decide)) member

private theorem lift512 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0512) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 512) (by decide)) member

private theorem lift513 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0513) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 513) (by decide)) member

private theorem lift514 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0514) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 514) (by decide)) member

private theorem lift515 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0515) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 515) (by decide)) member

private theorem lift516 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0516) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 516) (by decide)) member

private theorem lift517 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0517) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 517) (by decide)) member

private theorem lift518 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0518) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 518) (by decide)) member

private theorem lift519 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0519) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 519) (by decide)) member

private theorem lift520 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0520) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 520) (by decide)) member

private theorem lift521 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0521) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 521) (by decide)) member

private theorem lift522 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0522) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 522) (by decide)) member

private theorem lift523 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0523) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 523) (by decide)) member

private theorem lift524 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0524) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 524) (by decide)) member

private theorem lift525 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0525) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 525) (by decide)) member

private theorem lift526 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0526) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 526) (by decide)) member

private theorem lift527 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0527) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 527) (by decide)) member

private theorem lift528 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0528) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 528) (by decide)) member

private theorem lift529 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0529) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 529) (by decide)) member

private theorem lift530 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0530) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 530) (by decide)) member

private theorem lift531 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0531) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 531) (by decide)) member

private theorem lift532 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0532) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 532) (by decide)) member

private theorem lift533 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0533) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 533) (by decide)) member

private theorem lift534 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0534) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 534) (by decide)) member

private theorem lift535 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0535) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 535) (by decide)) member

private theorem lift536 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0536) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 536) (by decide)) member

private theorem lift537 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0537) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 537) (by decide)) member

private theorem lift538 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0538) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 538) (by decide)) member

private theorem lift539 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0539) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 539) (by decide)) member

private theorem lift540 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0540) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 540) (by decide)) member

private theorem lift541 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0541) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 541) (by decide)) member

private theorem lift542 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0542) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 542) (by decide)) member

private theorem lift543 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0543) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 543) (by decide)) member

private theorem lift544 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0544) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 544) (by decide)) member

private theorem lift545 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0545) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 545) (by decide)) member

private theorem lift546 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0546) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 546) (by decide)) member

private theorem lift547 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0547) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 547) (by decide)) member

private theorem lift548 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0548) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 548) (by decide)) member

private theorem lift549 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0549) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 549) (by decide)) member

private theorem lift550 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0550) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 550) (by decide)) member

private theorem lift551 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0551) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 551) (by decide)) member

private theorem lift552 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0552) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 552) (by decide)) member

private theorem lift553 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0553) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 553) (by decide)) member

private theorem lift554 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0554) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 554) (by decide)) member

private theorem lift555 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0555) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 555) (by decide)) member

private theorem lift556 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0556) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 556) (by decide)) member

private theorem lift570 {a : CsrExecutableAttempt}
    (member : a ∈ exactCsrAttemptsChunk0570) : a ∈ exactCsrAttempts := by
  unfold exactCsrAttempts
  exact List.mem_flatten_of_mem
    (List.getElem_mem (n := 570) (by decide)) member

def exactInitial (cell : InitialCell) : CsrExecutableAttempt where
  globalIndex := initialGlobal cell.1.val cell.2.val
  family := 16
  localIndex := 16 * cell.1.val + cell.2.val
  emission := 0
  terms := initialTerms cell
  targetRoot := initialTarget cell

def exactCurrent (cell : CopyCell) : CsrExecutableAttempt where
  globalIndex := currentGlobal cell.1.val cell.2.val
  family := 17
  localIndex := 7 * cell.1.val + cell.2.val
  emission := 0
  terms := currentTerms cell
  targetRoot := 0

def exactDirection (cell : CopyCell) : CsrExecutableAttempt where
  globalIndex := directionGlobal cell.1.val cell.2.val
  family := 18
  localIndex := 7 * cell.1.val + cell.2.val
  emission := 0
  terms := directionTerms cell
  targetRoot := 0

/-- These are exact selected-program data checks, not semantic assumptions.
The accompanying parser audit independently checked all indexed families
against the original 848231-byte artifact. -/
private theorem exact_initial_member :
    ∀ cell : InitialCell,
      exactInitial cell ∈
        HegemonCrypto.SmallWood.SmzaRp05Components.program.csrAttempts := by
  intro cell
  change exactInitial cell ∈ exactCsrAttempts
  rcases cell with ⟨step, lane⟩
  fin_cases step
  · fin_cases lane <;>
      first
      | apply lift496
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift496
        decide +revert
      | apply lift497
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift497
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift497
        decide +revert
      | apply lift498
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift498
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift498
        decide +revert
      | apply lift499
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift499
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift499
        decide +revert
      | apply lift500
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift500
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift500
        decide +revert
      | apply lift501
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift501
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift501
        decide +revert
      | apply lift502
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift502
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift502
        decide +revert
      | apply lift503
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift503
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift503
        decide +revert
      | apply lift504
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift504
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift504
        decide +revert
      | apply lift505
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift505
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift505
        decide +revert
      | apply lift506
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift506
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift506
        decide +revert
      | apply lift507
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift507
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift507
        decide +revert
      | apply lift508
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift508
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift508
        decide +revert
      | apply lift509
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift509
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift509
        decide +revert
      | apply lift510
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift510
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift510
        decide +revert
      | apply lift511
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift511
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift511
        decide +revert
      | apply lift512
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift512
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift512
        decide +revert
      | apply lift513
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift513
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift513
        decide +revert
      | apply lift514
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift514
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift514
        decide +revert
      | apply lift515
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift515
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift515
        decide +revert
      | apply lift516
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift516
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift516
        decide +revert
      | apply lift517
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift517
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift517
        decide +revert
      | apply lift518
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift518
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift518
        decide +revert
      | apply lift519
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift519
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift519
        decide +revert
      | apply lift520
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift520
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift520
        decide +revert
      | apply lift521
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift521
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift521
        decide +revert
      | apply lift522
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift522
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift522
        decide +revert
      | apply lift523
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift523
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift523
        decide +revert
      | apply lift524
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift524
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift524
        decide +revert
      | apply lift525
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift525
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift525
        decide +revert
      | apply lift526
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift526
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift526
        decide +revert
      | apply lift527
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift527
        decide +revert
  · fin_cases lane <;>
      first
      | apply lift527
        decide +revert
      | apply lift528
        decide +revert

private theorem exact_current_member :
    ∀ cell : CopyCell,
      exactCurrent cell ∈
        HegemonCrypto.SmallWood.SmzaRp05Components.program.csrAttempts := by
  intro cell
  change exactCurrent cell ∈ exactCsrAttempts
  rcases cell with ⟨step, limb⟩
  fin_cases step
  · fin_cases limb <;>
      first
      | apply lift528
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift528
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift528
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift528
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift528
        decide +revert
      | apply lift529
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift529
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift529
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift529
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift529
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift530
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift530
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift530
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift530
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift530
        decide +revert
      | apply lift531
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift531
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift531
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift531
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift531
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift531
        decide +revert
      | apply lift532
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift532
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift532
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift532
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift532
        decide +revert
      | apply lift533
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift533
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift533
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift533
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift533
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift533
        decide +revert
      | apply lift534
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift534
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift534
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift534
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift534
        decide +revert
      | apply lift535
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift535
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift535
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift535
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift535
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift535
        decide +revert
      | apply lift536
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift536
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift536
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift536
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift536
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift537
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift537
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift537
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift537
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift537
        decide +revert
      | apply lift538
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift538
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift538
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift538
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift538
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift538
        decide +revert
      | apply lift539
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift539
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift539
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift539
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift539
        decide +revert
      | apply lift540
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift540
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift540
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift540
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift540
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift540
        decide +revert
      | apply lift541
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift541
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift541
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift541
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift541
        decide +revert
      | apply lift542
        decide +revert

private theorem exact_direction_member :
    ∀ cell : CopyCell,
      exactDirection cell ∈
        HegemonCrypto.SmallWood.SmzaRp05Components.program.csrAttempts := by
  intro cell
  change exactDirection cell ∈ exactCsrAttempts
  rcases cell with ⟨step, limb⟩
  fin_cases step
  · fin_cases limb <;>
      first
      | apply lift542
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift542
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift542
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift542
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift542
        decide +revert
      | apply lift543
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift543
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift543
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift543
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift543
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift544
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift544
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift544
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift544
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift544
        decide +revert
      | apply lift545
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift545
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift545
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift545
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift545
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift545
        decide +revert
      | apply lift546
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift546
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift546
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift546
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift546
        decide +revert
      | apply lift547
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift547
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift547
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift547
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift547
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift547
        decide +revert
      | apply lift548
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift548
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift548
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift548
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift548
        decide +revert
      | apply lift549
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift549
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift549
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift549
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift549
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift549
        decide +revert
      | apply lift550
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift550
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift550
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift550
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift550
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift551
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift551
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift551
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift551
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift551
        decide +revert
      | apply lift552
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift552
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift552
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift552
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift552
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift552
        decide +revert
      | apply lift553
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift553
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift553
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift553
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift553
        decide +revert
      | apply lift554
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift554
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift554
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift554
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift554
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift554
        decide +revert
      | apply lift555
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift555
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift555
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift555
        decide +revert
  · fin_cases limb <;>
      first
      | apply lift555
        decide +revert
      | apply lift556
        decide +revert



def certificate : FrameCertificate
    HegemonCrypto.SmallWood.SmzaRp05Components.program where
  canonical := SmzaRp05DirectCsrCertificate.certificate.csrCanonicalWithRows
  zero := SmzaRp05DirectCsrCertificate.certificate.zeroRealizes
  one := SmzaRp05DirectCsrCertificate.certificate.oneRealizes
  negative := SmzaRp05DirectCsrCertificate.certificate.derivedMinusOneRealizes
  domain := Realizes.constant (by decide)
  suite := Realizes.constant (by decide)
  initial := exactInitial
  initialMember := exact_initial_member
  initialIdentity := by intro cell; exact ⟨rfl, rfl, rfl, rfl⟩
  initialExact := by intro cell; exact ⟨rfl, rfl⟩
  current := exactCurrent
  currentMember := exact_current_member
  currentIdentity := by intro cell; exact ⟨rfl, rfl, rfl, rfl⟩
  currentExact := by intro cell; exact ⟨rfl, rfl⟩
  direction := exactDirection
  directionMember := exact_direction_member
  directionIdentity := by intro cell; exact ⟨rfl, rfl, rfl, rfl⟩
  directionExact := by intro cell; exact ⟨rfl, rfl⟩

/-- Parsed roots 1207,1211,...,1231 remain source-live in RP05. -/
private theorem orientation_realizes (group : Fin 7) :
    Realizes program.nonlinearExecutable.expressions (1207 + 4 * group.val)
      (.sub (.witness (252 + 4 * group.val))
        (.add (.witness (253 + 4 * group.val))
          (.mul (.witness (255 + 4 * group.val))
            (.sub (.witness (254 + 4 * group.val))
              (.witness (253 + 4 * group.val)))))) := by
  apply Realizes.sub (leftNode := 376 + 4 * group.val)
    (rightNode := 1206 + 4 * group.val)
  · fin_cases group <;> decide
  · omega
  · omega
  · fin_cases group <;> exact Realizes.witness (by decide)
  · apply Realizes.add (leftNode := 377 + 4 * group.val)
      (rightNode := 1205 + 4 * group.val)
    · fin_cases group <;> decide
    · omega
    · omega
    · fin_cases group <;> exact Realizes.witness (by decide)
    · apply Realizes.mul (leftNode := 379 + 4 * group.val)
        (rightNode := 1204 + 4 * group.val)
      · fin_cases group <;> decide
      · omega
      · omega
      · fin_cases group <;> exact Realizes.witness (by decide)
      · apply Realizes.sub (leftNode := 378 + 4 * group.val)
          (rightNode := 377 + 4 * group.val)
        · fin_cases group <;> decide
        · omega
        · omega
        · fin_cases group <;> exact Realizes.witness (by decide)
        · fin_cases group <;> exact Realizes.witness (by decide)

def orientationCertificate : OrientationCertificate
    HegemonCrypto.SmallWood.SmzaRp05Components.program where
  canonical := SmzaRp05LocalCertificate.certificate.canonical
  root := fun group => 1207 + 4 * group.val
  member := by decide
  realizes := orientation_realizes

/-- The fourteen family20 rows bind the active final call (35 or 72) to
public anchor words 47..53. Parsed CSR targets are nodes 196..202 for input0
and 271..277 for input1; each is the active public bit multiplied by that
root word. -/
def exactPublicRoot (cell : PublicRootCell) : CsrExecutableAttempt where
  globalIndex := 18241 + 7 * cell.1.val + cell.2.val
  family := 20
  localIndex := 7 * cell.1.val + cell.2.val
  emission := 1
  terms := [(hashFinalIndex
    (currentMerkleCall cell.1 ⟨31, by decide⟩) cell.2.val,
      4 + cell.1.val)]
  targetRoot := if cell.1.val = 0 then 196 + cell.2.val
    else 271 + cell.2.val

theorem exact_public_root_member :
    ∀ cell : PublicRootCell,
      exactPublicRoot cell ∈
        HegemonCrypto.SmallWood.SmzaRp05Components.program.csrAttempts := by
  intro cell
  change exactPublicRoot cell ∈ exactCsrAttempts
  rcases cell with ⟨input, limb⟩
  fin_cases input <;> fin_cases limb <;>
    apply lift570 <;> decide

def publicRootCertificate : PublicRootCertificate
    HegemonCrypto.SmallWood.SmzaRp05Components.program where
  canonical := certificate.canonical
  activeNode := fun input => 4 + input.val
  targetNode := fun cell => if cell.1.val = 0 then 196 + cell.2.val
    else 271 + cell.2.val
  activeRealizes := by
    intro input
    fin_cases input <;> exact Realizes.publicInput (by decide)
  targetRealizes := by
    intro cell
    rcases cell with ⟨input, limb⟩
    apply Realizes.mul (leftNode := 4 + input.val)
      (rightNode := 51 + limb.val)
    · fin_cases input <;> fin_cases limb <;> decide +revert
    · have limbBound := limb.isLt
      fin_cases input <;> norm_num <;> omega
    · have limbBound := limb.isLt
      fin_cases input <;> norm_num
    · fin_cases input <;> exact Realizes.publicInput (by decide +revert)
    · fin_cases limb <;> exact Realizes.publicInput (by decide +revert)
  attempt := exactPublicRoot
  member := exact_public_root_member
  attemptTerms := by intro cell; rfl
  attemptTarget := by intro cell; rfl

end HegemonCrypto.SmallWood.SmzaRp05MerkleFrameInstance
