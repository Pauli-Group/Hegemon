import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr04

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr05
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [2560, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 2560 0 2560 0 [(2601, 1), (2560, 3)] 0, attempt 2561 0 2561 0 [(2602, 1), (2560, 3)] 0, attempt 2562 0 2562 0 [(2603, 1), (2560, 3)] 0, attempt 2563 0 2563 0 [(2604, 1), (2560, 3)] 0, attempt 2564 0 2564 0 [(2605, 1), (2560, 3)] 0, attempt 2565 0 2565 0 [(2606, 1), (2560, 3)] 0, attempt 2566 0 2566 0 [(2607, 1), (2560, 3)] 0, attempt 2567 0 2567 0 [(2608, 1), (2560, 3)] 0, attempt 2568 0 2568 0 [(2609, 1), (2560, 3)] 0, attempt 2569 0 2569 0 [(2610, 1), (2560, 3)] 0, attempt 2570 0 2570 0 [(2611, 1), (2560, 3)] 0, attempt 2571 0 2571 0 [(2612, 1), (2560, 3)] 0, attempt 2572 0 2572 0 [(2613, 1), (2560, 3)] 0, attempt 2573 0 2573 0 [(2614, 1), (2560, 3)] 0, attempt 2574 0 2574 0 [(2615, 1), (2560, 3)] 0, attempt 2575 0 2575 0 [(2616, 1), (2560, 3)] 0, attempt 2576 0 2576 0 [(2617, 1), (2560, 3)] 0, attempt 2577 0 2577 0 [(2618, 1), (2560, 3)] 0, attempt 2578 0 2578 0 [(2619, 1), (2560, 3)] 0, attempt 2579 0 2579 0 [(2620, 1), (2560, 3)] 0, attempt 2580 0 2580 0 [(2621, 1), (2560, 3)] 0, attempt 2581 0 2581 0 [(2622, 1), (2560, 3)] 0, attempt 2582 0 2582 0 [(2623, 1), (2560, 3)] 0, attempt 2583 0 2583 0 [(2625, 1), (2624, 3)] 0, attempt 2584 0 2584 0 [(2626, 1), (2624, 3)] 0, attempt 2585 0 2585 0 [(2627, 1), (2624, 3)] 0, attempt 2586 0 2586 0 [(2628, 1), (2624, 3)] 0, attempt 2587 0 2587 0 [(2629, 1), (2624, 3)] 0, attempt 2588 0 2588 0 [(2630, 1), (2624, 3)] 0, attempt 2589 0 2589 0 [(2631, 1), (2624, 3)] 0, attempt 2590 0 2590 0 [(2632, 1), (2624, 3)] 0, attempt 2591 0 2591 0 [(2633, 1), (2624, 3)] 0]
def counters001 : List Nat := [2592, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2560
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 2592 0 2592 0 [(2634, 1), (2624, 3)] 0, attempt 2593 0 2593 0 [(2635, 1), (2624, 3)] 0, attempt 2594 0 2594 0 [(2636, 1), (2624, 3)] 0, attempt 2595 0 2595 0 [(2637, 1), (2624, 3)] 0, attempt 2596 0 2596 0 [(2638, 1), (2624, 3)] 0, attempt 2597 0 2597 0 [(2639, 1), (2624, 3)] 0, attempt 2598 0 2598 0 [(2640, 1), (2624, 3)] 0, attempt 2599 0 2599 0 [(2641, 1), (2624, 3)] 0, attempt 2600 0 2600 0 [(2642, 1), (2624, 3)] 0, attempt 2601 0 2601 0 [(2643, 1), (2624, 3)] 0, attempt 2602 0 2602 0 [(2644, 1), (2624, 3)] 0, attempt 2603 0 2603 0 [(2645, 1), (2624, 3)] 0, attempt 2604 0 2604 0 [(2646, 1), (2624, 3)] 0, attempt 2605 0 2605 0 [(2647, 1), (2624, 3)] 0, attempt 2606 0 2606 0 [(2648, 1), (2624, 3)] 0, attempt 2607 0 2607 0 [(2649, 1), (2624, 3)] 0, attempt 2608 0 2608 0 [(2650, 1), (2624, 3)] 0, attempt 2609 0 2609 0 [(2651, 1), (2624, 3)] 0, attempt 2610 0 2610 0 [(2652, 1), (2624, 3)] 0, attempt 2611 0 2611 0 [(2653, 1), (2624, 3)] 0, attempt 2612 0 2612 0 [(2654, 1), (2624, 3)] 0, attempt 2613 0 2613 0 [(2655, 1), (2624, 3)] 0, attempt 2614 0 2614 0 [(2656, 1), (2624, 3)] 0, attempt 2615 0 2615 0 [(2657, 1), (2624, 3)] 0, attempt 2616 0 2616 0 [(2658, 1), (2624, 3)] 0, attempt 2617 0 2617 0 [(2659, 1), (2624, 3)] 0, attempt 2618 0 2618 0 [(2660, 1), (2624, 3)] 0, attempt 2619 0 2619 0 [(2661, 1), (2624, 3)] 0, attempt 2620 0 2620 0 [(2662, 1), (2624, 3)] 0, attempt 2621 0 2621 0 [(2663, 1), (2624, 3)] 0, attempt 2622 0 2622 0 [(2664, 1), (2624, 3)] 0, attempt 2623 0 2623 0 [(2665, 1), (2624, 3)] 0]
def counters002 : List Nat := [2624, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2592
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 2624 0 2624 0 [(2666, 1), (2624, 3)] 0, attempt 2625 0 2625 0 [(2667, 1), (2624, 3)] 0, attempt 2626 0 2626 0 [(2668, 1), (2624, 3)] 0, attempt 2627 0 2627 0 [(2669, 1), (2624, 3)] 0, attempt 2628 0 2628 0 [(2670, 1), (2624, 3)] 0, attempt 2629 0 2629 0 [(2671, 1), (2624, 3)] 0, attempt 2630 0 2630 0 [(2672, 1), (2624, 3)] 0, attempt 2631 0 2631 0 [(2673, 1), (2624, 3)] 0, attempt 2632 0 2632 0 [(2674, 1), (2624, 3)] 0, attempt 2633 0 2633 0 [(2675, 1), (2624, 3)] 0, attempt 2634 0 2634 0 [(2676, 1), (2624, 3)] 0, attempt 2635 0 2635 0 [(2677, 1), (2624, 3)] 0, attempt 2636 0 2636 0 [(2678, 1), (2624, 3)] 0, attempt 2637 0 2637 0 [(2679, 1), (2624, 3)] 0, attempt 2638 0 2638 0 [(2680, 1), (2624, 3)] 0, attempt 2639 0 2639 0 [(2681, 1), (2624, 3)] 0, attempt 2640 0 2640 0 [(2682, 1), (2624, 3)] 0, attempt 2641 0 2641 0 [(2683, 1), (2624, 3)] 0, attempt 2642 0 2642 0 [(2684, 1), (2624, 3)] 0, attempt 2643 0 2643 0 [(2685, 1), (2624, 3)] 0, attempt 2644 0 2644 0 [(2686, 1), (2624, 3)] 0, attempt 2645 0 2645 0 [(2687, 1), (2624, 3)] 0, attempt 2646 0 2646 0 [(2689, 1), (2688, 3)] 0, attempt 2647 0 2647 0 [(2690, 1), (2688, 3)] 0, attempt 2648 0 2648 0 [(2691, 1), (2688, 3)] 0, attempt 2649 0 2649 0 [(2692, 1), (2688, 3)] 0, attempt 2650 0 2650 0 [(2693, 1), (2688, 3)] 0, attempt 2651 0 2651 0 [(2694, 1), (2688, 3)] 0, attempt 2652 0 2652 0 [(2695, 1), (2688, 3)] 0, attempt 2653 0 2653 0 [(2696, 1), (2688, 3)] 0, attempt 2654 0 2654 0 [(2697, 1), (2688, 3)] 0, attempt 2655 0 2655 0 [(2698, 1), (2688, 3)] 0]
def counters003 : List Nat := [2656, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2624
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 2656 0 2656 0 [(2699, 1), (2688, 3)] 0, attempt 2657 0 2657 0 [(2700, 1), (2688, 3)] 0, attempt 2658 0 2658 0 [(2701, 1), (2688, 3)] 0, attempt 2659 0 2659 0 [(2702, 1), (2688, 3)] 0, attempt 2660 0 2660 0 [(2703, 1), (2688, 3)] 0, attempt 2661 0 2661 0 [(2704, 1), (2688, 3)] 0, attempt 2662 0 2662 0 [(2705, 1), (2688, 3)] 0, attempt 2663 0 2663 0 [(2706, 1), (2688, 3)] 0, attempt 2664 0 2664 0 [(2707, 1), (2688, 3)] 0, attempt 2665 0 2665 0 [(2708, 1), (2688, 3)] 0, attempt 2666 0 2666 0 [(2709, 1), (2688, 3)] 0, attempt 2667 0 2667 0 [(2710, 1), (2688, 3)] 0, attempt 2668 0 2668 0 [(2711, 1), (2688, 3)] 0, attempt 2669 0 2669 0 [(2712, 1), (2688, 3)] 0, attempt 2670 0 2670 0 [(2713, 1), (2688, 3)] 0, attempt 2671 0 2671 0 [(2714, 1), (2688, 3)] 0, attempt 2672 0 2672 0 [(2715, 1), (2688, 3)] 0, attempt 2673 0 2673 0 [(2716, 1), (2688, 3)] 0, attempt 2674 0 2674 0 [(2717, 1), (2688, 3)] 0, attempt 2675 0 2675 0 [(2718, 1), (2688, 3)] 0, attempt 2676 0 2676 0 [(2719, 1), (2688, 3)] 0, attempt 2677 0 2677 0 [(2720, 1), (2688, 3)] 0, attempt 2678 0 2678 0 [(2721, 1), (2688, 3)] 0, attempt 2679 0 2679 0 [(2722, 1), (2688, 3)] 0, attempt 2680 0 2680 0 [(2723, 1), (2688, 3)] 0, attempt 2681 0 2681 0 [(2724, 1), (2688, 3)] 0, attempt 2682 0 2682 0 [(2725, 1), (2688, 3)] 0, attempt 2683 0 2683 0 [(2726, 1), (2688, 3)] 0, attempt 2684 0 2684 0 [(2727, 1), (2688, 3)] 0, attempt 2685 0 2685 0 [(2728, 1), (2688, 3)] 0, attempt 2686 0 2686 0 [(2729, 1), (2688, 3)] 0, attempt 2687 0 2687 0 [(2730, 1), (2688, 3)] 0]
def counters004 : List Nat := [2688, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2656
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 2688 0 2688 0 [(2731, 1), (2688, 3)] 0, attempt 2689 0 2689 0 [(2732, 1), (2688, 3)] 0, attempt 2690 0 2690 0 [(2733, 1), (2688, 3)] 0, attempt 2691 0 2691 0 [(2734, 1), (2688, 3)] 0, attempt 2692 0 2692 0 [(2735, 1), (2688, 3)] 0, attempt 2693 0 2693 0 [(2736, 1), (2688, 3)] 0, attempt 2694 0 2694 0 [(2737, 1), (2688, 3)] 0, attempt 2695 0 2695 0 [(2738, 1), (2688, 3)] 0, attempt 2696 0 2696 0 [(2739, 1), (2688, 3)] 0, attempt 2697 0 2697 0 [(2740, 1), (2688, 3)] 0, attempt 2698 0 2698 0 [(2741, 1), (2688, 3)] 0, attempt 2699 0 2699 0 [(2742, 1), (2688, 3)] 0, attempt 2700 0 2700 0 [(2743, 1), (2688, 3)] 0, attempt 2701 0 2701 0 [(2744, 1), (2688, 3)] 0, attempt 2702 0 2702 0 [(2745, 1), (2688, 3)] 0, attempt 2703 0 2703 0 [(2746, 1), (2688, 3)] 0, attempt 2704 0 2704 0 [(2747, 1), (2688, 3)] 0, attempt 2705 0 2705 0 [(2748, 1), (2688, 3)] 0, attempt 2706 0 2706 0 [(2749, 1), (2688, 3)] 0, attempt 2707 0 2707 0 [(2750, 1), (2688, 3)] 0, attempt 2708 0 2708 0 [(2751, 1), (2688, 3)] 0, attempt 2709 0 2709 0 [(2753, 1), (2752, 3)] 0, attempt 2710 0 2710 0 [(2754, 1), (2752, 3)] 0, attempt 2711 0 2711 0 [(2755, 1), (2752, 3)] 0, attempt 2712 0 2712 0 [(2756, 1), (2752, 3)] 0, attempt 2713 0 2713 0 [(2757, 1), (2752, 3)] 0, attempt 2714 0 2714 0 [(2758, 1), (2752, 3)] 0, attempt 2715 0 2715 0 [(2759, 1), (2752, 3)] 0, attempt 2716 0 2716 0 [(2760, 1), (2752, 3)] 0, attempt 2717 0 2717 0 [(2761, 1), (2752, 3)] 0, attempt 2718 0 2718 0 [(2762, 1), (2752, 3)] 0, attempt 2719 0 2719 0 [(2763, 1), (2752, 3)] 0]
def counters005 : List Nat := [2720, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2688
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 2720 0 2720 0 [(2764, 1), (2752, 3)] 0, attempt 2721 0 2721 0 [(2765, 1), (2752, 3)] 0, attempt 2722 0 2722 0 [(2766, 1), (2752, 3)] 0, attempt 2723 0 2723 0 [(2767, 1), (2752, 3)] 0, attempt 2724 0 2724 0 [(2768, 1), (2752, 3)] 0, attempt 2725 0 2725 0 [(2769, 1), (2752, 3)] 0, attempt 2726 0 2726 0 [(2770, 1), (2752, 3)] 0, attempt 2727 0 2727 0 [(2771, 1), (2752, 3)] 0, attempt 2728 0 2728 0 [(2772, 1), (2752, 3)] 0, attempt 2729 0 2729 0 [(2773, 1), (2752, 3)] 0, attempt 2730 0 2730 0 [(2774, 1), (2752, 3)] 0, attempt 2731 0 2731 0 [(2775, 1), (2752, 3)] 0, attempt 2732 0 2732 0 [(2776, 1), (2752, 3)] 0, attempt 2733 0 2733 0 [(2777, 1), (2752, 3)] 0, attempt 2734 0 2734 0 [(2778, 1), (2752, 3)] 0, attempt 2735 0 2735 0 [(2779, 1), (2752, 3)] 0, attempt 2736 0 2736 0 [(2780, 1), (2752, 3)] 0, attempt 2737 0 2737 0 [(2781, 1), (2752, 3)] 0, attempt 2738 0 2738 0 [(2782, 1), (2752, 3)] 0, attempt 2739 0 2739 0 [(2783, 1), (2752, 3)] 0, attempt 2740 0 2740 0 [(2784, 1), (2752, 3)] 0, attempt 2741 0 2741 0 [(2785, 1), (2752, 3)] 0, attempt 2742 0 2742 0 [(2786, 1), (2752, 3)] 0, attempt 2743 0 2743 0 [(2787, 1), (2752, 3)] 0, attempt 2744 0 2744 0 [(2788, 1), (2752, 3)] 0, attempt 2745 0 2745 0 [(2789, 1), (2752, 3)] 0, attempt 2746 0 2746 0 [(2790, 1), (2752, 3)] 0, attempt 2747 0 2747 0 [(2791, 1), (2752, 3)] 0, attempt 2748 0 2748 0 [(2792, 1), (2752, 3)] 0, attempt 2749 0 2749 0 [(2793, 1), (2752, 3)] 0, attempt 2750 0 2750 0 [(2794, 1), (2752, 3)] 0, attempt 2751 0 2751 0 [(2795, 1), (2752, 3)] 0]
def counters006 : List Nat := [2752, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2720
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 2752 0 2752 0 [(2796, 1), (2752, 3)] 0, attempt 2753 0 2753 0 [(2797, 1), (2752, 3)] 0, attempt 2754 0 2754 0 [(2798, 1), (2752, 3)] 0, attempt 2755 0 2755 0 [(2799, 1), (2752, 3)] 0, attempt 2756 0 2756 0 [(2800, 1), (2752, 3)] 0, attempt 2757 0 2757 0 [(2801, 1), (2752, 3)] 0, attempt 2758 0 2758 0 [(2802, 1), (2752, 3)] 0, attempt 2759 0 2759 0 [(2803, 1), (2752, 3)] 0, attempt 2760 0 2760 0 [(2804, 1), (2752, 3)] 0, attempt 2761 0 2761 0 [(2805, 1), (2752, 3)] 0, attempt 2762 0 2762 0 [(2806, 1), (2752, 3)] 0, attempt 2763 0 2763 0 [(2807, 1), (2752, 3)] 0, attempt 2764 0 2764 0 [(2808, 1), (2752, 3)] 0, attempt 2765 0 2765 0 [(2809, 1), (2752, 3)] 0, attempt 2766 0 2766 0 [(2810, 1), (2752, 3)] 0, attempt 2767 0 2767 0 [(2811, 1), (2752, 3)] 0, attempt 2768 0 2768 0 [(2812, 1), (2752, 3)] 0, attempt 2769 0 2769 0 [(2813, 1), (2752, 3)] 0, attempt 2770 0 2770 0 [(2814, 1), (2752, 3)] 0, attempt 2771 0 2771 0 [(2815, 1), (2752, 3)] 0, attempt 2772 0 2772 0 [(2817, 1), (2816, 3)] 0, attempt 2773 0 2773 0 [(2818, 1), (2816, 3)] 0, attempt 2774 0 2774 0 [(2819, 1), (2816, 3)] 0, attempt 2775 0 2775 0 [(2820, 1), (2816, 3)] 0, attempt 2776 0 2776 0 [(2821, 1), (2816, 3)] 0, attempt 2777 0 2777 0 [(2822, 1), (2816, 3)] 0, attempt 2778 0 2778 0 [(2823, 1), (2816, 3)] 0, attempt 2779 0 2779 0 [(2824, 1), (2816, 3)] 0, attempt 2780 0 2780 0 [(2825, 1), (2816, 3)] 0, attempt 2781 0 2781 0 [(2826, 1), (2816, 3)] 0, attempt 2782 0 2782 0 [(2827, 1), (2816, 3)] 0, attempt 2783 0 2783 0 [(2828, 1), (2816, 3)] 0]
def counters007 : List Nat := [2784, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2752
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 2784 0 2784 0 [(2829, 1), (2816, 3)] 0, attempt 2785 0 2785 0 [(2830, 1), (2816, 3)] 0, attempt 2786 0 2786 0 [(2831, 1), (2816, 3)] 0, attempt 2787 0 2787 0 [(2832, 1), (2816, 3)] 0, attempt 2788 0 2788 0 [(2833, 1), (2816, 3)] 0, attempt 2789 0 2789 0 [(2834, 1), (2816, 3)] 0, attempt 2790 0 2790 0 [(2835, 1), (2816, 3)] 0, attempt 2791 0 2791 0 [(2836, 1), (2816, 3)] 0, attempt 2792 0 2792 0 [(2837, 1), (2816, 3)] 0, attempt 2793 0 2793 0 [(2838, 1), (2816, 3)] 0, attempt 2794 0 2794 0 [(2839, 1), (2816, 3)] 0, attempt 2795 0 2795 0 [(2840, 1), (2816, 3)] 0, attempt 2796 0 2796 0 [(2841, 1), (2816, 3)] 0, attempt 2797 0 2797 0 [(2842, 1), (2816, 3)] 0, attempt 2798 0 2798 0 [(2843, 1), (2816, 3)] 0, attempt 2799 0 2799 0 [(2844, 1), (2816, 3)] 0, attempt 2800 0 2800 0 [(2845, 1), (2816, 3)] 0, attempt 2801 0 2801 0 [(2846, 1), (2816, 3)] 0, attempt 2802 0 2802 0 [(2847, 1), (2816, 3)] 0, attempt 2803 0 2803 0 [(2848, 1), (2816, 3)] 0, attempt 2804 0 2804 0 [(2849, 1), (2816, 3)] 0, attempt 2805 0 2805 0 [(2850, 1), (2816, 3)] 0, attempt 2806 0 2806 0 [(2851, 1), (2816, 3)] 0, attempt 2807 0 2807 0 [(2852, 1), (2816, 3)] 0, attempt 2808 0 2808 0 [(2853, 1), (2816, 3)] 0, attempt 2809 0 2809 0 [(2854, 1), (2816, 3)] 0, attempt 2810 0 2810 0 [(2855, 1), (2816, 3)] 0, attempt 2811 0 2811 0 [(2856, 1), (2816, 3)] 0, attempt 2812 0 2812 0 [(2857, 1), (2816, 3)] 0, attempt 2813 0 2813 0 [(2858, 1), (2816, 3)] 0, attempt 2814 0 2814 0 [(2859, 1), (2816, 3)] 0, attempt 2815 0 2815 0 [(2860, 1), (2816, 3)] 0]
def counters008 : List Nat := [2816, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2784
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 2816 0 2816 0 [(2861, 1), (2816, 3)] 0, attempt 2817 0 2817 0 [(2862, 1), (2816, 3)] 0, attempt 2818 0 2818 0 [(2863, 1), (2816, 3)] 0, attempt 2819 0 2819 0 [(2864, 1), (2816, 3)] 0, attempt 2820 0 2820 0 [(2865, 1), (2816, 3)] 0, attempt 2821 0 2821 0 [(2866, 1), (2816, 3)] 0, attempt 2822 0 2822 0 [(2867, 1), (2816, 3)] 0, attempt 2823 0 2823 0 [(2868, 1), (2816, 3)] 0, attempt 2824 0 2824 0 [(2869, 1), (2816, 3)] 0, attempt 2825 0 2825 0 [(2870, 1), (2816, 3)] 0, attempt 2826 0 2826 0 [(2871, 1), (2816, 3)] 0, attempt 2827 0 2827 0 [(2872, 1), (2816, 3)] 0, attempt 2828 0 2828 0 [(2873, 1), (2816, 3)] 0, attempt 2829 0 2829 0 [(2874, 1), (2816, 3)] 0, attempt 2830 0 2830 0 [(2875, 1), (2816, 3)] 0, attempt 2831 0 2831 0 [(2876, 1), (2816, 3)] 0, attempt 2832 0 2832 0 [(2877, 1), (2816, 3)] 0, attempt 2833 0 2833 0 [(2878, 1), (2816, 3)] 0, attempt 2834 0 2834 0 [(2879, 1), (2816, 3)] 0, attempt 2835 0 2835 0 [(2881, 1), (2880, 3)] 0, attempt 2836 0 2836 0 [(2882, 1), (2880, 3)] 0, attempt 2837 0 2837 0 [(2883, 1), (2880, 3)] 0, attempt 2838 0 2838 0 [(2884, 1), (2880, 3)] 0, attempt 2839 0 2839 0 [(2885, 1), (2880, 3)] 0, attempt 2840 0 2840 0 [(2886, 1), (2880, 3)] 0, attempt 2841 0 2841 0 [(2887, 1), (2880, 3)] 0, attempt 2842 0 2842 0 [(2888, 1), (2880, 3)] 0, attempt 2843 0 2843 0 [(2889, 1), (2880, 3)] 0, attempt 2844 0 2844 0 [(2890, 1), (2880, 3)] 0, attempt 2845 0 2845 0 [(2891, 1), (2880, 3)] 0, attempt 2846 0 2846 0 [(2892, 1), (2880, 3)] 0, attempt 2847 0 2847 0 [(2893, 1), (2880, 3)] 0]
def counters009 : List Nat := [2848, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2816
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 2848 0 2848 0 [(2894, 1), (2880, 3)] 0, attempt 2849 0 2849 0 [(2895, 1), (2880, 3)] 0, attempt 2850 0 2850 0 [(2896, 1), (2880, 3)] 0, attempt 2851 0 2851 0 [(2897, 1), (2880, 3)] 0, attempt 2852 0 2852 0 [(2898, 1), (2880, 3)] 0, attempt 2853 0 2853 0 [(2899, 1), (2880, 3)] 0, attempt 2854 0 2854 0 [(2900, 1), (2880, 3)] 0, attempt 2855 0 2855 0 [(2901, 1), (2880, 3)] 0, attempt 2856 0 2856 0 [(2902, 1), (2880, 3)] 0, attempt 2857 0 2857 0 [(2903, 1), (2880, 3)] 0, attempt 2858 0 2858 0 [(2904, 1), (2880, 3)] 0, attempt 2859 0 2859 0 [(2905, 1), (2880, 3)] 0, attempt 2860 0 2860 0 [(2906, 1), (2880, 3)] 0, attempt 2861 0 2861 0 [(2907, 1), (2880, 3)] 0, attempt 2862 0 2862 0 [(2908, 1), (2880, 3)] 0, attempt 2863 0 2863 0 [(2909, 1), (2880, 3)] 0, attempt 2864 0 2864 0 [(2910, 1), (2880, 3)] 0, attempt 2865 0 2865 0 [(2911, 1), (2880, 3)] 0, attempt 2866 0 2866 0 [(2912, 1), (2880, 3)] 0, attempt 2867 0 2867 0 [(2913, 1), (2880, 3)] 0, attempt 2868 0 2868 0 [(2914, 1), (2880, 3)] 0, attempt 2869 0 2869 0 [(2915, 1), (2880, 3)] 0, attempt 2870 0 2870 0 [(2916, 1), (2880, 3)] 0, attempt 2871 0 2871 0 [(2917, 1), (2880, 3)] 0, attempt 2872 0 2872 0 [(2918, 1), (2880, 3)] 0, attempt 2873 0 2873 0 [(2919, 1), (2880, 3)] 0, attempt 2874 0 2874 0 [(2920, 1), (2880, 3)] 0, attempt 2875 0 2875 0 [(2921, 1), (2880, 3)] 0, attempt 2876 0 2876 0 [(2922, 1), (2880, 3)] 0, attempt 2877 0 2877 0 [(2923, 1), (2880, 3)] 0, attempt 2878 0 2878 0 [(2924, 1), (2880, 3)] 0, attempt 2879 0 2879 0 [(2925, 1), (2880, 3)] 0]
def counters010 : List Nat := [2880, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2848
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 2880 0 2880 0 [(2926, 1), (2880, 3)] 0, attempt 2881 0 2881 0 [(2927, 1), (2880, 3)] 0, attempt 2882 0 2882 0 [(2928, 1), (2880, 3)] 0, attempt 2883 0 2883 0 [(2929, 1), (2880, 3)] 0, attempt 2884 0 2884 0 [(2930, 1), (2880, 3)] 0, attempt 2885 0 2885 0 [(2931, 1), (2880, 3)] 0, attempt 2886 0 2886 0 [(2932, 1), (2880, 3)] 0, attempt 2887 0 2887 0 [(2933, 1), (2880, 3)] 0, attempt 2888 0 2888 0 [(2934, 1), (2880, 3)] 0, attempt 2889 0 2889 0 [(2935, 1), (2880, 3)] 0, attempt 2890 0 2890 0 [(2936, 1), (2880, 3)] 0, attempt 2891 0 2891 0 [(2937, 1), (2880, 3)] 0, attempt 2892 0 2892 0 [(2938, 1), (2880, 3)] 0, attempt 2893 0 2893 0 [(2939, 1), (2880, 3)] 0, attempt 2894 0 2894 0 [(2940, 1), (2880, 3)] 0, attempt 2895 0 2895 0 [(2941, 1), (2880, 3)] 0, attempt 2896 0 2896 0 [(2942, 1), (2880, 3)] 0, attempt 2897 0 2897 0 [(2943, 1), (2880, 3)] 0, attempt 2898 0 2898 0 [(2945, 1), (2944, 3)] 0, attempt 2899 0 2899 0 [(2946, 1), (2944, 3)] 0, attempt 2900 0 2900 0 [(2947, 1), (2944, 3)] 0, attempt 2901 0 2901 0 [(2948, 1), (2944, 3)] 0, attempt 2902 0 2902 0 [(2949, 1), (2944, 3)] 0, attempt 2903 0 2903 0 [(2950, 1), (2944, 3)] 0, attempt 2904 0 2904 0 [(2951, 1), (2944, 3)] 0, attempt 2905 0 2905 0 [(2952, 1), (2944, 3)] 0, attempt 2906 0 2906 0 [(2953, 1), (2944, 3)] 0, attempt 2907 0 2907 0 [(2954, 1), (2944, 3)] 0, attempt 2908 0 2908 0 [(2955, 1), (2944, 3)] 0, attempt 2909 0 2909 0 [(2956, 1), (2944, 3)] 0, attempt 2910 0 2910 0 [(2957, 1), (2944, 3)] 0, attempt 2911 0 2911 0 [(2958, 1), (2944, 3)] 0]
def counters011 : List Nat := [2912, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2880
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 2912 0 2912 0 [(2959, 1), (2944, 3)] 0, attempt 2913 0 2913 0 [(2960, 1), (2944, 3)] 0, attempt 2914 0 2914 0 [(2961, 1), (2944, 3)] 0, attempt 2915 0 2915 0 [(2962, 1), (2944, 3)] 0, attempt 2916 0 2916 0 [(2963, 1), (2944, 3)] 0, attempt 2917 0 2917 0 [(2964, 1), (2944, 3)] 0, attempt 2918 0 2918 0 [(2965, 1), (2944, 3)] 0, attempt 2919 0 2919 0 [(2966, 1), (2944, 3)] 0, attempt 2920 0 2920 0 [(2967, 1), (2944, 3)] 0, attempt 2921 0 2921 0 [(2968, 1), (2944, 3)] 0, attempt 2922 0 2922 0 [(2969, 1), (2944, 3)] 0, attempt 2923 0 2923 0 [(2970, 1), (2944, 3)] 0, attempt 2924 0 2924 0 [(2971, 1), (2944, 3)] 0, attempt 2925 0 2925 0 [(2972, 1), (2944, 3)] 0, attempt 2926 0 2926 0 [(2973, 1), (2944, 3)] 0, attempt 2927 0 2927 0 [(2974, 1), (2944, 3)] 0, attempt 2928 0 2928 0 [(2975, 1), (2944, 3)] 0, attempt 2929 0 2929 0 [(2976, 1), (2944, 3)] 0, attempt 2930 0 2930 0 [(2977, 1), (2944, 3)] 0, attempt 2931 0 2931 0 [(2978, 1), (2944, 3)] 0, attempt 2932 0 2932 0 [(2979, 1), (2944, 3)] 0, attempt 2933 0 2933 0 [(2980, 1), (2944, 3)] 0, attempt 2934 0 2934 0 [(2981, 1), (2944, 3)] 0, attempt 2935 0 2935 0 [(2982, 1), (2944, 3)] 0, attempt 2936 0 2936 0 [(2983, 1), (2944, 3)] 0, attempt 2937 0 2937 0 [(2984, 1), (2944, 3)] 0, attempt 2938 0 2938 0 [(2985, 1), (2944, 3)] 0, attempt 2939 0 2939 0 [(2986, 1), (2944, 3)] 0, attempt 2940 0 2940 0 [(2987, 1), (2944, 3)] 0, attempt 2941 0 2941 0 [(2988, 1), (2944, 3)] 0, attempt 2942 0 2942 0 [(2989, 1), (2944, 3)] 0, attempt 2943 0 2943 0 [(2990, 1), (2944, 3)] 0]
def counters012 : List Nat := [2944, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2912
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 2944 0 2944 0 [(2991, 1), (2944, 3)] 0, attempt 2945 0 2945 0 [(2992, 1), (2944, 3)] 0, attempt 2946 0 2946 0 [(2993, 1), (2944, 3)] 0, attempt 2947 0 2947 0 [(2994, 1), (2944, 3)] 0, attempt 2948 0 2948 0 [(2995, 1), (2944, 3)] 0, attempt 2949 0 2949 0 [(2996, 1), (2944, 3)] 0, attempt 2950 0 2950 0 [(2997, 1), (2944, 3)] 0, attempt 2951 0 2951 0 [(2998, 1), (2944, 3)] 0, attempt 2952 0 2952 0 [(2999, 1), (2944, 3)] 0, attempt 2953 0 2953 0 [(3000, 1), (2944, 3)] 0, attempt 2954 0 2954 0 [(3001, 1), (2944, 3)] 0, attempt 2955 0 2955 0 [(3002, 1), (2944, 3)] 0, attempt 2956 0 2956 0 [(3003, 1), (2944, 3)] 0, attempt 2957 0 2957 0 [(3004, 1), (2944, 3)] 0, attempt 2958 0 2958 0 [(3005, 1), (2944, 3)] 0, attempt 2959 0 2959 0 [(3006, 1), (2944, 3)] 0, attempt 2960 0 2960 0 [(3007, 1), (2944, 3)] 0, attempt 2961 0 2961 0 [(3009, 1), (3008, 3)] 0, attempt 2962 0 2962 0 [(3010, 1), (3008, 3)] 0, attempt 2963 0 2963 0 [(3011, 1), (3008, 3)] 0, attempt 2964 0 2964 0 [(3012, 1), (3008, 3)] 0, attempt 2965 0 2965 0 [(3013, 1), (3008, 3)] 0, attempt 2966 0 2966 0 [(3014, 1), (3008, 3)] 0, attempt 2967 0 2967 0 [(3015, 1), (3008, 3)] 0, attempt 2968 0 2968 0 [(3016, 1), (3008, 3)] 0, attempt 2969 0 2969 0 [(3017, 1), (3008, 3)] 0, attempt 2970 0 2970 0 [(3018, 1), (3008, 3)] 0, attempt 2971 0 2971 0 [(3019, 1), (3008, 3)] 0, attempt 2972 0 2972 0 [(3020, 1), (3008, 3)] 0, attempt 2973 0 2973 0 [(3021, 1), (3008, 3)] 0, attempt 2974 0 2974 0 [(3022, 1), (3008, 3)] 0, attempt 2975 0 2975 0 [(3023, 1), (3008, 3)] 0]
def counters013 : List Nat := [2976, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2944
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 2976 0 2976 0 [(3024, 1), (3008, 3)] 0, attempt 2977 0 2977 0 [(3025, 1), (3008, 3)] 0, attempt 2978 0 2978 0 [(3026, 1), (3008, 3)] 0, attempt 2979 0 2979 0 [(3027, 1), (3008, 3)] 0, attempt 2980 0 2980 0 [(3028, 1), (3008, 3)] 0, attempt 2981 0 2981 0 [(3029, 1), (3008, 3)] 0, attempt 2982 0 2982 0 [(3030, 1), (3008, 3)] 0, attempt 2983 0 2983 0 [(3031, 1), (3008, 3)] 0, attempt 2984 0 2984 0 [(3032, 1), (3008, 3)] 0, attempt 2985 0 2985 0 [(3033, 1), (3008, 3)] 0, attempt 2986 0 2986 0 [(3034, 1), (3008, 3)] 0, attempt 2987 0 2987 0 [(3035, 1), (3008, 3)] 0, attempt 2988 0 2988 0 [(3036, 1), (3008, 3)] 0, attempt 2989 0 2989 0 [(3037, 1), (3008, 3)] 0, attempt 2990 0 2990 0 [(3038, 1), (3008, 3)] 0, attempt 2991 0 2991 0 [(3039, 1), (3008, 3)] 0, attempt 2992 0 2992 0 [(3040, 1), (3008, 3)] 0, attempt 2993 0 2993 0 [(3041, 1), (3008, 3)] 0, attempt 2994 0 2994 0 [(3042, 1), (3008, 3)] 0, attempt 2995 0 2995 0 [(3043, 1), (3008, 3)] 0, attempt 2996 0 2996 0 [(3044, 1), (3008, 3)] 0, attempt 2997 0 2997 0 [(3045, 1), (3008, 3)] 0, attempt 2998 0 2998 0 [(3046, 1), (3008, 3)] 0, attempt 2999 0 2999 0 [(3047, 1), (3008, 3)] 0, attempt 3000 0 3000 0 [(3048, 1), (3008, 3)] 0, attempt 3001 0 3001 0 [(3049, 1), (3008, 3)] 0, attempt 3002 0 3002 0 [(3050, 1), (3008, 3)] 0, attempt 3003 0 3003 0 [(3051, 1), (3008, 3)] 0, attempt 3004 0 3004 0 [(3052, 1), (3008, 3)] 0, attempt 3005 0 3005 0 [(3053, 1), (3008, 3)] 0, attempt 3006 0 3006 0 [(3054, 1), (3008, 3)] 0, attempt 3007 0 3007 0 [(3055, 1), (3008, 3)] 0]
def counters014 : List Nat := [3008, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2976
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 3008 0 3008 0 [(3056, 1), (3008, 3)] 0, attempt 3009 0 3009 0 [(3057, 1), (3008, 3)] 0, attempt 3010 0 3010 0 [(3058, 1), (3008, 3)] 0, attempt 3011 0 3011 0 [(3059, 1), (3008, 3)] 0, attempt 3012 0 3012 0 [(3060, 1), (3008, 3)] 0, attempt 3013 0 3013 0 [(3061, 1), (3008, 3)] 0, attempt 3014 0 3014 0 [(3062, 1), (3008, 3)] 0, attempt 3015 0 3015 0 [(3063, 1), (3008, 3)] 0, attempt 3016 0 3016 0 [(3064, 1), (3008, 3)] 0, attempt 3017 0 3017 0 [(3065, 1), (3008, 3)] 0, attempt 3018 0 3018 0 [(3066, 1), (3008, 3)] 0, attempt 3019 0 3019 0 [(3067, 1), (3008, 3)] 0, attempt 3020 0 3020 0 [(3068, 1), (3008, 3)] 0, attempt 3021 0 3021 0 [(3069, 1), (3008, 3)] 0, attempt 3022 0 3022 0 [(3070, 1), (3008, 3)] 0, attempt 3023 0 3023 0 [(3071, 1), (3008, 3)] 0, attempt 3024 0 3024 0 [(3073, 1), (3072, 3)] 0, attempt 3025 0 3025 0 [(3074, 1), (3072, 3)] 0, attempt 3026 0 3026 0 [(3075, 1), (3072, 3)] 0, attempt 3027 0 3027 0 [(3076, 1), (3072, 3)] 0, attempt 3028 0 3028 0 [(3077, 1), (3072, 3)] 0, attempt 3029 0 3029 0 [(3078, 1), (3072, 3)] 0, attempt 3030 0 3030 0 [(3079, 1), (3072, 3)] 0, attempt 3031 0 3031 0 [(3080, 1), (3072, 3)] 0, attempt 3032 0 3032 0 [(3081, 1), (3072, 3)] 0, attempt 3033 0 3033 0 [(3082, 1), (3072, 3)] 0, attempt 3034 0 3034 0 [(3083, 1), (3072, 3)] 0, attempt 3035 0 3035 0 [(3084, 1), (3072, 3)] 0, attempt 3036 0 3036 0 [(3085, 1), (3072, 3)] 0, attempt 3037 0 3037 0 [(3086, 1), (3072, 3)] 0, attempt 3038 0 3038 0 [(3087, 1), (3072, 3)] 0, attempt 3039 0 3039 0 [(3088, 1), (3072, 3)] 0]
def counters015 : List Nat := [3040, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3008
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 3040 0 3040 0 [(3089, 1), (3072, 3)] 0, attempt 3041 0 3041 0 [(3090, 1), (3072, 3)] 0, attempt 3042 0 3042 0 [(3091, 1), (3072, 3)] 0, attempt 3043 0 3043 0 [(3092, 1), (3072, 3)] 0, attempt 3044 0 3044 0 [(3093, 1), (3072, 3)] 0, attempt 3045 0 3045 0 [(3094, 1), (3072, 3)] 0, attempt 3046 0 3046 0 [(3095, 1), (3072, 3)] 0, attempt 3047 0 3047 0 [(3096, 1), (3072, 3)] 0, attempt 3048 0 3048 0 [(3097, 1), (3072, 3)] 0, attempt 3049 0 3049 0 [(3098, 1), (3072, 3)] 0, attempt 3050 0 3050 0 [(3099, 1), (3072, 3)] 0, attempt 3051 0 3051 0 [(3100, 1), (3072, 3)] 0, attempt 3052 0 3052 0 [(3101, 1), (3072, 3)] 0, attempt 3053 0 3053 0 [(3102, 1), (3072, 3)] 0, attempt 3054 0 3054 0 [(3103, 1), (3072, 3)] 0, attempt 3055 0 3055 0 [(3104, 1), (3072, 3)] 0, attempt 3056 0 3056 0 [(3105, 1), (3072, 3)] 0, attempt 3057 0 3057 0 [(3106, 1), (3072, 3)] 0, attempt 3058 0 3058 0 [(3107, 1), (3072, 3)] 0, attempt 3059 0 3059 0 [(3108, 1), (3072, 3)] 0, attempt 3060 0 3060 0 [(3109, 1), (3072, 3)] 0, attempt 3061 0 3061 0 [(3110, 1), (3072, 3)] 0, attempt 3062 0 3062 0 [(3111, 1), (3072, 3)] 0, attempt 3063 0 3063 0 [(3112, 1), (3072, 3)] 0, attempt 3064 0 3064 0 [(3113, 1), (3072, 3)] 0, attempt 3065 0 3065 0 [(3114, 1), (3072, 3)] 0, attempt 3066 0 3066 0 [(3115, 1), (3072, 3)] 0, attempt 3067 0 3067 0 [(3116, 1), (3072, 3)] 0, attempt 3068 0 3068 0 [(3117, 1), (3072, 3)] 0, attempt 3069 0 3069 0 [(3118, 1), (3072, 3)] 0, attempt 3070 0 3070 0 [(3119, 1), (3072, 3)] 0, attempt 3071 0 3071 0 [(3120, 1), (3072, 3)] 0]
def counters016 : List Nat := [3072, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3040
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3072
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3040
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 3040 3072 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 3040) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3008
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 3008 3040 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 3008) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2976
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 2976 3008 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 2976) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2944
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 2944 2976 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 2944) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2912
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 2912 2944 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 2912) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2880
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 2880 2912 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 2880) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2848
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 2848 2880 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 2848) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2816
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 2816 2848 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 2816) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2784
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 2784 2816 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 2784) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2752
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 2752 2784 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 2752) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2720
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 2720 2752 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 2720) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2688
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 2688 2720 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 2688) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2656
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 2656 2688 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 2656) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2624
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 2624 2656 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 2624) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2592
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 2592 2624 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 2592) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2560
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 2560 2592 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 2560) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr05
