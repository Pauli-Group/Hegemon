import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr06

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr07
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [3584, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 3584 0 3584 0 [(3641, 1), (3584, 3)] 0, attempt 3585 0 3585 0 [(3642, 1), (3584, 3)] 0, attempt 3586 0 3586 0 [(3643, 1), (3584, 3)] 0, attempt 3587 0 3587 0 [(3644, 1), (3584, 3)] 0, attempt 3588 0 3588 0 [(3645, 1), (3584, 3)] 0, attempt 3589 0 3589 0 [(3646, 1), (3584, 3)] 0, attempt 3590 0 3590 0 [(3647, 1), (3584, 3)] 0, attempt 3591 0 3591 0 [(3649, 1), (3648, 3)] 0, attempt 3592 0 3592 0 [(3650, 1), (3648, 3)] 0, attempt 3593 0 3593 0 [(3651, 1), (3648, 3)] 0, attempt 3594 0 3594 0 [(3652, 1), (3648, 3)] 0, attempt 3595 0 3595 0 [(3653, 1), (3648, 3)] 0, attempt 3596 0 3596 0 [(3654, 1), (3648, 3)] 0, attempt 3597 0 3597 0 [(3655, 1), (3648, 3)] 0, attempt 3598 0 3598 0 [(3656, 1), (3648, 3)] 0, attempt 3599 0 3599 0 [(3657, 1), (3648, 3)] 0, attempt 3600 0 3600 0 [(3658, 1), (3648, 3)] 0, attempt 3601 0 3601 0 [(3659, 1), (3648, 3)] 0, attempt 3602 0 3602 0 [(3660, 1), (3648, 3)] 0, attempt 3603 0 3603 0 [(3661, 1), (3648, 3)] 0, attempt 3604 0 3604 0 [(3662, 1), (3648, 3)] 0, attempt 3605 0 3605 0 [(3663, 1), (3648, 3)] 0, attempt 3606 0 3606 0 [(3664, 1), (3648, 3)] 0, attempt 3607 0 3607 0 [(3665, 1), (3648, 3)] 0, attempt 3608 0 3608 0 [(3666, 1), (3648, 3)] 0, attempt 3609 0 3609 0 [(3667, 1), (3648, 3)] 0, attempt 3610 0 3610 0 [(3668, 1), (3648, 3)] 0, attempt 3611 0 3611 0 [(3669, 1), (3648, 3)] 0, attempt 3612 0 3612 0 [(3670, 1), (3648, 3)] 0, attempt 3613 0 3613 0 [(3671, 1), (3648, 3)] 0, attempt 3614 0 3614 0 [(3672, 1), (3648, 3)] 0, attempt 3615 0 3615 0 [(3673, 1), (3648, 3)] 0]
def counters001 : List Nat := [3616, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3584
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 3616 0 3616 0 [(3674, 1), (3648, 3)] 0, attempt 3617 0 3617 0 [(3675, 1), (3648, 3)] 0, attempt 3618 0 3618 0 [(3676, 1), (3648, 3)] 0, attempt 3619 0 3619 0 [(3677, 1), (3648, 3)] 0, attempt 3620 0 3620 0 [(3678, 1), (3648, 3)] 0, attempt 3621 0 3621 0 [(3679, 1), (3648, 3)] 0, attempt 3622 0 3622 0 [(3680, 1), (3648, 3)] 0, attempt 3623 0 3623 0 [(3681, 1), (3648, 3)] 0, attempt 3624 0 3624 0 [(3682, 1), (3648, 3)] 0, attempt 3625 0 3625 0 [(3683, 1), (3648, 3)] 0, attempt 3626 0 3626 0 [(3684, 1), (3648, 3)] 0, attempt 3627 0 3627 0 [(3685, 1), (3648, 3)] 0, attempt 3628 0 3628 0 [(3686, 1), (3648, 3)] 0, attempt 3629 0 3629 0 [(3687, 1), (3648, 3)] 0, attempt 3630 0 3630 0 [(3688, 1), (3648, 3)] 0, attempt 3631 0 3631 0 [(3689, 1), (3648, 3)] 0, attempt 3632 0 3632 0 [(3690, 1), (3648, 3)] 0, attempt 3633 0 3633 0 [(3691, 1), (3648, 3)] 0, attempt 3634 0 3634 0 [(3692, 1), (3648, 3)] 0, attempt 3635 0 3635 0 [(3693, 1), (3648, 3)] 0, attempt 3636 0 3636 0 [(3694, 1), (3648, 3)] 0, attempt 3637 0 3637 0 [(3695, 1), (3648, 3)] 0, attempt 3638 0 3638 0 [(3696, 1), (3648, 3)] 0, attempt 3639 0 3639 0 [(3697, 1), (3648, 3)] 0, attempt 3640 0 3640 0 [(3698, 1), (3648, 3)] 0, attempt 3641 0 3641 0 [(3699, 1), (3648, 3)] 0, attempt 3642 0 3642 0 [(3700, 1), (3648, 3)] 0, attempt 3643 0 3643 0 [(3701, 1), (3648, 3)] 0, attempt 3644 0 3644 0 [(3702, 1), (3648, 3)] 0, attempt 3645 0 3645 0 [(3703, 1), (3648, 3)] 0, attempt 3646 0 3646 0 [(3704, 1), (3648, 3)] 0, attempt 3647 0 3647 0 [(3705, 1), (3648, 3)] 0]
def counters002 : List Nat := [3648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3616
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 3648 0 3648 0 [(3706, 1), (3648, 3)] 0, attempt 3649 0 3649 0 [(3707, 1), (3648, 3)] 0, attempt 3650 0 3650 0 [(3708, 1), (3648, 3)] 0, attempt 3651 0 3651 0 [(3709, 1), (3648, 3)] 0, attempt 3652 0 3652 0 [(3710, 1), (3648, 3)] 0, attempt 3653 0 3653 0 [(3711, 1), (3648, 3)] 0, attempt 3654 0 3654 0 [(3713, 1), (3712, 3)] 0, attempt 3655 0 3655 0 [(3714, 1), (3712, 3)] 0, attempt 3656 0 3656 0 [(3715, 1), (3712, 3)] 0, attempt 3657 0 3657 0 [(3716, 1), (3712, 3)] 0, attempt 3658 0 3658 0 [(3717, 1), (3712, 3)] 0, attempt 3659 0 3659 0 [(3718, 1), (3712, 3)] 0, attempt 3660 0 3660 0 [(3719, 1), (3712, 3)] 0, attempt 3661 0 3661 0 [(3720, 1), (3712, 3)] 0, attempt 3662 0 3662 0 [(3721, 1), (3712, 3)] 0, attempt 3663 0 3663 0 [(3722, 1), (3712, 3)] 0, attempt 3664 0 3664 0 [(3723, 1), (3712, 3)] 0, attempt 3665 0 3665 0 [(3724, 1), (3712, 3)] 0, attempt 3666 0 3666 0 [(3725, 1), (3712, 3)] 0, attempt 3667 0 3667 0 [(3726, 1), (3712, 3)] 0, attempt 3668 0 3668 0 [(3727, 1), (3712, 3)] 0, attempt 3669 0 3669 0 [(3728, 1), (3712, 3)] 0, attempt 3670 0 3670 0 [(3729, 1), (3712, 3)] 0, attempt 3671 0 3671 0 [(3730, 1), (3712, 3)] 0, attempt 3672 0 3672 0 [(3731, 1), (3712, 3)] 0, attempt 3673 0 3673 0 [(3732, 1), (3712, 3)] 0, attempt 3674 0 3674 0 [(3733, 1), (3712, 3)] 0, attempt 3675 0 3675 0 [(3734, 1), (3712, 3)] 0, attempt 3676 0 3676 0 [(3735, 1), (3712, 3)] 0, attempt 3677 0 3677 0 [(3736, 1), (3712, 3)] 0, attempt 3678 0 3678 0 [(3737, 1), (3712, 3)] 0, attempt 3679 0 3679 0 [(3738, 1), (3712, 3)] 0]
def counters003 : List Nat := [3680, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3648
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 3680 0 3680 0 [(3739, 1), (3712, 3)] 0, attempt 3681 0 3681 0 [(3740, 1), (3712, 3)] 0, attempt 3682 0 3682 0 [(3741, 1), (3712, 3)] 0, attempt 3683 0 3683 0 [(3742, 1), (3712, 3)] 0, attempt 3684 0 3684 0 [(3743, 1), (3712, 3)] 0, attempt 3685 0 3685 0 [(3744, 1), (3712, 3)] 0, attempt 3686 0 3686 0 [(3745, 1), (3712, 3)] 0, attempt 3687 0 3687 0 [(3746, 1), (3712, 3)] 0, attempt 3688 0 3688 0 [(3747, 1), (3712, 3)] 0, attempt 3689 0 3689 0 [(3748, 1), (3712, 3)] 0, attempt 3690 0 3690 0 [(3749, 1), (3712, 3)] 0, attempt 3691 0 3691 0 [(3750, 1), (3712, 3)] 0, attempt 3692 0 3692 0 [(3751, 1), (3712, 3)] 0, attempt 3693 0 3693 0 [(3752, 1), (3712, 3)] 0, attempt 3694 0 3694 0 [(3753, 1), (3712, 3)] 0, attempt 3695 0 3695 0 [(3754, 1), (3712, 3)] 0, attempt 3696 0 3696 0 [(3755, 1), (3712, 3)] 0, attempt 3697 0 3697 0 [(3756, 1), (3712, 3)] 0, attempt 3698 0 3698 0 [(3757, 1), (3712, 3)] 0, attempt 3699 0 3699 0 [(3758, 1), (3712, 3)] 0, attempt 3700 0 3700 0 [(3759, 1), (3712, 3)] 0, attempt 3701 0 3701 0 [(3760, 1), (3712, 3)] 0, attempt 3702 0 3702 0 [(3761, 1), (3712, 3)] 0, attempt 3703 0 3703 0 [(3762, 1), (3712, 3)] 0, attempt 3704 0 3704 0 [(3763, 1), (3712, 3)] 0, attempt 3705 0 3705 0 [(3764, 1), (3712, 3)] 0, attempt 3706 0 3706 0 [(3765, 1), (3712, 3)] 0, attempt 3707 0 3707 0 [(3766, 1), (3712, 3)] 0, attempt 3708 0 3708 0 [(3767, 1), (3712, 3)] 0, attempt 3709 0 3709 0 [(3768, 1), (3712, 3)] 0, attempt 3710 0 3710 0 [(3769, 1), (3712, 3)] 0, attempt 3711 0 3711 0 [(3770, 1), (3712, 3)] 0]
def counters004 : List Nat := [3712, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3680
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 3712 0 3712 0 [(3771, 1), (3712, 3)] 0, attempt 3713 0 3713 0 [(3772, 1), (3712, 3)] 0, attempt 3714 0 3714 0 [(3773, 1), (3712, 3)] 0, attempt 3715 0 3715 0 [(3774, 1), (3712, 3)] 0, attempt 3716 0 3716 0 [(3775, 1), (3712, 3)] 0, attempt 3717 0 3717 0 [(3777, 1), (3776, 3)] 0, attempt 3718 0 3718 0 [(3778, 1), (3776, 3)] 0, attempt 3719 0 3719 0 [(3779, 1), (3776, 3)] 0, attempt 3720 0 3720 0 [(3780, 1), (3776, 3)] 0, attempt 3721 0 3721 0 [(3781, 1), (3776, 3)] 0, attempt 3722 0 3722 0 [(3782, 1), (3776, 3)] 0, attempt 3723 0 3723 0 [(3783, 1), (3776, 3)] 0, attempt 3724 0 3724 0 [(3784, 1), (3776, 3)] 0, attempt 3725 0 3725 0 [(3785, 1), (3776, 3)] 0, attempt 3726 0 3726 0 [(3786, 1), (3776, 3)] 0, attempt 3727 0 3727 0 [(3787, 1), (3776, 3)] 0, attempt 3728 0 3728 0 [(3788, 1), (3776, 3)] 0, attempt 3729 0 3729 0 [(3789, 1), (3776, 3)] 0, attempt 3730 0 3730 0 [(3790, 1), (3776, 3)] 0, attempt 3731 0 3731 0 [(3791, 1), (3776, 3)] 0, attempt 3732 0 3732 0 [(3792, 1), (3776, 3)] 0, attempt 3733 0 3733 0 [(3793, 1), (3776, 3)] 0, attempt 3734 0 3734 0 [(3794, 1), (3776, 3)] 0, attempt 3735 0 3735 0 [(3795, 1), (3776, 3)] 0, attempt 3736 0 3736 0 [(3796, 1), (3776, 3)] 0, attempt 3737 0 3737 0 [(3797, 1), (3776, 3)] 0, attempt 3738 0 3738 0 [(3798, 1), (3776, 3)] 0, attempt 3739 0 3739 0 [(3799, 1), (3776, 3)] 0, attempt 3740 0 3740 0 [(3800, 1), (3776, 3)] 0, attempt 3741 0 3741 0 [(3801, 1), (3776, 3)] 0, attempt 3742 0 3742 0 [(3802, 1), (3776, 3)] 0, attempt 3743 0 3743 0 [(3803, 1), (3776, 3)] 0]
def counters005 : List Nat := [3744, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3712
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 3744 0 3744 0 [(3804, 1), (3776, 3)] 0, attempt 3745 0 3745 0 [(3805, 1), (3776, 3)] 0, attempt 3746 0 3746 0 [(3806, 1), (3776, 3)] 0, attempt 3747 0 3747 0 [(3807, 1), (3776, 3)] 0, attempt 3748 0 3748 0 [(3808, 1), (3776, 3)] 0, attempt 3749 0 3749 0 [(3809, 1), (3776, 3)] 0, attempt 3750 0 3750 0 [(3810, 1), (3776, 3)] 0, attempt 3751 0 3751 0 [(3811, 1), (3776, 3)] 0, attempt 3752 0 3752 0 [(3812, 1), (3776, 3)] 0, attempt 3753 0 3753 0 [(3813, 1), (3776, 3)] 0, attempt 3754 0 3754 0 [(3814, 1), (3776, 3)] 0, attempt 3755 0 3755 0 [(3815, 1), (3776, 3)] 0, attempt 3756 0 3756 0 [(3816, 1), (3776, 3)] 0, attempt 3757 0 3757 0 [(3817, 1), (3776, 3)] 0, attempt 3758 0 3758 0 [(3818, 1), (3776, 3)] 0, attempt 3759 0 3759 0 [(3819, 1), (3776, 3)] 0, attempt 3760 0 3760 0 [(3820, 1), (3776, 3)] 0, attempt 3761 0 3761 0 [(3821, 1), (3776, 3)] 0, attempt 3762 0 3762 0 [(3822, 1), (3776, 3)] 0, attempt 3763 0 3763 0 [(3823, 1), (3776, 3)] 0, attempt 3764 0 3764 0 [(3824, 1), (3776, 3)] 0, attempt 3765 0 3765 0 [(3825, 1), (3776, 3)] 0, attempt 3766 0 3766 0 [(3826, 1), (3776, 3)] 0, attempt 3767 0 3767 0 [(3827, 1), (3776, 3)] 0, attempt 3768 0 3768 0 [(3828, 1), (3776, 3)] 0, attempt 3769 0 3769 0 [(3829, 1), (3776, 3)] 0, attempt 3770 0 3770 0 [(3830, 1), (3776, 3)] 0, attempt 3771 0 3771 0 [(3831, 1), (3776, 3)] 0, attempt 3772 0 3772 0 [(3832, 1), (3776, 3)] 0, attempt 3773 0 3773 0 [(3833, 1), (3776, 3)] 0, attempt 3774 0 3774 0 [(3834, 1), (3776, 3)] 0, attempt 3775 0 3775 0 [(3835, 1), (3776, 3)] 0]
def counters006 : List Nat := [3776, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3744
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 3776 0 3776 0 [(3836, 1), (3776, 3)] 0, attempt 3777 0 3777 0 [(3837, 1), (3776, 3)] 0, attempt 3778 0 3778 0 [(3838, 1), (3776, 3)] 0, attempt 3779 0 3779 0 [(3839, 1), (3776, 3)] 0, attempt 3780 0 3780 0 [(3841, 1), (3840, 3)] 0, attempt 3781 0 3781 0 [(3842, 1), (3840, 3)] 0, attempt 3782 0 3782 0 [(3843, 1), (3840, 3)] 0, attempt 3783 0 3783 0 [(3844, 1), (3840, 3)] 0, attempt 3784 0 3784 0 [(3845, 1), (3840, 3)] 0, attempt 3785 0 3785 0 [(3846, 1), (3840, 3)] 0, attempt 3786 0 3786 0 [(3847, 1), (3840, 3)] 0, attempt 3787 0 3787 0 [(3848, 1), (3840, 3)] 0, attempt 3788 0 3788 0 [(3849, 1), (3840, 3)] 0, attempt 3789 0 3789 0 [(3850, 1), (3840, 3)] 0, attempt 3790 0 3790 0 [(3851, 1), (3840, 3)] 0, attempt 3791 0 3791 0 [(3852, 1), (3840, 3)] 0, attempt 3792 0 3792 0 [(3853, 1), (3840, 3)] 0, attempt 3793 0 3793 0 [(3854, 1), (3840, 3)] 0, attempt 3794 0 3794 0 [(3855, 1), (3840, 3)] 0, attempt 3795 0 3795 0 [(3856, 1), (3840, 3)] 0, attempt 3796 0 3796 0 [(3857, 1), (3840, 3)] 0, attempt 3797 0 3797 0 [(3858, 1), (3840, 3)] 0, attempt 3798 0 3798 0 [(3859, 1), (3840, 3)] 0, attempt 3799 0 3799 0 [(3860, 1), (3840, 3)] 0, attempt 3800 0 3800 0 [(3861, 1), (3840, 3)] 0, attempt 3801 0 3801 0 [(3862, 1), (3840, 3)] 0, attempt 3802 0 3802 0 [(3863, 1), (3840, 3)] 0, attempt 3803 0 3803 0 [(3864, 1), (3840, 3)] 0, attempt 3804 0 3804 0 [(3865, 1), (3840, 3)] 0, attempt 3805 0 3805 0 [(3866, 1), (3840, 3)] 0, attempt 3806 0 3806 0 [(3867, 1), (3840, 3)] 0, attempt 3807 0 3807 0 [(3868, 1), (3840, 3)] 0]
def counters007 : List Nat := [3808, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3776
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 3808 0 3808 0 [(3869, 1), (3840, 3)] 0, attempt 3809 0 3809 0 [(3870, 1), (3840, 3)] 0, attempt 3810 0 3810 0 [(3871, 1), (3840, 3)] 0, attempt 3811 0 3811 0 [(3872, 1), (3840, 3)] 0, attempt 3812 0 3812 0 [(3873, 1), (3840, 3)] 0, attempt 3813 0 3813 0 [(3874, 1), (3840, 3)] 0, attempt 3814 0 3814 0 [(3875, 1), (3840, 3)] 0, attempt 3815 0 3815 0 [(3876, 1), (3840, 3)] 0, attempt 3816 0 3816 0 [(3877, 1), (3840, 3)] 0, attempt 3817 0 3817 0 [(3878, 1), (3840, 3)] 0, attempt 3818 0 3818 0 [(3879, 1), (3840, 3)] 0, attempt 3819 0 3819 0 [(3880, 1), (3840, 3)] 0, attempt 3820 0 3820 0 [(3881, 1), (3840, 3)] 0, attempt 3821 0 3821 0 [(3882, 1), (3840, 3)] 0, attempt 3822 0 3822 0 [(3883, 1), (3840, 3)] 0, attempt 3823 0 3823 0 [(3884, 1), (3840, 3)] 0, attempt 3824 0 3824 0 [(3885, 1), (3840, 3)] 0, attempt 3825 0 3825 0 [(3886, 1), (3840, 3)] 0, attempt 3826 0 3826 0 [(3887, 1), (3840, 3)] 0, attempt 3827 0 3827 0 [(3888, 1), (3840, 3)] 0, attempt 3828 0 3828 0 [(3889, 1), (3840, 3)] 0, attempt 3829 0 3829 0 [(3890, 1), (3840, 3)] 0, attempt 3830 0 3830 0 [(3891, 1), (3840, 3)] 0, attempt 3831 0 3831 0 [(3892, 1), (3840, 3)] 0, attempt 3832 0 3832 0 [(3893, 1), (3840, 3)] 0, attempt 3833 0 3833 0 [(3894, 1), (3840, 3)] 0, attempt 3834 0 3834 0 [(3895, 1), (3840, 3)] 0, attempt 3835 0 3835 0 [(3896, 1), (3840, 3)] 0, attempt 3836 0 3836 0 [(3897, 1), (3840, 3)] 0, attempt 3837 0 3837 0 [(3898, 1), (3840, 3)] 0, attempt 3838 0 3838 0 [(3899, 1), (3840, 3)] 0, attempt 3839 0 3839 0 [(3900, 1), (3840, 3)] 0]
def counters008 : List Nat := [3840, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3808
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 3840 0 3840 0 [(3901, 1), (3840, 3)] 0, attempt 3841 0 3841 0 [(3902, 1), (3840, 3)] 0, attempt 3842 0 3842 0 [(3903, 1), (3840, 3)] 0, attempt 3843 0 3843 0 [(3905, 1), (3904, 3)] 0, attempt 3844 0 3844 0 [(3906, 1), (3904, 3)] 0, attempt 3845 0 3845 0 [(3907, 1), (3904, 3)] 0, attempt 3846 0 3846 0 [(3908, 1), (3904, 3)] 0, attempt 3847 0 3847 0 [(3909, 1), (3904, 3)] 0, attempt 3848 0 3848 0 [(3910, 1), (3904, 3)] 0, attempt 3849 0 3849 0 [(3911, 1), (3904, 3)] 0, attempt 3850 0 3850 0 [(3912, 1), (3904, 3)] 0, attempt 3851 0 3851 0 [(3913, 1), (3904, 3)] 0, attempt 3852 0 3852 0 [(3914, 1), (3904, 3)] 0, attempt 3853 0 3853 0 [(3915, 1), (3904, 3)] 0, attempt 3854 0 3854 0 [(3916, 1), (3904, 3)] 0, attempt 3855 0 3855 0 [(3917, 1), (3904, 3)] 0, attempt 3856 0 3856 0 [(3918, 1), (3904, 3)] 0, attempt 3857 0 3857 0 [(3919, 1), (3904, 3)] 0, attempt 3858 0 3858 0 [(3920, 1), (3904, 3)] 0, attempt 3859 0 3859 0 [(3921, 1), (3904, 3)] 0, attempt 3860 0 3860 0 [(3922, 1), (3904, 3)] 0, attempt 3861 0 3861 0 [(3923, 1), (3904, 3)] 0, attempt 3862 0 3862 0 [(3924, 1), (3904, 3)] 0, attempt 3863 0 3863 0 [(3925, 1), (3904, 3)] 0, attempt 3864 0 3864 0 [(3926, 1), (3904, 3)] 0, attempt 3865 0 3865 0 [(3927, 1), (3904, 3)] 0, attempt 3866 0 3866 0 [(3928, 1), (3904, 3)] 0, attempt 3867 0 3867 0 [(3929, 1), (3904, 3)] 0, attempt 3868 0 3868 0 [(3930, 1), (3904, 3)] 0, attempt 3869 0 3869 0 [(3931, 1), (3904, 3)] 0, attempt 3870 0 3870 0 [(3932, 1), (3904, 3)] 0, attempt 3871 0 3871 0 [(3933, 1), (3904, 3)] 0]
def counters009 : List Nat := [3872, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3840
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 3872 0 3872 0 [(3934, 1), (3904, 3)] 0, attempt 3873 0 3873 0 [(3935, 1), (3904, 3)] 0, attempt 3874 0 3874 0 [(3936, 1), (3904, 3)] 0, attempt 3875 0 3875 0 [(3937, 1), (3904, 3)] 0, attempt 3876 0 3876 0 [(3938, 1), (3904, 3)] 0, attempt 3877 0 3877 0 [(3939, 1), (3904, 3)] 0, attempt 3878 0 3878 0 [(3940, 1), (3904, 3)] 0, attempt 3879 0 3879 0 [(3941, 1), (3904, 3)] 0, attempt 3880 0 3880 0 [(3942, 1), (3904, 3)] 0, attempt 3881 0 3881 0 [(3943, 1), (3904, 3)] 0, attempt 3882 0 3882 0 [(3944, 1), (3904, 3)] 0, attempt 3883 0 3883 0 [(3945, 1), (3904, 3)] 0, attempt 3884 0 3884 0 [(3946, 1), (3904, 3)] 0, attempt 3885 0 3885 0 [(3947, 1), (3904, 3)] 0, attempt 3886 0 3886 0 [(3948, 1), (3904, 3)] 0, attempt 3887 0 3887 0 [(3949, 1), (3904, 3)] 0, attempt 3888 0 3888 0 [(3950, 1), (3904, 3)] 0, attempt 3889 0 3889 0 [(3951, 1), (3904, 3)] 0, attempt 3890 0 3890 0 [(3952, 1), (3904, 3)] 0, attempt 3891 0 3891 0 [(3953, 1), (3904, 3)] 0, attempt 3892 0 3892 0 [(3954, 1), (3904, 3)] 0, attempt 3893 0 3893 0 [(3955, 1), (3904, 3)] 0, attempt 3894 0 3894 0 [(3956, 1), (3904, 3)] 0, attempt 3895 0 3895 0 [(3957, 1), (3904, 3)] 0, attempt 3896 0 3896 0 [(3958, 1), (3904, 3)] 0, attempt 3897 0 3897 0 [(3959, 1), (3904, 3)] 0, attempt 3898 0 3898 0 [(3960, 1), (3904, 3)] 0, attempt 3899 0 3899 0 [(3961, 1), (3904, 3)] 0, attempt 3900 0 3900 0 [(3962, 1), (3904, 3)] 0, attempt 3901 0 3901 0 [(3963, 1), (3904, 3)] 0, attempt 3902 0 3902 0 [(3964, 1), (3904, 3)] 0, attempt 3903 0 3903 0 [(3965, 1), (3904, 3)] 0]
def counters010 : List Nat := [3904, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3872
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 3904 0 3904 0 [(3966, 1), (3904, 3)] 0, attempt 3905 0 3905 0 [(3967, 1), (3904, 3)] 0, attempt 3906 0 3906 0 [(3969, 1), (3968, 3)] 0, attempt 3907 0 3907 0 [(3970, 1), (3968, 3)] 0, attempt 3908 0 3908 0 [(3971, 1), (3968, 3)] 0, attempt 3909 0 3909 0 [(3972, 1), (3968, 3)] 0, attempt 3910 0 3910 0 [(3973, 1), (3968, 3)] 0, attempt 3911 0 3911 0 [(3974, 1), (3968, 3)] 0, attempt 3912 0 3912 0 [(3975, 1), (3968, 3)] 0, attempt 3913 0 3913 0 [(3976, 1), (3968, 3)] 0, attempt 3914 0 3914 0 [(3977, 1), (3968, 3)] 0, attempt 3915 0 3915 0 [(3978, 1), (3968, 3)] 0, attempt 3916 0 3916 0 [(3979, 1), (3968, 3)] 0, attempt 3917 0 3917 0 [(3980, 1), (3968, 3)] 0, attempt 3918 0 3918 0 [(3981, 1), (3968, 3)] 0, attempt 3919 0 3919 0 [(3982, 1), (3968, 3)] 0, attempt 3920 0 3920 0 [(3983, 1), (3968, 3)] 0, attempt 3921 0 3921 0 [(3984, 1), (3968, 3)] 0, attempt 3922 0 3922 0 [(3985, 1), (3968, 3)] 0, attempt 3923 0 3923 0 [(3986, 1), (3968, 3)] 0, attempt 3924 0 3924 0 [(3987, 1), (3968, 3)] 0, attempt 3925 0 3925 0 [(3988, 1), (3968, 3)] 0, attempt 3926 0 3926 0 [(3989, 1), (3968, 3)] 0, attempt 3927 0 3927 0 [(3990, 1), (3968, 3)] 0, attempt 3928 0 3928 0 [(3991, 1), (3968, 3)] 0, attempt 3929 0 3929 0 [(3992, 1), (3968, 3)] 0, attempt 3930 0 3930 0 [(3993, 1), (3968, 3)] 0, attempt 3931 0 3931 0 [(3994, 1), (3968, 3)] 0, attempt 3932 0 3932 0 [(3995, 1), (3968, 3)] 0, attempt 3933 0 3933 0 [(3996, 1), (3968, 3)] 0, attempt 3934 0 3934 0 [(3997, 1), (3968, 3)] 0, attempt 3935 0 3935 0 [(3998, 1), (3968, 3)] 0]
def counters011 : List Nat := [3936, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3904
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 3936 0 3936 0 [(3999, 1), (3968, 3)] 0, attempt 3937 0 3937 0 [(4000, 1), (3968, 3)] 0, attempt 3938 0 3938 0 [(4001, 1), (3968, 3)] 0, attempt 3939 0 3939 0 [(4002, 1), (3968, 3)] 0, attempt 3940 0 3940 0 [(4003, 1), (3968, 3)] 0, attempt 3941 0 3941 0 [(4004, 1), (3968, 3)] 0, attempt 3942 0 3942 0 [(4005, 1), (3968, 3)] 0, attempt 3943 0 3943 0 [(4006, 1), (3968, 3)] 0, attempt 3944 0 3944 0 [(4007, 1), (3968, 3)] 0, attempt 3945 0 3945 0 [(4008, 1), (3968, 3)] 0, attempt 3946 0 3946 0 [(4009, 1), (3968, 3)] 0, attempt 3947 0 3947 0 [(4010, 1), (3968, 3)] 0, attempt 3948 0 3948 0 [(4011, 1), (3968, 3)] 0, attempt 3949 0 3949 0 [(4012, 1), (3968, 3)] 0, attempt 3950 0 3950 0 [(4013, 1), (3968, 3)] 0, attempt 3951 0 3951 0 [(4014, 1), (3968, 3)] 0, attempt 3952 0 3952 0 [(4015, 1), (3968, 3)] 0, attempt 3953 0 3953 0 [(4016, 1), (3968, 3)] 0, attempt 3954 0 3954 0 [(4017, 1), (3968, 3)] 0, attempt 3955 0 3955 0 [(4018, 1), (3968, 3)] 0, attempt 3956 0 3956 0 [(4019, 1), (3968, 3)] 0, attempt 3957 0 3957 0 [(4020, 1), (3968, 3)] 0, attempt 3958 0 3958 0 [(4021, 1), (3968, 3)] 0, attempt 3959 0 3959 0 [(4022, 1), (3968, 3)] 0, attempt 3960 0 3960 0 [(4023, 1), (3968, 3)] 0, attempt 3961 0 3961 0 [(4024, 1), (3968, 3)] 0, attempt 3962 0 3962 0 [(4025, 1), (3968, 3)] 0, attempt 3963 0 3963 0 [(4026, 1), (3968, 3)] 0, attempt 3964 0 3964 0 [(4027, 1), (3968, 3)] 0, attempt 3965 0 3965 0 [(4028, 1), (3968, 3)] 0, attempt 3966 0 3966 0 [(4029, 1), (3968, 3)] 0, attempt 3967 0 3967 0 [(4030, 1), (3968, 3)] 0]
def counters012 : List Nat := [3968, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3936
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 3968 0 3968 0 [(4031, 1), (3968, 3)] 0, attempt 3969 0 3969 0 [(4033, 1), (4032, 3)] 0, attempt 3970 0 3970 0 [(4034, 1), (4032, 3)] 0, attempt 3971 0 3971 0 [(4035, 1), (4032, 3)] 0, attempt 3972 0 3972 0 [(4036, 1), (4032, 3)] 0, attempt 3973 0 3973 0 [(4037, 1), (4032, 3)] 0, attempt 3974 0 3974 0 [(4038, 1), (4032, 3)] 0, attempt 3975 0 3975 0 [(4039, 1), (4032, 3)] 0, attempt 3976 0 3976 0 [(4040, 1), (4032, 3)] 0, attempt 3977 0 3977 0 [(4041, 1), (4032, 3)] 0, attempt 3978 0 3978 0 [(4042, 1), (4032, 3)] 0, attempt 3979 0 3979 0 [(4043, 1), (4032, 3)] 0, attempt 3980 0 3980 0 [(4044, 1), (4032, 3)] 0, attempt 3981 0 3981 0 [(4045, 1), (4032, 3)] 0, attempt 3982 0 3982 0 [(4046, 1), (4032, 3)] 0, attempt 3983 0 3983 0 [(4047, 1), (4032, 3)] 0, attempt 3984 0 3984 0 [(4048, 1), (4032, 3)] 0, attempt 3985 0 3985 0 [(4049, 1), (4032, 3)] 0, attempt 3986 0 3986 0 [(4050, 1), (4032, 3)] 0, attempt 3987 0 3987 0 [(4051, 1), (4032, 3)] 0, attempt 3988 0 3988 0 [(4052, 1), (4032, 3)] 0, attempt 3989 0 3989 0 [(4053, 1), (4032, 3)] 0, attempt 3990 0 3990 0 [(4054, 1), (4032, 3)] 0, attempt 3991 0 3991 0 [(4055, 1), (4032, 3)] 0, attempt 3992 0 3992 0 [(4056, 1), (4032, 3)] 0, attempt 3993 0 3993 0 [(4057, 1), (4032, 3)] 0, attempt 3994 0 3994 0 [(4058, 1), (4032, 3)] 0, attempt 3995 0 3995 0 [(4059, 1), (4032, 3)] 0, attempt 3996 0 3996 0 [(4060, 1), (4032, 3)] 0, attempt 3997 0 3997 0 [(4061, 1), (4032, 3)] 0, attempt 3998 0 3998 0 [(4062, 1), (4032, 3)] 0, attempt 3999 0 3999 0 [(4063, 1), (4032, 3)] 0]
def counters013 : List Nat := [4000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3968
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 4000 0 4000 0 [(4064, 1), (4032, 3)] 0, attempt 4001 0 4001 0 [(4065, 1), (4032, 3)] 0, attempt 4002 0 4002 0 [(4066, 1), (4032, 3)] 0, attempt 4003 0 4003 0 [(4067, 1), (4032, 3)] 0, attempt 4004 0 4004 0 [(4068, 1), (4032, 3)] 0, attempt 4005 0 4005 0 [(4069, 1), (4032, 3)] 0, attempt 4006 0 4006 0 [(4070, 1), (4032, 3)] 0, attempt 4007 0 4007 0 [(4071, 1), (4032, 3)] 0, attempt 4008 0 4008 0 [(4072, 1), (4032, 3)] 0, attempt 4009 0 4009 0 [(4073, 1), (4032, 3)] 0, attempt 4010 0 4010 0 [(4074, 1), (4032, 3)] 0, attempt 4011 0 4011 0 [(4075, 1), (4032, 3)] 0, attempt 4012 0 4012 0 [(4076, 1), (4032, 3)] 0, attempt 4013 0 4013 0 [(4077, 1), (4032, 3)] 0, attempt 4014 0 4014 0 [(4078, 1), (4032, 3)] 0, attempt 4015 0 4015 0 [(4079, 1), (4032, 3)] 0, attempt 4016 0 4016 0 [(4080, 1), (4032, 3)] 0, attempt 4017 0 4017 0 [(4081, 1), (4032, 3)] 0, attempt 4018 0 4018 0 [(4082, 1), (4032, 3)] 0, attempt 4019 0 4019 0 [(4083, 1), (4032, 3)] 0, attempt 4020 0 4020 0 [(4084, 1), (4032, 3)] 0, attempt 4021 0 4021 0 [(4085, 1), (4032, 3)] 0, attempt 4022 0 4022 0 [(4086, 1), (4032, 3)] 0, attempt 4023 0 4023 0 [(4087, 1), (4032, 3)] 0, attempt 4024 0 4024 0 [(4088, 1), (4032, 3)] 0, attempt 4025 0 4025 0 [(4089, 1), (4032, 3)] 0, attempt 4026 0 4026 0 [(4090, 1), (4032, 3)] 0, attempt 4027 0 4027 0 [(4091, 1), (4032, 3)] 0, attempt 4028 0 4028 0 [(4092, 1), (4032, 3)] 0, attempt 4029 0 4029 0 [(4093, 1), (4032, 3)] 0, attempt 4030 0 4030 0 [(4094, 1), (4032, 3)] 0, attempt 4031 0 4031 0 [(4095, 1), (4032, 3)] 0]
def counters014 : List Nat := [4032, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4000
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 4032 0 4032 0 [(4097, 1), (4096, 3)] 0, attempt 4033 0 4033 0 [(4098, 1), (4096, 3)] 0, attempt 4034 0 4034 0 [(4099, 1), (4096, 3)] 0, attempt 4035 0 4035 0 [(4100, 1), (4096, 3)] 0, attempt 4036 0 4036 0 [(4101, 1), (4096, 3)] 0, attempt 4037 0 4037 0 [(4102, 1), (4096, 3)] 0, attempt 4038 0 4038 0 [(4103, 1), (4096, 3)] 0, attempt 4039 0 4039 0 [(4104, 1), (4096, 3)] 0, attempt 4040 0 4040 0 [(4105, 1), (4096, 3)] 0, attempt 4041 0 4041 0 [(4106, 1), (4096, 3)] 0, attempt 4042 0 4042 0 [(4107, 1), (4096, 3)] 0, attempt 4043 0 4043 0 [(4108, 1), (4096, 3)] 0, attempt 4044 0 4044 0 [(4109, 1), (4096, 3)] 0, attempt 4045 0 4045 0 [(4110, 1), (4096, 3)] 0, attempt 4046 0 4046 0 [(4111, 1), (4096, 3)] 0, attempt 4047 0 4047 0 [(4112, 1), (4096, 3)] 0, attempt 4048 0 4048 0 [(4113, 1), (4096, 3)] 0, attempt 4049 0 4049 0 [(4114, 1), (4096, 3)] 0, attempt 4050 0 4050 0 [(4115, 1), (4096, 3)] 0, attempt 4051 0 4051 0 [(4116, 1), (4096, 3)] 0, attempt 4052 0 4052 0 [(4117, 1), (4096, 3)] 0, attempt 4053 0 4053 0 [(4118, 1), (4096, 3)] 0, attempt 4054 0 4054 0 [(4119, 1), (4096, 3)] 0, attempt 4055 0 4055 0 [(4120, 1), (4096, 3)] 0, attempt 4056 0 4056 0 [(4121, 1), (4096, 3)] 0, attempt 4057 0 4057 0 [(4122, 1), (4096, 3)] 0, attempt 4058 0 4058 0 [(4123, 1), (4096, 3)] 0, attempt 4059 0 4059 0 [(4124, 1), (4096, 3)] 0, attempt 4060 0 4060 0 [(4125, 1), (4096, 3)] 0, attempt 4061 0 4061 0 [(4126, 1), (4096, 3)] 0, attempt 4062 0 4062 0 [(4127, 1), (4096, 3)] 0, attempt 4063 0 4063 0 [(4128, 1), (4096, 3)] 0]
def counters015 : List Nat := [4064, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4032
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 4064 0 4064 0 [(4129, 1), (4096, 3)] 0, attempt 4065 0 4065 0 [(4130, 1), (4096, 3)] 0, attempt 4066 0 4066 0 [(4131, 1), (4096, 3)] 0, attempt 4067 0 4067 0 [(4132, 1), (4096, 3)] 0, attempt 4068 0 4068 0 [(4133, 1), (4096, 3)] 0, attempt 4069 0 4069 0 [(4134, 1), (4096, 3)] 0, attempt 4070 0 4070 0 [(4135, 1), (4096, 3)] 0, attempt 4071 0 4071 0 [(4136, 1), (4096, 3)] 0, attempt 4072 0 4072 0 [(4137, 1), (4096, 3)] 0, attempt 4073 0 4073 0 [(4138, 1), (4096, 3)] 0, attempt 4074 0 4074 0 [(4139, 1), (4096, 3)] 0, attempt 4075 0 4075 0 [(4140, 1), (4096, 3)] 0, attempt 4076 0 4076 0 [(4141, 1), (4096, 3)] 0, attempt 4077 0 4077 0 [(4142, 1), (4096, 3)] 0, attempt 4078 0 4078 0 [(4143, 1), (4096, 3)] 0, attempt 4079 0 4079 0 [(4144, 1), (4096, 3)] 0, attempt 4080 0 4080 0 [(4145, 1), (4096, 3)] 0, attempt 4081 0 4081 0 [(4146, 1), (4096, 3)] 0, attempt 4082 0 4082 0 [(4147, 1), (4096, 3)] 0, attempt 4083 0 4083 0 [(4148, 1), (4096, 3)] 0, attempt 4084 0 4084 0 [(4149, 1), (4096, 3)] 0, attempt 4085 0 4085 0 [(4150, 1), (4096, 3)] 0, attempt 4086 0 4086 0 [(4151, 1), (4096, 3)] 0, attempt 4087 0 4087 0 [(4152, 1), (4096, 3)] 0, attempt 4088 0 4088 0 [(4153, 1), (4096, 3)] 0, attempt 4089 0 4089 0 [(4154, 1), (4096, 3)] 0, attempt 4090 0 4090 0 [(4155, 1), (4096, 3)] 0, attempt 4091 0 4091 0 [(4156, 1), (4096, 3)] 0, attempt 4092 0 4092 0 [(4157, 1), (4096, 3)] 0, attempt 4093 0 4093 0 [(4158, 1), (4096, 3)] 0, attempt 4094 0 4094 0 [(4159, 1), (4096, 3)] 0, attempt 4095 0 4095 0 [(4161, 1), (4160, 3)] 0]
def counters016 : List Nat := [4096, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4064
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4096
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4064
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 4064 4096 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 4064) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4032
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 4032 4064 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 4032) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4000
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 4000 4032 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 4000) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3968
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 3968 4000 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 3968) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3936
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 3936 3968 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 3936) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3904
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 3904 3936 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 3904) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3872
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 3872 3904 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 3872) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3840
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 3840 3872 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 3840) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3808
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 3808 3840 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 3808) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3776
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 3776 3808 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 3776) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3744
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 3744 3776 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 3744) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3712
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 3712 3744 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 3712) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3680
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 3680 3712 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 3680) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3648
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 3648 3680 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 3648) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3616
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 3616 3648 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 3616) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3584
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 3584 3616 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 3584) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr07
