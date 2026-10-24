//! Source-owned admission age for authenticated launch proof references.
//! This host policy does not rewrite proof bytes or supply release authority.

pub const LAUNCH_REFERENCE_WINDOW: u64 = 12;

/// Reference age counts inclusion parents, so a reference R may be included
/// at block heights R+1 through R+13. HTLC Lock is restricted to R+1.
pub fn launch_reference_distance_allowed(
    reference_parent: u64,
    inclusion_parent: u64,
    is_lock: bool,
) -> bool {
    inclusion_parent
        .checked_sub(reference_parent)
        .is_some_and(|age| age <= if is_lock { 0 } else { LAUNCH_REFERENCE_WINDOW })
}
