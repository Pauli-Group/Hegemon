use sp_runtime::DispatchError;

use crate::manifest::KernelManifest;
use crate::traits::{ApplyOutcome, KernelStateView, KernelStateWrite, ValidActionMeta};
use crate::types::ActionEnvelope;

pub trait FamilyRouter {
    fn validate(
        manifest: &KernelManifest,
        state: &dyn KernelStateView,
        envelope: &ActionEnvelope,
    ) -> Result<ValidActionMeta, DispatchError>;

    fn apply(
        manifest: &KernelManifest,
        state: &mut dyn KernelStateWrite,
        envelope: &ActionEnvelope,
    ) -> Result<ApplyOutcome, DispatchError>;
}
