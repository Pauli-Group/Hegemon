use crate::manifest::KernelManifest;
use crate::traits::{
    ApplyOutcome, KernelError, KernelStateView, KernelStateWrite, ValidActionMeta,
};
use crate::types::ActionEnvelope;

pub trait FamilyRouter {
    fn validate(
        manifest: &KernelManifest,
        state: &dyn KernelStateView,
        envelope: &ActionEnvelope,
    ) -> Result<ValidActionMeta, KernelError>;

    fn apply(
        manifest: &KernelManifest,
        state: &mut dyn KernelStateWrite,
        envelope: &ActionEnvelope,
    ) -> Result<ApplyOutcome, KernelError>;
}
