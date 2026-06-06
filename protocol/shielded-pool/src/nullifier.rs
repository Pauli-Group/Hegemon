use alloc::collections::BTreeSet;

use crate::types::Nullifier;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullifierReject {
    Zero,
    AlreadySpent,
    AlreadyPending,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NullifierState {
    spent: BTreeSet<Nullifier>,
    pending: BTreeSet<Nullifier>,
}

impl NullifierState {
    pub fn new(spent: BTreeSet<Nullifier>, pending: BTreeSet<Nullifier>) -> Self {
        Self { spent, pending }
    }

    pub fn spent(&self) -> &BTreeSet<Nullifier> {
        &self.spent
    }

    pub fn pending(&self) -> &BTreeSet<Nullifier> {
        &self.pending
    }

    pub fn can_stage(&self, nullifier: &Nullifier) -> Result<(), NullifierReject> {
        if is_zero_nullifier(nullifier) {
            return Err(NullifierReject::Zero);
        }
        if self.spent.contains(nullifier) {
            return Err(NullifierReject::AlreadySpent);
        }
        if self.pending.contains(nullifier) {
            return Err(NullifierReject::AlreadyPending);
        }
        Ok(())
    }

    pub fn stage(&mut self, nullifier: Nullifier) -> Result<(), NullifierReject> {
        self.can_stage(&nullifier)?;
        self.pending.insert(nullifier);
        Ok(())
    }

    pub fn import_one(&mut self, nullifier: Nullifier) -> Result<(), NullifierReject> {
        if is_zero_nullifier(&nullifier) {
            return Err(NullifierReject::Zero);
        }
        if self.spent.contains(&nullifier) {
            return Err(NullifierReject::AlreadySpent);
        }
        self.pending.remove(&nullifier);
        self.spent.insert(nullifier);
        Ok(())
    }
}

pub fn is_zero_nullifier(nullifier: &Nullifier) -> bool {
    *nullifier == [0u8; 48]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn nullifier_state_blocks_zero_pending_and_spent_duplicates() {
        let key = [9u8; 48];
        let zero = [0u8; 48];
        let mut state = NullifierState::default();
        assert_eq!(state.stage(zero), Err(NullifierReject::Zero));
        assert_eq!(state.import_one(zero), Err(NullifierReject::Zero));
        assert_eq!(state.stage(key), Ok(()));
        assert_eq!(state.stage(key), Err(NullifierReject::AlreadyPending));
        assert_eq!(state.import_one(key), Ok(()));
        assert_eq!(state.stage(key), Err(NullifierReject::AlreadySpent));
        assert_eq!(state.import_one(key), Err(NullifierReject::AlreadySpent));
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanShieldedVectorFile {
        schema_version: u32,
        nullifier_cases: Vec<LeanNullifierCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNullifierCase {
        name: String,
        initial_spent: Vec<String>,
        initial_pending: Vec<String>,
        key: String,
        stage: bool,
        stage_then_import: bool,
        stage_after_import: bool,
        import: bool,
    }

    #[test]
    fn lean_generated_nullifier_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_SHIELDED_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_SHIELDED_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean shielded vectors");
        let vectors: LeanShieldedVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean shielded vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.nullifier_cases.is_empty(),
            "Lean nullifier cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.nullifier_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_nullifier_case(case);
        }
    }

    fn verify_lean_nullifier_case(case: &LeanNullifierCase) {
        let state = NullifierState::new(
            parse_nullifier_set(&case.initial_spent),
            parse_nullifier_set(&case.initial_pending),
        );
        let key = parse_nullifier(&case.key);

        let mut stage_state = state.clone();
        assert_eq!(
            stage_state.stage(key).is_ok(),
            case.stage,
            "{} stage result drifted from Lean spec",
            case.name
        );

        let mut stage_then_import_state = state.clone();
        let stage_then_import = if stage_then_import_state.stage(key).is_ok() {
            stage_then_import_state.import_one(key).is_ok()
        } else {
            false
        };
        assert_eq!(
            stage_then_import, case.stage_then_import,
            "{} stage_then_import result drifted from Lean spec",
            case.name
        );

        let mut stage_after_import_state = state.clone();
        let stage_after_import = if stage_after_import_state.import_one(key).is_ok() {
            stage_after_import_state.stage(key).is_ok()
        } else {
            false
        };
        assert_eq!(
            stage_after_import, case.stage_after_import,
            "{} stage_after_import result drifted from Lean spec",
            case.name
        );

        let mut import_state = state;
        assert_eq!(
            import_state.import_one(key).is_ok(),
            case.import,
            "{} import result drifted from Lean spec",
            case.name
        );
    }

    fn parse_nullifier_set(values: &[String]) -> BTreeSet<Nullifier> {
        let mut out = BTreeSet::new();
        for value in values {
            assert!(
                out.insert(parse_nullifier(value)),
                "duplicate nullifier {value}"
            );
        }
        out
    }

    fn parse_nullifier(value: &str) -> Nullifier {
        let stripped = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(stripped).expect("decode nullifier hex");
        assert_eq!(bytes.len(), 48, "expected 48-byte nullifier");
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        out
    }
}
