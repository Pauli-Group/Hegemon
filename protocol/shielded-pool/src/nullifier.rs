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

    #[derive(Clone, Copy, Debug)]
    enum NullifierOperation {
        CanStage(Nullifier),
        Stage(Nullifier),
        Import(Nullifier),
    }

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

    #[test]
    fn nullifier_state_matches_independent_transition_oracle() {
        let zero = [0u8; 48];
        let a = patterned_nullifier(1);
        let b = patterned_nullifier(2);
        let c = patterned_nullifier(3);
        let d = patterned_nullifier(4);
        let mut state = NullifierState::new(BTreeSet::from([a]), BTreeSet::from([b]));
        let mut oracle_spent = BTreeSet::from([a]);
        let mut oracle_pending = BTreeSet::from([b]);

        let operations = [
            NullifierOperation::CanStage(zero),
            NullifierOperation::Stage(zero),
            NullifierOperation::Import(zero),
            NullifierOperation::CanStage(a),
            NullifierOperation::Stage(a),
            NullifierOperation::Import(a),
            NullifierOperation::CanStage(b),
            NullifierOperation::Stage(b),
            NullifierOperation::Import(b),
            NullifierOperation::CanStage(c),
            NullifierOperation::Stage(c),
            NullifierOperation::Stage(c),
            NullifierOperation::Import(c),
            NullifierOperation::CanStage(c),
            NullifierOperation::Import(c),
            NullifierOperation::Import(d),
            NullifierOperation::CanStage(d),
            NullifierOperation::Stage(d),
        ];

        for (idx, op) in operations.into_iter().enumerate() {
            let (expected_result, expected_spent, expected_pending) =
                oracle_apply_nullifier_operation(&oracle_spent, &oracle_pending, op);
            let actual = match op {
                NullifierOperation::CanStage(nullifier) => state.can_stage(&nullifier),
                NullifierOperation::Stage(nullifier) => state.stage(nullifier),
                NullifierOperation::Import(nullifier) => state.import_one(nullifier),
            };

            assert_eq!(
                actual, expected_result,
                "nullifier operation {idx} result drifted from oracle: {op:?}"
            );
            assert_eq!(
                state.spent(),
                &expected_spent,
                "nullifier operation {idx} spent set drifted from oracle"
            );
            assert_eq!(
                state.pending(),
                &expected_pending,
                "nullifier operation {idx} pending set drifted from oracle"
            );
            oracle_spent = expected_spent;
            oracle_pending = expected_pending;
        }
    }

    fn oracle_apply_nullifier_operation(
        spent: &BTreeSet<Nullifier>,
        pending: &BTreeSet<Nullifier>,
        op: NullifierOperation,
    ) -> (
        Result<(), NullifierReject>,
        BTreeSet<Nullifier>,
        BTreeSet<Nullifier>,
    ) {
        let mut next_spent = spent.clone();
        let mut next_pending = pending.clone();
        let nullifier = match op {
            NullifierOperation::CanStage(nullifier)
            | NullifierOperation::Stage(nullifier)
            | NullifierOperation::Import(nullifier) => nullifier,
        };

        let result = if nullifier == [0u8; 48] {
            Err(NullifierReject::Zero)
        } else if spent.contains(&nullifier) {
            Err(NullifierReject::AlreadySpent)
        } else if matches!(
            op,
            NullifierOperation::CanStage(_) | NullifierOperation::Stage(_)
        ) && pending.contains(&nullifier)
        {
            Err(NullifierReject::AlreadyPending)
        } else {
            match op {
                NullifierOperation::CanStage(_) => {}
                NullifierOperation::Stage(_) => {
                    next_pending.insert(nullifier);
                }
                NullifierOperation::Import(_) => {
                    next_pending.remove(&nullifier);
                    next_spent.insert(nullifier);
                }
            }
            Ok(())
        };

        (result, next_spent, next_pending)
    }

    fn patterned_nullifier(seed: u8) -> Nullifier {
        let mut out = [0u8; 48];
        for (idx, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_mul(17).wrapping_add(idx as u8);
        }
        out
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
