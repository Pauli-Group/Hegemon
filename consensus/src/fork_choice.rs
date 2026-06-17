use std::cmp::Ordering;

/// Deterministic fork-choice ordering shared by PoW consensus and native-node
/// metadata import paths.
pub fn fork_choice_prefers_candidate(
    candidate_work_cmp: Ordering,
    candidate_height: u64,
    current_height: u64,
    candidate_hash: &[u8; 32],
    current_hash: &[u8; 32],
) -> bool {
    match candidate_work_cmp {
        Ordering::Greater => return true,
        Ordering::Less => return false,
        Ordering::Equal => {}
    }
    if candidate_height != current_height {
        return candidate_height > current_height;
    }
    candidate_hash < current_hash
}

#[cfg(test)]
mod tests {
    use super::fork_choice_prefers_candidate;
    use num_bigint::BigUint;
    use serde::Deserialize;
    use std::collections::BTreeSet;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanConsensusVectorFile {
        schema_version: u32,
        fork_choice_cases: Vec<LeanForkChoiceCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanForkChoiceCase {
        name: String,
        current_work: String,
        current_height: u64,
        current_hash: String,
        candidate_work: String,
        candidate_height: u64,
        candidate_hash: String,
        select_candidate: bool,
        selected_source: String,
        selected_work: String,
        selected_height: u64,
        selected_hash: String,
        selected_work_at_least_current: bool,
    }

    #[test]
    fn lean_generated_fork_choice_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_CONSENSUS_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_CONSENSUS_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean consensus vectors");
        let vectors: LeanConsensusVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean consensus vectors");
        assert_eq!(vectors.schema_version, 2);
        assert!(
            !vectors.fork_choice_cases.is_empty(),
            "Lean fork-choice cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.fork_choice_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_fork_choice_case(case);
        }
    }

    fn verify_lean_fork_choice_case(case: &LeanForkChoiceCase) {
        let current_work = parse_biguint(&case.current_work);
        let candidate_work = parse_biguint(&case.candidate_work);
        let selected_work = parse_biguint(&case.selected_work);
        let current_hash = parse_hash32(&case.current_hash);
        let candidate_hash = parse_hash32(&case.candidate_hash);
        let selected_hash = parse_hash32(&case.selected_hash);
        let selected = fork_choice_prefers_candidate(
            candidate_work.cmp(&current_work),
            case.candidate_height,
            case.current_height,
            &candidate_hash,
            &current_hash,
        );
        assert_eq!(
            selected, case.select_candidate,
            "{} production fork-choice ordering drifted from Lean spec",
            case.name
        );
        let expected_source = if selected { "candidate" } else { "current" };
        assert_eq!(
            case.selected_source, expected_source,
            "{} Lean selected source must match the production preference",
            case.name
        );
        let expected_work = if selected {
            &candidate_work
        } else {
            &current_work
        };
        let expected_height = if selected {
            case.candidate_height
        } else {
            case.current_height
        };
        let expected_hash = if selected {
            candidate_hash
        } else {
            current_hash
        };
        assert_eq!(
            selected_work, *expected_work,
            "{} selected work drifted from Lean selectBest",
            case.name
        );
        assert_eq!(
            case.selected_height, expected_height,
            "{} selected height drifted from Lean selectBest",
            case.name
        );
        assert_eq!(
            selected_hash, expected_hash,
            "{} selected hash drifted from Lean selectBest",
            case.name
        );
        assert!(
            case.selected_work_at_least_current,
            "{} Lean selectBest must not lower cumulative work",
            case.name
        );
        assert!(
            selected_work >= current_work,
            "{} production-selected work must not lower cumulative work",
            case.name
        );
    }

    fn parse_biguint(raw: &str) -> BigUint {
        raw.parse::<BigUint>()
            .expect("Lean work value must be a decimal BigUint")
    }

    fn parse_hash32(raw: &str) -> [u8; 32] {
        let bytes = parse_hex_vec(raw);
        assert_eq!(bytes.len(), 32, "Lean hash must be 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn parse_hex_vec(raw: &str) -> Vec<u8> {
        let value = raw.strip_prefix("0x").unwrap_or(raw);
        assert!(
            value.len().is_multiple_of(2),
            "hex strings must have even length"
        );
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("valid hex byte"))
            .collect()
    }
}
