use hegemon_standalone_pay1x2_relation_prototype::{
    mutation_matrix, valid_fixture, verify_relation, PROFILE_NAME,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (statement, witness) = valid_fixture()?;
    let stats = verify_relation(&statement, &witness)?;
    println!("profile={PROFILE_NAME}");
    println!("shape=1-input/2-output depth=32 native_asset=1 recipient=1 change=1");
    println!(
        "bytes private_witness={} public_statement={}",
        stats.private_witness_bytes, stats.public_statement_bytes
    );
    println!(
        "hashes invocations={} absorbed_bytes={} merkle_parents={}",
        stats.semantic_invocations, stats.absorbed_bytes, stats.merkle_parent_invocations
    );
    println!(
        "keccak_f={} boolean_and_floor={}",
        stats.keccak_f_permutations, stats.keccak_boolean_and_floor
    );
    println!(
        "balance_tag=external_derived in_relation_permutations=0 range_checks={}",
        stats.range_checks
    );
    println!(
        "statement_scope=narrow_cryptographic_core canonical_action_adapter_complete={}",
        stats.canonical_action_adapter_complete
    );

    let outcomes = mutation_matrix()?;
    for outcome in &outcomes {
        println!(
            "mutation={} result={} reason={}",
            outcome.name,
            if outcome.rejected {
                "rejected"
            } else {
                "ACCEPTED"
            },
            outcome.reason
        );
    }
    let rejected = outcomes.iter().filter(|outcome| outcome.rejected).count();
    println!("mutation_summary rejected={rejected}/{}", outcomes.len());
    if rejected != outcomes.len() {
        return Err("mutation matrix admitted at least one counterfeit".into());
    }
    Ok(())
}
