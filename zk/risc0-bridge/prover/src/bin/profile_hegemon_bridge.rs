use anyhow::{anyhow, Context, Result};
use codec::{Decode, Encode};
use consensus_light_client::{
    bridge_checkpoint_output_wire_bytes_v1, verify_hegemon_long_range_proof,
    HegemonLongRangeProofV1,
};
use hegemon_risc0_bridge_methods::HEGEMON_BRIDGE_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};
use std::{path::Path, time::Instant};

fn main() -> Result<()> {
    let proof_hex = proof_hex_arg()?;
    let proof_bytes = hex::decode(proof_hex.trim_start_matches("0x").trim())
        .context("decode HegemonLongRangeProofV1 hex")?;
    let mut encoded = proof_bytes.as_slice();
    let proof = HegemonLongRangeProofV1::decode(&mut encoded)
        .map_err(|err| anyhow!("decode HegemonLongRangeProofV1 failed: {err:?}"))?;
    if !encoded.is_empty() {
        return Err(anyhow!("HegemonLongRangeProofV1 has trailing bytes"));
    }

    println!("proof_bytes={}", proof_bytes.len());
    println!("sample_count={}", proof.sample_count);
    println!("sample_headers={}", proof.sample_headers.len());
    println!("messages={}", proof.messages.len());
    println!(
        "message_opening_siblings={}",
        proof.message_header_opening.sibling_hashes.len()
    );
    println!(
        "message_opening_peaks={}",
        proof.message_header_opening.peak_hashes.len()
    );

    let native_start = Instant::now();
    let native_output = verify_hegemon_long_range_proof(
        &proof,
        proof.output.confirmations_checked,
        proof.output.min_work_checked,
    )
    .map_err(|err| anyhow!("native verification failed: {err:?}"))?;
    let native_elapsed = native_start.elapsed();
    let native_journal = bridge_checkpoint_output_wire_bytes_v1(&native_output);
    println!("native_verify_ms={}", native_elapsed.as_millis());
    println!("journal_bytes={}", native_journal.len());

    let input = proof.encode();
    let input_len = u32::try_from(input.len()).map_err(|_| anyhow!("bridge proof too large"))?;
    let env = ExecutorEnv::builder()
        .write_slice(&input_len.to_le_bytes())
        .write_slice(&input)
        .build()?;

    let execute_start = Instant::now();
    let session = default_executor().execute(env, HEGEMON_BRIDGE_ELF)?;
    let execute_elapsed = execute_start.elapsed();
    println!("guest_execute_ms={}", execute_elapsed.as_millis());
    println!("guest_cycles={}", session.cycles());
    println!("guest_segments={}", session.segments.len());
    for (index, segment) in session.segments.iter().enumerate() {
        println!(
            "guest_segment_{index}_po2={} cycles={}",
            segment.po2, segment.cycles
        );
    }
    println!("guest_journal_bytes={}", session.journal.bytes.len());
    println!("guest_journal_matches={}", session.journal.bytes == native_journal);
    println!("guest_exit={:?}", session.exit_code);
    Ok(())
}

fn proof_hex_arg() -> Result<String> {
    let mut args = std::env::args().skip(1);
    let first = args
        .next()
        .ok_or_else(|| anyhow!("usage: profile_hegemon_bridge <0x-proof> | --proof-file <path>"))?;
    if first == "--proof-file" {
        let path = args
            .next()
            .ok_or_else(|| anyhow!("--proof-file requires a path"))?;
        return std::fs::read_to_string(Path::new(&path))
            .with_context(|| format!("read proof file {path}"));
    }
    if args.next().is_some() {
        return Err(anyhow!(
            "usage: profile_hegemon_bridge <0x-proof> | --proof-file <path>"
        ));
    }
    Ok(first)
}
