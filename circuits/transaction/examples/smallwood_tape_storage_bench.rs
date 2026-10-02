//! Isolated DECS storage comparison using the actual contiguous sampler,
//! unchanged partition helper, and actual transaction error type.
//!
//! Build: cargo build --locked --offline -p transaction-circuit --release \
//!          --example smallwood_tape_storage_bench
//! Run each mode in a fresh process (macOS records peak RSS with time -l):
//!   /usr/bin/time -l TARGET/release/examples/smallwood_tape_storage_bench legacy 8388608
//!   /usr/bin/time -l TARGET/release/examples/smallwood_tape_storage_bench flat 8388608
//!
//! The injected byte source is deterministic measurement input only. It is
//! not the production entropy provider or distribution/security evidence.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use sha2::{Digest, Sha512};
use transaction_circuit::smallwood_poseidon2_v8_rng_refinement::{
    HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1, SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
};

mod error {
    pub use transaction_circuit::TransactionCircuitError;
}
#[allow(dead_code)]
#[path = "../src/smallwood_poseidon2_v8_rng_refinement/mapping.rs"]
mod mapping;
#[allow(dead_code)]
#[path = "../src/smallwood_poseidon2_v8_rng_refinement/tapes.rs"]
mod tapes;

struct CountingAllocator;
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static REALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

// Counters include requested allocation bytes, not allocator metadata or RSS.
// Snapshot differences exclude process setup and result formatting.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn allocation_snapshot() -> [usize; 3] {
    [
        ALLOCATIONS.load(Ordering::Relaxed),
        REALLOCATIONS.load(Ordering::Relaxed),
        ALLOCATED_BYTES.load(Ordering::Relaxed),
    ]
}

fn legacy_sample(
    count: usize,
    width: usize,
    batch_limit: usize,
    mut before_fill: impl FnMut(usize) -> Result<(), error::TransactionCircuitError>,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), error::TransactionCircuitError>,
) -> Result<Vec<Vec<u8>>, error::TransactionCircuitError> {
    let mut tapes = Vec::with_capacity(count);
    while tapes.len() < count {
        let batch_count = (count - tapes.len()).min(batch_limit);
        let byte_count = batch_count.checked_mul(width).ok_or(
            error::TransactionCircuitError::ConstraintViolation("benchmark tape size overflow"),
        )?;
        before_fill(byte_count)?;
        let mut bytes = vec![0u8; byte_count];
        fill(&mut bytes)?;
        mapping::append_fixed_width_tapes_v1(&mut tapes, &bytes, width)?;
    }
    Ok(tapes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or("expected legacy or flat, then optional tape count")?;
    let count = args
        .next()
        .map(|arg| arg.parse())
        .transpose()?
        .unwrap_or(1usize << 23);
    if args.next().is_some() || !matches!(mode.as_str(), "legacy" | "flat") {
        return Err("usage: smallwood_tape_storage_bench legacy|flat [count]".into());
    }
    let width = SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES;
    let batch_limit = HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1;
    let total_bytes = count
        .checked_mul(width)
        .ok_or("benchmark byte count overflow")?;
    let header_bytes = count
        .checked_mul(std::mem::size_of::<Vec<u8>>())
        .ok_or("benchmark header count overflow")?;
    let accounted_calls = Cell::new(0usize);
    let fill_calls = Cell::new(0usize);
    let accounted_bytes = Cell::new(0usize);
    let expected_fill = Cell::new(0usize);
    let before_fill = |size| {
        let remaining = total_bytes - accounted_bytes.get();
        assert_eq!(size, remaining.min(batch_limit * width));
        accounted_calls.set(accounted_calls.get() + 1);
        accounted_bytes.set(accounted_bytes.get() + size);
        expected_fill.set(size);
        Ok(())
    };
    let mut source_offset = 0usize;
    let fill = |output: &mut [u8]| {
        assert_eq!(output.len(), expected_fill.replace(0));
        fill_calls.set(fill_calls.get() + 1);
        for byte in output {
            *byte = (source_offset
                .wrapping_mul(73)
                .wrapping_add(source_offset / 256)
                .wrapping_add(19)) as u8;
            source_offset += 1;
        }
        Ok(())
    };
    let before = allocation_snapshot();
    let started = Instant::now();
    let (elapsed, allocations, digest) = if mode == "legacy" {
        let sampled = legacy_sample(count, width, batch_limit, before_fill, fill)?;
        let elapsed = started.elapsed();
        let after = allocation_snapshot();
        let mut hash = Sha512::new();
        for tape in &sampled {
            hash.update(tape);
        }
        std::hint::black_box(&sampled);
        (elapsed, after, hash.finalize())
    } else {
        let sampled = tapes::sample_contiguous_tapes_with_source_v1(
            count,
            width,
            batch_limit,
            before_fill,
            fill,
        )?;
        let elapsed = started.elapsed();
        let after = allocation_snapshot();
        let mut hash = Sha512::new();
        for index in 0..sampled.len() {
            hash.update(sampled.get(index).expect("valid canonical leaf index"));
        }
        std::hint::black_box(&sampled);
        (elapsed, after, hash.finalize())
    };
    assert_eq!(accounted_calls.get(), count.div_ceil(batch_limit));
    assert_eq!(accounted_calls.get(), fill_calls.get());
    assert_eq!(accounted_bytes.get(), total_bytes);
    assert_eq!(source_offset, total_bytes);
    println!(
        "mode={mode} count={count} width={width} batch_limit={batch_limit} entropy_calls={} entropy_bytes={total_bytes} sampling_seconds={:.6} allocation_calls={} reallocation_calls={} allocated_requested_bytes={} legacy_vector_header_bytes={header_bytes} sha512={}",
        fill_calls.get(), elapsed.as_secs_f64(),
        allocations[0] - before[0], allocations[1] - before[1], allocations[2] - before[2],
        hex::encode(digest),
    );
    Ok(())
}
