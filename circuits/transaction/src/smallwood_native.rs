use std::ffi::{c_int, c_uchar, c_uint, c_void};
use std::slice;

use blake3::Hasher;

use crate::error::TransactionCircuitError;

const GOLDILOCKS_MODULUS: u128 = 0xffff_ffff_0000_0001;
const SMALLWOOD_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.f64-xof.v1";
const SMALLWOOD_COMPRESS2_DOMAIN: &[u8] = b"hegemon.smallwood.f64-compress2.v1";

unsafe extern "C" {
    fn hegemon_smallwood_candidate_prove(
        witness_values: *const u64,
        witness_len: c_uint,
        nb_rows: c_uint,
        packing_factor: c_uint,
        constraint_degree: c_uint,
        selector_indices: *const c_uint,
        public_targets: *const u64,
        public_target_count: c_uint,
        binded_data: *const c_uchar,
        binded_data_bytesize: c_uint,
        proof_out: *mut *mut c_uchar,
        proof_size_out: *mut c_uint,
    ) -> c_int;

    fn hegemon_smallwood_candidate_verify(
        nb_rows: c_uint,
        packing_factor: c_uint,
        constraint_degree: c_uint,
        selector_indices: *const c_uint,
        public_targets: *const u64,
        public_target_count: c_uint,
        binded_data: *const c_uchar,
        binded_data_bytesize: c_uint,
        proof: *const c_uchar,
        proof_size: c_uint,
    ) -> c_int;

    fn hegemon_smallwood_candidate_free(ptr: *mut c_void);
}

pub fn prove_candidate(
    witness_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    selector_indices: &[u32],
    public_targets: &[u64],
    binded_data: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let mut proof_ptr = std::ptr::null_mut();
    let mut proof_size = 0u32;
    let ret = unsafe {
        hegemon_smallwood_candidate_prove(
            witness_values.as_ptr(),
            witness_values.len() as u32,
            row_count as u32,
            packing_factor as u32,
            u32::from(constraint_degree),
            selector_indices.as_ptr(),
            public_targets.as_ptr(),
            public_targets.len() as u32,
            binded_data.as_ptr(),
            binded_data.len() as u32,
            &mut proof_ptr,
            &mut proof_size,
        )
    };
    if ret != 0 || proof_ptr.is_null() {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood candidate prover failed with code {ret}"
        )));
    }
    let bytes = unsafe { slice::from_raw_parts(proof_ptr, proof_size as usize).to_vec() };
    unsafe { hegemon_smallwood_candidate_free(proof_ptr.cast()) };
    Ok(bytes)
}

pub fn verify_candidate(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    selector_indices: &[u32],
    public_targets: &[u64],
    binded_data: &[u8],
    proof: &[u8],
) -> Result<(), TransactionCircuitError> {
    let ret = unsafe {
        hegemon_smallwood_candidate_verify(
            row_count as u32,
            packing_factor as u32,
            u32::from(constraint_degree),
            selector_indices.as_ptr(),
            public_targets.as_ptr(),
            public_targets.len() as u32,
            binded_data.as_ptr(),
            binded_data.len() as u32,
            proof.as_ptr(),
            proof.len() as u32,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood candidate verifier failed with code {ret}"
        )))
    }
}

fn xof_words_with_domain(domain: &[u8], input_words: &[u64], output_words: &mut [u64]) {
    let mut hasher = Hasher::new();
    hasher.update(domain);
    hasher.update(&(input_words.len() as u64).to_le_bytes());
    for word in input_words {
        hasher.update(&word.to_le_bytes());
    }
    let mut reader = hasher.finalize_xof();
    for output in output_words {
        let mut buf = [0u8; 16];
        reader.fill(&mut buf);
        *output = (u128::from_le_bytes(buf) % GOLDILOCKS_MODULUS) as u64;
    }
}

#[no_mangle]
pub extern "C" fn randombytes(x: *mut c_uchar, xlen: u64) -> c_int {
    if x.is_null() {
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts_mut(x, xlen as usize) };
    match getrandom::fill(slice) {
        Ok(()) => 0,
        Err(_) => {
            slice.fill(0);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn f64_xof(
    output: *mut u64,
    input: *const u64,
    input_size: c_uint,
    output_size: c_uint,
) {
    if output.is_null() {
        return;
    }
    let inputs = if input.is_null() || input_size == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(input, input_size as usize) }
    };
    let outputs = unsafe { slice::from_raw_parts_mut(output, output_size as usize) };
    xof_words_with_domain(SMALLWOOD_XOF_DOMAIN, inputs, outputs);
}

#[no_mangle]
pub extern "C" fn f64_compress2(output: *mut u64, input: *const u64) {
    if output.is_null() || input.is_null() {
        return;
    }
    let inputs = unsafe { slice::from_raw_parts(input, 8) };
    let outputs = unsafe { slice::from_raw_parts_mut(output, 4) };
    xof_words_with_domain(SMALLWOOD_COMPRESS2_DOMAIN, inputs, outputs);
}
