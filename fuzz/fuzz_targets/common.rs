pub fn mutate_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0];
    }

    let mut out = data.to_vec();
    for (idx, byte) in data.iter().take(64).enumerate() {
        let offset = (idx.wrapping_mul(17) + usize::from(*byte)) % out.len();
        out[offset] ^= byte.wrapping_add(idx as u8).wrapping_add(1);
    }

    if data.len() % 7 == 0 {
        out.push(data[0]);
    } else if data.len() % 11 == 0 && out.len() > 1 {
        out.truncate(out.len() - 1);
    }

    out
}
