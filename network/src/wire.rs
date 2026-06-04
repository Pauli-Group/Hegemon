use crate::NetworkError;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const NETWORK_WIRE_MAGIC: &[u8; 4] = b"HNW1";
pub const MAX_HANDSHAKE_FRAME_LEN: usize = 64 * 1024;
pub const MAX_WIRE_FRAME_LEN: usize = 16 * 1024 * 1024;
pub const MAX_PEER_STORE_LEN: usize = 2 * 1024 * 1024;

pub fn encode<T: Serialize>(value: &T, max_len: usize) -> Result<Vec<u8>, NetworkError> {
    let body = postcard::to_allocvec(value)
        .map_err(|err| NetworkError::Serialization(format!("postcard encode failed: {err}")))?;
    let total_len = NETWORK_WIRE_MAGIC.len().saturating_add(body.len());
    if total_len > max_len {
        return Err(NetworkError::Serialization(format!(
            "encoded frame too large: {total_len} > {max_len}"
        )));
    }
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(NETWORK_WIRE_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8], max_len: usize) -> Result<T, NetworkError> {
    decode_borrowed(bytes, max_len)
}

pub fn decode_borrowed<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    max_len: usize,
) -> Result<T, NetworkError> {
    let body = checked_body(bytes, max_len)?;
    let (value, remaining) = postcard::take_from_bytes(body)
        .map_err(|err| NetworkError::Serialization(format!("postcard decode failed: {err}")))?;
    if !remaining.is_empty() {
        return Err(NetworkError::Serialization(format!(
            "postcard decode left {} trailing bytes",
            remaining.len()
        )));
    }
    Ok(value)
}

fn checked_body<'a>(bytes: &'a [u8], max_len: usize) -> Result<&'a [u8], NetworkError> {
    if bytes.len() > max_len {
        return Err(NetworkError::Serialization(format!(
            "encoded frame too large: {} > {max_len}",
            bytes.len()
        )));
    }
    if !bytes.starts_with(NETWORK_WIRE_MAGIC) {
        return Err(NetworkError::Serialization(
            "missing network wire codec marker".to_string(),
        ));
    }
    Ok(&bytes[NETWORK_WIRE_MAGIC.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        name: String,
        payload: Vec<u8>,
    }

    #[test]
    fn codec_roundtrip_uses_version_marker() {
        let sample = Sample {
            name: "sync".to_string(),
            payload: vec![1, 2, 3],
        };
        let encoded = encode(&sample, 128).expect("encode");
        assert!(encoded.starts_with(NETWORK_WIRE_MAGIC));
        let decoded: Sample = decode(&encoded, 128).expect("decode");
        assert_eq!(decoded, sample);
    }

    #[test]
    fn codec_rejects_unmarked_or_oversized_frames() {
        assert!(decode::<Sample>(b"\x00\x01", 128).is_err());

        let sample = Sample {
            name: "oversized".to_string(),
            payload: vec![0; 32],
        };
        assert!(encode(&sample, 8).is_err());
    }

    #[test]
    fn codec_rejects_trailing_bytes() {
        let sample = Sample {
            name: "sync".to_string(),
            payload: vec![1, 2, 3],
        };
        let mut encoded = encode(&sample, 128).expect("encode");
        encoded.push(0xff);

        assert!(decode::<Sample>(&encoded, 128).is_err());
    }
}
