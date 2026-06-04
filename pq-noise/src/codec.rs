use crate::error::{PqNoiseError, Result};
use serde::{de::DeserializeOwned, Serialize};

pub(crate) const HANDSHAKE_MAX_FRAME_LEN: usize = 64 * 1024;

const HANDSHAKE_MAGIC: &[u8; 4] = b"PNH1";
const SESSION_MAGIC: &[u8; 4] = b"PNS1";
const TRANSCRIPT_MAGIC: &[u8; 4] = b"PNT1";

pub(crate) fn encode_handshake<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_with_magic(value, HANDSHAKE_MAGIC, HANDSHAKE_MAX_FRAME_LEN)
}

pub(crate) fn decode_handshake<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    decode_with_magic(bytes, HANDSHAKE_MAGIC, HANDSHAKE_MAX_FRAME_LEN)
}

pub(crate) fn encode_session<T: Serialize>(value: &T, max_len: usize) -> Result<Vec<u8>> {
    encode_with_magic(value, SESSION_MAGIC, max_len)
}

pub(crate) fn decode_session<T: DeserializeOwned>(bytes: &[u8], max_len: usize) -> Result<T> {
    decode_with_magic(bytes, SESSION_MAGIC, max_len)
}

pub(crate) fn encode_transcript<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_with_magic(value, TRANSCRIPT_MAGIC, HANDSHAKE_MAX_FRAME_LEN)
}

fn encode_with_magic<T: Serialize>(value: &T, magic: &[u8; 4], max_len: usize) -> Result<Vec<u8>> {
    let body = postcard::to_allocvec(value)
        .map_err(|err| PqNoiseError::Serialization(format!("postcard encode failed: {err}")))?;
    let total_len = magic.len().saturating_add(body.len());
    if total_len > max_len {
        return Err(PqNoiseError::Serialization(format!(
            "encoded frame too large: {total_len} > {max_len}"
        )));
    }
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(magic);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_with_magic<T: DeserializeOwned>(
    bytes: &[u8],
    magic: &[u8; 4],
    max_len: usize,
) -> Result<T> {
    if bytes.len() > max_len {
        return Err(PqNoiseError::Serialization(format!(
            "encoded frame too large: {} > {max_len}",
            bytes.len()
        )));
    }
    if !bytes.starts_with(magic) {
        return Err(PqNoiseError::Serialization(
            "missing PQ Noise codec marker".to_string(),
        ));
    }
    let (value, remaining) = postcard::take_from_bytes(&bytes[magic.len()..])
        .map_err(|err| PqNoiseError::Serialization(format!("postcard decode failed: {err}")))?;
    if !remaining.is_empty() {
        return Err(PqNoiseError::Serialization(format!(
            "postcard decode left {} trailing bytes",
            remaining.len()
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        nonce: u64,
        payload: Vec<u8>,
    }

    #[test]
    fn codec_rejects_wrong_marker() {
        let sample = Sample {
            nonce: 7,
            payload: vec![1, 2, 3],
        };
        let encoded = encode_handshake(&sample).expect("encode");
        assert!(decode_session::<Sample>(&encoded, HANDSHAKE_MAX_FRAME_LEN).is_err());
    }

    #[test]
    fn codec_roundtrip_is_bounded() {
        let sample = Sample {
            nonce: 9,
            payload: vec![0; 32],
        };
        let encoded = encode_session(&sample, 128).expect("encode");
        assert_eq!(
            decode_session::<Sample>(&encoded, 128).expect("decode"),
            sample
        );
        assert!(encode_session(&sample, 8).is_err());
    }

    #[test]
    fn codec_rejects_trailing_bytes() {
        let sample = Sample {
            nonce: 11,
            payload: vec![4, 5, 6],
        };
        let mut encoded = encode_session(&sample, 128).expect("encode");
        encoded.push(0xff);

        assert!(decode_session::<Sample>(&encoded, 128).is_err());
    }
}
