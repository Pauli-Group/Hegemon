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

    #[derive(serde::Deserialize)]
    struct LeanFrameResourceVectorFile {
        schema_version: u32,
        constants: Vec<LeanFrameResourceConstant>,
        decode_cases: Vec<LeanFrameResourceDecodeCase>,
        encode_cases: Vec<LeanFrameResourceEncodeCase>,
    }

    #[derive(serde::Deserialize)]
    struct LeanFrameResourceConstant {
        kind: String,
        max_len: usize,
        magic_hex: String,
        postcard_encoded: bool,
    }

    #[derive(serde::Deserialize)]
    struct LeanFrameResourceDecodeCase {
        name: String,
        kind: String,
        encoded_bytes: usize,
        marker_matches: bool,
        postcard_decodes: bool,
        postcard_consumes_all: bool,
        expected_valid: bool,
        expected_reject: Option<String>,
        expected_max_len: usize,
        expected_magic_hex: String,
        expected_postcard_encoded: bool,
    }

    #[derive(serde::Deserialize)]
    struct LeanFrameResourceEncodeCase {
        name: String,
        kind: String,
        body_bytes: usize,
        expected_total_len: usize,
        expected_valid: bool,
        expected_reject: Option<String>,
        expected_max_len: usize,
        expected_magic_hex: String,
    }

    fn lean_network_frame_kind_constants(kind: &str) -> Option<(usize, &'static [u8; 4], bool)> {
        match kind {
            "network_handshake" => Some((MAX_HANDSHAKE_FRAME_LEN, NETWORK_WIRE_MAGIC, true)),
            "network_wire" => Some((MAX_WIRE_FRAME_LEN, NETWORK_WIRE_MAGIC, true)),
            "network_peer_store" => Some((MAX_PEER_STORE_LEN, NETWORK_WIRE_MAGIC, true)),
            _ => None,
        }
    }

    fn lean_magic_hex(magic: &[u8; 4]) -> String {
        format!("0x{}", hex::encode(magic))
    }

    fn mirror_frame_decode_rejection(
        case: &LeanFrameResourceDecodeCase,
        max_len: usize,
        postcard_encoded: bool,
    ) -> Option<&'static str> {
        if case.encoded_bytes > max_len {
            Some("encoded_bytes_exceeded")
        } else if !case.marker_matches {
            Some("missing_marker")
        } else if postcard_encoded && !case.postcard_decodes {
            Some("postcard_decode_failed")
        } else if postcard_encoded && !case.postcard_consumes_all {
            Some("trailing_bytes")
        } else {
            None
        }
    }

    fn mirror_frame_encode_rejection(
        case: &LeanFrameResourceEncodeCase,
        max_len: usize,
    ) -> Option<&'static str> {
        if case.expected_total_len > max_len {
            Some("encoded_bytes_exceeded")
        } else {
            None
        }
    }

    fn assert_decode_error_contains(bytes: &[u8], max_len: usize, fragment: &str, label: &str) {
        let err = decode::<Sample>(bytes, max_len).expect_err(label);
        assert!(
            err.to_string().contains(fragment),
            "{label}: expected error containing {fragment:?}, got {err}"
        );
    }

    fn assert_network_decode_case_hits_production_path(case: &LeanFrameResourceDecodeCase) {
        let Some((max_len, _magic, _postcard_encoded)) =
            lean_network_frame_kind_constants(&case.kind)
        else {
            return;
        };
        let sample = Sample {
            name: "frame".to_string(),
            payload: vec![1, 2, 3],
        };
        match case.expected_reject.as_deref() {
            None => {
                let encoded = encode(&sample, max_len).expect("encode valid frame");
                let decoded: Sample = decode(&encoded, max_len).expect("decode valid frame");
                assert_eq!(decoded, sample, "{}", case.name);
            }
            Some("encoded_bytes_exceeded") => {
                let oversized = vec![0u8; max_len + 1];
                assert_decode_error_contains(
                    &oversized,
                    max_len,
                    "encoded frame too large",
                    &case.name,
                );
            }
            Some("missing_marker") => {
                assert_decode_error_contains(
                    b"BAD1\x00",
                    max_len,
                    "missing network wire codec marker",
                    &case.name,
                );
            }
            Some("postcard_decode_failed") => {
                assert_decode_error_contains(
                    NETWORK_WIRE_MAGIC,
                    max_len,
                    "postcard decode failed",
                    &case.name,
                );
            }
            Some("trailing_bytes") => {
                let mut encoded = encode(&sample, max_len).expect("encode valid frame");
                encoded.push(0xff);
                assert_decode_error_contains(&encoded, max_len, "postcard decode left", &case.name);
            }
            Some(other) => panic!("unknown Lean rejection {other} in {}", case.name),
        }
    }

    #[test]
    fn lean_generated_frame_resource_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_FRAME_RESOURCE_ADMISSION_VECTORS") else {
            eprintln!("skipping Lean frame-resource vectors; env var not set");
            return;
        };
        let contents = std::fs::read_to_string(path).expect("read Lean frame-resource vectors");
        let vectors: LeanFrameResourceVectorFile =
            serde_json::from_str(&contents).expect("parse Lean frame-resource vectors");
        assert_eq!(vectors.schema_version, 1);

        for constant in &vectors.constants {
            let Some((max_len, magic, postcard_encoded)) =
                lean_network_frame_kind_constants(&constant.kind)
            else {
                continue;
            };
            assert_eq!(constant.max_len, max_len, "{}", constant.kind);
            assert_eq!(
                constant.magic_hex,
                lean_magic_hex(magic),
                "{}",
                constant.kind
            );
            assert_eq!(
                constant.postcard_encoded, postcard_encoded,
                "{}",
                constant.kind
            );
        }

        for case in &vectors.decode_cases {
            let Some((max_len, magic, postcard_encoded)) =
                lean_network_frame_kind_constants(&case.kind)
            else {
                continue;
            };
            assert_eq!(case.expected_max_len, max_len, "{}", case.name);
            assert_eq!(
                case.expected_magic_hex,
                lean_magic_hex(magic),
                "{}",
                case.name
            );
            assert_eq!(
                case.expected_postcard_encoded, postcard_encoded,
                "{}",
                case.name
            );
            let expected = mirror_frame_decode_rejection(case, max_len, postcard_encoded);
            assert_eq!(case.expected_valid, expected.is_none(), "{}", case.name);
            assert_eq!(case.expected_reject.as_deref(), expected, "{}", case.name);
            assert_network_decode_case_hits_production_path(case);
        }

        for case in &vectors.encode_cases {
            let Some((max_len, magic, _postcard_encoded)) =
                lean_network_frame_kind_constants(&case.kind)
            else {
                continue;
            };
            assert_eq!(case.expected_max_len, max_len, "{}", case.name);
            assert_eq!(
                case.expected_magic_hex,
                lean_magic_hex(magic),
                "{}",
                case.name
            );
            assert_eq!(
                case.expected_total_len,
                NETWORK_WIRE_MAGIC.len() + case.body_bytes,
                "{}",
                case.name
            );
            let expected = mirror_frame_encode_rejection(case, max_len);
            assert_eq!(case.expected_valid, expected.is_none(), "{}", case.name);
            assert_eq!(case.expected_reject.as_deref(), expected, "{}", case.name);
        }
    }
}
