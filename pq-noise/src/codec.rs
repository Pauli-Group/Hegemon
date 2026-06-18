use crate::error::{PqNoiseError, Result};
use serde::{de::DeserializeOwned, Serialize};

pub(crate) const HANDSHAKE_MAX_FRAME_LEN: usize = 64 * 1024;

pub(crate) const HANDSHAKE_MAGIC: &[u8; 4] = b"PNH1";
pub(crate) const SESSION_MAGIC: &[u8; 4] = b"PNS1";
pub(crate) const TRANSCRIPT_MAGIC: &[u8; 4] = b"PNT1";

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

    #[derive(Deserialize)]
    struct LeanFrameResourceVectorFile {
        schema_version: u32,
        constants: Vec<LeanFrameResourceConstant>,
        decode_cases: Vec<LeanFrameResourceDecodeCase>,
        encode_cases: Vec<LeanFrameResourceEncodeCase>,
    }

    #[derive(Deserialize)]
    struct LeanFrameResourceConstant {
        kind: String,
        max_len: usize,
        magic_hex: String,
        postcard_encoded: bool,
    }

    #[derive(Deserialize)]
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

    #[derive(Deserialize)]
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

    fn lean_pq_frame_kind_constants(kind: &str) -> Option<(usize, &'static [u8; 4], bool)> {
        match kind {
            "pq_handshake" => Some((HANDSHAKE_MAX_FRAME_LEN, HANDSHAKE_MAGIC, true)),
            "pq_session_plaintext" => Some((
                crate::session::SESSION_MAX_PLAINTEXT_LEN,
                SESSION_MAGIC,
                true,
            )),
            "pq_transcript" => Some((HANDSHAKE_MAX_FRAME_LEN, TRANSCRIPT_MAGIC, true)),
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

    fn assert_decode_error_contains(result: Result<Sample>, fragment: &str, label: &str) {
        let err = result.expect_err(label);
        assert!(
            err.to_string().contains(fragment),
            "{label}: expected error containing {fragment:?}, got {err}"
        );
    }

    fn assert_pq_decode_case_hits_production_path(case: &LeanFrameResourceDecodeCase) {
        let Some((max_len, _magic, _postcard_encoded)) = lean_pq_frame_kind_constants(&case.kind)
        else {
            return;
        };
        if case.kind == "pq_transcript" {
            return;
        }
        let sample = Sample {
            nonce: 13,
            payload: vec![1, 2, 3],
        };
        match (case.kind.as_str(), case.expected_reject.as_deref()) {
            ("pq_handshake", None) => {
                let encoded = encode_handshake(&sample).expect("encode valid handshake frame");
                let decoded: Sample = decode_handshake(&encoded).expect("decode valid frame");
                assert_eq!(decoded, sample, "{}", case.name);
            }
            ("pq_session_plaintext", None) => {
                let encoded = encode_session(&sample, max_len).expect("encode valid session frame");
                let decoded: Sample =
                    decode_session(&encoded, max_len).expect("decode valid session frame");
                assert_eq!(decoded, sample, "{}", case.name);
            }
            (_, Some("encoded_bytes_exceeded")) => {
                let oversized = vec![0u8; max_len + 1];
                let result = match case.kind.as_str() {
                    "pq_handshake" => decode_handshake::<Sample>(&oversized),
                    "pq_session_plaintext" => decode_session::<Sample>(&oversized, max_len),
                    other => panic!("unsupported PQ decode kind {other}"),
                };
                assert_decode_error_contains(result, "encoded frame too large", &case.name);
            }
            (_, Some("missing_marker")) => {
                let result = match case.kind.as_str() {
                    "pq_handshake" => decode_handshake::<Sample>(b"BAD1\x00"),
                    "pq_session_plaintext" => decode_session::<Sample>(b"BAD1\x00", max_len),
                    other => panic!("unsupported PQ decode kind {other}"),
                };
                assert_decode_error_contains(result, "missing PQ Noise codec marker", &case.name);
            }
            ("pq_handshake", Some("postcard_decode_failed")) => {
                assert_decode_error_contains(
                    decode_handshake::<Sample>(HANDSHAKE_MAGIC),
                    "postcard decode failed",
                    &case.name,
                );
            }
            ("pq_session_plaintext", Some("postcard_decode_failed")) => {
                assert_decode_error_contains(
                    decode_session::<Sample>(SESSION_MAGIC, max_len),
                    "postcard decode failed",
                    &case.name,
                );
            }
            ("pq_handshake", Some("trailing_bytes")) => {
                let mut encoded = encode_handshake(&sample).expect("encode valid handshake frame");
                encoded.push(0xff);
                assert_decode_error_contains(
                    decode_handshake::<Sample>(&encoded),
                    "postcard decode left",
                    &case.name,
                );
            }
            ("pq_session_plaintext", Some("trailing_bytes")) => {
                let mut encoded = encode_session(&sample, max_len).expect("encode valid frame");
                encoded.push(0xff);
                assert_decode_error_contains(
                    decode_session::<Sample>(&encoded, max_len),
                    "postcard decode left",
                    &case.name,
                );
            }
            (_, Some(other)) => panic!("unknown Lean rejection {other} in {}", case.name),
            (other, None) => panic!("unsupported PQ valid decode kind {other}"),
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
                lean_pq_frame_kind_constants(&constant.kind)
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
            let Some((max_len, magic, postcard_encoded)) = lean_pq_frame_kind_constants(&case.kind)
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
            assert_pq_decode_case_hits_production_path(case);
        }

        for case in &vectors.encode_cases {
            let Some((max_len, magic, _postcard_encoded)) =
                lean_pq_frame_kind_constants(&case.kind)
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
                magic.len() + case.body_bytes,
                "{}",
                case.name
            );
            let expected = mirror_frame_encode_rejection(case, max_len);
            assert_eq!(case.expected_valid, expected.is_none(), "{}", case.name);
            assert_eq!(case.expected_reject.as_deref(), expected, "{}", case.name);
        }

        let transcript = encode_transcript(&Sample {
            nonce: 21,
            payload: vec![8, 9],
        })
        .expect("encode transcript");
        assert!(transcript.starts_with(TRANSCRIPT_MAGIC));
    }
}
