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

    fn decode_transcript_for_test<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        decode_with_magic(bytes, TRANSCRIPT_MAGIC, HANDSHAKE_MAX_FRAME_LEN)
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
            ("pq_transcript", None) => {
                let encoded = encode_transcript(&sample).expect("encode valid transcript frame");
                let decoded: Sample =
                    decode_transcript_for_test(&encoded).expect("decode valid transcript frame");
                assert_eq!(decoded, sample, "{}", case.name);
            }
            (_, Some("encoded_bytes_exceeded")) => {
                let oversized = vec![0u8; max_len + 1];
                let result = match case.kind.as_str() {
                    "pq_handshake" => decode_handshake::<Sample>(&oversized),
                    "pq_session_plaintext" => decode_session::<Sample>(&oversized, max_len),
                    "pq_transcript" => decode_transcript_for_test::<Sample>(&oversized),
                    other => panic!("unsupported PQ decode kind {other}"),
                };
                assert_decode_error_contains(result, "encoded frame too large", &case.name);
            }
            (_, Some("missing_marker")) => {
                let result = match case.kind.as_str() {
                    "pq_handshake" => decode_handshake::<Sample>(b"BAD1\x00"),
                    "pq_session_plaintext" => decode_session::<Sample>(b"BAD1\x00", max_len),
                    "pq_transcript" => decode_transcript_for_test::<Sample>(b"BAD1\x00"),
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
            ("pq_transcript", Some("postcard_decode_failed")) => {
                assert_decode_error_contains(
                    decode_transcript_for_test::<Sample>(TRANSCRIPT_MAGIC),
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
            ("pq_transcript", Some("trailing_bytes")) => {
                let mut encoded =
                    encode_transcript(&sample).expect("encode valid transcript frame");
                encoded.push(0xff);
                assert_decode_error_contains(
                    decode_transcript_for_test::<Sample>(&encoded),
                    "postcard decode left",
                    &case.name,
                );
            }
            (_, Some(other)) => panic!("unknown Lean rejection {other} in {}", case.name),
            (other, None) => panic!("unsupported PQ valid decode kind {other}"),
        }
    }

    #[test]
    fn pq_noise_decode_matches_marker_limit_postcard_oracle_on_mutation_corpus() {
        let sample = Sample {
            nonce: 37,
            payload: vec![1, 2, 3, 4, 5],
        };

        let handshake = encode_handshake(&sample).expect("encode handshake oracle sample");
        let handshake_corpus =
            frame_decode_oracle_corpus(HANDSHAKE_MAGIC, HANDSHAKE_MAX_FRAME_LEN, vec![handshake]);
        assert_pq_decode_corpus_matches_oracle(
            "pq-handshake",
            &handshake_corpus,
            HANDSHAKE_MAGIC,
            HANDSHAKE_MAX_FRAME_LEN,
            |raw| decode_handshake::<Sample>(raw).is_ok(),
        );

        let session = encode_session(&sample, crate::session::SESSION_MAX_PLAINTEXT_LEN)
            .expect("encode session oracle sample");
        let session_corpus = frame_decode_oracle_corpus(
            SESSION_MAGIC,
            crate::session::SESSION_MAX_PLAINTEXT_LEN,
            vec![session],
        );
        assert_pq_decode_corpus_matches_oracle(
            "pq-session",
            &session_corpus,
            SESSION_MAGIC,
            crate::session::SESSION_MAX_PLAINTEXT_LEN,
            |raw| decode_session::<Sample>(raw, crate::session::SESSION_MAX_PLAINTEXT_LEN).is_ok(),
        );

        let transcript = encode_transcript(&sample).expect("encode transcript oracle sample");
        let transcript_corpus =
            frame_decode_oracle_corpus(TRANSCRIPT_MAGIC, HANDSHAKE_MAX_FRAME_LEN, vec![transcript]);
        assert_pq_decode_corpus_matches_oracle(
            "pq-transcript",
            &transcript_corpus,
            TRANSCRIPT_MAGIC,
            HANDSHAKE_MAX_FRAME_LEN,
            |raw| decode_transcript_for_test::<Sample>(raw).is_ok(),
        );
    }

    fn assert_pq_decode_corpus_matches_oracle<F>(
        label: &str,
        corpus: &[Vec<u8>],
        magic: &[u8; 4],
        max_len: usize,
        decode_accepts: F,
    ) where
        F: Fn(&[u8]) -> bool,
    {
        assert!(
            corpus.len() >= 256,
            "{label} corpus must stay broad enough to catch parser drift"
        );
        for (idx, raw) in corpus.iter().enumerate() {
            let expected = frame_decode_postcard_oracle_accepts::<Sample>(raw, magic, max_len);
            let actual = decode_accepts(raw);
            assert_eq!(
                actual,
                expected,
                "{label} oracle mismatch at corpus index {idx}, len={}, prefix={}",
                raw.len(),
                hex::encode(&raw[..raw.len().min(16)])
            );
        }
    }

    fn frame_decode_postcard_oracle_accepts<T: serde::de::DeserializeOwned>(
        raw: &[u8],
        magic: &[u8; 4],
        max_len: usize,
    ) -> bool {
        if raw.len() > max_len || !raw.starts_with(magic) {
            return false;
        }
        let Ok((_value, remaining)) = postcard::take_from_bytes::<T>(&raw[magic.len()..]) else {
            return false;
        };
        remaining.is_empty()
    }

    fn frame_decode_oracle_corpus(
        magic: &[u8; 4],
        max_len: usize,
        valid_frames: Vec<Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        let mut corpus = vec![
            Vec::new(),
            vec![0],
            magic.to_vec(),
            b"BAD1".to_vec(),
            b"BAD1\x00".to_vec(),
            vec![0xff; magic.len()],
        ];
        for len in [
            1usize, 2, 3, 4, 5, 8, 16, 31, 32, 33, 48, 64, 96, 127, 128, 129, 255, 256, 257, 512,
        ] {
            for seed_offset in 0..16u64 {
                corpus.push(deterministic_frame_noise(
                    0x5051_4e4f_4953_45 ^ len as u64 ^ seed_offset.wrapping_mul(0x9e37_79b9),
                    len,
                ));

                if len >= magic.len() {
                    let mut marker_prefixed = deterministic_frame_noise(
                        0x4d41_524b_5051_4e ^ len as u64 ^ seed_offset.wrapping_mul(0x517c_c1b7),
                        len,
                    );
                    marker_prefixed[..magic.len()].copy_from_slice(magic);
                    corpus.push(marker_prefixed);
                }
            }
        }
        let mut oversized = Vec::with_capacity(max_len.saturating_add(1));
        oversized.extend_from_slice(magic);
        oversized.resize(max_len.saturating_add(1), 0);
        corpus.push(oversized);

        for encoded in valid_frames {
            extend_frame_decode_corpus_from_valid_frame(&mut corpus, magic, &encoded);
        }
        corpus
    }

    fn deterministic_frame_noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.push((state >> 32) as u8);
        }
        out
    }

    fn extend_frame_decode_corpus_from_valid_frame(
        corpus: &mut Vec<Vec<u8>>,
        magic: &[u8; 4],
        encoded: &[u8],
    ) {
        corpus.push(encoded.to_vec());

        for byte in [0x00, 0x55, 0xaa, 0xff] {
            let mut trailing = encoded.to_vec();
            trailing.push(byte);
            corpus.push(trailing);
        }

        for cut in frame_decode_cut_points(encoded.len()) {
            corpus.push(encoded[..cut].to_vec());
        }

        for offset in frame_decode_mutation_offsets(encoded.len()) {
            let mut mutated = encoded.to_vec();
            mutated[offset] ^= 0xff;
            corpus.push(mutated);
        }

        for offset in 0..encoded.len().min(8) {
            let mut mutated = encoded.to_vec();
            mutated.insert(offset, 0);
            corpus.push(mutated);
        }

        let mut wrong_magic = encoded.to_vec();
        wrong_magic[..magic.len()].copy_from_slice(b"BAD1");
        corpus.push(wrong_magic);
    }

    fn frame_decode_cut_points(len: usize) -> std::collections::BTreeSet<usize> {
        let mut cuts = std::collections::BTreeSet::new();
        for cut in 0..=len.min(64) {
            cuts.insert(cut);
        }
        for boundary in [1usize, 2, 3, 4, 5, 8, 16, 32, 64, 128, len] {
            for delta in [0usize, 1, 2, 3] {
                if let Some(cut) = boundary.checked_sub(delta) {
                    if cut <= len {
                        cuts.insert(cut);
                    }
                }
                let cut = boundary.saturating_add(delta);
                if cut <= len {
                    cuts.insert(cut);
                }
            }
        }
        cuts
    }

    fn frame_decode_mutation_offsets(len: usize) -> std::collections::BTreeSet<usize> {
        let mut offsets = std::collections::BTreeSet::new();
        if len == 0 {
            return offsets;
        }
        for offset in 0..len.min(64) {
            offsets.insert(offset);
        }
        for offset in [
            0usize,
            1,
            2,
            3,
            4,
            5,
            8,
            16,
            31,
            32,
            47,
            48,
            63,
            64,
            len - 1,
        ] {
            if offset < len {
                offsets.insert(offset);
            }
        }
        offsets
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
