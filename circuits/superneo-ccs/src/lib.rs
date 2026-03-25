use std::fmt;

use anyhow::{bail, ensure, Result};
use blake3::Hasher;
use p3_field::PrimeField64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RelationId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapeDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StatementDigest(pub [u8; 48]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessField {
    pub name: &'static str,
    pub bit_width: u16,
    pub signed: bool,
    pub count: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WitnessSchema {
    pub fields: Vec<WitnessField>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseEntry<F> {
    pub row: usize,
    pub col: usize,
    pub value: F,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMatrix<F> {
    pub row_count: usize,
    pub col_count: usize,
    pub entries: Vec<SparseEntry<F>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CcsShape<F> {
    pub num_rows: usize,
    pub num_cols: usize,
    pub matrices: Vec<SparseMatrix<F>>,
    pub selectors: Vec<F>,
    pub witness_schema: WitnessSchema,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementEncoding<F> {
    pub public_inputs: Vec<F>,
    pub statement_digest: StatementDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment<F> {
    pub witness: Vec<F>,
}

pub trait Relation<F> {
    type Statement;
    type Witness;

    fn relation_id(&self) -> RelationId;
    fn shape(&self) -> &CcsShape<F>;
    fn encode_statement(&self, statement: &Self::Statement) -> Result<StatementEncoding<F>>;
    fn build_assignment(
        &self,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Assignment<F>>;
}

pub trait CanonicalFieldBytes {
    fn append_canonical_bytes(&self, out: &mut Vec<u8>);
}

impl<F> CanonicalFieldBytes for F
where
    F: PrimeField64,
{
    fn append_canonical_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.as_canonical_u64().to_le_bytes());
    }
}

impl RelationId {
    pub const BYTES: usize = 32;

    pub fn from_label(label: &str) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.relation.v1");
        hasher.update(label.as_bytes());
        let mut out = [0u8; 32];
        hasher.finalize_xof().fill(&mut out);
        Self(out)
    }

    pub fn to_hex(&self) -> String {
        hex_bytes(&self.0)
    }
}

impl Serialize for RelationId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelationId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let len = bytes.len();
        let array: [u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(len, &"32 bytes"))?;
        Ok(Self(array))
    }
}

impl Serialize for ShapeDigest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ShapeDigest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let len = bytes.len();
        let array: [u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(len, &"32 bytes"))?;
        Ok(Self(array))
    }
}

impl Serialize for StatementDigest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for StatementDigest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let len = bytes.len();
        let array: [u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(len, &"48 bytes"))?;
        Ok(Self(array))
    }
}

impl ShapeDigest {
    pub const BYTES: usize = 32;

    pub fn to_hex(&self) -> String {
        hex_bytes(&self.0)
    }
}

impl StatementDigest {
    pub const BYTES: usize = 48;

    pub fn to_hex(&self) -> String {
        hex_bytes(&self.0)
    }
}

impl fmt::Display for RelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for ShapeDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for StatementDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl WitnessSchema {
    pub fn total_witness_elements(&self) -> usize {
        self.fields.iter().map(|field| field.count).sum()
    }

    pub fn total_witness_bits(&self) -> usize {
        self.fields
            .iter()
            .map(|field| field.bit_width as usize * field.count)
            .sum()
    }
}

impl<F> CcsShape<F> {
    pub fn expected_witness_len(&self) -> usize {
        self.witness_schema.total_witness_elements()
    }

    pub fn validate(&self) -> Result<()> {
        if self.num_rows == 0 || self.num_cols == 0 {
            bail!("CCS shape must have non-zero dimensions");
        }

        for (matrix_idx, matrix) in self.matrices.iter().enumerate() {
            ensure!(
                matrix.row_count == self.num_rows,
                "matrix {matrix_idx} row count {} does not match shape rows {}",
                matrix.row_count,
                self.num_rows
            );
            ensure!(
                matrix.col_count == self.num_cols,
                "matrix {matrix_idx} col count {} does not match shape cols {}",
                matrix.col_count,
                self.num_cols
            );
            for entry in &matrix.entries {
                ensure!(
                    entry.row < self.num_rows,
                    "matrix {matrix_idx} entry row {} out of bounds {}",
                    entry.row,
                    self.num_rows
                );
                ensure!(
                    entry.col < self.num_cols,
                    "matrix {matrix_idx} entry col {} out of bounds {}",
                    entry.col,
                    self.num_cols
                );
            }
        }

        for field in &self.witness_schema.fields {
            ensure!(
                field.bit_width > 0,
                "witness field {} has zero width",
                field.name
            );
            ensure!(
                field.bit_width <= 64,
                "witness field {} exceeds 64-bit packing budget",
                field.name
            );
        }

        Ok(())
    }
}

pub fn ensure_assignment_matches_shape<F>(
    shape: &CcsShape<F>,
    assignment: &Assignment<F>,
) -> Result<()> {
    shape.validate()?;
    ensure!(
        assignment.witness.len() == shape.expected_witness_len(),
        "assignment length {} does not match witness schema length {}",
        assignment.witness.len(),
        shape.expected_witness_len()
    );
    Ok(())
}

pub fn digest_shape<F>(shape: &CcsShape<F>) -> ShapeDigest
where
    F: CanonicalFieldBytes,
{
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.shape.v1");
    hasher.update(&(shape.num_rows as u64).to_le_bytes());
    hasher.update(&(shape.num_cols as u64).to_le_bytes());
    hasher.update(&(shape.matrices.len() as u64).to_le_bytes());
    hasher.update(&(shape.selectors.len() as u64).to_le_bytes());

    for matrix in &shape.matrices {
        hasher.update(&(matrix.row_count as u64).to_le_bytes());
        hasher.update(&(matrix.col_count as u64).to_le_bytes());
        hasher.update(&(matrix.entries.len() as u64).to_le_bytes());
        for entry in &matrix.entries {
            hasher.update(&(entry.row as u64).to_le_bytes());
            hasher.update(&(entry.col as u64).to_le_bytes());
            let mut bytes = Vec::with_capacity(8);
            entry.value.append_canonical_bytes(&mut bytes);
            hasher.update(&bytes);
        }
    }

    for selector in &shape.selectors {
        let mut bytes = Vec::with_capacity(8);
        selector.append_canonical_bytes(&mut bytes);
        hasher.update(&bytes);
    }

    for field in &shape.witness_schema.fields {
        hasher.update(field.name.as_bytes());
        hasher.update(&field.bit_width.to_le_bytes());
        hasher.update(&[u8::from(field.signed)]);
        hasher.update(&(field.count as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    ShapeDigest(out)
}

pub fn digest_statement(bytes: &[u8]) -> StatementDigest {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.statement.v1");
    hasher.update(bytes);
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    StatementDigest(out)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use p3_goldilocks::Goldilocks;

    use super::{
        digest_shape, digest_statement, ensure_assignment_matches_shape, Assignment, CcsShape,
        SparseEntry, SparseMatrix, WitnessField, WitnessSchema,
    };

    fn sample_shape() -> CcsShape<Goldilocks> {
        CcsShape {
            num_rows: 2,
            num_cols: 3,
            matrices: vec![SparseMatrix {
                row_count: 2,
                col_count: 3,
                entries: vec![SparseEntry {
                    row: 0,
                    col: 1,
                    value: Goldilocks::new(7),
                }],
            }],
            selectors: vec![Goldilocks::new(1)],
            witness_schema: WitnessSchema {
                fields: vec![
                    WitnessField {
                        name: "a",
                        bit_width: 8,
                        signed: false,
                        count: 1,
                    },
                    WitnessField {
                        name: "b",
                        bit_width: 3,
                        signed: false,
                        count: 2,
                    },
                ],
            },
        }
    }

    #[test]
    fn digest_helpers_are_stable_shape_sensitive() {
        let left = sample_shape();
        let mut right = sample_shape();
        right.matrices[0].entries[0].col = 2;
        assert_ne!(digest_shape(&left), digest_shape(&right));
        assert_ne!(digest_statement(b"a"), digest_statement(b"b"));
    }

    #[test]
    fn assignment_validation_uses_schema_width() {
        let shape = sample_shape();
        let assignment = Assignment {
            witness: vec![Goldilocks::new(1), Goldilocks::new(2), Goldilocks::new(3)],
        };
        ensure_assignment_matches_shape(&shape, &assignment).unwrap();
    }
}
