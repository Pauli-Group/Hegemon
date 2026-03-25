use anyhow::{bail, ensure, Result};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use serde::Serialize;
use superneo_ccs::{ensure_assignment_matches_shape, Assignment, CcsShape};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldilocksPackingConfig {
    pub limb_bits: u16,
    pub coeff_capacity_bits: u16,
    pub reject_out_of_range: bool,
}

impl Default for GoldilocksPackingConfig {
    fn default() -> Self {
        Self {
            limb_bits: 8,
            coeff_capacity_bits: 60,
            reject_out_of_range: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PackedWitness<R> {
    pub coeffs: Vec<R>,
    pub original_len: usize,
    pub used_bits: usize,
    pub coeff_capacity_bits: u16,
}

pub trait WitnessPacker<F, R> {
    fn pack(&self, shape: &CcsShape<F>, assignment: &Assignment<F>) -> Result<PackedWitness<R>>;
    fn unpack(&self, shape: &CcsShape<F>, packed: &PackedWitness<R>) -> Result<Assignment<F>>;
}

#[derive(Clone, Debug, Default)]
pub struct GoldilocksPayPerBitPacker {
    pub config: GoldilocksPackingConfig,
}

impl GoldilocksPayPerBitPacker {
    pub fn new(config: GoldilocksPackingConfig) -> Self {
        Self { config }
    }
}

impl WitnessPacker<Goldilocks, u64> for GoldilocksPayPerBitPacker {
    fn pack(
        &self,
        shape: &CcsShape<Goldilocks>,
        assignment: &Assignment<Goldilocks>,
    ) -> Result<PackedWitness<u64>> {
        ensure_assignment_matches_shape(shape, assignment)?;

        let coeff_capacity = self.config.coeff_capacity_bits;
        ensure!(
            (1..=64).contains(&coeff_capacity),
            "coeff_capacity_bits must be in 1..=64"
        );
        ensure!(
            (1..=64).contains(&self.config.limb_bits),
            "limb_bits must be in 1..=64"
        );

        let mut coeffs = Vec::new();
        let mut current = 0u64;
        let mut bits_used = 0u16;
        let mut witness_idx = 0usize;
        let mut used_bits = 0usize;

        for field in &shape.witness_schema.fields {
            ensure!(
                !field.signed,
                "signed witness fields are not yet supported by GoldilocksPayPerBitPacker"
            );
            for _ in 0..field.count {
                let raw = assignment.witness[witness_idx].as_canonical_u64();
                witness_idx += 1;

                if self.config.reject_out_of_range && field.bit_width < 64 {
                    let max = 1u128 << field.bit_width;
                    ensure!(
                        u128::from(raw) < max,
                        "witness field {} value {} exceeds {} bits",
                        field.name,
                        raw,
                        field.bit_width
                    );
                }

                let mut remaining = field.bit_width;
                let mut source_offset = 0u16;
                while remaining > 0 {
                    if bits_used == coeff_capacity {
                        coeffs.push(current);
                        current = 0;
                        bits_used = 0;
                    }

                    let available = coeff_capacity - bits_used;
                    let take = remaining.min(available);
                    let chunk = extract_bits(raw, source_offset, take);
                    current |= chunk << bits_used;
                    bits_used += take;
                    source_offset += take;
                    remaining -= take;
                    used_bits += usize::from(take);

                    if bits_used == coeff_capacity {
                        coeffs.push(current);
                        current = 0;
                        bits_used = 0;
                    }
                }
            }
        }

        if bits_used > 0 {
            coeffs.push(current);
        }

        Ok(PackedWitness {
            coeffs,
            original_len: assignment.witness.len(),
            used_bits,
            coeff_capacity_bits: coeff_capacity,
        })
    }

    fn unpack(
        &self,
        shape: &CcsShape<Goldilocks>,
        packed: &PackedWitness<u64>,
    ) -> Result<Assignment<Goldilocks>> {
        shape.validate()?;
        let coeff_capacity = self.config.coeff_capacity_bits;
        ensure!(
            (1..=64).contains(&coeff_capacity),
            "coeff_capacity_bits must be in 1..=64"
        );
        ensure!(
            packed.coeff_capacity_bits == coeff_capacity,
            "packed witness coeff capacity {} does not match packer config {}",
            packed.coeff_capacity_bits,
            coeff_capacity
        );
        ensure!(
            (1..=64).contains(&self.config.limb_bits),
            "limb_bits must be in 1..=64"
        );

        let mut witness = Vec::with_capacity(shape.expected_witness_len());
        let mut coeff_idx = 0usize;
        let mut coeff_offset = 0u16;

        for field in &shape.witness_schema.fields {
            ensure!(
                !field.signed,
                "signed witness fields are not yet supported by GoldilocksPayPerBitPacker"
            );
            for _ in 0..field.count {
                let mut raw = 0u64;
                let mut remaining = field.bit_width;
                let mut destination_offset = 0u16;

                while remaining > 0 {
                    let coeff = *packed
                        .coeffs
                        .get(coeff_idx)
                        .ok_or_else(|| anyhow::anyhow!("packed witness ended early"))?;
                    let available = coeff_capacity - coeff_offset;
                    let take = remaining.min(available);
                    let chunk = extract_bits(coeff, coeff_offset, take);
                    raw |= chunk << destination_offset;

                    coeff_offset += take;
                    destination_offset += take;
                    remaining -= take;

                    if coeff_offset == coeff_capacity {
                        coeff_offset = 0;
                        coeff_idx += 1;
                    }
                }

                witness.push(Goldilocks::new(raw));
            }
        }

        if witness.len() != packed.original_len {
            bail!(
                "unpacked witness length {} does not match original {}",
                witness.len(),
                packed.original_len
            );
        }

        Ok(Assignment { witness })
    }
}

fn extract_bits(value: u64, offset: u16, width: u16) -> u64 {
    let shifted = value >> offset;
    match width {
        0 => 0,
        64 => shifted,
        _ => shifted & ((1u64 << width) - 1),
    }
}

#[cfg(test)]
mod tests {
    use superneo_ccs::{Assignment, CcsShape, SparseMatrix, WitnessField, WitnessSchema};

    use super::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};
    use p3_goldilocks::Goldilocks;

    fn shape() -> CcsShape<Goldilocks> {
        CcsShape {
            num_rows: 4,
            num_cols: 4,
            matrices: vec![SparseMatrix {
                row_count: 4,
                col_count: 4,
                entries: Vec::new(),
            }],
            selectors: vec![Goldilocks::new(1)],
            witness_schema: WitnessSchema {
                fields: vec![
                    WitnessField {
                        name: "receipt_len",
                        bit_width: 16,
                        signed: false,
                        count: 1,
                    },
                    WitnessField {
                        name: "byte",
                        bit_width: 8,
                        signed: false,
                        count: 4,
                    },
                    WitnessField {
                        name: "flag",
                        bit_width: 1,
                        signed: false,
                        count: 3,
                    },
                ],
            },
        }
    }

    #[test]
    fn pay_per_bit_packer_round_trips_assignment() {
        let assignment = Assignment {
            witness: vec![
                Goldilocks::new(4),
                Goldilocks::new(200),
                Goldilocks::new(17),
                Goldilocks::new(3),
                Goldilocks::new(99),
                Goldilocks::new(1),
                Goldilocks::new(0),
                Goldilocks::new(1),
            ],
        };
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let packed = packer.pack(&shape(), &assignment).unwrap();
        let unpacked = packer.unpack(&shape(), &packed).unwrap();
        assert_eq!(assignment, unpacked);
        assert!(packed.used_bits < packed.coeffs.len() * 64);
    }

    #[test]
    fn signed_fields_fail_fast() {
        let mut signed_shape = shape();
        signed_shape.witness_schema.fields[0].signed = true;
        let assignment = Assignment {
            witness: vec![
                Goldilocks::new(4),
                Goldilocks::new(200),
                Goldilocks::new(17),
                Goldilocks::new(3),
                Goldilocks::new(99),
                Goldilocks::new(1),
                Goldilocks::new(0),
                Goldilocks::new(1),
            ],
        };
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        assert!(packer.pack(&signed_shape, &assignment).is_err());
    }
}
