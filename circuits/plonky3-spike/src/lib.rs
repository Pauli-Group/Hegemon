#![cfg(feature = "plonky3")]

mod fibonacci;

pub use fibonacci::{prove_and_verify, FibProofStats};

#[cfg(test)]
mod tests {
    use super::prove_and_verify;

    #[test]
    fn fibonacci_prove_verify() {
        prove_and_verify();
    }
}
