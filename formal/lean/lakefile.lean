import Lake
open Lake DSL

package hegemon_formal where
  version := v!"0.1.0"

lean_lib Hegemon where
  roots := #[`Hegemon]

lean_exe gen_bridge_vectors where
  root := `Hegemon.Bridge.GenerateVectors

lean_exe gen_shielded_vectors where
  root := `Hegemon.Shielded.GenerateVectors

lean_exe gen_consensus_vectors where
  root := `Hegemon.Consensus.GenerateVectors

lean_exe gen_transaction_vectors where
  root := `Hegemon.Transaction.GenerateVectors
