import Hegemon.Consensus.Supply

/-! Source-shaped monetary projection of the fresh native database genesis.
PRIMARY node/src/native/storage.rs genesis_meta and the shipping SRC successor
genesis_meta_for_network both create a height0 header with zero
supply/transactions/actions; SRC additionally validates compact PoW bits.
Fresh commitment/nullifier state allocates no funded notes. Nonzero empty-tree
hashes are not balances.
The projection below deliberately omits root/hash/DA encodings and PoW validity:
those require independent Rust conformance. It proves this model, not absence
of allocations in every test/helper, not native execution/refinement. -/
namespace Hegemon.Native.GenesisMonetaryPolicy

structure GenesisContext where
  powBits : Nat
  networkTag : Nat
  timestampMs : Nat
  deriving DecidableEq, Repr

structure MonetaryProjection where
  height : Nat
  supplyDigest : Nat
  txCount : Nat
  messageCount : Nat
  actionBytes : List UInt8
  fundedNativeNotes : List Nat
  spentNullifiers : List Nat
  coinbaseAllocation : Nat
  deriving DecidableEq, Repr

/-- Projection of a successfully constructed fresh native genesis. Invalid bits
may be rejected before this state exists; changing valid PoW metadata does not
change this allocation projection. -/
def freshNativeGenesis (_context : GenesisContext) : MonetaryProjection :=
  { height := 0, supplyDigest := 0, txCount := 0, messageCount := 0,
    actionBytes := [], fundedNativeNotes := [], spentNullifiers := [],
    coinbaseAllocation := 0 }

theorem fresh_height_zero (context : GenesisContext) :
    (freshNativeGenesis context).height = 0 := rfl

theorem fresh_supply_zero (context : GenesisContext) :
    (freshNativeGenesis context).supplyDigest = 0 := rfl

theorem fresh_transactions_zero (context : GenesisContext) :
    (freshNativeGenesis context).txCount = 0 := rfl

theorem fresh_messages_zero (context : GenesisContext) :
    (freshNativeGenesis context).messageCount = 0 := rfl

theorem fresh_action_bytes_empty (context : GenesisContext) :
    (freshNativeGenesis context).actionBytes = [] := rfl

theorem fresh_native_notes_empty (context : GenesisContext) :
    (freshNativeGenesis context).fundedNativeNotes = [] := rfl

theorem fresh_nullifiers_empty (context : GenesisContext) :
    (freshNativeGenesis context).spentNullifiers = [] := rfl

theorem fresh_coinbase_allocation_zero (context : GenesisContext) :
    (freshNativeGenesis context).coinbaseAllocation = 0 := rfl

theorem fresh_subsidy_zero (context : GenesisContext) :
    Hegemon.Consensus.blockSubsidy (freshNativeGenesis context).height = 0 :=
  Hegemon.Consensus.blockSubsidy_zero_height

theorem pow_bits_independent (context : GenesisContext) (otherBits : Nat) :
    freshNativeGenesis { context with powBits := otherBits } = freshNativeGenesis context := rfl

theorem network_timestamp_independent (left right : GenesisContext) :
    freshNativeGenesis left = freshNativeGenesis right := rfl

end Hegemon.Native.GenesisMonetaryPolicy
