import HegemonCrypto.SmallWoodV8Smz9StableCollateralEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableCanonicalEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCollateralEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCollateral

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

theorem admitted_stable_mint_collateral {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (direction : statement.stablecoin.direction = .mint) :
    let config := decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin
    statement.stablecoin.after.totalDebt * config.oraclePriceDenominator * config.minCollateralRatioPpm ≤
      config.collateralAmount * config.oraclePriceNumerator * stablecoinV8RatioScalePpm := by
  have publicFields := admitted_stable_public_counters domain
  have rawDirection : publicWords.getD 83 0 = 1 := by rw [publicFields.1,direction]; rfl
  have source (word : Nat) (bound : word < 55) := admitted_stable_config_word_source domain bound
  have result := accepted_mint_collateral domain.2.2 rawDirection
  simpa only [decodeV8StablecoinConfig,source 18 (by decide),source 13 (by decide),source 19 (by decide),
    source 17 (by decide),Nat.reduceAdd,stablecoinV8RatioScalePpm,publicFields.2.2.2.2.2.1] using result


end HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCollateralEndpoint
