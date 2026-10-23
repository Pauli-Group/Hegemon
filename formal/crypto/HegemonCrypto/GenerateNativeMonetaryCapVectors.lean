import HegemonCrypto.NativeMonetaryCap

namespace HegemonCrypto.NativeMonetaryCapVectors
open Hegemon.Consensus
open NativeMonetaryCap

def epochCaseJson (epoch : Nat) : String :=
  "    {\"epoch\": " ++ toString epoch
    ++ ", \"remaining_budget\": \"" ++ toString (remainingBudget epoch)
    ++ "\", \"next_remaining_budget\": \"" ++ toString (remainingBudget (epoch + 1))
    ++ "\", \"epoch_budget\": \"" ++ toString (epochBudget epoch)
    ++ "\", \"first_height\": " ++ toString (epoch * halvingInterval + 1)
    ++ ", \"last_height\": " ++ toString ((epoch + 1) * halvingInterval)
    ++ ", \"first_subsidy\": " ++ toString (slotSubsidy epoch 0)
    ++ ", \"last_subsidy\": " ++ toString (slotSubsidy epoch (halvingInterval - 1))
    ++ ", \"scheduled_prefix_before\": \"" ++ toString (scheduledPrefix (epoch * halvingInterval))
    ++ "\", \"scheduled_prefix_after\": \"" ++ toString (scheduledPrefix ((epoch + 1) * halvingInterval))
    ++ "\"}"

/-- Evaluate the actual floor prefix, without iterating millions of slots.
Boundary slotH uses the first slot of the next epoch through blockSubsidy. -/
def slotCaseJson (epoch slots : Nat) : String :=
  "    {\"epoch\": " ++ toString epoch
    ++ ", \"slots\": " ++ toString slots
    ++ ", \"slot_prefix_subsidy\": \""
      ++ toString (slots * epochBudget epoch / halvingInterval)
    ++ "\", \"height_after_slots\": " ++ toString (epoch * halvingInterval + slots)
    ++ ", \"next_height\": " ++ toString (epoch * halvingInterval + slots + 1)
    ++ ", \"next_subsidy\": " ++ toString (blockSubsidy (epoch * halvingInterval + slots + 1))
    ++ ", \"scheduled_prefix\": \"" ++ toString (scheduledPrefix (epoch * halvingInterval + slots))
    ++ "\"}"

def heightCaseJson (name : String) (height : Nat) : String :=
  "    {\"name\": \"" ++ name ++ "\", \"height\": " ++ toString height
    ++ ", \"expected_subsidy\": " ++ toString (blockSubsidy height)
    ++ ", \"scheduled_prefix\": \"" ++ toString (scheduledPrefix height) ++ "\"}"

def epochCasesJson : String :=
  String.intercalate ",\n" ((List.range 64).map epochCaseJson)

def slotCasesJson : String :=
  String.intercalate ",\n" ((List.range 64).flatMap (fun epoch =>
    [0, 1, halvingInterval / 2, halvingInterval - 1, halvingInterval].map
      (fun slots => slotCaseJson epoch slots)))

/-- Actual definition evaluations. Strict producer/proof receipts must be
independently authenticated; previous-policy vectors remain historical. -/
def vectorJson : String :=
  "{\n  \"schema_version\": 2,\n"
    ++ "  \"schedule_mode\": \"epoch-budget-prefix-differences-v1\",\n"
    ++ "  \"exact_total_subsidy_base_units\": \"" ++ toString lifetimeIssuance ++ "\",\n"
    ++ "  \"subsidy_bucket_count\": 51,\n"
    ++ "  \"max_schedule_epoch\": 64,\n"
    ++ "  \"max_monetary_supply\": \"" ++ toString maxMonetarySupply ++ "\",\n"
    ++ "  \"coin\": " ++ toString coin ++ ",\n"
    ++ "  \"halving_interval\": " ++ toString halvingInterval ++ ",\n"
    ++ "  \"initial_subsidy_base_units\": \"" ++ toString (blockSubsidy 1) ++ "\",\n"
    ++ "  \"last_positive_height\": 107100000,\n"
    ++ "  \"cutoff_height\": 107100001,\n"
    ++ "  \"formula\": \"R(e)=if e<64 then S/2^e else 0; B(e)=R(e)-R(e+1); reward(e,j)=floor((j+1)*B(e)/H)-floor(j*B(e)/H)\",\n"
    ++ "  \"epoch_budget_cases\": [\n" ++ epochCasesJson ++ "\n  ],\n"
    ++ "  \"slot_prefix_cases\": [\n" ++ slotCasesJson ++ "\n  ],\n"
    ++ "  \"height_cases\": [\n"
    ++ heightCaseJson "zero-height" 0 ++ ",\n"
    ++ heightCaseJson "initial-five-coins" 1 ++ ",\n"
    ++ heightCaseJson "first-epoch-last" halvingInterval ++ ",\n"
    ++ heightCaseJson "first-halving-first" (halvingInterval + 1) ++ ",\n"
    ++ heightCaseJson "last-positive-slot" 107100000 ++ ",\n"
    ++ heightCaseJson "finite-cutoff" 107100001 ++ ",\n"
    ++ heightCaseJson "after64-window" (64 * halvingInterval + 1) ++ ",\n"
    ++ heightCaseJson "u64-height-maximum" maxU64 ++ "\n  ]\n}\n"

end HegemonCrypto.NativeMonetaryCapVectors

def main : IO Unit := IO.print HegemonCrypto.NativeMonetaryCapVectors.vectorJson
