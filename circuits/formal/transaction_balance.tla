----------------------------- MODULE transaction_balance -----------------------------
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS MAX_INPUTS, MAX_OUTPUTS, FeeLimit, NativeAsset

VARIABLES inputs, outputs, fee, nullifiers

Input == [value : Nat, asset : Nat, rho : Nat]
Output == [value : Nat, asset : Nat]

vars == <<inputs, outputs, fee, nullifiers>>

Init ==
    /\ inputs \in Seq(Input)
    /\ outputs \in Seq(Output)
    /\ Len(inputs) <= MAX_INPUTS
    /\ Len(outputs) <= MAX_OUTPUTS
    /\ fee \in 0..FeeLimit
    /\ fee <= SumInputs(inputs, NativeAsset)
    /\ nullifiers = NullifierSet(inputs)

Next == UNCHANGED vars

AssetUniverse == {NativeAsset}
    \cup { inputs[i].asset : i \in DOMAIN inputs }
    \cup { outputs[i].asset : i \in DOMAIN outputs }

RECURSIVE SumInputs(_, _)
SumInputs(seq, asset) ==
    IF seq = << >> THEN 0
    ELSE LET head == Head(seq)
             tail == Tail(seq) IN
         (IF head.asset = asset THEN head.value ELSE 0) + SumInputs(tail, asset)

RECURSIVE SumOutputs(_, _)
SumOutputs(seq, asset) ==
    IF seq = << >> THEN 0
    ELSE LET head == Head(seq)
             tail == Tail(seq) IN
         (IF head.asset = asset THEN head.value ELSE 0) + SumOutputs(tail, asset)

NativeInputSum == SumInputs(inputs, NativeAsset)
NativeOutputSum == SumOutputs(outputs, NativeAsset)

BalanceInvariant ==
    /\ NativeInputSum = NativeOutputSum + fee
    /\ \A asset \in (AssetUniverse \ {NativeAsset}): SumInputs(inputs, asset) = SumOutputs(outputs, asset)

NullifierSet(seq) == { seq[i].rho : i \in DOMAIN seq }

NullifierUniqueness == Cardinality(nullifiers) = Len(inputs)

TypeOK ==
    /\ inputs \in Seq(Input)
    /\ outputs \in Seq(Output)
    /\ Len(inputs) <= MAX_INPUTS
    /\ Len(outputs) <= MAX_OUTPUTS
    /\ fee \in 0..FeeLimit
    /\ nullifiers = NullifierSet(inputs)

Spec == Init /\ [][Next]_vars

=============================================================================
