------------------------------ MODULE pow_longest_chain ------------------------------
EXTENDS Naturals, TLC

CONSTANTS
    RETARGET_WINDOW, \* 120
    TARGET_INTERVAL, \* 20-second target interval (expressed in seconds)
    MAX_TARGET,
    MIN_TARGET,
    MAX_SKEW, \* 90-second bound on timestamps
    FINALITY_DEPTH, \* 120 confirmation guideline
    ADV_NUM, ADV_DEN \* adversary hash share bound (e.g., 3 / 10)

VARIABLES height, target, sinceRetarget, windowAnchor, timestamp,
          honestWork, adversaryWork, published

MaxWork == (MAX_TARGET - 1)

Work(t) == MaxWork \div (t + 1)

Clamp(x) == IF x < MIN_TARGET THEN MIN_TARGET ELSE IF x > MAX_TARGET THEN MAX_TARGET ELSE x

Init == /\ height = 0
        /\ target = MAX_TARGET
        /\ sinceRetarget = 0
        /\ windowAnchor = 0
        /\ timestamp = 0
        /\ honestWork = 0
        /\ adversaryWork = 0
        /\ published = "honest"

HonestBlock ==
    \E delta \in 1..(TARGET_INTERVAL + MAX_SKEW):
      LET nextTimestamp == timestamp + delta IN
      LET needsRetarget == (sinceRetarget = RETARGET_WINDOW - 1) IN
      LET elapsed == nextTimestamp - windowAnchor IN
      LET nextTarget == IF needsRetarget
                        THEN Clamp(target * elapsed \div (RETARGET_WINDOW * TARGET_INTERVAL))
                        ELSE target IN
      /\ timestamp' = nextTimestamp
      /\ height' = height + 1
      /\ sinceRetarget' = IF needsRetarget THEN 0 ELSE sinceRetarget + 1
      /\ windowAnchor' = IF needsRetarget THEN nextTimestamp ELSE windowAnchor
      /\ target' = nextTarget
      /\ honestWork' = honestWork + Work(nextTarget)
      /\ adversaryWork' = adversaryWork
      /\ published' = IF honestWork' >= adversaryWork' THEN "honest" ELSE published

AdversaryBlock ==
    LET nextAdvWork == adversaryWork + Work(target) IN
    /\ timestamp' = timestamp
    /\ height' = height
    /\ sinceRetarget' = sinceRetarget
    /\ windowAnchor' = windowAnchor
    /\ target' = target
    /\ honestWork' = honestWork
    /\ adversaryWork' = nextAdvWork
    /\ ADV_DEN * nextAdvWork <= ADV_NUM * MAX(1, honestWork)
    /\ published' = IF nextAdvWork > honestWork THEN "adversary" ELSE published

Reorg ==
    /\ published' = IF honestWork >= adversaryWork THEN "honest" ELSE "adversary"
    /\ UNCHANGED << height, target, sinceRetarget, windowAnchor, timestamp, honestWork, adversaryWork >>

Next == HonestBlock \/ AdversaryBlock \/ Reorg

TypeOK == /\ height \in Nat
          /\ target \in Nat
          /\ sinceRetarget \in Nat
          /\ windowAnchor \in Nat
          /\ timestamp \in Nat
          /\ honestWork \in Nat
          /\ adversaryWork \in Nat
          /\ published \in {"honest", "adversary"}

ForkChoiceInvariant == published = IF honestWork >= adversaryWork THEN "honest" ELSE "adversary"

FinalityInvariant == (height >= FINALITY_DEPTH) => honestWork >= adversaryWork

Spec == Init /\ [][Next]_<<height, target, sinceRetarget, windowAnchor, timestamp, honestWork, adversaryWork, published>>

THEOREM Spec => []TypeOK
THEOREM Spec => []ForkChoiceInvariant
THEOREM Spec => []FinalityInvariant
================================================================================
