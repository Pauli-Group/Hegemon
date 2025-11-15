----------------------------- MODULE hotstuff_safety -----------------------------
EXTENDS Naturals, FiniteSets

CONSTANT MaxView

VARIABLES blocks, locked, committed, currentView

Root == [id |-> 0, parent |-> 0, view |-> 0]

vars == <<blocks, locked, committed, currentView>>

Init ==
    /\ blocks = {Root}
    /\ locked = Root.id
    /\ committed = {}
    /\ currentView = 0

NewId == Cardinality(blocks)

Block(id) == CHOOSE b \in blocks : b.id = id

ParentId(id) == IF id = 0 THEN 0 ELSE Block(id).parent

RECURSIVE IsAncestor(_, _)
IsAncestor(a, b) ==
    IF a = b THEN TRUE
    ELSE IF b = 0 THEN FALSE
    ELSE IsAncestor(a, ParentId(b))

Propose ==
    /\ currentView < MaxView
    /\ \E parent \in blocks :
        LET newView == currentView + 1 IN
        LET newBlock == [id |-> NewId, parent |-> parent.id, view |-> newView] IN
            /\ blocks' = blocks \cup {newBlock}
            /\ currentView' = newView
            /\ locked' = IF parent.id = locked THEN newBlock.id ELSE locked
            /\ committed' = committed

Commit ==
    \E b0, b1, b2 \in blocks :
        /\ b0.id = locked
        /\ b1.parent = b0.id
        /\ b2.parent = b1.id
        /\ committed' = committed \cup {b0.id}
        /\ locked' = b1.id
        /\ UNCHANGED <<blocks, currentView>>

AdvanceLock ==
    \E blk \in blocks :
        /\ blk.view > Block(locked).view
        /\ locked' = blk.id
        /\ UNCHANGED <<blocks, committed, currentView>>

Next == Propose \/ Commit \/ AdvanceLock

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ Root \in blocks
    /\ \A b1, b2 \in blocks : b1.id = b2.id => b1 = b2
    /\ locked \in { b.id : b \in blocks }
    /\ committed \subseteq { b.id : b \in blocks }
    /\ currentView <= MaxView

NoDoubleCommit ==
    \A c1 \in committed : \A c2 \in committed :
        (c1 = c2) \/ IsAncestor(c1, c2) \/ IsAncestor(c2, c1)

HighestBlock == CHOOSE b \in blocks : \A other \in blocks : other.view <= b.view

EventualCommit == \A c \in committed : IsAncestor(c, HighestBlock.id)

=============================================================================
