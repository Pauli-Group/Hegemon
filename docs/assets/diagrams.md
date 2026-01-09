# Architecture Diagrams

This file contains Mermaid diagrams that visualize key architectural concepts from the whitepaper. Embed these in README.md, DESIGN.md, or METHODS.md as needed.

---

## 1. System Architecture Overview

```mermaid
flowchart TB
    subgraph User["User Layer"]
        W[wallet/]
        UI[hegemon-app/]
    end

    subgraph Proving["Proving Layer"]
        CT[circuits/transaction]
        CB[circuits/block]
        CF[circuits/formal]
    end

    subgraph Crypto["Cryptographic Primitives"]
        CR[crypto/]
        ML_DSA["ML-DSA Signatures"]
        ML_KEM["ML-KEM Encryption"]
        HASH["Blake3/SHA3/Poseidon"]
    end

    subgraph Consensus["Consensus & Networking"]
        CON[consensus/]
        NET[network/]
        POW["PoW Engine"]
    end

    subgraph State["State Management"]
        SM[state/merkle]
        PV[protocol/versioning]
        RT[runtime/]
    end

    subgraph Pallets["Substrate Pallets"]
        SP[pallet-shielded-pool]
        PA[pallet-attestations]
        PS[pallet-settlement]
        PI[pallet-identity]
    end

    W -->|craft tx| CT
    CT -->|proof| CB
    CB -->|block proof| CON
    CON -->|validate| POW
    POW -->|seal| RT
    RT --> Pallets
    CT --> CR
    CB --> SM
    SM --> RT
    PV --> CON
    W --> ML_KEM
    CON --> ML_DSA
    CT --> HASH
```

---

## 2. Shielded Transaction Flow

```mermaid
sequenceDiagram
    participant Sender as Sender Wallet
    participant Circuit as Transaction Circuit
    participant Merkle as state/merkle
    participant Consensus as PoW Consensus
    participant Chain as Blockchain

    Sender->>Sender: Select input notes (value, asset_id, rho, r)
    Sender->>Sender: Compute nullifiers: nf = H("nf" || nk || rho || pos)
    Sender->>Sender: Create output notes for recipients
    Sender->>Sender: Compute commitments: cm = H("note" || value || asset || pk || rho || r)
    Sender->>Circuit: Submit witness (notes, Merkle paths, sk_spend)
    Circuit->>Circuit: Verify Merkle membership for inputs
    Circuit->>Circuit: Verify nullifier derivation
    Circuit->>Circuit: Verify balance conservation per asset
    Circuit->>Circuit: Generate STARK proof
    Circuit-->>Sender: Return TransactionProof
    Sender->>Consensus: Submit (nullifiers, commitments, proof, ciphertexts)
    Consensus->>Consensus: Verify STARK proof
    Consensus->>Merkle: Check nullifiers not spent
    Consensus->>Merkle: Append new commitments
    Consensus->>Chain: Include in block
    Chain-->>Sender: Transaction confirmed
```

---

## 3. Key Hierarchy

```mermaid
flowchart TD
    ROOT[sk_root<br/>256-bit master secret]

    ROOT -->|HKDF "spend"| SK_SPEND[sk_spend<br/>Spending key]
    ROOT -->|HKDF "view"| SK_VIEW[sk_view<br/>Viewing key]
    ROOT -->|HKDF "enc"| SK_ENC[sk_enc<br/>Encryption key]
    ROOT -->|HKDF "derive"| SK_DERIVE[sk_derive<br/>Diversifier key]

    SK_SPEND -->|H "nk"| NK[nk<br/>Nullifier key]
    NK -->|H "nf" + rho + pos| NF[Nullifiers]

    SK_VIEW --> ADDR_TAG[addr_tag_i<br/>Address tags]
    SK_ENC --> ML_KEM_KEYS[ML-KEM keypairs<br/>per diversifier]
    SK_DERIVE --> DIV[Diversified addresses]

    subgraph Viewing Keys
        IVK[Incoming VK<br/>sk_view + sk_enc]
        OVK[Outgoing VK<br/>can audit sent notes]
        FVK[Full VK<br/>IVK + vk_nf]
    end

    SK_VIEW --> IVK
    SK_ENC --> IVK
    SK_SPEND -->|H "view_nf"| VK_NF[vk_nf]
    VK_NF --> FVK
    IVK --> FVK

    DIV --> ADDR[Shielded Address<br/>shca1...]
    ML_KEM_KEYS --> ADDR
    ADDR_TAG --> ADDR
```

---

## 4. Version Upgrade Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Draft: Author proposes VersionBinding

    Draft --> Review: Submit VersionProposal
    Review --> Scheduled: Governance ratifies

    state Scheduled {
        [*] --> Pending
        Pending --> Active: activates_at height reached
        Active --> GracePeriod: retires_at approaching
        GracePeriod --> Retired: retires_at height reached
    }

    Scheduled --> Rejected: Review fails

    Active --> Active: Normal operation<br/>Miners accept binding

    GracePeriod --> GracePeriod: Migration circuit available<br/>Monitor version_counts

    Retired --> [*]: Binding removed from VersionSchedule

    note right of Draft
        - Define circuit_version, crypto_suite
        - Attach verifying keys
        - Set activation/retirement heights
    end note

    note right of Active
        - Miners must include binding
        - Blocks validated against schedule
        - version_commitment in headers
    end note

    note right of GracePeriod
        - UpgradeDirective enables migration
        - Old notes can migrate to new binding
        - Track adoption via version_counts
    end note
```

---

## 5. MASP Balance Conservation

```mermaid
flowchart LR
    subgraph Inputs["Input Notes"]
        I1["Note 1<br/>asset: HGM<br/>value: +100"]
        I2["Note 2<br/>asset: USD<br/>value: +50"]
        I3["Note 3<br/>asset: HGM<br/>value: +25"]
    end

    subgraph Outputs["Output Notes"]
        O1["Note 1<br/>asset: HGM<br/>value: -80"]
        O2["Note 2<br/>asset: USD<br/>value: -50"]
        O3["Note 3<br/>asset: HGM<br/>value: -45"]
    end

    subgraph Circuit["In-Circuit Processing"]
        MS["Form Multiset<br/>(asset_id, ±value)"]
        SORT["Sort by asset_id"]
        AGG["Aggregate per asset"]
        CHECK["Verify Δ = 0<br/>or Δ = fee"]
    end

    I1 --> MS
    I2 --> MS
    I3 --> MS
    O1 --> MS
    O2 --> MS
    O3 --> MS

    MS --> SORT
    SORT --> AGG
    AGG --> CHECK

    subgraph Result["Balance Check"]
        R1["HGM: +125 - 125 = 0 ✓"]
        R2["USD: +50 - 50 = 0 ✓"]
    end

    CHECK --> R1
    CHECK --> R2
```

---

## 6. Block Proof Aggregation

```mermaid
flowchart TB
    subgraph Transactions["Transaction Layer"]
        TX1[TX Proof 1<br/>nullifiers, commitments]
        TX2[TX Proof 2<br/>nullifiers, commitments]
        TX3[TX Proof 3<br/>nullifiers, commitments]
    end

    subgraph BlockCircuit["circuits/block"]
        VER["Verify each TX proof"]
        NF_CHECK["Check nullifier uniqueness"]
        TREE["Update Merkle tree"]
        ROOT["Compute root_new"]
        VB["Collect VersionBindings"]
        REC["RecursiveBlockProof<br/>recursive proof"]
    end

    subgraph Header["Block Header"]
        POW["PoW seal<br/>sha256(header) ≤ target"]
        VC["version_commitment"]
        SD["supply_digest"]
        MR["merkle_root"]
    end

    TX1 --> VER
    TX2 --> VER
    TX3 --> VER

    VER --> NF_CHECK
    NF_CHECK --> TREE
    TREE --> ROOT

    TX1 --> VB
    TX2 --> VB
    TX3 --> VB
    VB --> VC

    ROOT --> MR
    VER --> REC

    MR --> POW
    VC --> POW
    SD --> POW
    REC --> POW

    POW --> BROADCAST["Broadcast to network"]
```

---

## Usage

To embed these diagrams in markdown files on GitHub:

1. Copy the desired diagram's Mermaid code block
2. Paste into README.md, DESIGN.md, or METHODS.md
3. GitHub will render the diagram automatically

For local preview, use:
- VS Code with Mermaid extension
- `mermaid-cli` (`npm install -g @mermaid-js/mermaid-cli`)
- Online editor: https://mermaid.live
