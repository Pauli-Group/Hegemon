# Compliance Architecture

This document explains how HEGEMON's privacy-preserving design accommodates regulatory requirements without compromising user privacy or introducing backdoors. It complements `DESIGN.md`, `USER_PRIVACY_GUIDELINES.md`, and `THREAT_MODEL.md` by addressing the intersection of cryptographic privacy and financial compliance.

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Selective Disclosure via Viewing Keys](#2-selective-disclosure-via-viewing-keys)
3. [Travel Rule Compliance](#3-travel-rule-compliance)
4. [Sanctions Screening Without Mass Surveillance](#4-sanctions-screening-without-mass-surveillance)
5. [Money Transmission Analysis](#5-money-transmission-analysis)
6. [Post-Quantum Cryptography as Compliance Feature](#6-post-quantum-cryptography-as-compliance-feature)
7. [Optional Compliance Attestation Circuits](#7-optional-compliance-attestation-circuits)
8. [Exchange and VASP Integration](#8-exchange-and-vasp-integration)
9. [Governance and Regulatory Adaptation](#9-governance-and-regulatory-adaptation)
10. [Comparison with Transparent Chains](#10-comparison-with-transparent-chains)

---

## 1. Design Philosophy

HEGEMON provides **privacy by default** with **disclosure by choice**. This inverts the traditional financial surveillance model while remaining compatible with legitimate regulatory needs:

| Traditional Model | HEGEMON Model |
|-------------------|---------------|
| Transparent by default, privacy requires effort | Private by default, disclosure is explicit |
| Bulk surveillance possible | Targeted investigation only |
| Third parties see all transactions | Third parties see only what users reveal |
| Retroactive analysis by anyone | Retroactive analysis requires viewing keys |

### Core Principles

1. **No backdoors** — The protocol contains no master keys, regulatory escrow, or hidden decryption capabilities. Privacy guarantees are cryptographic, not policy-based.

2. **User-controlled disclosure** — Only the user (or their delegate) can reveal transaction details. This mirrors attorney-client privilege and banking confidentiality in traditional finance.

3. **Compliance at the edges** — Regulated entities (exchanges, custodians) implement compliance at their layer, not at the protocol layer. The protocol remains neutral infrastructure.

4. **Auditability without surveillance** — Users can prove specific properties (balance, source of funds, sanctions clearance) without revealing their entire transaction history.

---

## 2. Selective Disclosure via Viewing Keys

HEGEMON's key hierarchy (defined in `DESIGN.md §4`) enables granular disclosure:

### Key Types and Disclosure Scope

| Key Type | What It Reveals | Typical Recipient |
|----------|-----------------|-------------------|
| `sk_spend` | Full control (spend + view) | User only |
| `vk_full` | All incoming and outgoing transactions | Tax auditor, estate executor |
| `vk_incoming` | Only incoming transactions | Payment processor, accountant |
| Scoped viewing key | Specific accounts + time range | Regulator for targeted investigation |

### Scoped Viewing Keys

Users can derive viewing keys with built-in limitations:

```
vk_scoped = KDF("scope" || vk_full || account_filter || start_height || end_height)
```

Properties:
- **Account-limited**: Only reveals transactions for specified diversified addresses
- **Time-bounded**: Viewing capability expires at `end_height`
- **Non-transferable**: Derived key cannot be used to create broader viewing keys
- **Revocable**: User can rotate to new addresses, making old scoped keys useless for future transactions

### Disclosure Workflow

1. Regulator/auditor requests transaction visibility with legal basis
2. User (or custodian on user's behalf) generates scoped viewing key
3. Viewing key is transmitted via encrypted channel
4. Auditor scans the chain using the viewing key
5. Auditor sees only the scoped transactions; all other chain activity remains private

This mirrors traditional subpoena processes—targeted, documented, and proportionate.

---

## 3. Travel Rule Compliance

The FATF Travel Rule requires Virtual Asset Service Providers (VASPs) to share originator and beneficiary information for transfers exceeding thresholds (typically $1,000–$3,000).

### Challenge

Shielded transactions reveal no on-chain identity information. How can VASPs comply?

### Solution: Encrypted Memo Channel

HEGEMON transactions include an encrypted memo field (ML-KEM + AEAD). VASPs use this channel for Travel Rule data:

```
Memo Structure (VASP-to-VASP):
{
  "travel_rule": {
    "originator": {
      "name": "...",
      "account": "...",
      "institution": "VASP_A"
    },
    "beneficiary": {
      "name": "...",
      "account": "...",
      "institution": "VASP_B"
    },
    "amount": "...",
    "timestamp": "..."
  },
  "vasp_signature": "..." // VASP A signs the payload
}
```

Properties:
- **Encrypted end-to-end**: Only originating and receiving VASPs can read
- **Chain-invisible**: Validators/miners see only ciphertext
- **Auditable**: Both VASPs retain decrypted records for regulatory examination
- **User-invisible**: Travel Rule data is VASP-layer, not user-layer

### Implementation

VASPs maintain:
1. Mutual TLS channels for VASP-to-VASP communication (TRISA, OpenVASP, or proprietary)
2. Encrypted memo injection for on-chain Travel Rule binding
3. Off-chain record keeping with user viewing key escrow (per custody agreement)

Users transacting between personal wallets (non-VASP) are not subject to Travel Rule—this is consistent with traditional cash and bearer instrument treatment.

---

## 4. Sanctions Screening Without Mass Surveillance

### The Problem

OFAC and similar authorities maintain sanctions lists (SDN, etc.). Regulated entities must not process transactions involving sanctioned parties. On transparent chains, this is trivial—screen all addresses. On shielded chains, addresses are not visible.

### Solution 1: Edge Screening (Current Best Practice)

Screening occurs at the VASP/exchange boundary:
- Deposits: Screen the source (if transparent) or require attestation (if shielded)
- Withdrawals: Screen the destination address before allowing withdrawal
- Internal transfers: VASP knows both parties via KYC

This is identical to how banks screen wire transfers—they don't see the entire SWIFT network, only their counterparties.

### Solution 2: Proof of Non-Inclusion (Future Circuit)

An optional compliance circuit could prove:

> "The nullifiers in this transaction do not correspond to any commitment derived from addresses on list L."

Technical approach:
1. Sanctions list is published as a Merkle tree of address commitments
2. User generates a ZK proof that their spending addresses are NOT in the tree
3. Proof is attached to the transaction (optional)
4. VASPs can require this proof for their customers

Properties:
- **Privacy-preserving**: Proves non-membership without revealing address
- **List-agnostic**: Works with any published commitment list
- **Optional**: Protocol does not mandate; VASPs choose to require
- **Updateable**: New lists can be published; proofs reference specific list versions

### Solution 3: Regulatory Viewing Keys

For targeted investigations (not bulk surveillance):
1. Court order specifies target addresses or transaction hashes
2. User or custodian provides scoped viewing keys
3. Investigator examines specific transactions
4. No bulk decryption capability exists

This mirrors traditional financial investigation—subpoenas, not dragnet surveillance.

---

## 5. Money Transmission Analysis

### The Question

Are protocol developers, miners, or validators "money transmitters" under FinCEN/state money transmission laws?

### Analysis

| Actor | Custody of Funds? | Knowledge of Parties? | Control of Transmission? | MSB Status |
|-------|-------------------|----------------------|--------------------------|------------|
| Protocol developers | No | No | No | No |
| PoW miners | No | No (verify proofs only) | No (can't censor specific users) | No |
| Full node operators | No | No | No | No |
| Wallet software providers | No (non-custodial) | No | No | No |
| Exchanges/custodians | Yes | Yes | Yes | **Yes** |

### Key Arguments

1. **Miners verify proofs, not identities**: STARK verification confirms mathematical validity. Miners have no knowledge of transaction participants, amounts, or purposes. They are analogous to telecommunications carriers, not money transmitters.

2. **No custody at protocol layer**: The protocol moves cryptographic commitments, not funds. "Funds" only exist at the application layer where users hold keys.

3. **Decentralized validation**: No single party can block or reverse transactions. This distinguishes the protocol from centralized payment processors.

4. **FinCEN 2019 Guidance alignment**: Non-custodial wallet providers and protocol developers are generally not MSBs. Miners performing validation (not custody) fall outside MSB definitions.

### Regulatory References

- FinCEN Guidance FIN-2019-G001 (May 2019)
- FinCEN v. Ripple Labs (settlement, not precedent, but instructive)
- State-by-state analysis required for specific operations

---

## 6. Post-Quantum Cryptography as Compliance Feature

### The Overlooked Advantage

Financial regulations often require record retention for extended periods:
- Bank Secrecy Act: 5 years
- Tax records: 7+ years
- Securities regulations: 6+ years
- AML records: 5 years after account closure

### The Quantum Threat to Compliance

Chains using elliptic curve cryptography (ECDSA, EdDSA, BLS) face a compliance problem:
- Quantum computers can retroactively break ECC
- "Harvest now, decrypt later" attacks are already occurring
- Within 10–15 years, today's ECC-protected records may be exposed
- Retroactive decryption violates the privacy expectations under which records were created

### HEGEMON's Solution

HEGEMON uses exclusively post-quantum cryptography:
- **ML-DSA** (Dilithium) for signatures
- **ML-KEM** (Kyber) for key encapsulation
- **STARK proofs** (hash-based) for ZK
- **No ECC anywhere** in the cryptographic stack

Compliance benefits:
1. **Durable confidentiality**: Records encrypted today remain confidential in 2050
2. **Regulatory certainty**: No need to re-encrypt or migrate when quantum arrives
3. **Audit integrity**: Historical viewing key disclosures remain bounded to their scope
4. **Future-proof travel rule**: VASP-to-VASP communications stay confidential

### Positioning

> "HEGEMON is designed for the 50-year regulatory record-keeping requirement. Unlike legacy chains, our cryptographic guarantees don't expire when quantum computers arrive."

---

## 7. Optional Compliance Attestation Circuits

The protocol supports optional attestation circuits that allow users to attach compliance proofs without revealing underlying data.

### Attestation Types

| Attestation | Proves | Use Case |
|-------------|--------|----------|
| VASP Screening | "VASP X has screened this transaction" | Travel Rule |
| Sanctions Non-Inclusion | "My addresses are not on list L" | OFAC compliance |
| Source of Funds | "Funds derive from addresses in set S" | AML |
| Tax Residency | "I am a tax resident of jurisdiction J" | Tax reporting |
| Accredited Investor | "I meet accreditation criteria" | Securities |

### Technical Design

Attestations are implemented as optional fields in the transaction witness:

```rust
pub struct ComplianceAttestation {
    /// Type of attestation
    pub attestation_type: AttestationType,
    /// Commitment to the claim (hides details)
    pub claim_commitment: [u8; 32],
    /// STARK proof that claim is valid
    pub proof: StarkProof,
    /// Optional: encrypted payload for authorized parties
    pub encrypted_details: Option<Vec<u8>>,
    /// Attestor identity (e.g., VASP public key)
    pub attestor: Option<[u8; 32]>,
    /// Expiration height
    pub valid_until: Option<u64>,
}
```

### Governance Integration

New attestation types are introduced via `VersionProposal`:

```rust
// Example: Adding sanctions attestation circuit
VersionProposal {
    binding: VersionBinding::new(CIRCUIT_V3, CRYPTO_SUITE_ALPHA),
    activates_at: 500_000,
    retires_at: None,
    description: "Optional OFAC non-inclusion attestation circuit",
}
```

Properties:
- **Opt-in only**: Users choose whether to attach attestations
- **Protocol-neutral**: Core consensus does not require attestations
- **VASP-enforceable**: VASPs can require attestations for their customers
- **Upgradeable**: New attestation types added via governance, not hard forks

---

## 8. Exchange and VASP Integration

### For Compliant Exchanges

Exchanges integrating HEGEMON should implement:

1. **Deposit screening**
   - Accept deposits from shielded addresses
   - Require customer to provide viewing key for the deposit address
   - Scan deposit history for source-of-funds verification
   - Apply standard AML/KYC to the customer, not the chain

2. **Withdrawal processing**
   - Screen destination addresses (if transparent context available)
   - Attach Travel Rule memo for VASP-to-VASP transfers
   - Retain transaction records with customer viewing key escrow

3. **Internal transfers**
   - Between exchange customers: off-chain ledger (no chain visibility needed)
   - Customer-to-customer: full KYC on both parties

4. **Regulatory reporting**
   - SAR filing: Use customer viewing keys to document suspicious activity
   - Tax reporting: Provide customers with transaction history via their keys
   - Audit response: Provide scoped viewing keys per subpoena scope

### Viewing Key Custody

Exchanges holding customer funds typically also hold viewing keys:

| Model | Description | Customer Privacy |
|-------|-------------|------------------|
| **Full custody** | Exchange holds spend + view keys | Exchange sees all |
| **Spend custody** | Exchange holds spend, customer holds view | Customer controls disclosure |
| **Viewing escrow** | Customer holds both, escrows view key | Disclosure on demand |

Recommended: **Viewing escrow** — Exchange can fulfill regulatory obligations on request without continuous surveillance of customer activity.

---

## 9. Governance and Regulatory Adaptation

### Responding to Regulatory Changes

HEGEMON's versioning system (`governance/VERSIONING.md`) enables protocol adaptation without fragmenting the privacy pool:

| Regulatory Scenario | Governance Response |
|---------------------|---------------------|
| New attestation requirement | Add optional circuit via `VersionProposal` |
| Cryptographic vulnerability | Emergency primitive swap via `UpgradeDirective` |
| Jurisdiction-specific rule | Application-layer enforcement, not protocol change |
| Outright ban | No protocol response possible; user/VASP responsibility |

### Governance Structure

| Decision Type | Authority | Process |
|---------------|-----------|---------|
| Circuit versions | Core team + security reviewers | `VersionProposal` → review → activation |
| Cryptographic upgrades | External audit + core team | Cryptanalysis review → `VersionProposal` |
| Economic parameters | Miner + community signaling | Proposal → discussion → miner adoption |
| Emergency response | Pre-authorized fast-track | `runbooks/emergency_version_swap.md` |

### Decentralization Timeline

1. **Phase 1 (Current)**: Core team proposes, community reviews, miners activate
2. **Phase 2**: Formalized proposal process with economic stake
3. **Phase 3**: On-chain governance with viewing-key-weighted voting (prevents plutocracy)
4. **Phase 4**: Full decentralization with foundation dissolution

---

## 10. Comparison with Transparent Chains

### Privacy vs. Compliance Trade-offs

| Property | Transparent Chain (BTC/ETH) | HEGEMON |
|----------|----------------------------|---------|
| Default visibility | Everything public | Nothing public |
| Bulk surveillance | Trivial | Impossible |
| Targeted investigation | Trivial | Requires viewing keys |
| Travel Rule | Address matching | Encrypted memos |
| Sanctions screening | On-chain | At VASP boundary |
| Retroactive analysis | By anyone, forever | By key holders only |
| Quantum resistance | None (ECC) | Full (PQC) |

### The Compliance Paradox

Transparent chains appear more "compliant" but create problems:

1. **Over-disclosure**: Users reveal far more than regulations require
2. **Commercial surveillance**: Competitors, employers, and adversaries can analyze activity
3. **Honeypot risk**: Centralized chain analysis databases become attack targets
4. **Chilling effects**: Legal activities (donations, healthcare, legal fees) become surveilled
5. **Quantum vulnerability**: Today's compliance records become tomorrow's privacy breaches

HEGEMON's model provides **necessary and sufficient** disclosure:
- Regulators get what they need (via viewing keys, attestations)
- Users retain privacy for everything else
- Records remain confidential even as technology evolves

---

## Appendix A: Regulatory Reference Matrix

| Regulation | Requirement | HEGEMON Solution |
|------------|-------------|------------------|
| Bank Secrecy Act | Record keeping, SAR filing | Viewing key escrow, transaction records |
| FATF Travel Rule | Originator/beneficiary info | Encrypted memo channel |
| OFAC Sanctions | Screen prohibited parties | Edge screening, optional non-inclusion proofs |
| GDPR | Data minimization, right to erasure | Privacy by default, no unnecessary data on-chain |
| MiCA (EU) | VASP licensing, Travel Rule | Standard VASP compliance, memo channel |
| FinCEN MSB Rules | Registration if money transmitter | Protocol layer is not MSB (see §5) |

## Appendix B: Document Maintenance

This document must be updated when:
- New attestation circuits are proposed via `VersionProposal`
- Regulatory guidance changes (FinCEN, FATF, SEC, etc.)
- Viewing key derivation or memo structure changes in `DESIGN.md`
- Exchange integration patterns evolve

**Owners**: Governance team, with input from legal counsel.

**Review cadence**: Quarterly, or upon significant regulatory developments.

---

*This document is informational and does not constitute legal advice. Consult qualified legal counsel for jurisdiction-specific compliance requirements.*
