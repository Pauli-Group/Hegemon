# Post-Quantum Browser Wallet Extension

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md`.


## Purpose / Big Picture

Users need a browser extension wallet to sign transactions on Hegemon using ML-DSA-65 post-quantum signatures. The Polkadot.js extension only supports classical cryptography (Sr25519/Ed25519/ECDSA), which is incompatible with our PQ-only chain.

After this work, a user can:
1. Install the "Hegemon Wallet" browser extension
2. Generate or import an ML-DSA keypair from a seed phrase
3. Connect to Polkadot.js Apps (or any dapp) running against a Hegemon node
4. Sign and submit transactions (transfers, shielded operations) using ML-DSA signatures
5. View account balances and transaction history

Observable proof: User creates account in extension, connects to `https://polkadot.js.org/apps/?rpc=ws://127.0.0.1:9944`, sees their address in the accounts list, initiates a transfer, extension popup requests signature confirmation, transaction appears on-chain.


## Progress

- [ ] Milestone 1: WASM build of crypto crate
- [ ] Milestone 2: Fork and scaffold extension
- [ ] Milestone 3: Replace key generation
- [ ] Milestone 4: Replace signing logic
- [ ] Milestone 5: UI adaptations
- [ ] Milestone 6: Integration testing with live node
- [ ] Milestone 7: Package for distribution


## Surprises & Discoveries

(None yet)


## Decision Log

- Decision: Fork polkadot-js/extension rather than build from scratch
  Rationale: Existing extension has mature UX, dapp injection protocol, and Chrome/Firefox packaging. Reusing saves months of work. Apache-2.0 license permits modification.
  Date/Author: 2025-11-30

- Decision: Support ML-DSA-65 only, not SLH-DSA
  Rationale: ML-DSA signatures are ~3.3KB vs ~17KB for SLH-DSA. Browser storage and UX are manageable with ML-DSA. SLH-DSA can be added later if needed.
  Date/Author: 2025-11-30

- Decision: Use same seed phrase format (BIP39 12/24 words) with different derivation
  Rationale: Familiar UX for users. Derive ML-DSA seed deterministically from BIP39 entropy using domain-separated SHAKE256.
  Date/Author: 2025-11-30


## Outcomes & Retrospective

(To be completed)


## Context and Orientation

### Repository Structure

The Hegemon monorepo contains these relevant components:

- `crypto/` - Rust crate implementing ML-DSA-65 and SLH-DSA signatures, ML-KEM key encapsulation
- `crypto/src/ml_dsa.rs` - ML-DSA implementation wrapping the `ml-dsa` crate
- `runtime/src/lib.rs` - Defines the `pq_crypto::Signature` enum (MlDsa variant) and `pq_crypto::Public` enum used on-chain
- `wallet/` - Rust CLI wallet that can sign transactions (reference implementation)

### External Dependency

The Polkadot.js extension lives at `https://github.com/polkadot-js/extension` (Apache-2.0). Key packages:

- `packages/extension/` - Main extension entry, background scripts, injection
- `packages/extension-ui/` - React UI components for the popup
- `packages/extension-base/` - Core logic: keyring, messaging, state management
- Uses `@polkadot/util-crypto` for all cryptographic operations (Sr25519, Ed25519, ECDSA)
- Uses `@polkadot/keyring` for key management

### Key Terms

- **ML-DSA-65**: NIST-standardized post-quantum digital signature algorithm (formerly Dilithium). Security level 2 (~128-bit). Public key: 1952 bytes. Signature: 3293 bytes.
- **Seed phrase**: 12 or 24 BIP39 mnemonic words encoding 128 or 256 bits of entropy.
- **Injection**: Browser extensions inject objects into `window.injectedWeb3` allowing dapps to discover and use wallet functionality.
- **Signer**: Interface that dapps call to request transaction signatures. Extension intercepts, shows confirmation popup, returns signed payload.


## Plan of Work

### Milestone 1: WASM Build of Crypto Crate

Compile the `crypto/` crate to WebAssembly so it can run in the browser extension. This requires:

1. Add `wasm32-unknown-unknown` target support to `crypto/Cargo.toml`
2. Create `crypto/src/wasm.rs` exposing FFI-safe functions for:
   - `generate_keypair(seed: &[u8]) -> (PublicKey, SecretKey)`
   - `sign(secret_key: &[u8], message: &[u8]) -> Signature`
   - `verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool`
   - `public_key_from_secret(secret_key: &[u8]) -> PublicKey`
3. Use `wasm-bindgen` to generate JS bindings
4. Build with `wasm-pack build --target web`
5. Verify WASM bundle size is acceptable (<500KB gzipped target)

The output is an NPM-publishable package `@hegemon/crypto-wasm` or similar.


### Milestone 2: Fork and Scaffold Extension

1. Fork `polkadot-js/extension` to `Pauli-Group/hegemon-wallet`
2. Rename package names from `@polkadot/extension-*` to `@hegemon/wallet-*`
3. Update branding: icons, names, descriptions per `BRAND.md`
4. Verify the fork builds and loads in Chrome developer mode
5. Update manifest to use different extension ID to allow side-by-side installation

No functional changes yet - just rebrand and verify build pipeline works.


### Milestone 3: Replace Key Generation

In `packages/extension-base/src/`, the keyring logic uses `@polkadot/keyring` which wraps `@polkadot/util-crypto`.

1. Create `packages/extension-base/src/pq-keyring.ts`:
   - Import the WASM crypto module
   - Implement `generateMnemonic()` - reuse BIP39 from `@polkadot/util-crypto` (entropy generation is not PQ-sensitive)
   - Implement `keypairFromMnemonic(mnemonic: string, password?: string)`:
     - Derive 64 bytes from mnemonic using PBKDF2 (standard BIP39)
     - Feed into SHAKE256 with domain separator `"hegemon-ml-dsa-v1"` to get 32-byte ML-DSA seed
     - Call WASM `generate_keypair(seed)` to get ML-DSA keypair
   - Implement `addressFromPublicKey(pubkey: Uint8Array)`:
     - Hash public key with Blake2b-256 to get 32-byte AccountId
     - Encode as SS58 with network prefix 42

2. Update `packages/extension-base/src/stores/Account.ts` to use pq-keyring
3. Update account creation flow to store ML-DSA keys (larger than classical keys)
4. Storage format: `{ address, publicKey: hex, encryptedSecretKey: hex, meta }`

Validation: Create account in extension, verify address format matches runtime expectations.


### Milestone 4: Replace Signing Logic

The extension's Signer interface lives in `packages/extension-base/src/page/Signer.ts`.

1. Create `packages/extension-base/src/pq-signer.ts`:
   - `signPayload(payload: SignerPayloadJSON)`:
     - Decode the `payload.method` (call data)
     - Construct the signing payload per Substrate extrinsic format
     - Retrieve secret key from encrypted storage (prompt for password)
     - Call WASM `sign(secretKey, payload)` to get ML-DSA signature
     - Return `{ id, signature: hex }` where signature is SCALE-encoded `pq_crypto::Signature::MlDsa`

2. The signature format must match runtime expectations. In `runtime/src/lib.rs`, the `Signature` enum is:

       enum Signature {
           MlDsa { signature: [u8; 3293], public: Public },
           SlhDsa { ... }
       }

   The SCALE encoding is: `0x00` (variant index) + 3293 signature bytes + public key encoding.

3. Update `packages/extension/src/background/handlers/` to route signing through pq-signer

4. Handle the larger signature size in message passing (Chrome limits message size, but 4KB should be fine)

Validation: Sign a dummy payload, verify the signature decodes correctly in Rust test.


### Milestone 5: UI Adaptations

1. Update `packages/extension-ui/src/Popup/Signing/` components:
   - Display "ML-DSA Signature" in confirmation dialog
   - Show signature size warning if needed
   - Update any hardcoded signature length assumptions

2. Update account display to show "Hegemon" network badge

3. Update `packages/extension-ui/src/` styling per `BRAND.md`:
   - Colors: Electric cyan (#00FFFF), deep space (#0a0a14)
   - Typography: Inter for body, JetBrains Mono for addresses/hashes

4. Update popup dimensions if needed (ML-DSA keys are larger to display)


### Milestone 6: Integration Testing with Live Node

1. Start Hegemon node locally:

       HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

2. Load extension in Chrome developer mode

3. Create new account in extension

4. Navigate to `https://polkadot.js.org/apps/?rpc=ws://127.0.0.1:9944`

5. Verify extension injects and account appears in Apps

6. Attempt a balance transfer (will fail if no balance - need to mine to that address first)

7. For testing with balance:
   - Get the hex-encoded AccountId from extension
   - Restart node with `HEGEMON_MINER_ACCOUNT=<hex>` to mine rewards to that address
   - Verify balance appears in Apps
   - Submit transfer transaction
   - Verify transaction succeeds on-chain

8. Test error cases:
   - Wrong password
   - Canceling signature request
   - Network disconnection


### Milestone 7: Package for Distribution

1. Build production bundles:

       yarn build:chrome
       yarn build:ff

2. Create Chrome Web Store developer account (if not exists)
3. Submit to Chrome Web Store for review
4. Submit to Firefox Add-ons for review
5. Document installation from source for users who prefer that


## Concrete Steps

Commands are run from the extension repository root unless otherwise noted.

### Setup (one-time)

    # Clone the fork
    git clone https://github.com/Pauli-Group/hegemon-wallet.git
    cd hegemon-wallet
    
    # Enable corepack for yarn
    corepack enable
    
    # Install dependencies
    yarn install

### Build WASM crypto (from hegemon monorepo)

    cd /path/to/synthetic-hegemonic-currency/crypto
    
    # Add wasm target
    rustup target add wasm32-unknown-unknown
    
    # Install wasm-pack
    cargo install wasm-pack
    
    # Build
    wasm-pack build --target web --out-dir pkg
    
    # Check size
    ls -lh pkg/*.wasm
    # Should be under 1MB uncompressed

### Build extension

    yarn build:chrome
    
    # Output in packages/extension/build/

### Load in Chrome

1. Navigate to `chrome://extensions/`
2. Enable "Developer mode" toggle
3. Click "Load unpacked"
4. Select `packages/extension/build/` directory
5. Extension icon appears in toolbar


## Validation and Acceptance

### Milestone 1 Acceptance

Run from `crypto/` directory:

    wasm-pack test --headless --chrome

All tests pass. WASM bundle exists at `crypto/pkg/crypto_bg.wasm`.

### Milestone 3 Acceptance

In extension popup:
1. Click "+" to create account
2. See 12-word mnemonic displayed
3. Complete account creation
4. Account appears in list with SS58 address starting with `5`
5. Export account JSON, verify it contains `"type": "ml-dsa-65"`

### Milestone 6 Acceptance

Full flow with live node:

1. Node running, extension loaded
2. Apps shows extension account with non-zero balance
3. User initiates transfer to another address
4. Extension popup shows signing request with amount and recipient
5. User enters password and confirms
6. Transaction submits successfully
7. Recipient balance increases (visible in Apps or via RPC query)
8. Transaction visible in block explorer / chain state


## Idempotence and Recovery

- Extension can be unloaded/reloaded without losing accounts (stored in browser local storage)
- If WASM build fails, delete `crypto/pkg/` and `crypto/target/` and rebuild
- If extension build fails, run `yarn clean && yarn install && yarn build:chrome`
- Account JSON export/import allows recovery if browser storage is lost


## Artifacts and Notes

### Expected WASM Exports

The `crypto/src/wasm.rs` module should export:

    #[wasm_bindgen]
    pub fn ml_dsa_generate_keypair(seed: &[u8]) -> JsValue;
    // Returns { publicKey: Uint8Array, secretKey: Uint8Array }
    
    #[wasm_bindgen]
    pub fn ml_dsa_sign(secret_key: &[u8], message: &[u8]) -> Uint8Array;
    // Returns 3293-byte signature
    
    #[wasm_bindgen]
    pub fn ml_dsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
    
    #[wasm_bindgen]
    pub fn ml_dsa_public_from_secret(secret_key: &[u8]) -> Uint8Array;
    // Returns 1952-byte public key

### Signature Encoding for Substrate

The signed extrinsic format requires the signature to be SCALE-encoded. For ML-DSA:

    0x00                      // Variant index for MlDsa
    <3293 bytes signature>    // Raw signature bytes  
    0x00                      // Variant index for Public::MlDsa
    <1952 bytes public key>   // Raw public key bytes

Total signature field: 1 + 3293 + 1 + 1952 = 5247 bytes

This is large but acceptable for blockchain transactions.


## Interfaces and Dependencies

### NPM Dependencies to Add

    @aspect/pqcrypto-wasm    # Our WASM build (or inline)

### NPM Dependencies to Remove/Replace

    @polkadot/keyring        # Replace with pq-keyring
    @polkadot/util-crypto    # Keep for BIP39, replace signing

### TypeScript Interfaces

In `packages/extension-base/src/pq-keyring.ts`:

    export interface MlDsaKeypair {
      publicKey: Uint8Array;  // 1952 bytes
      secretKey: Uint8Array;  // 4032 bytes
    }
    
    export interface PqKeyring {
      generateMnemonic(words?: 12 | 24): string;
      keypairFromMnemonic(mnemonic: string, password?: string): MlDsaKeypair;
      addressFromPublicKey(publicKey: Uint8Array): string;
      sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array;
      verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
    }

In `packages/extension-base/src/pq-signer.ts`:

    export interface PqSigner {
      signPayload(payload: SignerPayloadJSON): Promise<SignerResult>;
      signRaw(raw: SignerPayloadRaw): Promise<SignerResult>;
    }


---

Revision: Initial draft created 2025-11-30. Defines full scope for PQ browser wallet extension based on polkadot-js/extension fork.
