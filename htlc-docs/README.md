# How to swap testnet coins with Hegemon HTLC swaps

**Open the swap website:** https://hegemon-swap-testnet.willdoyle422.workers.dev/

This guide walks two people through creating an offer, accepting it, approving the swap, and recovering unclaimed funds. It covers the native coins **HGN, BTC, ETH and ADA** on the test networks below. Use small test amounts and keep enough coins for fees.

**The most important distinction:** creating or reserving an offer does not lock coins. Funds are locked only when you approve a funding transaction later in the guided swap.

## Find your place

- [What an HTLC swap does](#what-an-htlc-swap-does)
- [What you need before starting](#what-you-need-before-starting)
- [Run and connect the Hegemon companion](#run-and-connect-the-hegemon-companion)
- [Create an offer: the maker](#create-an-offer-the-maker)
- [Accept an offer: the taker](#accept-an-offer-the-taker)
- [Complete the swap: both people](#complete-the-swap-both-people)
- [Bitcoin signing steps](#bitcoin-signing-steps)
- [Hegemon approval steps](#hegemon-approval-steps)
- [Waiting, refresh and reopening](#waiting-refresh-and-reopening)
- [Refunds and recovery](#refunds-and-recovery)
- [Troubleshooting](#troubleshooting)

## What an HTLC swap does

An **HTLC**, or hash time locked contract, temporarily locks coins with two ways to spend them:

- The agreed recipient can claim them using the correct secret and their wallet authorization.
- If they remain unclaimed, the original sender can refund them after the deadline by approving a refund transaction.

The two locks use the same secret. The maker's refund deadline is later than the taker's, giving the taker time to finish after the maker reveals the secret by claiming. The wizard calculates the deadlines and checks the locks before offering the next action.

Here is the order for an example in which Alice offers **5 ADA** for Bob's **0.0001 ETH**. These amounts illustrate the interface; they are not a suggested exchange rate.

```mermaid
sequenceDiagram
    participant Alice as Alice · maker
    participant Bob as Bob · taker
    Alice->>Bob: Posts 5 ADA for 0.0001 ETH
    Bob->>Alice: Reserves the offer
    Alice->>Bob: Accepts the reservation
    Note over Alice,Bob: Both save backups and confirm details
    Alice->>Alice: Approves locking 5 ADA
    Note over Bob: Waits for verified confirmation
    Bob->>Bob: Approves locking 0.0001 ETH
    Note over Alice: Waits for verified confirmation
    Alice->>Alice: Approves claiming the ETH
    Note over Bob: Refreshes to observe the claim
    Bob->>Bob: Approves claiming the ADA
    Note over Alice,Bob: Both check the final confirmations
```

You do not need a free-form chat to negotiate transaction fields. The software exchanges structured swap details. You still need to compare verification codes through a separate trusted channel and approve each transaction. Both people must return in time to act; closing the page does not pause a deadline.

The hosted service relays offers and encrypted swap messages. Your wallets sign locally. Hegemon additionally uses a companion on your computer. Public-chain data and the website code are still trust dependencies; this is an experimental testnet interface.

## What you need before starting

| Coin | Select this network | What you need |
| --- | --- | --- |
| HGN | Hegemon v0.11 pre-mainnet public testnet | A synced local node, a funded spend-capable wallet, and the companion in **hosted swap mode**. |
| BTC | **Bitcoin testnet4** | A funded wallet that can sign supported Bitcoin messages and PSBTs. Testnet3 and signet are different networks. |
| ETH | **Ethereum Sepolia** | A funded Ethereum browser wallet. You also need ETH for gas when receiving and claiming ETH. |
| ADA | **Cardano preview** | A funded CIP-30 browser wallet with message-signing support. Preview is different from preprod. Keep ADA available for fees and, when the wallet requests it, collateral. |

Both participants need wallets for **both coins** in their swap: one to send from and one to receive into. For HGN, keep a separate ordinary spendable note available for claim/refund fees; a total balance alone does not establish that the wallet has a usable fee note.

Use a normal persistent browser profile. Save the offer link and backups. If you are playing both roles on one computer, use **two separate browser profiles**, each with its own wallets and browser storage.

For ADA–ETH, you can leave the Hegemon companion disconnected. The hosted interface uses public providers for Bitcoin, Ethereum and Cardano; you do not have to sync those three nodes yourself.

Stay in the default guided view. The asset menu may also contain tokens and NFTs, but this guide and the current four-coin workflow are for native BTC, ETH, ADA and HGN between different chains.

![Start page with Create an offer, Explore public offers, and Open an offer link.](images/01-start.png)

*Click a screenshot to enlarge it. These are new captures of the deployed interface code running in a local demonstration. Example offers were not published to the public board and no coins were spent. The HGN asset-selection image illustrates that choice; the amount and review images use the ADA–ETH example.*

## Run and connect the Hegemon companion

**Skip this section if neither coin is HGN.**

### 1. Prepare the local software

Use a checkout of the [`local-private-spend-htlc` branch](https://github.com/Pauli-Group/Hegemon/tree/local-private-spend-htlc). If you already run your node from a checkout with local changes, keep that checkout intact and ask your local agent to prepare a separate worktree for the companion.

The node must already be synced to the pinned v0.11 pre-mainnet, with wallet RPC available on **`http://127.0.0.1:9944`**. The source launcher provides `--wallet-rpc` for this. Keep the RPC on loopback. See the [network operator documentation](../config/testnet/0.11/README.md) for node setup; you do not need to enable mining to use the swap website. Keep the computer's time synchronized with NTP or chrony.

In a terminal inside the swap branch checkout, build the matching wallet executable if you have not already done so:

```bash
cargo build --release -p wallet --bin private-spend --features rpc-client
```

Use this branch's executable. The older official `private-spend` 0.11.2 executable does not contain all the swap checks the companion needs.

If Python dependencies are not installed, create a dedicated environment once:

```bash
python3 -m venv "$HOME/.local/share/hegemon-swap/venv"
"$HOME/.local/share/hegemon-swap/venv/bin/python" -m pip install \
  -r scripts/requirements-htlc-public.txt
```

On Debian/Ubuntu, creating a venv may require `python3-venv`. The optional companion window needs `python3-tk`; its **Remember on this computer** option needs `secret-tool`, provided by `libsecret-tools`.

### 2. Start the companion in swap mode

Run the following **from the repository root**, replacing `/absolute/path/to/your.wallet` with your existing encrypted testnet wallet file. Keep this terminal open for approvals.

```bash
umask 077
mkdir -p "$HOME/.local/share/hegemon-swap/refund-handoffs"
chmod 700 "$HOME/.local/share/hegemon-swap" \
  "$HOME/.local/share/hegemon-swap/refund-handoffs"

"$HOME/.local/share/hegemon-swap/venv/bin/python" \
  scripts/local_swap_companion.py \
  --hosted-hegemon-swap \
  --hegemon-rpc http://127.0.0.1:9944 \
  --hegemon-wallet /absolute/path/to/your.wallet \
  --private-spend "$PWD/target/release/private-spend" \
  --hegemon-handoff-dir "$HOME/.local/share/hegemon-swap/refund-handoffs" \
  --token-file "$HOME/.local/share/hegemon-swap/companion-token" \
  --gui
```

If the dependencies are already available to your usual `python3`, you can use `python3` in place of the venv interpreter. For terminal-only operation, omit **`--gui`**. Run swap mode in an interactive terminal even when using the window: transaction approvals still happen locally in the terminal.

**Use `--hosted-hegemon-swap` for the complete workflow.** `--hosted-node-status` checks the node only. `--hosted-wallet-status` can read a balance, but cannot complete the transactions. Do not combine those modes or add the older `--hegemon-public` flag to the command above.

### 3. Pair the browser

1. Open the [website](https://hegemon-swap-testnet.willdoyle422.workers.dev/).
2. Press **Companion not connected**, or **Connect my Hegemon node**.
3. In the companion window, press **Copy token**. With no window, read your token in a second terminal:

   ```bash
   cat "$HOME/.local/share/hegemon-swap/companion-token"
   ```

4. Paste it into **Companion pairing token** on the website.
5. Press **Connect local companion**. Allow local-network access if the browser asks.
6. Confirm the indicator turns green. Pressing the indicator again opens the connection details.

![Connection page showing the pairing field and Connect local companion button.](images/02-connect-companion.png)

Keep the pairing token private. It is not your wallet passphrase. Your browser remembers a successful pairing; **Forget pairing code** removes it from that browser. The companion normally listens on `127.0.0.1:8788`; this is separate from your node's RPC port, `9944`.

### 4. Unlock when asked

When the page needs your HGN address or balance, it asks you to unlock the local wallet. In GUI mode, enter the wallet passphrase in the **companion window** and press **Unlock**. With no GUI, type `UNLOCK` in its terminal, then enter the passphrase at the hidden prompt.

The initial wallet scan can take several minutes. **Checking saved notes** is progress through notes, not blocks. A **Caught up** node does not mean the wallet's note scan has finished. Wait for an available-balance result before continuing. The optional **Remember** setting uses the local desktop keyring.

One companion process serves one Hegemon wallet. To switch participants on the same computer, stop the companion and restart it with the other wallet file; the wizard checks the address against the saved swap terms.

## Create an offer: the maker

Alice is the **maker**: she posts what she will give and what she wants back. Our worked example is **5 ADA for 0.0001 ETH**.

### 1. Choose the coin to give

On the home page, press **Create an offer**. On **What will you offer?**, select your coin and press **Continue**.

![Offer step 1: choose the coin to give. HGN is selected in this illustration.](images/03-choose-asset.png)

For the worked example, select **Cardano · ADA** instead of HGN.

### 2. Enter how much to give

On **How much will you offer?**, type `5` in **Amount in ADA**. Check the exact amount below it: `5000000 lovelace`. Press **Continue**.

![Offer step 2: 5 ADA equals 5000000 lovelace.](images/04-offer-amount.png)

For HGN, this step additionally reads your unlocked companion wallet. **Continue** requires enough ordinary available HGN for the offer plus the displayed 1,000-atom public fee. This check does not lock or reserve those coins. Later funding, claim and refund steps still need their own fees.

### 3. Choose the coin to receive

On **What would you like in return?**, choose **Ethereum · ETH** and press **Continue**.

![Offer step 3: select Ethereum ETH to receive.](images/05-receive-asset.png)

### 4. Enter how much to receive

On **How much would you like?**, enter `0.0001`. Check the units and press **Continue**. This is the amount the other person will pay you, before accounting for their separate network fees.

![Offer step 4: request 0.0001 ETH.](images/06-receive-amount.png)

### 5. Choose who can find the offer

On **Who should see your offer?**, choose either:

- **Private link**: share the complete link with the person you want to trade with.
- **Public board**: let people discover it through **Explore public offers**.

A private link is shareable access to the offer, not proof of someone's identity. Press **Continue**.

![Offer step 5: select private or public visibility.](images/07-visibility.png)

### 6. Choose the listing lifetime

On **How long should it be available?**, select a lifetime and press **Continue**.

**This is the offer's listing expiry, not a refund deadline.** The swap's on-chain deadlines are calculated later, once both participants prepare the swap.

![Offer step 6: select how long the listing stays available.](images/08-offer-lifetime.png)

### 7. Protect your inbox key

Your browser creates a private **inbox key** so a person reserving your offer can establish an encrypted swap channel with you. The software uses that channel to exchange structured details; you do not have to conduct a free-form conversation.

Select the encrypted-backup option and enter a separate passphrase of at least 12 characters twice. Then press **Continue**. This is your one opportunity to export that inbox key.

![Offer step 7: choose an encrypted inbox backup.](images/09-inbox-backup.png)

The inbox backup restores only the inbox key. It does **not** restore your wallet, your offer-owner credential, or the full swap. Full swap recovery comes later.

### 8. Review and create

On **Review your offer**, check **You give**, **You receive**, the exact base units, visibility and lifetime. Use **Back** to correct a mistake. When correct, press **Create offer**.

![Offer step 8: review 5 ADA for 0.0001 ETH before creating the offer.](images/10-review-offer.png)

Drafts are not saved across refreshes. Finish or copy your draft before reloading. Creating the offer publishes a listing; it does not ask a wallet to lock funds.

### 9. Save the backup and share the link

On **Your offer is ready to share**:

1. Copy and save the encrypted inbox backup outside the browser.
2. Keep the passphrase separately.
3. Tick **I saved the encrypted inbox backup and its passphrase**.
4. Press **Copy offer link** and share the complete link with Bob.
5. Press **Continue to offer** and keep this browser profile available.

![Offer created: save the inbox backup, copy the link, then continue. Example link and backup content are hidden in this capture.](images/11-save-and-share.png)

Wait for Bob to reserve. Press **Refresh progress** to check. Your offer-owner credential is still in this browser; the inbox backup alone cannot recreate it if you clear browser storage.

## Accept an offer: the taker

Bob is the **taker**: he finds Alice's offer and agrees to provide what Alice requested.

### 1. Find the offer

Open Alice's complete shared link directly. Alternatively, on the home page press **Open an offer link**, paste it and open it. For public listings, press **Explore public offers** and select one.

![Open an offer link screen.](images/12-open-link.png)

### 2. Read the offer from the maker's perspective

The details say **Maker gives** and **Maker wants**. For this example:

- **Alice gives 5 ADA. Bob receives that ADA.**
- **Alice wants 0.0001 ETH. Bob must provide that ETH.**

Check the amounts, networks and expiry. Then press **Reserve offer**. A reservation does not transfer or lock your coins.

![Bob reviews the offer and presses Reserve offer.](images/13-review-before-reserving.png)

### 3. Open the guided session

After reserving, press **Continue the guided swap →** on the offer page.

![Reserved offer with the Continue the guided swap button.](images/14-reserved.png)

Alice must also reopen her offer in her original browser, press **Continue the guided swap →**, and choose **Accept and start**. This accepts the reservation and closes the listing to new takers. It is not a funding transaction.

![Alice accepts the reservation and starts the swap session.](images/15-maker-accepts.png)

Bob then presses **Join swap**. If the page is waiting for Alice, refresh after she accepts. Alice may then need to refresh after Bob joins.

**Use the button on the offer page.** The home-page **Continue a swap** tile currently opens the older manual engine reviewer. If it asks you to paste terms JSON and engine status, return to your saved offer link and choose **Continue the guided swap →** instead.

## Complete the swap: both people

From here, use the current **Swap progress** card. It names who must act next and gives you the next control. Some backup and approval steps repeat whenever new information must be saved.

### 1. Save each person's swap recovery backup

When **Protect your swap recovery** appears, choose a separate recovery passphrase, repeat it and press **Create recovery backup**.

![The guided session asks for a swap recovery passphrase.](images/16-swap-recovery.png)

On **Save your encrypted recovery backup**, copy the entire encrypted JSON into a private file, keep its passphrase separately, then press **I saved the backup**. When **Update your recovery backup** appears later, update and save a new copy before proceeding. Keep the newest copy for each participant.

Label passphrases as you save them. The **Backup passphrase** protects the whole session backup. A later **Recovery passphrase** protects the swap secret inside it; the software does not require these to be the same. Keep both if you choose different ones. Neither is your wallet passphrase or companion pairing token.

### 2. Connect wallets and sign participant details

Follow the one-at-a-time prompts to connect the wallets for both coins. Check the networks in the prerequisites table. The wizard then asks you to sign participant details with the supported wallets.

Connecting a wallet and signing an identity message do not transfer coins. Transaction approvals come later. For Bitcoin, follow the [message-signing steps below](#bitcoin-signing-steps). For HGN, the companion supplies your address; the page explains that it cannot independently prove HGN address control with a wallet signature.

### 3. Compare verification codes

The wizard shows **your code** and **their code**. Through a separate trusted channel, each person tells the other their own displayed code. On **Confirm the other person's code**, enter the code they gave you and press **Confirm code**. Do not copy the other code from your own page and treat that as an independent comparison.

If a code changes unexpectedly, stop and check with the other person.

### 4. Maker prepares and sends the terms

Alice sees **Prepare the swap terms**. She chooses and records a **Recovery passphrase** for the swap secret, then presses **Prepare terms**. The page creates the encrypted secret and calculates both refund deadlines from the two networks. She will need this secret-recovery passphrase when claiming; updating the session backup still uses the original **Backup passphrase**.

Alice saves any requested updated recovery backup, reviews the exact amounts, addresses and deadlines, then presses **Send these terms**. This exchanges the proposal; it does not fund a contract.

### 5. Taker accepts the exact terms

Bob refreshes, reviews the proposed terms and presses **Accept these terms** if correct. He saves updated backups when prompted. Alice refreshes after Bob accepts.

### 6. Maker locks the first coin

Alice follows **Prepare funding**, saves the updated backup, and follows the wallet review. She approves the displayed funding transaction only after checking the coin, amount, recipient and refund details.

For our example, Alice locks **5 ADA**. For BTC or HGN, follow the additional chain-specific steps below. Proof generation, signing, submission and confirmation may appear as separate steps.

Bob refreshes while the page checks Alice's confirmed lock. **He must wait until the wizard verifies it before locking his side.**

### 7. Taker locks the second coin

After verification, Bob follows **Prepare funding**, saves the requested backup and approves his own funding transaction. Here, he locks **0.0001 ETH** with the shorter refund deadline.

Alice refreshes until the wizard verifies Bob's lock. A relay announcement or a wallet's “submitted” status alone is not the required confirmation.

### 8. Maker claims the second coin

Once both locks are verified, Alice presses **Prepare claim**, saves the updated backup and follows **Claim your asset**. For ADA/ETH, she enters the secret-recovery passphrase she chose when preparing the terms and presses **Review claim transaction**. She checks the summary, presses **Approve and open wallet**, and approves the transaction in her wallet. In our example, she receives Bob's ETH. BTC and HGN use their signing and terminal steps below instead.

Claiming reveals the shared secret on-chain. That is the intended step that lets Bob finish. Do not send this secret through chat or a relay message.

### 9. Taker claims the first coin

Bob refreshes. The software observes Alice's claim and checks the revealed secret. On **Save the claim recovery data**, he chooses a recovery passphrase and presses **Protect claim recovery**. He saves the updated encrypted backup, follows **Prepare claim**, and reviews and approves his claim transaction. He receives Alice's ADA.

Both people refresh to check the final confirmations and verify receipt in their wallets. Receiving the final coin still involves a claim transaction; the page does not sign it unattended.

## Bitcoin signing steps

Bitcoin uses a wallet handoff rather than a general browser-wallet connection.

**Identity proof:**

1. Enter the compressed public key for the intended wallet key: 66 hexadecimal characters starting with `02` or `03`. Never enter a private key, seed phrase or extended private key.
2. Copy the exact message shown on **Sign with your Bitcoin wallet**.
3. Sign it using a wallet supporting the offered **BIP-137** or **BIP-322 simple** format with that key.
4. Select the matching format, paste the signature and press **Check signature**.

**Funding, claim or refund:**

1. Follow the wizard's address and fee-rate prompts. Use testnet4.
2. Save the updated recovery backup when asked.
3. Copy the unsigned **PSBT** into your external signer. A PSBT is a partially signed Bitcoin transaction, not a private key.
4. Review the amounts, outputs and fees in the signer, sign with the key matching your role, then export the signed PSBT.
5. Paste it into the wizard and press **Check and broadcast**.
6. Refresh until the required confirmations are seen.

The Bitcoin signer must support the supplied HTLC witness script for a claim or refund. A wallet being able to receive BTC does not guarantee this signing support. Establish that capability before locking funds; otherwise use another signer with the same authorized key.

## Hegemon approval steps

Keep the companion running in **hosted swap mode** with the correct wallet. A typical HGN funding sequence is:

1. **Prepare funding**, then save the updated browser recovery backup.
2. **Prepare Hegemon lock**: review and approve proof generation in the local terminal. This prepares the action without submitting it.
3. Save the encrypted refund handoff file from your configured `refund-handoffs` directory and its **separate passphrase**.
4. Save an updated browser recovery backup if prompted.
5. **Submit lock**: review and approve submission in the companion terminal.
6. Refresh until the chain confirms the lock.
7. **Import refund handoff**: approve the saved handoff import and provide its passphrase locally, so the wallet can later refund that exact note.

HGN claims and refunds likewise have preparation, backup, submission and confirmation steps. Follow the exact prompt in the local terminal rather than typing a guessed approval phrase. The GUI handles wallet unlock; it does not remove the transaction-approval prompts.

Your browser backup records the handoff filename. It does **not** contain that encrypted file, its passphrase, or your wallet. Back these up separately. Keep a usable ordinary HGN fee note available.

## Waiting, refresh and reopening

| The card says | What you should do |
| --- | --- |
| **Next action: You** | Read the card and take its displayed action. |
| **The other person** | Ask them to complete their step, then press **Refresh progress**. |
| **Network** or **Network or service** | Wait for confirmation or provider recovery, then refresh. Do not repeat the transaction. |
| **Unknown** or **Could not check the swap** | Resolve the error before proceeding; do not assume that the previous action failed. |
| **Update/Save your recovery backup** | Save the newest encrypted backup and keep the passphrase separately. |
| **Complete** | Check the stated confirmation result and wallet receipt. |

**Refresh progress reloads the page.** It checks saved state and the networks; it does not authorize a new wallet transaction. Do not refresh an unfinished offer draft, because that draft is cleared.

To return to an active swap, open its saved **offer link in the same browser profile**, then press **Continue the guided swap →**. Use only one browser/profile to operate each participant's active swap at a time. Browser storage is part of your local state; clearing it can require recovery.

There are no unattended claims or refunds. Keep track of the actual deadlines. Bitcoin and Hegemon testnet timing can require long windows, sometimes days. The displayed chain deadline is more useful than an assumed wall-clock duration for a block-height timeout.

## Refunds and recovery

### If the other person stops before either lock

No swap funds have moved. You can decline to proceed. Closing a listing or letting its reservation expire does not cancel any transaction you already submitted.

### If you already locked coins

1. Reopen the saved swap and choose **Refund options** when available.
2. Save or update the recovery backup if asked.
3. The page checks the escrow and its deadline. If it says **Refund not ready**, wait until the stated time or block height and refresh.
4. When eligible, prepare and approve the refund using your wallet. Follow the BTC or HGN handoff steps if applicable.
5. Refresh until the refund is confirmed, then check your wallet.

**Refunds are not automatic, and transaction fees are not returned.** An escrow already claimed is no longer refundable. The shorter deadline expiring does not instantly unlock the maker's longer lock.

### If a wallet response is lost

Do not create another funding transaction. Check wallet history and pending transactions first. The wizard may ask for the **funding transaction ID** on **Find your locked funds**; it verifies the actual escrow before recording that reference. For HGN it uses the local candidate and encrypted handoff records. Preserve those records and ask for help if the outcome remains uncertain.

### If you lose browser state

On the home page, press **Restore an encrypted swap backup**, paste the newest complete recovery JSON, enter its passphrase and restore. Review both wallets' activity when prompted: an older backup may omit transactions you already approved.

| Keep this | What it restores |
| --- | --- |
| Wallet's own backup and passphrase | Your ability to use the wallet. |
| Offer link and original browser profile | Access to the listing and locally stored participant credentials. |
| Encrypted inbox backup and its passphrase | The private inbox key, not the full swap or owner credential. |
| Newest encrypted swap recovery backup and its Backup passphrase | Swap coordination state and the encrypted secret when included. |
| Secret-recovery passphrase chosen at Prepare terms or Protect claim recovery | Unlocks the encrypted secret inside the saved swap state for claiming; keep this too if it differs from the session Backup passphrase. |
| HGN encrypted refund handoff file and its passphrase | The local wallet's recovery information for the exact HGN lock. |

The website cannot reconstruct lost wallet keys or forgotten backup passphrases.

## Troubleshooting

| Problem | Next action |
| --- | --- |
| Companion indicator stays red | Keep the process running; check the token and `127.0.0.1:8788`, allow browser local-network access, and use the pinned hosted website. |
| Indicator is green but HGN swap operations are unavailable | Restart the companion with `--hosted-hegemon-swap`, not a status-only mode. Keep the same wallet and handoff directory. |
| “Caught up” but “Reading wallet…” | The node and wallet have separate progress. Finish the unlock and wait for the saved-note scan; it can take several minutes. |
| HGN balance snapshot is stale | Press **Read balance again**, finish any local unlock, and wait for a fresh result before continuing. |
| HGN total balance looks sufficient but funding fails | Check ordinary available notes and fees. Reserved, locked HTLC and immature notes are excluded; claims/refunds also need a usable separate fee note. |
| Node is syncing, tip differs from the public network, or peers are missing | Wait for the node/network to recover. Do not bypass readiness checks or turn on mining as a workaround. |
| Cardano wallet missing from the list | Enable a supported wallet extension in this browser profile and select **preview**, then reload. |
| Wallet refuses identity signing | The wallet needs the specified message-signing support, not just transaction sending. Use a compatible wallet before funding. |
| Wallet is on the wrong network | Select Sepolia, Cardano preview or Bitcoin testnet4 as appropriate; check HGN's pinned pre-mainnet. |
| Page asks for engine status JSON | You opened the older manual reviewer. Reopen your offer link and press **Continue the guided swap →**. |
| Waiting for the other person even though they acted | Both people should reopen their correct offer in their original profiles and refresh. Check for unfinished setup, backup or signing steps. |
| Funding or claim is submitted but not confirmed | Check its transaction ID and network progress. Refresh; do not submit another copy because the page is waiting. |
| Closing an offer did not return locked coins | Listing controls do not spend the escrow. Use the swap's refund path after its on-chain deadline. |

For a useful bug report, include the coin pair, test networks, maker/taker role, exact step title, error text and public transaction IDs. Remove pairing tokens, recovery JSON, private link fragments, wallet data and passphrases from screenshots or logs.

For implementation and operator details, see [METHODS.md](../METHODS.md#local-public-testnet-rehearsal-before-deployment) and [the swap service documentation](../swap-service/README.md). The current guide follows the native-coin session wizard; older manual tools are separate workflows.
