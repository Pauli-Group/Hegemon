# First P2P Transaction Guide

To set up a P2P connection between two computers in different cities, you both need to act as nodes. Since you are on different networks (across the internet), you must ensure your computers can "see" each other through your home routers.

Here is the step-by-step guide to finding your information and exactly what to enter.

### 1. Find Your Information (Do this on your MacBook)

You need two pieces of information: your **Local IP** (for your router to know which device to send traffic to) and your **Public IP** (for your friend to connect to you).

**Step A: Find your Local IP**
Open your terminal and run:
```bash
ipconfig getifaddr en0
```
*   *Output example:* `192.168.1.15`
*   *Note:* If you are on Wi-Fi, it is usually `en0`. If that returns nothing, try `en1`.

**Step B: Find your Public IP**
In the terminal, run:
```bash
curl ifconfig.me
```
*   *Output example:* `203.0.113.45`
*   *Share this:* Send this IP address to your friend. You will need theirs as well.

### 2. Configure Port Forwarding (Crucial)

Because you are behind a home router, your friend cannot connect directly to your MacBook unless you "open the door."

1.  Log in to your router's admin panel (usually `192.168.1.1` or `10.0.0.1` in a browser).
2.  Look for **Port Forwarding** or **Virtual Server**.
3.  Create a new rule:
    *   **Port:** `9000` (TCP and UDP)
    *   **IP Address:** Your **Local IP** from Step 1A (e.g., `192.168.1.15`).
4.  Save the settings.
*Your friend must do this on their router as well, pointing to their own Local IP.*

### 3. Start the Nodes (What to enter where)

Now you can start the software. You will tell your node to listen on all interfaces (`0.0.0.0`) and connect to your friend's **Public IP**.

**Your Command (Run this in your terminal):**
Replace `<FRIEND_PUBLIC_IP>` with the IP they sent you.
```bash
cargo run -p node --bin node -- \
  --db-path /tmp/my-node.db \
  --api-addr 127.0.0.1:8080 \
  --api-token my-secret-token \
  --p2p-addr 0.0.0.0:9000 \
  --seeds <FRIEND_PUBLIC_IP>:9000 \
  --miner-workers 2 \
  --wallet-store /tmp/my-wallet.store \
  --wallet-passphrase my-passphrase
```

**Your Friend's Command (They run this):**
Replace `<YOUR_PUBLIC_IP>` with the IP you found in Step 1B.
```bash
cargo run -p node --bin node -- \
  --db-path /tmp/friend-node.db \
  --api-addr 127.0.0.1:8080 \
  --api-token friend-secret-token \
  --p2p-addr 0.0.0.0:9000 \
  --seeds <YOUR_PUBLIC_IP>:9000 \
  --miner-workers 2 \
  --wallet-store /tmp/friend-wallet.store \
  --wallet-passphrase friend-passphrase
```

### 4. Create the Transaction

Once both nodes are running and you see logs indicating they are peering/mining, you can send the transaction.

**A. Initialize your wallets (if you haven't already):**
```bash
# Open a new terminal tab
cargo run -p wallet --bin wallet -- init --store /tmp/my-wallet.store --passphrase my-passphrase
```

**B. Get your Friend's Address:**
Your friend runs this to see their address:
```bash
cargo run -p wallet --bin wallet -- address --store /tmp/friend-wallet.store --passphrase friend-passphrase
```
*They send you the string starting with `hgn...`*

**C. Send the funds:**
Create a file named `recipient.json` with your friend's address:
```json
[
  {
    "address": "hgn1...", 
    "value": 50,
    "asset_id": 1,
    "memo": "Hello from my city!"
  }
]
```

Run the send command:
```bash
cargo run -p wallet --bin wallet -- send \
  --store /tmp/my-wallet.store \
  --passphrase my-passphrase \
  --rpc-url http://127.0.0.1:8080 \
  --auth-token my-secret-token \
  --recipients recipient.json \
  --fee 1
```

### Summary Checklist
| Information | Where to find it | Where to enter it |
| :--- | :--- | :--- |
| **Local IP** | `ipconfig getifaddr en0` | Router Port Forwarding rule |
| **Public IP** | `curl ifconfig.me` | In your **friend's** `--seeds` flag |
| **Friend's Public IP** | Ask your friend | In **your** `--seeds` flag |
| **Wallet Address** | `wallet address` command | In the `recipient.json` file |

---

## Local Network Test (Mac & Windows)

If you are testing between a MacBook and a Windows PC on the **same Wi-Fi network**, you do **not** need to configure port forwarding on your router. You only need your **Local IPs**.

### 1. Find Local IPs

**On MacBook:**
Run in Terminal:
```bash
ipconfig getifaddr en0
```
*   *Example:* `192.168.1.15` (This is your **Mac IP**)

**On Windows:**
Run in Command Prompt (cmd) or PowerShell:
```powershell
ipconfig
```
*   Look for "Wireless LAN adapter Wi-Fi" -> "IPv4 Address".
*   *Example:* `192.168.1.20` (This is your **Windows IP**)

### 2. Firewall Settings

*   **Windows:** When you run the node for the first time, Windows Firewall may pop up. Ensure you check the boxes to **Allow** access on Private networks.
*   **Mac:** Usually allows outbound connections by default. If prompted, allow incoming connections.

### 3. Start the Nodes (Local Network)

**On MacBook (connecting to Windows):**
Replace `<WINDOWS_IP>` with the IP you found on the PC (e.g., `192.168.1.20`).
```bash
cargo run -p node --bin node -- \
  --db-path /tmp/mac-node.db \
  --api-addr 127.0.0.1:8080 \
  --api-token mac-secret \
  --p2p-addr 0.0.0.0:9000 \
  --seeds <WINDOWS_IP>:9000 \
  --miner-workers 2 \
  --wallet-store /tmp/mac-wallet.store \
  --wallet-passphrase mac-pass
```

**On Windows (connecting to Mac):**
Replace `<MAC_IP>` with the IP you found on the Mac (e.g., `192.168.1.15`).
*Note: Windows paths use backslashes or you can use forward slashes in PowerShell. The `^` is the line continuation character in Command Prompt. In PowerShell, use backtick `` ` ``.*

**PowerShell Example:**
```powershell
cargo run -p node --bin node -- `
  --db-path C:\Temp\win-node.db `
  --api-addr 127.0.0.1:8080 `
  --api-token win-secret `
  --p2p-addr 0.0.0.0:9000 `
  --seeds <MAC_IP>:9000 `
  --miner-workers 2 `
  --wallet-store C:\Temp\win-wallet.store `
  --wallet-passphrase win-pass
```

### 4. Test Transaction

Follow the same "Create the Transaction" steps as above, but use the addresses generated on these local nodes.
