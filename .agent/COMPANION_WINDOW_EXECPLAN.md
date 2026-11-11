# Optional local window for the swap companion

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

A person running the local companion today has to open the pairing-token file in a text editor and type the wallet passphrase into the terminal every time the hosted page asks to read the wallet. After this change they can add `--gui` and get a small window on the same computer. That window shows the pairing token and a Copy button, and it can remember the wallet passphrase in the desktop keyring so the next launch fills the field in. The window does not replace the terminal mode. Without `--gui`, the companion behaves as it does now. The hosted website still never receives the token or the passphrase.

## Progress

- [x] (2026-11-10 22:35Z) Write this ExecPlan before changing product code.
- [x] (2026-11-10 22:45Z) Add desktop keyring save, load, and delete keyed by the wallet path, using `secret-tool` and stdin.
- [x] (2026-11-10 22:45Z) Add `--gui`, the local window, and the click that replaces the terminal unlock prompt.
- [x] (2026-11-10 22:50Z) Cover the keyring and the headless approval in unit tests, and update DESIGN.md, METHODS.md, and scripts/SWAP_SCRIPTS.md.

## Surprises & Discoveries

- Observation: this machine's `python3` cannot import `tkinter`, and `secret-tool` is not on `PATH`.
  Evidence: `import tkinter` raises `ModuleNotFoundError`, and `command -v secret-tool` prints nothing. `--gui` now exits with `The companion window needs Python tkinter. Install the python3-tk package and start again.` A missing `secret-tool` raises `KeyringUnavailable` and does not create a file.

## Decision Log

- Decision: the window is opt-in through `--gui`. The default remains the terminal prompts.
  Rationale: the companion is already used from a terminal, and tests start it without a display.
  Date/Author: 2026-11-10

- Decision: the remembered passphrase is stored with the `secret-tool` program, which talks to the desktop Secret Service. The lookup attributes are `service=hegemon-swap-companion` and `wallet=<absolute wallet path>`. The secret is written on the tool's standard input, never as a command argument and never as a file next to the wallet.
  Rationale: the desktop login already unlocks that keyring. A mode-0600 file would be a second copy of the passphrase on disk. If `secret-tool` is missing, Remember reports that and the scan can still proceed.
  Date/Author: 2026-11-10

- Decision: the window uses the Python `tkinter` toolkit and runs on the main thread. The loopback HTTP server moves to a background thread only when `--gui` is set.
  Rationale: `tkinter` is part of the Python standard library, so the hosted page cannot be the window. A browser window could be reached by the same machine's hosted origin. Tk requires the main thread.
  Date/Author: 2026-11-10

- Decision: clicking Unlock is the local approval. The person does not also type the word UNLOCK. The click does nothing until the hosted page has asked for a read, so opening the window does not scan the wallet.
  Rationale: the click is the same local consent the terminal word provided. Scanning on open would surprise someone who only wanted the token.
  Date/Author: 2026-11-10

- Decision: the keyring is updated only after a successful wallet read. A checked Remember saves; an unchecked Remember deletes. A failed read leaves the stored secret unchanged.
  Rationale: a wrong passphrase must not replace a good stored one, and unchecking must be able to forget it.
  Date/Author: 2026-11-10

## Outcomes & Retrospective

`--gui` opens a local window that copies the pairing token and, in wallet-status mode, approves the passphrase with one click. Remember stores that passphrase through `secret-tool` after a successful read and fills it on the next launch. Without `--gui`, the terminal prompts are unchanged. `PYTHONPATH=scripts python3 -m unittest scripts.test_local_swap_companion` reports 13 tests OK, including the keyring round trip and the headless window approval. The activity JSON from that approval does not contain the passphrase.

What remains outside this change: this computer still needs the `python3-tk` package before the window can open, and `libsecret-tools` before Remember can store a passphrase. The hosted page still never receives either secret. A real window was not opened in the unit test, because creating one requires tkinter and a display.

## Context and Orientation

The companion is `scripts/local_swap_companion.py`. It listens only on `127.0.0.1`, normally port 8788, and the hosted page at `https://hegemon-swap-testnet.willdoyle422.workers.dev` calls it with a bearer token. That token is the pairing code. `private_token` creates or reads it from the `--token-file` path. The file must be mode 0600 inside a user-owned directory of mode 0700. The token is not the wallet passphrase.

`--hosted-wallet-status` is the mode that reads one encrypted Hegemon wallet. Hegemon is this project's chain. The wallet file is opened by the `private-spend` program. Today `HostedWalletSession.unlock` prints a prompt, calls `confirm_unlock` (the person types UNLOCK), then `read_passphrase` (`getpass` with echo off). The passphrase is kept as a `bytearray` in the process and wiped on exit. `GET /hegemon/wallet-activity` returns only a phase and, while scanning, block heights. It must not return the passphrase, note positions, or a balance.

A desktop keyring is the Secret Service already used by the login session. `secret-tool` is the command-line client. `lookup` prints a stored secret, `store` reads one line from stdin, and `clear` deletes the matching item.

`tkinter` is the window library shipped with CPython. Creating a `Tk()` root needs a display. Unit tests must not create one.

## Plan of Work

Add `KeyringUnavailable`, `DesktopKeyring`, `GuiApproval`, `describe_companion_status`, and `CompanionWindow` to `scripts/local_swap_companion.py`.

`DesktopKeyring.load`, `save`, and `delete` take a wallet path. They call `secret-tool` with the attributes above. `save` sends the passphrase only as stdin and refuses an empty passphrase or one that contains a newline or a NUL. A missing `secret-tool`, or a failed store, raises `KeyringUnavailable` with the fixed sentence `The desktop keyring is unavailable. The passphrase was not saved.` `load` returns `None` when the item is absent. `delete` treats exit codes 0 and 1 as success so a missing item is not an error.

`GuiApproval.ask` blocks the caller until `submit(passphrase, remember)` or `decline`. `waiting` is true only while a request is unanswered. `report` stores a notice string for the window.

`HostedWalletSession` gains optional `prompt` and `keyring`. When `prompt` is set, `unlock` uses `ask` instead of `confirm_unlock` and `read_passphrase`. After the wallet read succeeds, a true remember flag calls `keyring.save` and a false flag calls `keyring.delete`. A `KeyringUnavailable` is reported on the prompt and printed; it does not fail the read. The passphrase is still wiped from the process on close.

`describe_companion_status(snapshot, notice='')` turns an activity snapshot into one sentence. Heights are included only when they are decimal strings. A notice replaces the sentence.

`CompanionWindow.run` imports `tkinter`, builds one window, and blocks in `mainloop`. The background is `#0E1C36`, the body text is `#F4F7FB`, Copy and Unlock use `#1BE7FF`, and errors use `#FF4E4E`. The token is a read-only field. Copy writes it to the local clipboard and changes the button text to `Copied` for two seconds. When a wallet path is supplied, the window loads the keyring entry into the passphrase field and checks Remember. Unlock calls `prompt.submit` only while `prompt.waiting()` is true. A timer reads `activity.snapshot()` and `prompt.notice`. Closing the window ends `mainloop`.

`main` adds `--gui`. For `--hosted-wallet-status`, the interactive-terminal requirement is skipped when `--gui` is set. The server starts on a daemon thread and `CompanionWindow.run` occupies the main thread. Without `--gui`, `serve_forever` stays on the main thread and the terminal prompts are unchanged.

## Concrete Steps

From the repository root `/home/william/Hegemon`:

    PYTHONPATH=scripts python3 -m unittest scripts.test_local_swap_companion

Expect `OK` and the new tests `test_desktop_keyring_roundtrip_keeps_the_passphrase_off_the_command_and_off_disk` and `test_gui_approval_unlocks_without_putting_the_passphrase_on_the_activity_read`.

To see the window, with a display available and the node already running:

    python3 scripts/local_swap_companion.py --hosted-wallet-status --gui \
      --hegemon-rpc http://127.0.0.1:9944 \
      --hegemon-wallet /path/to/one.wallet \
      --token-file "$HOME/.local/share/hegemon-swap/companion-token"

The window shows the token. Copy places it on the clipboard. The passphrase field is empty until Remember has succeeded once. The hosted page's unlock click enables Unlock in the window.

## Validation and Acceptance

The keyring test uses a fake `secret-tool`. After save, lookup returns the same passphrase. After delete, lookup returns nothing. The passphrase never appears in the argument list, and a temporary directory passed to the test stays empty.

The approval test starts `unlock` on a thread, submits a passphrase through `GuiApproval` without creating a window, and asserts the returned snapshot and the activity JSON do not contain that passphrase. A decline raises `ValueError` with `wallet unlock declined locally`.

`describe_companion_status` on `{phase: syncing, current_height: 15440, target_height: 15445, resumed: true}` returns a sentence that starts `Resuming from the saved wallet`.

Without `--gui`, the existing terminal tests still pass, including the declined UNLOCK case.

## Idempotence and Recovery

Re-running the unit test is safe. `--gui` does not change the token file. Remember writes only through `secret-tool`. If that program is absent, the window says the keyring is unavailable and no passphrase file is created. Closing the window stops the server thread and wipes the in-memory passphrase. Starting again without `--gui` returns to the terminal prompts.

## Artifacts and Notes

The keyring command shapes are:

    secret-tool lookup service hegemon-swap-companion wallet /absolute/wallet/path
    secret-tool store --label 'Hegemon companion wallet' service hegemon-swap-companion wallet /absolute/wallet/path
    secret-tool clear service hegemon-swap-companion wallet /absolute/wallet/path

The store command reads the passphrase from stdin and appends a newline because `secret-tool` reads one line.

## Interfaces and Dependencies

In `scripts/local_swap_companion.py`:

    class KeyringUnavailable(RuntimeError): ...

    class DesktopKeyring:
        def __init__(self, run=None): ...
        def load(self, wallet_path): ...  # str or None
        def save(self, wallet_path, passphrase): ...
        def delete(self, wallet_path): ...

    class GuiApproval:
        def ask(self): ...  # ('ok', passphrase, remember) or ('decline',)
        def waiting(self): ...
        def submit(self, passphrase, remember): ...
        def decline(self): ...
        def report(self, text): ...

    def describe_companion_status(snapshot, notice=''): ...

    class CompanionWindow:
        def __init__(self, *, token, wallet_path=None, keyring=None, prompt=None, activity=None): ...
        def run(self): ...

`HostedWalletSession.__init__` accepts `prompt=None` and `keyring=None`. No new third-party Python package is required. The external program is `secret-tool` from libsecret.

## Revision note

2026-11-10: Created this plan before the window or the keyring helper existed, so a later reader can implement it from this file alone.

2026-11-10: Marked the work complete after the unit tests passed. Recorded that this computer's Python has no tkinter module and no secret-tool command, and that the window and Remember now name the packages to install instead of failing silently or writing a passphrase file.
