"""The chain adapter contract for the two-party swap engine.

An adapter belongs to one participant and one chain. The engine owns every
decision; an adapter only reads one chain and performs one signed write when
told to. Reads return plain data so the decision function stays pure. Writes go
through a private journal directory (see scripts/public_swap_journal.py): the
signed transaction is journaled before it is broadcast, so a crash can always be
resolved from the journal.

Error contract:
  ChainUnavailable  a read failed or lagged (HTTP 429, timeout, unindexed data,
                    "snapshot or chain changed"); retry later, nothing changed.
  ActionRefused     a write was refused before anything was signed or journaled
                    (insufficient funds, bad parameters); nothing happened.
  any other error   from fund/claim/refund is treated as uncertain: the engine
                    compares the journal with what it knew before the call.
"""
import re


class ChainUnavailable(Exception):
    pass


class ActionRefused(Exception):
    pass


HEX64 = re.compile('[0-9a-f]{64}')
LEG_KEYS = ('chain', 'amount', 'refundee', 'claimant', 'expiry', 'hashlock')
OBSERVATION_KEYS = ('found', 'verified', 'problem', 'confirmations', 'spent', 'spend_confirmations', 'spend_txid', 'preimage')


def empty_observation():
    return {'found': False, 'verified': False, 'problem': None, 'confirmations': 0,
            'spent': None, 'spend_confirmations': 0, 'spend_txid': None, 'preimage': None}


def check_observation(value):
    """Reject a malformed LegObservation instead of acting on it."""
    if not isinstance(value, dict) or set(value) != set(OBSERVATION_KEYS):
        raise ValueError('Malformed leg observation')
    if not isinstance(value['found'], bool) or not isinstance(value['verified'], bool):
        raise ValueError('Malformed leg observation flags')
    if value['problem'] is not None and not isinstance(value['problem'], str):
        raise ValueError('Malformed leg observation problem')
    for key in ('confirmations', 'spend_confirmations'):
        if not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 0:
            raise ValueError('Malformed leg observation depth')
    if value['spent'] not in (None, 'claimed', 'refunded'):
        raise ValueError('Malformed leg observation spend')
    if value['preimage'] is not None and not (isinstance(value['preimage'], str) and HEX64.fullmatch(value['preimage'])):
        raise ValueError('Malformed leg observation preimage')
    if value['spent'] and not value['found']:
        raise ValueError('A spent escrow must be found')
    return value


def check_escrow_ref(value):
    if not isinstance(value, dict) or not value or len(value) > 8:
        raise ValueError('Malformed escrow reference')
    for key, item in value.items():
        if not isinstance(key, str) or not (isinstance(item, (str, int)) and not isinstance(item, bool)) or len(str(item)) > 256:
            raise ValueError('Malformed escrow reference field')
    return value


class ChainAdapter:
    """Base class documenting the contract. Subclasses implement every method."""

    chain = None  # policy chain name: bitcoin, ethereum, cardano or hegemon

    def identity(self):
        """Public identity string of the local participant on this chain."""
        raise NotImplementedError

    def head(self):
        """Latest head: {'observedAt', 'height'} or {'observedAt', 'timestamp'}."""
        raise NotImplementedError

    def inspect(self, leg, escrow):
        """LegObservation for the escrow named by `escrow` under the agreed `leg` terms.

        `verified` is True only when the on-chain escrow matches amount, hashlock,
        claimant, refundee and expiry in `leg`. A deterministic mismatch sets
        `problem`; a lagging or missing read raises ChainUnavailable instead.
        """
        raise NotImplementedError

    def fund(self, leg, journal):
        """Fund a new escrow for `leg`. Returns {'txid': ...}."""
        raise NotImplementedError

    def claim(self, leg, escrow, preimage, journal):
        """Claim `escrow` with `preimage` (a bytes-like). Returns {'txid': ...}."""
        raise NotImplementedError

    def refund(self, leg, escrow, journal):
        """Refund `escrow` to the local participant. Returns {'txid': ...}."""
        raise NotImplementedError

    def escrow_ref(self, leg, txid):
        """Escrow reference implied by the funding transaction id `txid`."""
        raise NotImplementedError

    def journal_ids(self, journal):
        """Transaction ids journaled under `journal` for this chain, as a list."""
        raise NotImplementedError

    def transaction_seen(self, txid):
        """True if the chain or its mempool knows `txid`, False if not.

        False is not proof of absence on a lagging provider; the engine never
        treats it as such. Raises ChainUnavailable on a failed read.
        """
        raise NotImplementedError


class JournaledWrites:
    """Mixin: run a driver write and turn a refusal before signing into ActionRefused.

    Drivers raise ValueError and similar before they journal anything (insufficient funds,
    bad parameters). If the journal directory did not grow, nothing was signed and the engine
    may clear its inflight marker; otherwise the original error propagates and the engine
    resolves the uncertain action from the journal.
    """

    journal_chain = None

    def journal_ids(self, journal):
        try:
            from swap_engine.store import journal_ids
        except ImportError:  # plain-module use
            from store import journal_ids
        return journal_ids(journal, self.journal_chain)

    def _journaled(self, journal, call):
        before = set(self.journal_ids(journal))
        try:
            return call()
        except (ValueError, FileNotFoundError, PermissionError, KeyError) as error:
            if set(self.journal_ids(journal)) == before:
                raise ActionRefused(str(error)[:300]) from error
            raise


def read_failure(error):
    """Wrap any failure of a read as ChainUnavailable. A failed read never justifies an action."""
    return ChainUnavailable(f'{type(error).__name__}: {str(error)[:200]}')
