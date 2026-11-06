"""Hegemon adapter placeholder: conforms to ChainAdapter, does nothing real.

The Hegemon testnet leg is wired in P6/P8 (shielded private-spend HTLC through the wallet RPC).
Until then every read raises ChainUnavailable and every write raises ActionRefused, so an engine
configured with this adapter waits or refuses and never acts. It exists so the interface and the
engine's handling of an absent chain are tested now.
"""
try:
    from swap_engine.adapter import ActionRefused, ChainAdapter, ChainUnavailable
except ImportError:
    from adapter import ActionRefused, ChainAdapter, ChainUnavailable


class HegemonStubAdapter(ChainAdapter):
    chain = 'hegemon'
    journal_chain = 'hegemon-testnet'

    def __init__(self, identity='00' * 32):
        self._identity = identity

    def identity(self):
        return self._identity

    def head(self):
        raise ChainUnavailable('the Hegemon adapter is not implemented yet (P6/P8)')

    def inspect(self, leg, escrow):
        raise ChainUnavailable('the Hegemon adapter is not implemented yet (P6/P8)')

    def fund(self, leg, journal):
        raise ActionRefused('the Hegemon adapter is not implemented yet (P6/P8)')

    def claim(self, leg, escrow, preimage, journal):
        raise ActionRefused('the Hegemon adapter is not implemented yet (P6/P8)')

    def refund(self, leg, escrow, journal):
        raise ActionRefused('the Hegemon adapter is not implemented yet (P6/P8)')

    def escrow_ref(self, leg, txid):
        raise ActionRefused('the Hegemon adapter is not implemented yet (P6/P8)')

    def journal_ids(self, journal):
        return []

    def transaction_seen(self, txid):
        raise ChainUnavailable('the Hegemon adapter is not implemented yet (P6/P8)')
