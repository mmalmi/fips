"""Check one durable funding operation across a held mint reply and restart."""

from .paid_settlement import require


SDK_FIELDS = ('admissions', 'openings', 'open_requests', 'funding', 'pending_funding')


class PendingQuote:
    """The first purchase must use the provider's original durable offer."""

    def __init__(self, requested, journal, buyer):
        require(len(requested) == 1, 'first funding needs exactly one requested quote')
        self.identifier, self.offer = next(iter(requested.items()))
        require(self.identifier == self.offer['id'] and self.offer['buyer'] == buyer
                and journal['version'] == 2
                and journal['binding']['local'] == bytes(self.offer['provider']).hex(),
                'first quote changed its identity or provider binding')
        self.binding = journal['binding']
        self.entry = journal['pending'].get(self.identifier)
        require(self.entry is not None and self.entry['offer'] == self.offer
                and self.entry['downstream'] is None
                and self.entry['local_fee_msat_per_kib'] == self.offer['price']['msat'] > 0,
                'first purchase lacks its exact durable provider quote')

    def retained(self, journal):
        require(journal['version'] == 2 and journal['binding'] == self.binding
                and journal['pending'].get(self.identifier) == self.entry,
                'restart lost or changed the original provider quote')

    def accepted(self, buyer, provider, channel):
        require(len(buyer['outgoing']) == len(provider['incoming']) == 1,
                'first quote recovery introduced another contract')
        outgoing = next(iter(buyer['outgoing'].values()))
        incoming = next(iter(provider['incoming'].values()))
        purchase = outgoing['purchase']
        require(outgoing['offer'] == incoming['offer'] == self.offer
                and outgoing['accepted'] and not outgoing['retired'] and incoming['phase'] == 'Active'
                and purchase['channel'] == incoming['channel'] and purchase['channel']['id'] == channel
                and purchase['contract'] == incoming['contract'],
                'recovered contract does not match the original quote and channel')


class PendingFunding:
    def __init__(self, request, intent, original, pending):
        self.request, self.intent = request, intent
        self.original, self.pending = original, pending
        admission = pending.get('admissions', {}).get(request)
        opening = pending.get('openings', {}).get('r:' + request)
        require((admission is None) != (opening is None), 'funding lacks one exact durable SDK stage')
        require(pending['open_requests'] == original.get('open_requests', {})
                and pending['funding'] == original.get('funding', {})
                and pending.get('pending_funding', {}) == original.get('pending_funding', {})
                and set(pending.get('admissions', {})) == ({request} if admission else set())
                and pending.get('openings', {}) == {
                    **original.get('openings', {}), **({'r:' + request: opening} if opening else {})},
                'held reply changed acknowledged funding or introduced another SDK request')
        self.stage = 'wallet_preparation' if admission else 'channel_opening'
        if admission:
            require(admission['funding_started'] and admission['request']['client_request_id'] == request,
                    'wallet preparation is not bound to the reserved request')
        else:
            require(opening['wallet_send']['operation_id']
                    and opening['request']['client_request_id'] == request,
                    'channel opening is not bound to its saved wallet operation')

    def unchanged(self, sdk):
        require(all(sdk.get(key, {}) == self.pending.get(key, {}) for key in SDK_FIELDS),
                'interruption lost the original pending SDK operation')

    def recovered(self, current, sdk, *, buyer, mint):
        require(all(current[key] == value for key, value in self.intent.items() if key != 'funded'),
                'recovery changed the reserved funding terms')
        funded = current['funded']
        terms = funded['terms']
        channel = terms['id']
        require(channel not in self.original.get('funding', {})
                and terms['buyer'] == buyer and terms['mint_url'] == mint
                and terms['capacity_sat'] == current['capacity_sat'] == current['max_wallet_debit_sat'] == 32
                and terms['grace_msat'] == current['grace_msat'] == 8000
                and terms['expires_unix'] == current['expires_unix']
                and terms['refund_after_unix'] == current['refund_after_unix']
                and funded['wallet_cost'] == {'token_amount_sat': 32, 'wallet_debit_sat': 32, 'swap_fee_sat': 0},
                'recovered funding changed its authorized terms or cost')
        require(sdk['open_requests'] == {**self.original.get('open_requests', {}), self.request: channel}
                and not sdk.get('admissions') and not sdk.get('pending_funding')
                and set(sdk['funding']) == set(self.original.get('funding', {})) | {channel}
                and all(sdk['funding'][key] == value for key, value in self.original.get('funding', {}).items())
                and set(sdk.get('openings', {})) == set(self.original.get('openings', {})) | {'r:' + self.request}
                and all(sdk['openings'][key] == value for key, value in self.original.get('openings', {}).items())
                and sdk['openings']['r:' + self.request]['channel_id'] == channel,
                'recovery left unresolved or duplicated SDK funding')
        if self.stage == 'channel_opening':
            opening = self.pending['openings']['r:' + self.request]
            require(channel == opening['channel_id']
                    and funded['wallet_operation_id'] == opening['wallet_send']['operation_id'],
                    'recovery replaced the saved wallet operation or channel')
        return channel
