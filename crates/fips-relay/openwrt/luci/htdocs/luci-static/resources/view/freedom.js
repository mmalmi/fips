'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
'require dom';

var status = rpc.declare({ object: 'luci.freedom', method: 'status', expect: {} });
var action = rpc.declare({ object: 'luci.freedom', method: 'action', params: ['action'], expect: {} });
var configure = rpc.declare({
	object: 'luci.freedom', method: 'configure',
	params: ['revision', 'mode', 'fee', 'max_rate', 'budget', 'wallet_spend', 'locked_funds', 'mint', 'interface'],
	expect: {}
});

function checked(result) {
	if (result.error) throw new Error(result.error);
	return result;
}

function sat(msat) {
	if (msat == null || !/^\d+$/.test(String(msat))) return _('Unavailable');
	var s = String(msat).padStart(4, '0');
	return s.slice(0, -3) + '.' + s.slice(-3) + ' sat';
}

function bytes(n) {
	if (n == null) return '—';
	return (Number(n) / 1048576).toFixed(2) + ' MiB';
}

return view.extend({
	load: function() { return status().then(checked); },

	render: function(data) {
		this.current = data;
		this.revision = data.revision;
		this.fields = {};
		this.busy = false;
		this.readonly = !L.hasViewPermission();
		this.overview = E('div', { 'aria-live': 'polite' });
		this.peerList = E('div');
		this.buttons = E('div', { 'class': 'cbi-page-actions' });
		this.error = E('p', { 'role': 'alert', 'style': 'color:var(--error-color, #b00)' });
		var settings = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Forwarding settings')),
			E('p', {}, data.account_exists
				? _('These settings belong to the existing account and cannot be changed here. Stopping the service preserves its wallet and payment channels.')
				: _('Choose your terms before creating an account. Account prices and lifetime limits are fixed after creation.'))
		]);
		var self = this;
		function field(name, label, hint, choices) {
			var input = choices ? E('select', { 'id': 'freedom-' + name }, choices.map(function(x) {
				return E('option', { 'value': x[0] }, x[1]);
			})) : E('input', { 'id': 'freedom-' + name, 'type': ['mint', 'interface'].includes(name) ? 'text' : 'number',
				'min': ['fee', 'max_rate'].includes(name) ? 0 : 1, 'max': 1000000000, 'step': 1, 'class': 'cbi-input-text' });
			input.value = data.settings[name] == null ? '' : data.settings[name];
			input.disabled = data.account_exists || self.readonly;
			self.fields[name] = input;
			settings.appendChild(E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title', 'for': input.id }, label),
				E('div', { 'class': 'cbi-value-field' }, [input, E('div', { 'class': 'cbi-value-description' }, hint)])
			]));
		}
		field('mode', _('Service'), _('Free forwarding can still incur onward costs, bounded by your spending limits.'),
			[['free', _('Free')], ['paid', _('Paid')]]);
		field('fee', _('Forwarding price'), _('Millisats per 1,024 bytes. 1,000 millisats = 1 sat.'));
		field('max_rate', _('Maximum route price'), _('Total route price ceiling, in millisats per 1,024 bytes.'));
		field('budget', _('Lifetime payment limit (sats)'), _('Maximum signed payments for this account.'));
		field('wallet_spend', _('Lifetime wallet spending (sats)'), _('Gross wallet spending, including funding costs. Refunds do not reset this limit.'));
		field('locked_funds', _('Maximum funds in channels (sats)'), _('Limits funds committed at the same time.'));
		field('mint', _('Cashu mint'), _('Use a mint you trust and that neighboring providers accept.'));
		field('interface', _('Mesh interface'), _('An existing, unbridged interface such as mesh0. Configure Wi-Fi in Network → Wireless.'));
		this.fields.mode.addEventListener('change', function() {
			self.fields.fee.disabled = self.readonly || data.account_exists || self.fields.mode.value == 'free';
		});
		this.fields.mode.dispatchEvent(new Event('change'));
		if (!data.account_exists) settings.appendChild(E('button', {
			'class': 'cbi-button cbi-button-save', 'disabled': this.readonly || null,
			'click': ui.createHandlerFn(this, 'saveSettings')
		}, _('Save settings')));
		var page = E('div', { 'class': 'freedom' }, [
			E('h2', {}, _('Freedom')),
			E('p', {}, _('Share connectivity with nearby peers. Offer free forwarding or earn payments for the traffic you carry.')),
			this.error, this.overview, this.buttons,
			E('div', { 'class': 'cbi-section' }, [E('h3', {}, _('Peers')), this.peerList]), settings
		]);
		this.update(data);
		poll.add(function() {
			if (self.busy) return Promise.resolve();
			return status().then(checked).then(function(next) {
				self.update(next);
			}).catch(function() {
				dom.content(self.error, _('Could not refresh Freedom. Displayed values may be out of date.'));
			});
		}, 10);
		return page;
	},

	update: function(data) {
		this.current = data;
		var title = data.ready ? _('Running') : data.account_exists
			? (data.enabled ? _('Starting or unavailable') : _('Stopped')) : _('Setup required');
		dom.content(this.overview, E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, title),
			E('p', {}, data.notice || (data.ready ? _('Relay is responding.') : _('Save settings, then create your account.'))),
			E('div', { 'class': 'table' }, [
				this.row(_('Accepted payments'), sat(data.credit_msat)),
				this.row(_('Funds in outgoing channels'), data.ready ? data.locked_sat + ' sat' : '—'),
				this.row(_('Remaining payment limit'), data.ready ? data.remaining_budget_sat + ' sat' : '—'),
				this.row(_('Start at boot'), data.boot ? _('Enabled') : _('Disabled'))
			]),
			E('p', { 'class': 'cbi-value-description' }, _('Accepted payments are signed credit, including retained history. They are not settled wallet income or profit.'))
		]));
		var rows = (data.peers || []).map(function(p) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', 'style': 'overflow-wrap:anywhere', 'title': p.npub }, p.npub),
				E('td', { 'class': 'td' }, p.connected ? _('Connected') : _('Disconnected')),
				E('td', { 'class': 'td' }, p.transport || '—'),
				E('td', { 'class': 'td' }, bytes(p.sent_bytes)),
				E('td', { 'class': 'td' }, bytes(p.received_bytes))
			]);
		});
		dom.content(this.peerList, rows.length ? E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr table-titles' }, ['Peer', 'Status', 'Link', 'Sent', 'Received'].map(function(s) {
				return E('th', { 'class': 'th' }, _(s));
			})), E('tbody', {}, rows)
		]) : E('p', {}, data.ready ? _('No peers connected yet.') : _('Peer information appears when the relay is running.')));
		var self = this;
		function button(label, name) {
			return E('button', { 'class': 'cbi-button cbi-button-action', 'disabled': self.readonly || self.busy || null,
				'click': ui.createHandlerFn(self, 'serviceAction', name) }, label);
		}
		dom.content(this.buttons, data.account_exists ? [
			button(data.enabled ? _('Stop') : _('Start'), data.enabled ? 'stop' : 'start'),
			button(data.boot ? _('Disable start at boot') : _('Enable start at boot'), data.boot ? 'disable' : 'enable')
		] : data.configured ? [button(_('Create account'), 'initialize')] : []);
		if (data.account_exists) Object.keys(this.fields).forEach(function(k) { self.fields[k].disabled = true; });
	},

	row: function(label, value) {
		return E('div', { 'class': 'tr' }, [E('div', { 'class': 'td' }, label), E('div', { 'class': 'td' }, value)]);
	},

	perform: function(work, saving) {
		if (this.busy || this.readonly) return Promise.resolve();
		this.busy = true;
		dom.content(this.error, '');
		this.update(this.current);
		var self = this;
		return work().then(checked).then(function() { return status().then(checked); })
			.then(function(data) { if (saving) self.revision = data.revision; self.update(data); })
			.catch(function(e) { dom.content(self.error, e.message); })
			.finally(function() { self.busy = false; self.update(self.current); });
	},

	serviceAction: function(name) {
		return this.perform(function() { return action(name); });
	},

	saveSettings: function() {
		var f = this.fields, self = this;
		return this.perform(function() {
			return configure(self.revision, f.mode.value, Number(f.fee.value), Number(f.max_rate.value),
				Number(f.budget.value), Number(f.wallet_spend.value), Number(f.locked_funds.value), f.mint.value, f.interface.value);
		}, true);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
