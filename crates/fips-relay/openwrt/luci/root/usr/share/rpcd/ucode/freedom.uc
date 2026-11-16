'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { sha256 } from 'digest';

const INIT = '/etc/init.d/fips-relay';
const LIMIT = 2097152;

function quote(s) {
	return "'" + replace(s, "'", "'\\''") + "'";
}

function read(path, limit) {
	let f = fs.open(path, 'r');
	if (!f) return null;
	let text = f.read(limit + 1);
	f.close();
	if (text == null || length(text) > limit) die('File exceeds the display limit');
	return text;
}

function command(argv, seconds, input) {
	let dir = fs.mkdtemp('/tmp/freedom-XXXXXX');
	if (!dir) die('Could not prepare service command');
	let out;
	try {
		if (fs.writefile(dir + '/input', input || '') == null) die('Could not prepare request');
		let cmd = 'ulimit -f 4096; exec ' + join(' ', map(argv, quote)) +
			' <' + quote(dir + '/input') + ' >' + quote(dir + '/output') + ' 2>/dev/null';
		if (system(cmd, seconds * 1000) != 0) die('Service command failed or timed out');
		out = read(dir + '/output', LIMIT);
	}
	catch (e) { fs.unlink(dir + '/input'); fs.unlink(dir + '/output'); fs.rmdir(dir); die(e); }
	fs.unlink(dir + '/input'); fs.unlink(dir + '/output'); fs.rmdir(dir);
	return out;
}

function context() {
	let u = cursor();
	let path = u.get('fips-relay', 'main', 'config') || '/etc/fips-relay/config.json';
	let binary = u.get('fips-relay', 'main', 'executable') || '/usr/sbin/fips-relay';
	if (substr(path, 0, 1) != '/' || substr(binary, 0, 1) != '/') die('Service paths must be absolute');
	let raw = read(path, 65536);
	let cfg = json(raw ?? read('/usr/share/fips-relay/config.example.json', 65536));
	if (type(cfg) != 'object' || type(cfg.terms?.controller) != 'object' ||
	    type(cfg.state_directory) != 'string' || substr(cfg.state_directory, 0, 1) != '/')
		die('Install a valid relay configuration first');
	// Any state, including a partial initialization, freezes financial terms.
	let locked = fs.lstat(cfg.state_directory) != null;
	return { u, path, binary, cfg, raw, locked };
}

function settings(c) {
	let t = c.cfg.terms, p = t.controller;
	return {
		mode: t.fee_msat_per_kib == 0 ? 'free' : 'paid',
		fee: t.fee_msat_per_kib, max_rate: t.max_rate_msat_per_kib,
		budget: t.buyer_budget_sat, wallet_spend: p.max_wallet_spend_sat,
		locked_funds: p.max_locked_sat, mint: p.mint_url,
		interface: c.cfg.transports?.ethernet?.mesh0?.interface || 'mesh0'
	};
}

function number(value, name, minimum) {
	if (type(value) != 'int' || value < minimum || value > 1000000000)
		die('Invalid ' + name);
	return value;
}

function configure(c, a) {
	if (c.locked) die('This account already exists. Its financial settings are fixed.');
	if (a.revision != sha256(c.raw || '')) die('Settings changed. Reload the page before saving.');
	if (a.mode != 'free' && a.mode != 'paid') die('Choose free or paid forwarding');
	if (type(a.mint) != 'string' || length(a.mint) > 512 ||
	    !match(a.mint, /^https?:\/\/[^\s]+$/)) die('Enter a valid mint URL');
	if (type(a.interface) != 'string' || !match(a.interface, /^[a-zA-Z0-9_.-]{1,15}$/))
		die('Enter an existing network interface');
	if (!fs.stat('/sys/class/net/' + a.interface)) die('Network interface does not exist');
	let t = c.cfg.terms, p = t.controller;
	t.fee_msat_per_kib = a.mode == 'free' ? 0 : number(a.fee, 'price', 1);
	t.max_rate_msat_per_kib = number(a.max_rate, 'route price limit', 0);
	t.buyer_budget_sat = number(a.budget, 'lifetime spending limit', 1);
	p.max_wallet_spend_sat = number(a.wallet_spend, 'wallet spending limit', 1);
	p.max_locked_sat = number(a.locked_funds, 'locked funds limit', 1);
	if (t.fee_msat_per_kib > t.max_rate_msat_per_kib ||
	    p.max_locked_sat < p.channel_capacity_sat || p.max_wallet_spend_sat < p.channel_capacity_sat)
		die('Price and spending limits must cover the configured price and channel capacity');
	p.mint_url = a.mint;
	t.billing = 'forwarding_data';
	// Set only the standard mesh instance; retain other configured transports/peers.
	c.cfg.transports ??= {};
	c.cfg.transports.ethernet ??= {};
	c.cfg.transports.ethernet.mesh0 = {
		interface: a.interface, discovery: true, announce: true,
		auto_connect: true, accept_connections: true
	};
	c.cfg.neighbor_admission = 'authenticated_adjacent';
	let directory = fs.dirname(c.path);
	if (!fs.stat(directory) && !fs.mkdir(directory, 0700)) die('Could not create configuration directory');
	if (fs.lstat(c.path)?.type == 'link') die('Configuration must be a regular file');
	let staging = fs.mkdtemp(directory + '/.freedom-XXXXXX');
	if (!staging) die('Could not prepare settings');
	let temp = staging + '/config.json';
	let file = fs.open(temp, 'wx', 0600);
	if (!file) { fs.rmdir(staging); die('Could not prepare settings'); }
	try {
		let text = sprintf('%.J\n', c.cfg);
		if (file.write(text) != length(text) || !file.flush()) die('Could not save settings');
		file.close();
		command(['sync', '-f', temp], 5, null);
		if (read(c.path, 65536) != c.raw || fs.lstat(c.cfg.state_directory))
			die('Account or settings changed. Reload before saving.');
		if (!fs.rename(temp, c.path)) die('Could not publish settings');
		fs.rmdir(staging);
		command(['sync', '-f', directory], 5, null);
	}
	catch (e) { file.close(); fs.unlink(temp); fs.rmdir(staging); die(e); }
	return { saved: true };
}

function status(c) {
	let enabled = c.u.get('fips-relay', 'main', 'enabled') == '1';
	let response = {
		configured: c.raw != null, account_exists: c.locked, enabled,
		boot: system([INIT, 'enabled'], 2000) == 0,
		settings: settings(c), revision: c.locked ? null : sha256(c.raw || ''),
		ready: false, peers: [], credit_msat: null
	};
	if (!c.locked) return response;
	try {
		let live = json(command([c.binary, 'ctl', c.path], 4, '{"type":"status"}'));
		if (type(live.npub) != 'string' || type(live.peers) != 'array') die('Invalid relay status');
		response.ready = true;
		response.npub = live.npub;
		response.locked_sat = live.locked_sat;
		response.remaining_budget_sat = live.remaining_budget_sat;
		response.peers = map(slice(live.peers || [], 0, 24), p => ({
			npub: p.npub, connected: p.connected, transport: p.transport,
			sent_bytes: p.sent_bytes, received_bytes: p.received_bytes, srtt_ms: p.srtt_ms
		}));
	}
	catch (e) { response.notice = enabled ? 'Waiting for the relay. Check its network interface and clock.' : 'Relay stopped.'; }
	try {
		let ledger = json(read(c.cfg.state_directory + '/seller/ledger.json', LIMIT));
		if (type(ledger.ledger.channels) != 'array') die('Unknown ledger format');
		let credit = ledger.ledger.history?.usage?.paid_msat || 0;
		for (let channel in ledger.ledger.channels) credit += channel.usage.paid_msat;
		response.credit_msat = sprintf('%d', credit);
	}
	catch (e) { response.credit_msat = null; }
	return response;
}

function action(c, a) {
	if (a == 'initialize') {
		if (c.locked || !c.raw) die('Save a new configuration first. Existing state cannot be initialized again.');
		command([c.binary, 'init', c.path], 25, null);
	}
	else if (a == 'start' || a == 'stop') {
		if (a == 'start' && !fs.stat(c.cfg.state_directory + '/service.json')) die('Initialize the account first');
		c.u.set('fips-relay', 'main', 'enabled', a == 'start' ? '1' : '0');
		if (!c.u.commit('fips-relay')) die('Could not save service setting');
		command([INIT, a], 10, null);
	}
	else if (a == 'enable' || a == 'disable') command([INIT, a], 5, null);
	else die('Unknown service action');
	return { applied: true };
}

function invoke(fn) {
	try { return fn(context()); }
	catch (e) { return { error: e.message || ('' + e) }; }
}

return { 'luci.freedom': {
	status: { call: () => invoke(status) },
	configure: {
		args: { revision: 'x', mode: 'x', fee: 0, max_rate: 0, budget: 0,
			wallet_spend: 0, locked_funds: 0, mint: 'x', interface: 'x' },
		call: request => invoke(c => configure(c, request.args))
	},
	action: { args: { action: 'x' }, call: request => invoke(c => action(c, request.args.action)) }
} };
