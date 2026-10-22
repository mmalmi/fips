// Run on OpenWrt: ucode test_freedom.uc freedom.uc service.example.json
// Real filesystem, UCI and subprocesses; all mutations stay in this scratch root.
import * as fs from 'fs';
import { sha256 } from 'digest';

const root = fs.mkdtemp('/tmp/freedom-test-XXXXXX');
assert(root);
const config = root + '/config.json';
const state = root + '/state';
fs.mkdir(root + '/uci');
let cfg = json(fs.readfile(ARGV[1]));
cfg.state_directory = state;
fs.writefile(config, sprintf('%J', cfg));
fs.writefile(root + '/uci/fips-relay', sprintf(
	"config relay 'main'\n option enabled '0'\n option config '%s'\n option executable '%s/relay'\n", config, root));
fs.writefile(root + '/init', '#!/bin/sh\necho "$1" >> ' + root + '/actions\n');
fs.chmod(root + '/init', 0700);
fs.writefile(root + '/relay', '#!/bin/sh\ncase "$1" in\n' +
	'init) mkdir ' + state + '; echo "{}" > ' + state + '/service.json;;\n' +
	'ctl) cat ' + root + '/status.json;;\nesac\n');
fs.chmod(root + '/relay', 0700);
fs.writefile(root + '/status.json', sprintf('%J', {
	npub: '<img src=x onerror=alert(1)>', peers: [], locked_sat: 3,
	remaining_budget_sat: 7, secret: 'must-not-leak', history: ['private']
}));

let source = fs.readfile(ARGV[0]);
assert(index(source, "import { cursor } from 'uci';") >= 0);
assert(index(source, "const INIT = '/etc/init.d/fips-relay';") >= 0);
source = replace(source, "import { cursor } from 'uci';",
	"import { cursor as original_cursor } from 'uci';\nlet cursor = () => original_cursor(" + sprintf('%J', root + '/uci') + ');');
source = replace(source, "const INIT = '/etc/init.d/fips-relay';", 'const INIT = ' + sprintf('%J', root + '/init') + ';');
fs.writefile(root + '/backend.uc', source);
let api = loadfile(root + '/backend.uc')()['luci.freedom'];
let checks = 0;
function ok(value, label) { assert(value, label); checks++; }
function call(name, args) { return api[name].call({ args: args || {} }); }
let initial = call('status');
ok(!initial.error && !initial.account_exists, 'fresh configuration');
ok(initial.revision == sha256(fs.readfile(config)), 'revision is a digest');
let settings = {
	revision: initial.revision, mode: 'free', fee: 0, max_rate: 0, budget: 128,
	wallet_spend: 128, locked_funds: 128, mint: 'http://127.0.0.1:3338', interface: 'lo'
};
let stale = { ...settings, revision: 'stale' };
ok(call('configure', stale).error != null, 'reject stale form');
ok(call('configure', { ...settings, budget: -1 }).error != null, 'reject negative budget');
ok(call('configure', { ...settings, budget: 1.5 }).error != null, 'reject fractional budget');
ok(call('configure', { ...settings, interface: 'lo;id' }).error != null, 'reject interface injection');
ok(fs.readfile(config) == sprintf('%J', cfg), 'rejections preserve original bytes');
ok(call('configure', settings).saved, 'free settings save');
cfg = json(fs.readfile(config));
ok(cfg.terms.fee_msat_per_kib == 0 && cfg.terms.max_rate_msat_per_kib == 0, 'free only ceiling');
ok(cfg.terms.billing == 'forwarding_data', 'bounded bootstrap billing');
ok((fs.stat(config).mode & 0777) == 0600, 'private atomic configuration');
ok(!fs.stat(state), 'save never initializes account');
settings.revision = call('status').revision;
ok(call('configure', { ...settings, mode: 'paid', fee: 20, max_rate: 10 }).error != null, 'reject price above ceiling');
ok(call('configure', { ...settings, mode: 'paid', fee: 20, max_rate: 40 }).saved, 'paid settings save');
ok(call('action', { action: 'start' }).error != null, 'start requires account');
ok(call('action', { action: 'initialize' }).applied, 'explicit account initialization');
let original = fs.readfile(config);
ok(call('configure', settings).error != null && fs.readfile(config) == original, 'saved financial terms immutable');
ok(call('action', { action: 'initialize' }).error != null, 'no reinitialization');
fs.unlink(state + '/service.json');
ok(call('configure', settings).error != null, 'partial state also protected');
fs.writefile(state + '/service.json', '{}');
fs.mkdir(state + '/seller');
fs.writefile(state + '/seller/ledger.json', sprintf('%J', {
	ledger: { history: { usage: { paid_msat: 5000 } }, channels: [{ usage: { paid_msat: 1234 } }] }
}));
let live = call('status');
ok(live.ready && live.credit_msat == '6234', 'accepted credit includes retired history');
ok(!exists(live, 'secret') && !exists(live, 'history') && live.revision == null, 'status projection excludes private records');
ok(call('action', { action: 'start' }).applied && call('status').enabled, 'start saves enabled flag');
ok(call('action', { action: 'stop' }).applied && !call('status').enabled, 'stop saves disabled flag');
ok(call('action', { action: 'enable' }).applied, 'enable boot');
ok(call('action', { action: 'disable' }).applied, 'disable boot');
let actions = fs.readfile(root + '/actions');
ok(call('action', { action: 'start; touch ' + root + '/injected' }).error != null, 'reject command injection');
ok(!fs.stat(root + '/injected') && fs.readfile(root + '/actions') == actions, 'rejected action never runs');
fs.writefile(root + '/relay', '#!/bin/sh\nexec sleep 10\n');
let start = time();
ok(!call('status').ready && time() - start < 7, 'bounded unresponsive service');
ok(fs.readfile(config) == original, 'service actions preserve financial configuration');

function clean(path) {
	for (let name in fs.lsdir(path)) {
		let p = path + '/' + name;
		if (fs.lstat(p).type == 'directory') clean(p); else fs.unlink(p);
	}
	fs.rmdir(path);
}
clean(root);
printf('%d Freedom backend checks passed\n', checks);
