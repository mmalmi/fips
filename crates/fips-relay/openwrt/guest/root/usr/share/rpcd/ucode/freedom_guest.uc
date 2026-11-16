'use strict';
import * as fs from 'fs';
import { cursor } from 'uci';
import { sha256 } from 'digest';
const CFG = 'freedom_guest';
function settings(u) {
	let profiles = [];
	u.foreach(CFG, 'uplink', s => {
		if (s['.name'] != 'direct' && s['.name'] != 'automatic')
			push(profiles, { name: s['.name'], label: s.label || s['.name'] });
	});
	let selected = u.get(CFG, 'main', 'provider');
	return {
		mode: u.get(CFG, 'main', 'mode') || 'off',
		providers: type(selected) == 'array' ? selected : (selected ? [selected] : []),
		profiles,
		direct: !!u.get(CFG, 'direct', 'device'), automatic: !!u.get(CFG, 'automatic', 'device'),
		revision: sha256(fs.readfile('/etc/config/freedom_guest') || ''),
		active: trim(fs.readfile('/var/run/freedom-guest.uplink') || '')
	};
}
function save(a) {
	let u = cursor(), old = settings(u);
	if (a.revision != old.revision) return { error: 'Settings changed. Reload this page.' };
	if (type(a.providers) != 'array' || length(a.providers) > 8 ||
	    index(['off', 'direct', 'selected', 'automatic'], a.mode) < 0) return { error: 'Invalid internet source.' };
	for (let p in a.providers)
		if (!length(filter(old.profiles, s => s.name == p))) return { error: 'Unknown provider.' };
	if (a.mode == 'selected' && !length(a.providers) || a.mode == 'automatic' && !old.automatic || a.mode == 'direct' && !old.direct)
		return { error: 'Configure the selected uplink first.' };
	u.set(CFG, 'main', 'mode', a.mode);
	u.delete(CFG, 'main', 'provider');
	if (length(a.providers)) u.set(CFG, 'main', 'provider', a.providers);
	if (!u.commit(CFG)) return { error: 'Could not save guest settings.' };
	if (system(['/etc/init.d/freedom-guest', a.mode == 'off' ? 'disable' : 'enable'], 5000) != 0 ||
	    system(['/etc/init.d/freedom-guest', a.mode == 'off' ? 'stop' : 'restart'], 10000) != 0) return { error: 'Saved. Check the guest service configuration.' };
	return settings(cursor());
}
return { 'luci.freedom.guest': {
	status: { call: () => settings(cursor()) },
	save: { args: { revision: 'x', mode: 'x', providers: [] }, call: req => save(req.args) }
} };
