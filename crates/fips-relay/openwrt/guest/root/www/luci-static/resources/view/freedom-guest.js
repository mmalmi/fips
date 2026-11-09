'use strict';
'require view';
'require rpc';
'require ui';

var status = rpc.declare({object: 'luci.freedom.guest', method: 'status', expect: {}});
var save = rpc.declare({object: 'luci.freedom.guest', method: 'save', params: ['revision', 'mode', 'providers'], expect: {}});
return view.extend({
	load: function() { return status(); },
	render: function(data) {
		var readOnly = !L.hasViewPermission(), revision = data.revision;
		var mode = E('select', {'aria-label': _('Guest internet source'), disabled: readOnly || null});
		[['off', _('Off'), true], ['direct', _('Local internet connection'), data.direct],
		 ['selected', _('My paid Nostr VPN exits'), data.profiles.length], ['automatic', _('Nostr VPN automatic selection'), data.automatic]].forEach(function(row) {
			mode.appendChild(E('option', {value: row[0], disabled: !row[2] || null}, row[1]));
		});
		mode.value = data.mode;
		var fields = E('fieldset', {}, [E('legend', {}, _('Allowed exits'))]);
		var selected = (data.providers || []).slice(), inputs = [];
		// Preserve the saved priority, then add newly available exits.
		var profiles = data.profiles.slice().sort(function(a,b) {
			var i=selected.indexOf(a.name), j=selected.indexOf(b.name);
			return (i<0?99:i) - (j<0?99:j);
		});
		profiles.forEach(function(p) {
			var input = E('input', {type:'checkbox', value:p.name, disabled:readOnly || null});
			input.checked = selected.indexOf(p.name) >= 0; inputs.push(input);
			fields.appendChild(E('p', {}, E('label', {}, [input, ' ', p.label])));
		});
		function toggle() { fields.hidden = mode.value !== 'selected'; }
		mode.onchange = toggle; toggle();
		var state = E('p', {'aria-live':'polite'}, data.active ? _('Active connection') + ' · ' + data.active : _('Guest internet is offline'));
		var button = E('button', {class:'cbi-button cbi-button-apply', disabled:readOnly || null, click:ui.createHandlerFn(this, function() {
			return save(revision,mode.value,inputs.filter(function(i){return i.checked;}).map(function(i){return i.value;})).then(function(result){
				if(result.error) throw new Error(result.error);
				revision=result.revision; state.textContent=_('Settings saved. Refresh to check the active connection.');
			});
		})}, _('Apply'));
		return E('div', {class:'cbi-map'}, [E('h2',{},_('Freedom guest internet')),state,
			E('p',{},_('Choose how guests reach the internet after paying for Wi-Fi.')),mode,fields,E('p',{},button)]);
	},
	handleSaveApply:null, handleSave:null, handleReset:null
});
