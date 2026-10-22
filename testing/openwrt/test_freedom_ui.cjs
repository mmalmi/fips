// Browser checks for the actual LuCI view, with only its RPC/host boundary mocked.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname,
  '../../crates/fips-relay/openwrt/luci/htdocs/luci-static/resources/view/freedom.js'), 'utf8');
const output = path.resolve(process.argv[2]);
fs.mkdirSync(output, { recursive: true });

(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.FREEDOM_TEST_CHROME });
  try {
    const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } });
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    async function mount(existing, readonly = false) {
      await page.setContent('<html><body></body></html>');
      await page.evaluate(({ source, existing, readonly }) => {
        window._ = s => s;
        window.L = { hasViewPermission: () => !readonly };
        window.E = (tag, attrs = {}, children = []) => {
          const el = document.createElement(tag);
          for (const [k, v] of Object.entries(attrs)) {
            if (k === 'click') el.addEventListener('click', v);
            else if (k === 'disabled') el.disabled = !!v;
            else el.setAttribute(k, v);
          }
          for (const child of Array.isArray(children) ? children : [children])
            if (child != null) el.append(child instanceof Node ? child : document.createTextNode(String(child)));
          return el;
        };
        window.state = {
          configured: true, account_exists: existing, enabled: existing, ready: existing,
          boot: false, revision: 'first', locked_sat: 3, remaining_budget_sat: 125,
          credit_msat: '9007199254740993', peers: [{ npub: '<img src=x onerror=alert(1)>',
            connected: true, transport: 'ethernet', sent_bytes: 1048576, received_bytes: 0 }],
          settings: { mode: 'paid', fee: 20, max_rate: 40, budget: 128,
            wallet_spend: 128, locked_funds: 128, mint: 'http://mint.test:3338', interface: 'mesh0' }
        };
        window.calls = [];
        const rpc = { declare: spec => async (...args) => {
          calls.push({ method: spec.method, args });
          if (spec.method === 'status') return structuredClone(state);
          if (spec.method === 'configure') {
            if (args[0] !== state.revision) return { error: 'Settings changed. Reload before saving.' };
            state.settings.mode = args[1]; state.revision = 'saved'; return { saved: true };
          }
          if (spec.method === 'action') {
            if (args[0] === 'initialize') state.account_exists = true;
            if (args[0] === 'stop') state.enabled = state.ready = false;
            if (args[0] === 'start') state.enabled = state.ready = true;
            if (args[0] === 'enable') state.boot = true;
            return { applied: true };
          }
        } };
        const ui = { createHandlerFn: (self, name, ...args) => event => self[name](...args, event) };
        const dom = { content: (el, children) => {
          el.replaceChildren(...(Array.isArray(children) ? children : [children])
            .map(c => c instanceof Node ? c : document.createTextNode(String(c))));
        } };
        const poll = { add: fn => { window.refresh = fn; } };
        window.view = new Function('view', 'rpc', 'ui', 'poll', 'dom', source)(
          { extend: x => x }, rpc, ui, poll, dom);
        document.body.append(view.render(structuredClone(state)));
      }, { source, existing, readonly });
    }
    await mount(true);
    assert.equal(await page.locator('img').count(), 0, 'peer labels cannot inject HTML');
    assert.match(await page.locator('body').innerText(), /9007199254740\.993 sat/, 'credit avoids floating-point loss');
    assert(await page.locator('#freedom-fee').isDisabled(), 'existing financial terms are locked');
    await page.getByRole('button', { name: 'Stop', exact: true }).click();
    await page.getByRole('button', { name: 'Start', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Start', exact: true }).click();
    await page.getByRole('button', { name: 'Stop', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Enable start at boot', exact: true }).click();
    await page.getByRole('button', { name: 'Disable start at boot', exact: true }).waitFor();
    await mount(false);
    await page.locator('#freedom-mode').selectOption('free');
    assert(await page.locator('#freedom-fee').isDisabled(), 'free mode disables paid price');
    await page.evaluate(async () => { state.revision = 'external-change'; await refresh(); });
    assert.equal(await page.locator('#freedom-mode').inputValue(), 'free', 'poll preserves dirty form');
    await page.getByRole('button', { name: 'Save settings', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Settings changed' }).waitFor();
    assert.equal(await page.evaluate(() => calls.filter(c => c.method === 'configure').at(-1).args[0]), 'first',
      'poll cannot bypass optimistic concurrency');
    await mount(false);
    await page.getByRole('button', { name: 'Save settings', exact: true }).click();
    await page.waitForFunction(() => view.revision === 'saved');
    await page.getByRole('button', { name: 'Create account', exact: true }).click();
    await page.getByRole('button', { name: 'Start', exact: true }).waitFor();
    assert(await page.locator('#freedom-budget').isDisabled());
    await mount(true, true);
    assert(await page.getByRole('button', { name: 'Stop', exact: true }).isDisabled(), 'read-only session');
    assert.deepEqual(errors, []);
    console.log('Freedom browser flows passed: status, exact credit, XSS, start/stop, boot, setup, stale form, read-only access');
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode = 1; });
