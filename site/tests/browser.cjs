const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.SITE_URL || 'http://127.0.0.1:4178';
const output = process.argv[2];
if (!output) throw Error('Supply a private screenshot output directory');
fs.mkdirSync(output, { recursive: true });
(async () => {
  const browser = await chromium.launch({ executablePath: process.env.SITE_CHROME, headless: true });
  const errors = [], failures = [];
  try {
    const context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    const page = await context.newPage();
    page.on('pageerror', e => errors.push(e.message));
    page.on('requestfailed', request => failures.push(request.url()));
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844], ['small', 320, 750]]) {
      await page.setViewportSize({ width, height });
      for (const route of ['/', '/setup/']) {
        const response = await page.goto(base + route, { waitUntil: 'networkidle' });
        assert.equal(response.status(), 200);
        assert.equal(await page.locator('h1').count(), 1);
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${name} ${route}: overflow`);
        await page.screenshot({ path: path.join(output, `${name}-${route === '/' ? 'home' : 'setup'}.png`), fullPage: true });
      }
    }
    await page.goto(base + '/', { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'What can I do with it?', exact: true }).waitFor();
    assert.equal(await page.locator('.message-hops li').count(), 4);
    assert.equal(await page.locator('.payment-example tbody tr').count(), 3);
    assert(await page.locator('#internet-access').innerText().then(s => s.includes('Not as a complete service today.')));
    await page.goto(base + '/setup/');
    const copy = page.locator('[data-copy="status-command"]');
    await copy.click();
    await page.waitForFunction(() => document.querySelector('[data-copy="status-command"]').textContent === 'Copied');
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), await page.locator('#status-command').textContent());
    await page.getByRole('link', { name: '04 · Configure Freedom', exact: true }).click();
    assert(page.url().endsWith('#freedom-settings'));
    const noJS = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 844 } });
    const plain = await noJS.newPage();
    for (const route of ['/', '/setup/']) {
      await plain.goto(base + route);
      assert((await plain.locator('main').innerText()).length > 3000);
      assert.equal(await plain.locator('button:visible').count(), 0);
    }
    await plain.getByText('The price fields are disabled', { exact: true }).click();
    assert.equal(await plain.locator('details[open]').count(), 1);
    assert.deepEqual(errors, []);
    assert.deepEqual(failures, []);
    console.log('Passed desktop/390px/320px layouts, message route, payment example, copy, anchors, troubleshooting, no-JS content; zero page errors or failed requests.');
    await noJS.close();
    await context.close();
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
