import test from 'node:test';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
const root = resolve('dist');
const pages = ['index.html', 'setup/index.html', '404.html'];
const read = file => readFileSync(file, 'utf8');

test('all pages ship readable content, metadata and working internal targets', () => {
  for (const page of pages) {
    const html = read(resolve(root, page));
    assert.match(html, /<html lang="en">/);
    assert.match(html, /<meta name="viewport"/);
    assert.equal((html.match(/<h1>/g) || []).length, 1);
    if (page !== '404.html') {
      assert.match(html, /rel="canonical"/);
      assert.match(html, /name="description"/);
      assert.match(html, /Services → Freedom/);
    }
    for (const [, attribute, link] of html.matchAll(/\b(href|src)="([^"]+)"/g)) {
      if (/^https?:/.test(link)) {
        assert(link.startsWith('https://'), 'external links use HTTPS');
        if (attribute === 'src') assert.fail('no external browser assets');
        continue;
      }
      const [pathname, hash] = link.split('#');
      let target = pathname ? (pathname.startsWith('/') ? resolve(root, '.' + pathname) : resolve(dirname(resolve(root, page)), pathname)) : resolve(root, page);
      if (pathname.endsWith('/')) target = resolve(target, 'index.html');
      assert(existsSync(target), `${page}: missing ${link}`);
      if (hash) assert(read(target).includes(`id="${hash}"`), `${page}: missing anchor ${link}`);
    }
    assert.doesNotMatch(html, /\/Users\/|192\.168\.|bench-ap\d|npub1[a-z0-9]{30}|CLOUDFLARE_API_TOKEN/);
  }
});

test('the deployment serves static assets only on the requested domain', () => {
  const config = JSON.parse(read('wrangler.jsonc'));
  assert.equal(config.assets.directory, './dist');
  assert.equal(config.assets.not_found_handling, '404-page');
  assert.deepEqual(config.routes, [{ pattern: 'freedom.iris.to', custom_domain: true }]);
  assert.equal(config.workers_dev, false);
  assert(!config.main && !config.account_id);
  assert.match(read(resolve(root, '_headers')), /Content-Security-Policy: default-src 'self'/);
  assert.match(read(resolve(root, 'sitemap.xml')), /https:\/\/freedom\.iris\.to\/setup\//);
});

test('the downloadable source is limited to the UI and matches its checksum', () => {
  const archive = resolve(root, 'downloads/freedom-ui-source.tar.gz');
  const manifest = JSON.parse(read(resolve(root, 'downloads/source.json')));
  assert.equal(createHash('sha256').update(readFileSync(archive)).digest('hex'), manifest.sha256);
  const paths = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' }).trim().split('\n');
  for (const path of paths.filter(p => !p.endsWith('/'))) {
    assert(manifest.contents.some(allowed => path === allowed || path.startsWith(allowed + '/')), path);
  }
  assert(paths.some(p => p.endsWith('/freedom.uc')));
  assert(existsSync(resolve(root, 'social.png')));
});
