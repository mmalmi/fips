import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

// Publish only the UI build sources; relay dependencies and operator state are excluded.
const repository = resolve('..');
const sources = ['LICENSE', 'crates/fips-relay/openwrt/luci',
  'crates/fips-relay/openwrt/build-luci-apk.sh', 'crates/fips-relay/openwrt/luci-reload'];
execFileSync('git', ['diff', '--exit-code', 'HEAD', '--', ...sources], { cwd: repository });
const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repository, encoding: 'utf8' }).trim();
mkdirSync('dist/downloads', { recursive: true });
const archive = execFileSync('git', ['archive', '--format=tar.gz', revision, ...sources], { cwd: repository });
const digest = createHash('sha256').update(archive).digest('hex');
writeFileSync('dist/downloads/freedom-ui-source.tar.gz', archive);
writeFileSync('dist/downloads/SHA256SUMS', `${digest}  freedom-ui-source.tar.gz\n`);
writeFileSync('dist/downloads/source.json', JSON.stringify({ revision, sha256: digest, contents: sources }, null, 2) + '\n');
const svg = readFileSync('src/social.svg');
if (!readFileSync('public/social.png').length || !svg.length) throw Error('Missing social artwork');
