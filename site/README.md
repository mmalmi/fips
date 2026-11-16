# freedom.iris.to

Plain-language Freedom overview and OpenWrt setup guide. Vite builds plain HTML, CSS
and copy buttons; all explanations and setup steps work without
JavaScript. The site lives with the implementation so feature claims and operator
instructions can be reviewed together.

```sh
cd site
npm ci
npm run build
npm test
npm run preview
```

Deploy with an authorized Cloudflare Wrangler login (`wrangler login`) or a
scoped `CLOUDFLARE_API_TOKEN` in the environment:

```sh
npm run deploy
```

`wrangler.jsonc` deploys the build as Workers Static Assets with the
`freedom.iris.to` custom domain. The custom-domain workflow provisions DNS and TLS.
The build also exports only the tracked Freedom UI build sources into a checksum-listed download; it does not publish relay binaries or private state.
No Worker JavaScript, database, analytics or third-party browser requests are
needed. Do not commit credentials or Cloudflare account identifiers.

Keep release availability and capability limits aligned with
`../crates/fips-relay/READINESS.md`, the relay service instructions and the OpenWrt
package guide. Do not add private bench identities, addresses or financial data.

The focused built-output test checks internal navigation, source links, basic
metadata, static content and the deployment/privacy boundary. Visual acceptance
also checks desktop/mobile, the message route, payment example, copy controls and JavaScript-
disabled rendering in a real browser. Recheck the public root, `/setup/`, a missing
URL and security headers after deploying.
