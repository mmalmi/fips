import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';
const page = name => fileURLToPath(new URL(name, import.meta.url));
export default defineConfig({
  build: { rollupOptions: { input: { home: page('index.html'), setup: page('setup/index.html'), missing: page('404.html') } } }
});
