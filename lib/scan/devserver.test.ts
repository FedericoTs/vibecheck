import { describe, it, expect } from 'vitest';
import { findDevSignals, extractScripts, scanDevServer, type Probe, type ProbeResponse } from './devserver';

const page = new URL('https://myapp.com/');

const res = (over: Partial<ProbeResponse> = {}): ProbeResponse => ({
  status: 404,
  contentType: 'text/html',
  body: '',
  ...over,
});
const probeOf = (map: Record<string, ProbeResponse>): Probe => async (url) => map[url] ?? res();

const html = (body: string): { html: string; status: number; contentType: string; url: URL } => ({
  html: body,
  status: 200,
  contentType: 'text/html; charset=utf-8',
  url: page,
});

// Verbatim from a vite 8.2.2 + plugin-react 6.1.0 dev server.
const VITE_PREAMBLE = `<script type="module">import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script>`;
const VITE_CLIENT_TAG = '<script type="module" src="/@vite/client"></script>';

describe('signal detection', () => {
  it('finds the Vite client tag and the react-refresh preamble', () => {
    const s = findDevSignals(`<head>${VITE_PREAMBLE}${VITE_CLIENT_TAG}</head>`, page);
    expect(s.map((x) => x.kind)).toEqual(['vite', 'vite']);
    expect(s.find((x) => x.evidence.includes('preamble'))?.probeUrl).toBe('https://myapp.com/@vite/client');
  });

  it('handles a non-default base — the false negative that broke the first rule', () => {
    // With base:'/myapp/', vite serves /myapp/@vite/client and a GET of
    // /@vite/client returns 404. Equality matching misses this entirely.
    const s = findDevSignals(
      `<script type="module">import { injectIntoGlobalHook } from "/myapp/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script><script type="module" src="/myapp/@vite/client"></script>`,
      page,
    );
    expect(s).toHaveLength(2);
    expect(s[0].probeUrl).toBe('https://myapp.com/myapp/@vite/client');
  });

  it('finds the Turbopack dev HMR chunk by its raw percent-encoded name', () => {
    const src = '/_next/static/chunks/%5Bturbopack%5D_browser_dev_hmr-client_hmr-client_ts_1di75ot._.js';
    expect(findDevSignals(`<script src="${src}"></script>`, page)[0].kind).toBe('next-turbopack');
  });

  it('does NOT treat a production Turbopack chunk as a signal', () => {
    // arvexlab.com serves this from a production build — `turbopack` alone
    // must never be the marker.
    expect(findDevSignals('<script src="/_next/static/chunks/turbopack-1mkwsw8n900cb.js"></script>', page)).toHaveLength(0);
  });

  it('finds unhashed Next runtime chunks, with or without the dev timestamp', () => {
    const s = findDevSignals(
      '<script src="/_next/static/chunks/webpack.js?v=1787259626145"></script><script src="/_next/static/chunks/app-pages-internals.js"></script>',
      page,
    );
    expect(s).toHaveLength(2);
    expect(s.every((x) => x.kind === 'next-webpack')).toBe(true);
  });

  it('does NOT flag content-hashed production chunks', () => {
    // codesandbox.io serves exactly this shape in production.
    expect(findDevSignals('<script src="/_next/static/chunks/main-app-75c43e41ef6ed856.js"></script>', page)).toHaveLength(0);
    // A production deployment token is not the dev timestamp.
    expect(findDevSignals('<script src="/_next/static/chunks/webpack.js?dpl=abc123"></script>', page)).toHaveLength(0);
  });

  it('reads __NEXT_DATA__ by ATTRIBUTE so a nonce cannot hide it', () => {
    const dev = `<script id="__NEXT_DATA__" type="application/json" nonce="abc" crossorigin="">{"buildId":"development"}</script>`;
    expect(findDevSignals(dev, page)[0].kind).toBe('next-build-id');
    const prod = `<script id="__NEXT_DATA__" type="application/json">{"buildId":"3e3e78f2"}</script>`;
    expect(findDevSignals(prod, page)).toHaveLength(0);
  });

  it('discards cross-origin scripts', () => {
    // StackBlitz and CodeSandbox genuinely run dev servers, but in nested
    // cross-origin iframes — the top-level document must stay clean.
    expect(findDevSignals('<script type="module" src="https://other.example/@vite/client"></script>', page)).toHaveLength(0);
  });

  it('ignores markers that are page TEXT rather than script elements', () => {
    // vite.dev's backend-integration guide contains the client path and the
    // whole preamble as highlighted example code. Element-level parsing is the
    // only reason that page does not fire.
    const docs = `<pre><code><span>&quot;http://localhost:5173/@vite/client&quot;</span>
<span>import { injectIntoGlobalHook } from "/@react-refresh";</span></code></pre>`;
    expect(findDevSignals(docs, page)).toHaveLength(0);
  });

  it('extractScripts reads attributes off the open tag', () => {
    const s = extractScripts('<script type="module" src="/a.js" id="x">body()</script>');
    expect(s[0]).toMatchObject({ type: 'module', src: '/a.js', id: 'x', body: 'body()' });
  });
});

describe('corroboration — the traps that defeat status-code probing', () => {
  it('CONFIRMS a Vite dev server when the client body is really served', async () => {
    const r = await scanDevServer(
      html(`<head>${VITE_CLIENT_TAG}</head>`),
      probeOf({
        'https://myapp.com/@vite/client': res({
          status: 200,
          contentType: 'text/javascript',
          body: 'console.debug("[vite] connecting...");',
        }),
      }),
    );
    expect(r.verdict).toBe('dev-artifacts');
  });

  it('does NOT fire on `vite preview`, which 200s every path via SPA fallback', async () => {
    // Reproduced live: vite preview returns 200 text/html for /@vite/client,
    // /@vite/env and even /@fs/etc/passwd. Status-only probing is 100% wrong.
    const r = await scanDevServer(
      html(`<head>${VITE_CLIENT_TAG}</head>`),
      probeOf({
        'https://myapp.com/@vite/client': res({ status: 200, contentType: 'text/html', body: '<!doctype html><div id="root">' }),
      }),
    );
    expect(r.verdict).toBe('clean');
  });

  it('does NOT fire on Hulu, which 200s the dev manifest path with HTML', async () => {
    // www.hulu.com is a production Next build and returns 200 + 1.5MB of HTML
    // for /_next/static/development/_buildManifest.js.
    const r = await scanDevServer(
      html('<script src="/_next/static/chunks/webpack.js"></script>'),
      probeOf({
        'https://myapp.com/_next/static/development/_buildManifest.js': res({
          status: 200,
          contentType: 'text/html; charset=utf-8',
          body: '<!doctype html><html>',
        }),
      }),
    );
    expect(r.verdict).toBe('clean');
  });

  it('CONFIRMS Next dev: manifest body prefix plus both dev-only endpoints at 400', async () => {
    const r = await scanDevServer(
      html('<script src="/_next/static/chunks/main-app.js?v=1787259626145"></script>'),
      probeOf({
        'https://myapp.com/_next/static/development/_buildManifest.js': res({
          status: 200,
          contentType: 'application/javascript; charset=UTF-8',
          body: 'self.__BUILD_MANIFEST = {"__rewrites":{}}',
        }),
        'https://myapp.com/__nextjs_source-map': res({ status: 400 }),
        'https://myapp.com/__nextjs_launch-editor': res({ status: 400 }),
      }),
    );
    expect(r.verdict).toBe('dev-artifacts');
  });

  it('requires EXACTLY 400 — production hosts return 200, 403 and 404 there', async () => {
    // vercel.com and linear.app return 200 for /__nextjs_source-map;
    // codesandbox.io returns 403. Only 400 means dev.
    const r = await scanDevServer(
      html('<script src="/_next/static/chunks/main-app.js"></script>'),
      probeOf({
        'https://myapp.com/_next/static/development/_buildManifest.js': res({
          status: 200,
          contentType: 'application/javascript',
          body: 'self.__BUILD_MANIFEST = {}',
        }),
        'https://myapp.com/__nextjs_source-map': res({ status: 200, body: '<html>' }),
        'https://myapp.com/__nextjs_launch-editor': res({ status: 400 }),
      }),
    );
    expect(r.verdict).toBe('clean');
  });

  it('anchors the manifest body on self., not a bare __BUILD_MANIFEST', async () => {
    // Edge middleware manifests emit `globalThis.__BUILD_MANIFEST = `.
    const r = await scanDevServer(
      html('<script src="/_next/static/chunks/webpack.js"></script>'),
      probeOf({
        'https://myapp.com/_next/static/development/_buildManifest.js': res({
          status: 200,
          contentType: 'application/javascript',
          body: 'globalThis.__BUILD_MANIFEST = {}',
        }),
      }),
    );
    expect(r.verdict).toBe('clean');
  });

  it('CONFIRMS create-react-app via the assets-report body literal', async () => {
    const r = await scanDevServer(
      html('<script src="/static/js/bundle.js"></script>'),
      probeOf({
        'https://myapp.com/webpack-dev-server': res({ status: 200, contentType: 'text/html', body: '<h1>Assets Report:</h1><ul>' }),
      }),
    );
    expect(r.verdict).toBe('dev-artifacts');
  });
});

describe('honesty', () => {
  it('reports UNKNOWN, never clean, when the page is not HTML we could read', async () => {
    const probe = probeOf({});
    expect((await scanDevServer({ ...html(''), status: 403 }, probe)).verdict).toBe('unknown');
    expect((await scanDevServer({ ...html(''), contentType: 'application/json' }, probe)).verdict).toBe('unknown');
  });

  it('reports UNKNOWN when the confirming request fails outright', async () => {
    const r = await scanDevServer(html(`<head>${VITE_CLIENT_TAG}</head>`), async () => {
      throw new Error('network');
    });
    expect(r.verdict).toBe('unknown');
    expect(r.signals).toHaveLength(1);
  });

  it('calls an ordinary production page clean without any extra request', async () => {
    let calls = 0;
    const r = await scanDevServer(html('<script src="/_next/static/chunks/main-app-75c43e41ef6ed856.js"></script>'), async () => {
      calls++;
      return res();
    });
    expect(r.verdict).toBe('clean');
    expect(calls).toBe(0);
  });
});
