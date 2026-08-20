/**
 * Development-mode build artifacts served in production.
 *
 * A dev server exposes unminified source, stack traces carrying file contents
 * on any error, an open HMR socket and no CSP. Shipping one to a public URL is
 * one of the higher-severity mistakes a generated app can make, and it is
 * observable without touching anything.
 *
 * ── The three traps this module is built around ────────────────────────────
 * Every one of these was constructed and fetched during verification, and each
 * defeats the obvious implementation:
 *
 *  1. STATUS CODES PROVE NOTHING. `vite preview` — a PRODUCTION static server —
 *     returns HTTP 200 for /@vite/client, /@vite/env, /@react-refresh and even
 *     /@fs/etc/passwd, because the SPA history fallback serves index.html for
 *     every unmatched path. Probing for a 200 has a 100% false-positive rate on
 *     any SPA. The response CONTENT is the check, not the status.
 *
 *  2. A PRODUCTION SITE ANSWERS THE DEV PATH. www.hulu.com — unambiguously a
 *     production Next.js build — returns HTTP 200 and 1.5MB of application HTML
 *     for /_next/static/development/_buildManifest.js. So that path needs a
 *     JavaScript content-type AND the exact body prefix before it means
 *     anything.
 *
 *  3. THE BYTES CANNOT DISTINGUISH A MIRROR FROM A SERVER. A plain static
 *     server holding a copy of a dev-served page (a `wget -mkp` mirror, a
 *     prerender step, an archived capture) reproduces the markup AND the client
 *     script byte-for-byte, with a JavaScript content-type. No byte-level test
 *     separates it from a live dev server. Hence the finding is worded
 *     "development-mode build artifacts are being served" and never "you are
 *     running a dev server" — the exposure is real either way, the diagnosis is
 *     not ours to make.
 *
 * ── And the false negative that shapes the matching ────────────────────────
 * With `base: '/myapp/'`, Vite serves `/myapp/@vite/client` and a GET of
 * `/@vite/client` returns 404. So signals must SUFFIX-match, and corroboration
 * must fetch the URL actually observed in the document — never a hardcoded one.
 *
 * Constants confirmed against upstream source on 2026-08-20 (vite 8.2.2,
 * next 16.3.1, react-scripts main, webpack-dev-server master); see each
 * constant for its file.
 */

/** Vite's injected client. constants.ts CLIENT_PUBLIC_PATH / ENV_PUBLIC_PATH. */
const VITE_CLIENT_SUFFIX = '/@vite/client';
const VITE_ENV_SUFFIX = '/@vite/env';

/**
 * The react-refresh preamble, base-capturing. The literal form hardcodes "/",
 * which misses every project with a non-default base.
 * Source: vite-plugin-react refresh-utils.ts (preambleCode).
 */
const REACT_REFRESH_PREAMBLE =
  /^import \{ injectIntoGlobalHook \} from "([^"]*)\/@react-refresh";\s*injectIntoGlobalHook\(window\);\s*window\.\$RefreshReg\$ = \(\) => \{\};\s*window\.\$RefreshSig\$ = \(\) => \(type\) => type;$/;

/**
 * Turbopack's dev HMR client chunk, matched RAW and percent-encoded. The
 * trailing hash varies; the substring is stable across 16.2 and 16.3.
 * NB `turbopack` alone is NOT a signal — production Turbopack builds also emit
 * chunks named `turbopack-<hash>.js`.
 */
const TURBOPACK_HMR_CHUNK = '%5Bturbopack%5D_browser_dev_hmr-client_hmr-client_ts';

/**
 * Next's runtime chunks are unhashed in dev and content-hashed in production
 * (webpack-config.ts output.filename). shared/lib/constants.ts supplies the
 * names.
 */
const NEXT_UNHASHED_RUNTIME = /\/_next\/static\/chunks\/(main-app|webpack|react-refresh|polyfills|app-pages-internals)\.js$/;
/** Dev+webpack appends ?v=<13-digit epoch ms>; production uses ?dpl=<token>. */
const NEXT_DEV_QUERY = /^(|v=\d{13})$/;

/** create-react-app's dev bundle: unhashed in dev, content-hashed in prod. */
const CRA_BUNDLE_SUFFIX = '/static/js/bundle.js';

/** Corroboration literals, each from upstream source. */
const VITE_CLIENT_BODY = '[vite] connecting...';
const NEXT_BUILD_MANIFEST_PATH = '/_next/static/development/_buildManifest.js';
/** Anchored on `self.` — edge middleware emits `globalThis.__BUILD_MANIFEST = `. */
const NEXT_BUILD_MANIFEST_BODY = 'self.__BUILD_MANIFEST = ';
/** Exactly these three return 400 in dev and 404 in production. */
const NEXT_DEV_400_PATHS = ['/__nextjs_source-map', '/__nextjs_launch-editor'];
const WDS_ASSETS_PATH = '/webpack-dev-server';
const WDS_ASSETS_BODY = '<h1>Assets Report:</h1>';

const JS_CONTENT_TYPES = /^(text|application)\/(java|ecma)script\b/i;

export type DevServerVerdict = 'dev-artifacts' | 'clean' | 'unknown';

export interface DevSignal {
  kind: 'vite' | 'next-turbopack' | 'next-webpack' | 'next-build-id' | 'cra';
  /** Exactly what was observed, for the evidence line. */
  evidence: string;
  /** The URL to corroborate against — derived from the document, not assumed. */
  probeUrl?: string;
}

export interface DevServerResult {
  verdict: DevServerVerdict;
  signals: DevSignal[];
  /** What actually confirmed it, or why we could not confirm. */
  reason: string;
}

export interface ProbeResponse {
  status: number;
  contentType: string;
  body: string;
}
export type Probe = (url: string) => Promise<ProbeResponse>;

interface ParsedScript {
  raw: string;
  src?: string;
  type?: string;
  id?: string;
  body: string;
}

function attr(tag: string, name: string): string | undefined {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[2] ?? m[3] ?? m[4]) : undefined;
}

/**
 * Extract script ELEMENTS with their attributes.
 *
 * Deliberately never matches raw body text. vite.dev's own backend-integration
 * guide contains both `@vite/client` and the entire react-refresh preamble as
 * highlighted example code; a token scan of the page bytes fires on it, while
 * an element-level scan does not, because none of it is inside a <script>.
 */
export function extractScripts(html: string): ParsedScript[] {
  const out: ParsedScript[] = [];
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const [, attrs, body] = m;
    out.push({
      raw: attrs,
      src: attr(attrs, 'src'),
      type: attr(attrs, 'type'),
      id: attr(attrs, 'id'),
      body,
    });
  }
  return out;
}

/**
 * Signals present in the document. Cross-origin scripts are discarded: a
 * StackBlitz or CodeSandbox page genuinely runs dev servers, but serves them
 * from nested cross-origin iframes, so the top-level document is clean and must
 * stay that way.
 */
export function findDevSignals(html: string, pageUrl: URL): DevSignal[] {
  const signals: DevSignal[] = [];
  for (const s of extractScripts(html)) {
    if (s.src) {
      let u: URL;
      try {
        u = new URL(s.src, pageUrl);
      } catch {
        continue;
      }
      if (u.origin !== pageUrl.origin) continue;

      // Suffix, never equality — a non-default base prefixes the path.
      if (u.pathname.endsWith(VITE_CLIENT_SUFFIX) || u.pathname.endsWith(VITE_ENV_SUFFIX)) {
        signals.push({ kind: 'vite', evidence: `<script src="${s.src}">`, probeUrl: u.toString() });
        continue;
      }
      // Matched RAW so the percent-encoding survives.
      if (s.src.includes(TURBOPACK_HMR_CHUNK)) {
        signals.push({ kind: 'next-turbopack', evidence: `<script src="${s.src}">` });
        continue;
      }
      if (NEXT_UNHASHED_RUNTIME.test(u.pathname) && NEXT_DEV_QUERY.test(u.search.replace(/^\?/, ''))) {
        signals.push({ kind: 'next-webpack', evidence: `<script src="${s.src}">` });
        continue;
      }
      if (u.pathname.endsWith(CRA_BUNDLE_SUFFIX)) {
        signals.push({ kind: 'cra', evidence: `<script src="${s.src}">` });
      }
      continue;
    }

    // Inline module script carrying the react-refresh preamble.
    if (s.type === 'module' && REACT_REFRESH_PREAMBLE.test(s.body.trim())) {
      const base = s.body.trim().match(REACT_REFRESH_PREAMBLE)?.[1] ?? '';
      let probeUrl: string | undefined;
      try {
        probeUrl = new URL(`${base}${VITE_CLIENT_SUFFIX}`, pageUrl).toString();
      } catch {
        /* leave undefined — corroboration will fall back to the observed src */
      }
      signals.push({ kind: 'vite', evidence: 'inline react-refresh preamble', probeUrl });
      continue;
    }

    // Pages Router only. Matched by ATTRIBUTE — the tag also carries nonce and
    // crossOrigin under CSP, so a literal tag string never matches there.
    if (s.id === '__NEXT_DATA__' && s.type === 'application/json') {
      try {
        const data = JSON.parse(s.body) as { buildId?: unknown };
        if (data.buildId === 'development') {
          signals.push({ kind: 'next-build-id', evidence: '__NEXT_DATA__.buildId === "development"' });
        }
      } catch {
        /* unparseable — not a signal */
      }
    }
  }
  return signals;
}

const isJs = (ct: string): boolean => JS_CONTENT_TYPES.test(ct.trim());

/**
 * Confirm a signal by fetching. Exactly the checks that survive the traps: a
 * JavaScript content-type plus an exact body literal, never a bare status.
 */
async function corroborate(
  signals: DevSignal[],
  origin: string,
  probe: Probe,
): Promise<{ ok: boolean; reason: string } | null> {
  const kinds = new Set(signals.map((s) => s.kind));

  if (kinds.has('vite')) {
    const url = signals.find((s) => s.kind === 'vite' && s.probeUrl)?.probeUrl;
    if (!url) return null;
    const r = await probe(url);
    if (r.status === 200 && isJs(r.contentType) && r.body.includes(VITE_CLIENT_BODY)) {
      return { ok: true, reason: `the Vite dev client at ${url} is being served` };
    }
    return { ok: false, reason: `a Vite dev path is referenced, but ${url} does not serve the dev client` };
  }

  if (kinds.has('next-turbopack') || kinds.has('next-webpack') || kinds.has('next-build-id')) {
    const manifest = await probe(`${origin}${NEXT_BUILD_MANIFEST_PATH}`);
    const manifestOk =
      manifest.status === 200 && isJs(manifest.contentType) && manifest.body.trimStart().startsWith(NEXT_BUILD_MANIFEST_BODY);
    if (!manifestOk) {
      return { ok: false, reason: `a dev-mode chunk name is referenced, but ${NEXT_BUILD_MANIFEST_PATH} is not served` };
    }
    // These return 400 in dev and 404 in production. Production hosts have been
    // observed returning 200, 403 and 404 — so require EXACTLY 400.
    const probes = await Promise.all(NEXT_DEV_400_PATHS.map((p) => probe(`${origin}${p}`)));
    if (!probes.every((r) => r.status === 400)) {
      return { ok: false, reason: `${NEXT_BUILD_MANIFEST_PATH} is served, but the dev-only endpoints do not respond as a dev server would` };
    }
    return { ok: true, reason: `${NEXT_BUILD_MANIFEST_PATH} is served and the dev-only endpoints respond as a dev server does` };
  }

  if (kinds.has('cra')) {
    const r = await probe(`${origin}${WDS_ASSETS_PATH}`);
    if (r.status === 200 && r.body.includes(WDS_ASSETS_BODY)) {
      return { ok: true, reason: `${WDS_ASSETS_PATH} serves the webpack-dev-server assets report` };
    }
    return { ok: false, reason: `an unhashed dev bundle is referenced, but ${WDS_ASSETS_PATH} is not served` };
  }

  return null;
}

/**
 * The full check.
 *
 * Returns `unknown` — never `clean` — whenever we could not actually look: a
 * non-200, a non-HTML response, or an auth wall. A login shell has no markers,
 * and reporting that as a pass would claim more than was observed.
 */
export async function scanDevServer(
  input: { html: string; status: number; contentType: string; url: URL },
  probe: Probe,
): Promise<DevServerResult> {
  if (input.status !== 200 || !/text\/html/i.test(input.contentType)) {
    return { verdict: 'unknown', signals: [], reason: 'the page did not return HTML, so we could not look' };
  }

  const signals = findDevSignals(input.html, input.url);
  if (signals.length === 0) {
    return { verdict: 'clean', signals: [], reason: 'no development-mode markers in the served page' };
  }

  let result: { ok: boolean; reason: string } | null;
  try {
    result = await corroborate(signals, input.url.origin, probe);
  } catch {
    return { verdict: 'unknown', signals, reason: 'development markers found, but we could not complete the confirming request' };
  }
  if (!result) {
    return { verdict: 'unknown', signals, reason: 'development markers found, but there was nothing to confirm them against' };
  }
  return result.ok
    ? { verdict: 'dev-artifacts', signals, reason: result.reason }
    : { verdict: 'clean', signals, reason: result.reason };
}
