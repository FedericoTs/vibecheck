import type { RouteKind, RouteProbe } from './routes';

/**
 * Route probes taken from the app's OWN bundle, instead of guessed.
 *
 * The fixed twelve-entry probe list asks every app the same question — is there
 * an /admin? — and most of the time the answer is "no, ours is /console". The
 * app's shipped JavaScript names its real routes, and probing one of those is
 * the same legality as probing /admin (a public GET a crawler could make) with a
 * far higher hit rate and a finding that is self-evidently about them.
 *
 * ⚠️ THE REFUSAL RULE ⚠️
 * A route named /api/admin/purge-all is exactly the kind of thing this finds,
 * and requesting it would be indefensible: we cannot verify ownership, the
 * caller may not be the owner, and a GET handler that deletes is a real pattern
 * in AI-generated code. Anything whose NAME implies a write is reported and
 * never requested. Saying so out loud is also the most convincing thing in the
 * report — it demonstrates restraint a scanner that just hammers paths cannot.
 */

/** Path segments that imply the route changes something. Never requested. */
const MUTATING =
  /(^|[/_-])(delete|destroy|drop|purge|truncate|reset|wipe|remove|revoke|send|invite|refund|charge|pay|payout|transfer|cancel|approve|reject|migrate|seed|restore|rollback|rotate|deploy|shutdown|signout|logout|unsubscribe)([/_-]|$)/i;

/** Quoted absolute paths under a prefix worth probing. */
const CANDIDATE = /["'`](\/(?:api|admin|internal|debug|dev|console|manage|staff|backoffice)(?:\/[A-Za-z0-9._~-]+)*)["'`]/g;

/** Next.js app-router page chunks name the route tree: app/admin/page-<hash>.js */
const APP_CHUNK = /\/_next\/static\/chunks\/app\/(.+?)\/(?:page|layout)-[A-Za-z0-9_-]+\.js$/;

/** Asset-ish suffixes that are files being fetched, not routes worth probing. */
const ASSET = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|txt|xml|wasm)$/i;

export interface ExtractedRoutes {
  /** Safe to GET — read-shaped names only. */
  probes: RouteProbe[];
  /** Found, deliberately NOT requested, because the name implies a write. */
  refused: RouteProbe[];
}

function kindFor(path: string): RouteKind {
  if (/\/(?:debug|dev)(?:\/|$)/i.test(path)) return 'debug';
  if (/^\/api(?:\/|$)/i.test(path)) return 'data';
  return 'admin';
}

/** Is this a plausible route rather than an i18n key, asset, or template? */
function isPlausible(path: string): boolean {
  if (path.length < 4 || path.length > 80) return false;
  if (ASSET.test(path)) return false;
  // Allowlist, not denylist. We are about to send this to someone's server, so
  // anything outside the safe URL-path alphabet — template holes, route params,
  // query strings, whitespace — disqualifies it rather than being escaped.
  if (/[^A-Za-z0-9._~/-]/.test(path)) return false;
  const segments = path.split('/').filter(Boolean);
  if (segments.length > 5) return false;
  // "/api" on its own is a namespace, not an endpoint — every app that calls
  // /api/anything also contains the bare string, and probing it proves nothing.
  // Other prefixes (/admin, /console) genuinely are pages worth checking.
  if (segments.length < 2 && segments[0]?.toLowerCase() === 'api') return false;
  return true;
}

/** A route the app's own bundle advertises, from a Next.js page-chunk name. */
export function routeFromChunkUrl(url: string): string | null {
  let pathname: string;
  try {
    pathname = new URL(url).pathname;
  } catch {
    pathname = url;
  }
  const m = pathname.match(APP_CHUNK);
  if (!m) return null;
  // Strip route groups "(marketing)" and parallel/intercepted segments.
  const segments = m[1]
    .split('/')
    .filter((s) => s && !s.startsWith('(') && !s.startsWith('@') && !s.startsWith('.'));
  if (!segments.length) return null;
  const path = '/' + segments.join('/');
  // A dynamic segment cannot be requested literally.
  if (path.includes('[')) return null;
  return path;
}

/**
 * Pull route candidates out of bundle text and chunk URLs.
 *
 * `limit` caps how many we will actually request, because every probe is a
 * request to someone else's server and restraint is part of the contract.
 */
export function extractRoutes(text: string, chunkUrls: string[] = [], limit = 12): ExtractedRoutes {
  const found = new Set<string>();

  for (const m of text.matchAll(CANDIDATE)) {
    const path = m[1].replace(/\/+$/, '');
    if (isPlausible(path)) found.add(path);
  }
  for (const url of chunkUrls) {
    const path = routeFromChunkUrl(url);
    if (path && isPlausible(path)) found.add(path);
  }

  const probes: RouteProbe[] = [];
  const refused: RouteProbe[] = [];
  // Sorted so a truncated list is stable rather than Set-order dependent.
  for (const path of [...found].sort()) {
    const probe: RouteProbe = { path, label: `${path} (from your bundle)`, kind: kindFor(path) };
    if (MUTATING.test(path)) refused.push(probe);
    else probes.push(probe);
  }
  return { probes: probes.slice(0, limit), refused: refused.slice(0, limit) };
}
