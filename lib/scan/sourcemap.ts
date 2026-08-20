/**
 * Source maps that ACTUALLY resolve.
 *
 * A source map republishes the original, unminified source of an app —
 * comments, logic, file names, and anything minification happened to hide. It
 * is one of the most common accidental leaks in a generated app, and one of the
 * easiest to get wrong in a scanner.
 *
 * Two failure modes this module exists to avoid, both observed live:
 *
 *  1. "The chunk has a sourceMappingURL comment, therefore the map is exposed."
 *     FALSE. resend.com serves the comment on 5 of 5 sampled chunks and every
 *     one of those maps 404s. Treating the annotation as the finding would
 *     accuse a site that leaks nothing.
 *
 *  2. "Append .map to the chunk URL." FALSE, and this is what we shipped before.
 *     Modern bundlers do not name the map after the chunk — on resend.com the
 *     chunk `26yaa-tw3zzt9.js` points at `1gjyac_a8hyhc.js.map`. Appending
 *     `.map` 404s on every such site, so the check reported "no source maps
 *     exposed" without ever having looked at the right URL. A silent false pass.
 *
 * The rule here is therefore: a source map is exposed only if we FETCHED it and
 * PARSED it. Everything else is "not exposed" or "could not determine", never a
 * guess.
 *
 * Format per the Source Map spec: a JSON object with `version: 3`, a `sources`
 * array, and optionally `sourcesContent` carrying the original text.
 */

/** Bundler-internal prefixes that are not the app author's code. */
const VENDOR_MARKERS = [
  /node_modules/i,
  /^webpack:\/\/(webpack)?\/(bootstrap|runtime)/i,
  /^webpack\/runtime/i,
];

/**
 * Entries that are not source files at all.
 *
 * Bundlers emit an entry per asset module — a few hundred bytes of wrapper
 * around a .png or .woff2 — plus a bare runtime-bootstrap entry. Counting those
 * as "your original source files" overstates the finding roughly threefold on a
 * real site, which is severity inflation dressed up as a number.
 */
const NOT_SOURCE = /\.(png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|mp4|webm|wasm)(\?|#|$)/i;
/** A bare bundler root like `webpack://_N_E/` — a path, not a file. */
const BARE_ROOT = /^\w+:\/\/[^/]*\/?$/;

export interface SourceMapFinding {
  /** Filename of the chunk that pointed at this map. */
  chunk: string;
  /** Where the map was actually found — a URL, or 'inline' for a data: URI. */
  mapUrl: string;
  /** Number of original files the map reconstructs. */
  totalFiles: number;
  /** Of those, how many are the app's own code rather than dependencies. */
  firstPartyFiles: number;
  /** A few first-party paths, for evidence. Never file CONTENT. */
  sampleSources: string[];
  /** True when the map ships the original text, not just file names. */
  hasContent: boolean;
}

export interface SourceMapScanResult {
  /** Chunks we looked at. */
  checked: number;
  /** Chunks carrying a sourceMappingURL annotation. */
  annotated: number;
  /** Maps we fetched AND parsed. */
  exposed: SourceMapFinding[];
  /** Annotated chunks whose map did not resolve — the resend.com case. */
  unresolved: number;
}

/**
 * The last `sourceMappingURL` annotation in a bundle.
 *
 * Both the current `//#` and the deprecated `//@` forms are accepted, as are
 * the block-comment forms some tools still emit. The LAST annotation wins,
 * which is what browsers do when a file somehow carries several.
 */
export function parseSourceMappingUrl(code: string): string | null {
  // Only the tail of a bundle can carry the real annotation, and scanning a
  // multi-megabyte string with a global regex is wasteful. But a string literal
  // elsewhere could contain the token, so anchor on end-of-line.
  const tail = code.length > 4096 ? code.slice(-4096) : code;
  const matches = [...tail.matchAll(/(?:\/\/|\/\*)[#@]\s*sourceMappingURL=([^\s'"*]+)/g)];
  if (matches.length === 0) return null;
  return matches[matches.length - 1][1] ?? null;
}

/**
 * Resolve an annotation against the CHUNK's own URL — never the page's.
 *
 * This is the whole bug in the previous implementation. A relative annotation
 * is relative to the resource that carries it, so a chunk served from a CDN
 * asset host resolves its map on that host, and a differently-named map
 * resolves to its own name rather than the chunk's.
 */
export function resolveMapUrl(annotation: string, chunkUrl: string): string | null {
  if (annotation.startsWith('data:')) return annotation;
  try {
    return new URL(annotation, chunkUrl).toString();
  } catch {
    return null;
  }
}

/** Decode an inline `data:` source map. Returns null if it is not decodable. */
export function decodeInlineMap(dataUri: string): string | null {
  const m = dataUri.match(/^data:application\/json[^,]*?(;base64)?,(.*)$/i);
  if (!m) return null;
  const [, isB64, payload] = m;
  try {
    return isB64 ? atob(payload) : decodeURIComponent(payload);
  } catch {
    return null;
  }
}

interface ParsedMap {
  sources: string[];
  hasContent: boolean;
  /** The recovered original text, for secret-scanning only. Never serialized. */
  content: string;
}

/**
 * Parse a candidate body as a source map.
 *
 * Deliberately strict: an SPA catch-all happily returns 200 and an HTML page
 * for any path, so "we got a 200" proves nothing. The body must parse as JSON,
 * declare `version: 3`, and carry a `sources` array before we will call it a
 * map.
 */
export function parseSourceMap(body: string): ParsedMap | null {
  if (!body || body.length > 40_000_000) return null;
  const trimmed = body.trimStart();
  if (!trimmed.startsWith('{')) return null; // an HTML fallback dies here
  let json: unknown;
  try {
    json = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (typeof json !== 'object' || json === null) return null;
  const map = json as { version?: unknown; sources?: unknown; sourcesContent?: unknown; sections?: unknown };
  if (map.version !== 3) return null;

  // An INDEX map carries `sections`, each with its own nested map, and has no
  // top-level `sources` at all. Requiring `sources` dropped these entirely —
  // a silent miss on any build that emits one.
  const parts: Array<{ sources?: unknown; sourcesContent?: unknown }> = Array.isArray(map.sections)
    ? map.sections
        .map((s) => (s && typeof s === 'object' ? (s as { map?: unknown }).map : null))
        .filter((m): m is { sources?: unknown; sourcesContent?: unknown } => !!m && typeof m === 'object')
    : [map];

  const sources: string[] = [];
  const contents: string[] = [];
  for (const part of parts) {
    if (Array.isArray(part.sources)) {
      sources.push(...part.sources.filter((s): s is string => typeof s === 'string'));
    }
    if (Array.isArray(part.sourcesContent)) {
      contents.push(...part.sourcesContent.filter((c): c is string => typeof c === 'string' && c.length > 0));
    }
  }
  if (sources.length === 0) return null;

  return { sources, hasContent: contents.length > 0, content: contents.join('\n') };
}

/**
 * Split a map's `sources` into the app's own source files and everything else.
 *
 * "Everything else" is both dependencies AND non-source entries: asset-module
 * stubs and bare bundler roots. Excluding them keeps the reported file count
 * honest rather than inflated.
 */
export function classifySources(sources: string[]): {
  total: number;
  firstParty: string[];
} {
  const firstParty = sources.filter(
    (s) => !VENDOR_MARKERS.some((re) => re.test(s)) && !NOT_SOURCE.test(s) && !BARE_ROOT.test(s),
  );
  return { total: sources.length, firstParty };
}

/** Trim a bundler-prefixed path down to something a human recognises. */
export function tidySourcePath(source: string): string {
  return source
    .replace(/^webpack:\/\/[^/]*\//, '')
    .replace(/^turbopack:\/\/\[project\]\//, '')
    .replace(/^(\.\/)+/, '');
}

/**
 * Assemble the result. `fetchText` is injected so this is testable without a
 * network and so the caller controls SSRF validation.
 */
export async function scanSourceMaps(
  chunks: Array<{ url: string; code: string }>,
  fetchText: (url: string) => Promise<string>,
  /**
   * Called with the recovered original source of each resolved map, so the
   * caller can scan it for secrets a minified bundle happened to hide. Passed
   * through a callback rather than returned so the source text can never end up
   * serialized into a shareable report by accident.
   */
  onRecoveredSource?: (text: string) => void,
): Promise<SourceMapScanResult> {
  const exposed: SourceMapFinding[] = [];
  let annotated = 0;
  let unresolved = 0;

  for (const { url, code } of chunks) {
    const annotation = parseSourceMappingUrl(code);
    if (!annotation) continue;
    annotated++;

    const mapUrl = resolveMapUrl(annotation, url);
    if (!mapUrl) {
      unresolved++;
      continue;
    }

    const body = mapUrl.startsWith('data:') ? decodeInlineMap(mapUrl) : await fetchText(mapUrl);
    const parsed = body ? parseSourceMap(body) : null;
    if (!parsed) {
      unresolved++;
      continue;
    }

    if (onRecoveredSource && parsed.content) onRecoveredSource(parsed.content);

    const { total, firstParty } = classifySources(parsed.sources);
    exposed.push({
      chunk: url.split('/').pop() ?? url,
      mapUrl: mapUrl.startsWith('data:') ? 'inline' : mapUrl,
      totalFiles: total,
      firstPartyFiles: firstParty.length,
      sampleSources: firstParty.slice(0, 5).map(tidySourcePath),
      hasContent: parsed.hasContent,
    });
  }

  return { checked: chunks.length, annotated, exposed, unresolved };
}

/**
 * A map that only reconstructs dependencies is not an app-source leak, so it is
 * reported without being graded.
 */
export function sourceMapsLeakFirstParty(result: SourceMapScanResult): boolean {
  return result.exposed.some((e) => e.firstPartyFiles > 0 && e.hasContent);
}
