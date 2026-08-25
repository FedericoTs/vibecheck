/**
 * JSON-LD structured-data analysis.
 *
 * The visibility scan already reports whether a page HAS structured data. This
 * goes one step deeper, deterministically: it PARSES each block. A JSON-LD block
 * with a syntax error is worse than none — Google and AI answer engines skip it
 * silently, so the page looks marked-up but is invisible to the exact systems
 * the markup was for, and nothing on the page tells the owner. A parse is a
 * fact, not a judgement, so this stays inside the tool's proof-over-inference
 * line.
 *
 * We report the @types found and how many blocks parsed, and flag only the
 * unambiguous failure: a block that is present and does not parse.
 */

export interface SchemaAnalysis {
  /** Number of <script type="application/ld+json"> blocks on the page. */
  blocks: number;
  /** How many of those blocks are valid JSON. */
  valid: number;
  /** How many failed to parse — the graded signal. */
  broken: number;
  /** Distinct @type values found across all valid blocks, sorted. */
  types: string[];
}

const BLOCK = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;

/** Pull every @type value out of a parsed JSON-LD value, however it is nested. */
function collectTypes(node: unknown, out: Set<string>): void {
  if (Array.isArray(node)) {
    for (const n of node) collectTypes(n, out);
    return;
  }
  if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    const t = obj['@type'];
    if (typeof t === 'string') out.add(t);
    else if (Array.isArray(t)) for (const x of t) if (typeof x === 'string') out.add(x);
    // @graph and nested objects can carry more entities.
    for (const v of Object.values(obj)) collectTypes(v, out);
  }
}

export function analyzeSchema(html: string): SchemaAnalysis {
  const types = new Set<string>();
  let blocks = 0;
  let valid = 0;

  for (const m of html.matchAll(BLOCK)) {
    const raw = m[1].trim();
    if (!raw) continue; // an empty tag is not a broken block
    blocks += 1;
    try {
      const parsed: unknown = JSON.parse(raw);
      valid += 1;
      collectTypes(parsed, types);
    } catch {
      /* counted as broken below */
    }
  }

  return { blocks, valid, broken: blocks - valid, types: [...types].sort() };
}

/** A short human summary, e.g. "3 blocks · Organization, WebSite" or "1 block failed to parse". */
export function describeSchema(s: SchemaAnalysis): string {
  if (s.blocks === 0) return 'no JSON-LD structured data found';
  if (s.broken > 0) {
    return `${s.broken} of ${s.blocks} JSON-LD block${s.blocks === 1 ? '' : 's'} did not parse — search and AI engines skip a malformed block silently`;
  }
  const names = s.types.slice(0, 6).join(', ');
  return `${s.blocks} valid block${s.blocks === 1 ? '' : 's'}${names ? ` · ${names}` : ''}`;
}
