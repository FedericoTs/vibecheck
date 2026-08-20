import { describe, it, expect } from 'vitest';
import {
  parseSourceMappingUrl,
  resolveMapUrl,
  parseSourceMap,
  classifySources,
  tidySourcePath,
  decodeInlineMap,
  scanSourceMaps,
  sourceMapsLeakFirstParty,
} from './sourcemap';

const validMap = JSON.stringify({
  version: 3,
  sources: ['webpack://_N_E/./src/lib/billing.ts', 'webpack://_N_E/./node_modules/react/index.js'],
  sourcesContent: ['export function chargeCard() {}', 'module.exports = {}'],
});

describe('parseSourceMappingUrl', () => {
  it('reads both the current //# and legacy //@ forms', () => {
    expect(parseSourceMappingUrl('a=1\n//# sourceMappingURL=main.js.map')).toBe('main.js.map');
    expect(parseSourceMappingUrl('a=1\n//@ sourceMappingURL=old.js.map')).toBe('old.js.map');
  });

  it('returns null when there is no annotation', () => {
    expect(parseSourceMappingUrl('console.log("no map here")')).toBe(null);
  });

  it('takes the LAST annotation, as browsers do', () => {
    expect(parseSourceMappingUrl('//# sourceMappingURL=a.map\n//# sourceMappingURL=b.map')).toBe('b.map');
  });

  it('finds the annotation at the end of a large bundle', () => {
    const big = 'x'.repeat(200_000) + '\n//# sourceMappingURL=late.js.map';
    expect(parseSourceMappingUrl(big)).toBe('late.js.map');
  });
});

describe('resolveMapUrl — the bug that made this check useless', () => {
  it('resolves against the CHUNK directory, not the page, and honours a different filename', () => {
    // Observed live on resend.com: the map is not named after the chunk.
    const chunk = 'https://resend.com/_next/static/chunks/26yaa-tw3zzt9.js';
    expect(resolveMapUrl('1gjyac_a8hyhc.js.map', chunk)).toBe(
      'https://resend.com/_next/static/chunks/1gjyac_a8hyhc.js.map',
    );
    // The old approach — appending .map to the chunk — would have produced a
    // URL that 404s on every such site.
    expect(resolveMapUrl('1gjyac_a8hyhc.js.map', chunk)).not.toBe(chunk + '.map');
  });

  it('keeps the CDN asset host when chunks are served cross-origin', () => {
    const chunk = 'https://frontend-assets.supabase.com/_next/static/chunks/main.js';
    expect(resolveMapUrl('main.js.map', chunk)).toBe(
      'https://frontend-assets.supabase.com/_next/static/chunks/main.js.map',
    );
  });

  it('passes absolute URLs and data: URIs through', () => {
    expect(resolveMapUrl('https://cdn.example.com/a.map', 'https://x.com/b.js')).toBe(
      'https://cdn.example.com/a.map',
    );
    expect(resolveMapUrl('data:application/json;base64,e30=', 'https://x.com/b.js')).toBe(
      'data:application/json;base64,e30=',
    );
  });
});

describe('parseSourceMap — a 200 proves nothing on its own', () => {
  it('accepts a real v3 map', () => {
    const p = parseSourceMap(validMap)!;
    expect(p.sources).toHaveLength(2);
    expect(p.hasContent).toBe(true);
  });

  it('REJECTS an SPA catch-all HTML page returned with status 200', () => {
    expect(parseSourceMap('<!doctype html><html><body>Not found</body></html>')).toBe(null);
  });

  it('rejects the wrong version, malformed JSON and missing sources', () => {
    expect(parseSourceMap(JSON.stringify({ version: 2, sources: [] }))).toBe(null);
    expect(parseSourceMap('{not json')).toBe(null);
    expect(parseSourceMap(JSON.stringify({ version: 3 }))).toBe(null);
  });

  it('parses a map that lists files but ships no content', () => {
    const p = parseSourceMap(JSON.stringify({ version: 3, sources: ['./a.ts'] }))!;
    expect(p.hasContent).toBe(false);
  });
});

describe('attribution — dependencies are not an app-source leak', () => {
  it('separates first-party files from node_modules', () => {
    const { total, firstParty } = classifySources([
      'webpack://_N_E/./src/lib/billing.ts',
      'webpack://_N_E/./node_modules/react/index.js',
      'webpack://webpack/bootstrap',
    ]);
    expect(total).toBe(3);
    expect(firstParty).toEqual(['webpack://_N_E/./src/lib/billing.ts']);
  });

  it('tidies bundler prefixes into recognisable paths', () => {
    expect(tidySourcePath('webpack://_N_E/./src/lib/billing.ts')).toBe('src/lib/billing.ts');
    expect(tidySourcePath('turbopack://[project]/app/page.tsx')).toBe('app/page.tsx');
  });
});

describe('decodeInlineMap', () => {
  it('decodes a base64 data: URI', () => {
    const b64 = Buffer.from(validMap).toString('base64');
    expect(parseSourceMap(decodeInlineMap(`data:application/json;base64,${b64}`)!)).not.toBe(null);
  });
  it('returns null for a non-JSON data URI', () => {
    expect(decodeInlineMap('data:text/plain,hello')).toBe(null);
  });
});

describe('scanSourceMaps — end to end', () => {
  const chunk = 'https://app.com/static/main.js';

  it('reports EXPOSED only when the map was fetched and parsed', async () => {
    const r = await scanSourceMaps(
      [{ url: chunk, code: '//# sourceMappingURL=main.js.map' }],
      async () => validMap,
    );
    expect(r.annotated).toBe(1);
    expect(r.exposed).toHaveLength(1);
    expect(r.exposed[0].firstPartyFiles).toBe(1);
    expect(r.exposed[0].sampleSources).toEqual(['src/lib/billing.ts']);
    expect(sourceMapsLeakFirstParty(r)).toBe(true);
  });

  it('the resend.com case: annotation present, map 404s → NOT exposed', async () => {
    const r = await scanSourceMaps(
      [{ url: chunk, code: '//# sourceMappingURL=other.js.map' }],
      async () => '', // 404 → empty body
    );
    expect(r.annotated).toBe(1);
    expect(r.unresolved).toBe(1);
    expect(r.exposed).toHaveLength(0);
    expect(sourceMapsLeakFirstParty(r)).toBe(false);
  });

  it('a dependency-only map does not count as leaking app source', async () => {
    const depsOnly = JSON.stringify({
      version: 3,
      sources: ['webpack://_N_E/./node_modules/react/index.js'],
      sourcesContent: ['module.exports = {}'],
    });
    const r = await scanSourceMaps([{ url: chunk, code: '//# sourceMappingURL=m.map' }], async () => depsOnly);
    expect(r.exposed).toHaveLength(1);
    expect(r.exposed[0].firstPartyFiles).toBe(0);
    expect(sourceMapsLeakFirstParty(r)).toBe(false);
  });

  it('never fetches anything for a chunk with no annotation', async () => {
    let calls = 0;
    const r = await scanSourceMaps([{ url: chunk, code: 'console.log(1)' }], async () => {
      calls++;
      return validMap;
    });
    expect(calls).toBe(0);
    expect(r.annotated).toBe(0);
  });
});

describe('REGRESSIONS from adversarial review', () => {
  it('does not inflate the count with asset stubs or the bundler root', () => {
    // A real map lists an entry per asset module (a few hundred bytes of
    // wrapper round a .png) plus a bare runtime root. Counting those as
    // "your source files" overstated the finding roughly threefold.
    const { firstParty } = classifySources([
      'webpack://_N_E/./src/app/page.tsx',
      'webpack://_N_E/./public/logo.png',
      'webpack://_N_E/./src/fonts/Inter.woff2',
      'webpack://_N_E/',
      'webpack://_N_E/./node_modules/react/index.js',
    ]);
    expect(firstParty).toEqual(['webpack://_N_E/./src/app/page.tsx']);
  });

  it('parses an INDEX map, which has sections and no top-level sources', () => {
    // Requiring a top-level `sources` array silently dropped these entirely.
    const indexMap = JSON.stringify({
      version: 3,
      sections: [
        { offset: { line: 0, column: 0 }, map: { version: 3, sources: ['./src/a.ts'], sourcesContent: ['export const a = 1'] } },
        { offset: { line: 9, column: 0 }, map: { version: 3, sources: ['./src/b.ts'], sourcesContent: ['export const b = 2'] } },
      ],
    });
    const p = parseSourceMap(indexMap)!;
    expect(p.sources).toEqual(['./src/a.ts', './src/b.ts']);
    expect(p.hasContent).toBe(true);
  });

  it('still rejects a sections map that carries no sources at all', () => {
    expect(parseSourceMap(JSON.stringify({ version: 3, sections: [] }))).toBe(null);
  });
});
