import { describe, expect, it } from 'vitest';
import { analyzeSchema, describeSchema } from './schema';

const block = (json: string) => `<script type="application/ld+json">${json}</script>`;

describe('analyzeSchema', () => {
  it('parses a valid block and collects its @types, @graph included', () => {
    const html = block(
      JSON.stringify({ '@context': 'https://schema.org', '@graph': [{ '@type': 'Organization' }, { '@type': 'WebSite' }] }),
    );
    const s = analyzeSchema(html);
    expect(s.blocks).toBe(1);
    expect(s.valid).toBe(1);
    expect(s.broken).toBe(0);
    expect(s.types).toEqual(['Organization', 'WebSite']);
  });

  it('flags a malformed block — the failure a presence check misses', () => {
    const html = block('{ "@type": "Product", }'); // trailing comma = invalid JSON
    const s = analyzeSchema(html);
    expect(s.blocks).toBe(1);
    expect(s.broken).toBe(1);
    expect(describeSchema(s)).toMatch(/did not parse/);
  });

  it('counts valid and broken blocks separately on one page', () => {
    const html = block('{"@type":"Article"}') + block('{bad json');
    const s = analyzeSchema(html);
    expect(s.blocks).toBe(2);
    expect(s.valid).toBe(1);
    expect(s.broken).toBe(1);
  });

  it('reports no markup as zero blocks, not a failure', () => {
    const s = analyzeSchema('<html><body>plain page</body></html>');
    expect(s.blocks).toBe(0);
    expect(s.broken).toBe(0);
    expect(describeSchema(s)).toMatch(/no JSON-LD/);
  });

  it('handles an array of @type on a single node', () => {
    const s = analyzeSchema(block('{"@type":["WebPage","FAQPage"]}'));
    expect(s.types).toEqual(['FAQPage', 'WebPage']);
  });

  it('ignores an empty ld+json tag rather than counting it broken', () => {
    expect(analyzeSchema(block('   ')).blocks).toBe(0);
  });
});
