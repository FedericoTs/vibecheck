import { describe, expect, it } from 'vitest';
import {
  dnsEvidence,
  fileEvidence,
  headerEvidence,
  originUrl,
  routeEvidence,
  shellQuote,
  sourceMapEvidence,
  tableEvidence,
} from './evidence';

describe('shellQuote', () => {
  it('quotes the ordinary values this module actually handles', () => {
    expect(shellQuote('https://my-startup.com/.env')).toBe("'https://my-startup.com/.env'");
    // Hyphens, dots, slashes and colons are the common case — an over-broad
    // guard here would silently switch evidence off for nearly every finding.
    expect(shellQuote('https://a-b-c.example.co.uk:8443/x')).not.toBe(null);
  });

  it('keeps the characters that are inert inside single quotes', () => {
    // & and = appear in every PostgREST probe URL. Refusing them would remove
    // evidence from precisely the check that most needs it.
    expect(shellQuote('https://x.supabase.co/rest/v1/users?select=*&limit=1')).toBe(
      "'https://x.supabase.co/rest/v1/users?select=*&limit=1'",
    );
    expect(shellQuote('https://x.com/$a;b`c|d')).not.toBe(null);
  });

  it('refuses anything that could break out of the quotes', () => {
    expect(shellQuote("https://x.com/'")).toBe(null);
    expect(shellQuote('https://x.com/a\nrm -rf /')).toBe(null);
    expect(shellQuote('https://x.com/a\r\nwhoami')).toBe(null);
    expect(shellQuote('https://x.com/a' + String.fromCharCode(0))).toBe(null);
    // A space is INERT inside single quotes and must not be refused — the
    // Firestore evidence placeholder '<your web api key>' contains spaces.
    expect(shellQuote('https://x.com/a b')).not.toBe(null);
    expect(shellQuote('')).toBe(null);
  });
});

describe('originUrl', () => {
  it('normalises scheme and slashes', () => {
    expect(originUrl('example.com', '/.env')).toBe('https://example.com/.env');
    expect(originUrl('https://example.com/', '.env')).toBe('https://example.com/.env');
    expect(originUrl('example.com')).toBe('https://example.com');
    expect(originUrl('')).toBe(null);
  });
});

describe('evidence builders', () => {
  it('builds a headers-only request for an exposed file', () => {
    expect(fileEvidence('example.com', '/.env')?.command).toBe("curl -sI 'https://example.com/.env'");
  });

  it('builds a route probe', () => {
    expect(routeEvidence('example.com', '/admin')?.command).toBe("curl -sI 'https://example.com/admin'");
  });

  it('proves a MISSING header by printing nothing', () => {
    const e = headerEvidence('example.com', 'content-security-policy');
    expect(e?.command).toBe("curl -sI 'https://example.com' | grep -i '^content-security-policy:'");
    expect(e?.label).toMatch(/no output/i);
  });

  /**
   * Not every check key is a wire header. Grepping for a header named
   * "csp-effective" prints nothing on every site alive, so pairing it with "no
   * output means it is missing" would manufacture proof for something the
   * command cannot test.
   */
  it('maps a judgement key to the header it is actually about', () => {
    const csp = headerEvidence('example.com', 'csp-effective');
    expect(csp?.command).toContain("'^content-security-policy:'");
    expect(csp?.command).not.toContain('csp-effective');
    expect(csp?.label).toMatch(/exact value/i);

    expect(headerEvidence('example.com', 'cors')?.command).toContain("'^access-control-allow-origin:'");
    expect(headerEvidence('example.com', 'cookie-flags')?.command).toContain("'^set-cookie:'");
  });

  it('does not claim absence for a check that fails on PRESENCE', () => {
    const e = headerEvidence('example.com', 'x-powered-by');
    expect(e?.label).toMatch(/any output means it is being sent/i);
    expect(e?.label).not.toMatch(/no output/i);
  });

  it('emits nothing for a key it does not recognise', () => {
    expect(headerEvidence('example.com', 'some-future-check')).toBe(null);
  });

  it('builds the right DNS lookup for each record', () => {
    expect(dnsEvidence('example.com', 'spf')?.command).toBe("dig +short TXT 'example.com'");
    expect(dnsEvidence('https://example.com/x', 'dmarc')?.command).toBe("dig +short TXT '_dmarc.example.com'");
  });

  it('truncates a source map rather than dumping it', () => {
    expect(sourceMapEvidence('https://example.com/a.js.map')?.command).toMatch(/head -c 400$/);
  });

  it('never puts a key in the database command', () => {
    const e = tableEvidence('https://abc.supabase.co/rest/v1/users?select=*&limit=1');
    expect(e?.command).toContain('<your anon key>');
    expect(e?.command).toContain('users?select=*&limit=1');
  });

  it('returns null rather than a command it cannot quote', () => {
    expect(fileEvidence('example.com', "/a'b")).toBe(null);
    expect(tableEvidence('https://x.com/a\nrm -rf /')).toBe(null);
    expect(routeEvidence('', '/admin')).toBe(null);
  });

  it('never emits a command containing a raw newline', () => {
    const all = [
      fileEvidence('example.com', '/.env'),
      routeEvidence('example.com', '/admin'),
      headerEvidence('example.com', 'x-frame-options'),
      dnsEvidence('example.com', 'spf'),
      sourceMapEvidence('https://example.com/a.js.map'),
      tableEvidence('https://abc.supabase.co/rest/v1/users?select=*'),
    ];
    for (const e of all) {
      expect(e).not.toBe(null);
      expect(e!.command).not.toMatch(/[\r\n]/);
    }
  });
});
