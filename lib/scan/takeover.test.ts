import { describe, it, expect } from 'vitest';
import { classifyTakeover, SERVICES, type TakeoverFacts } from './takeover';

const facts = (over: Partial<TakeoverFacts> = {}): TakeoverFacts => ({
  cname: null,
  cnameResolves: true,
  body: '<html><body>My real app</body></html>',
  status: 200,
  ...over,
});

describe('classifyTakeover', () => {
  it('no CNAME means there is nothing to take over', () => {
    const f = classifyTakeover(facts());
    expect(f.verdict).toBe('not-applicable');
    expect(f.detail).toMatch(/nothing to take over/);
  });

  it('a normal CNAME to a live service is SAFE — pointing at a host is not a bug', () => {
    const f = classifyTakeover(facts({ cname: 'myapp.github.io', body: '<html>my actual blog</html>' }));
    expect(f.verdict).toBe('safe');
    expect(f.service).toBe('GitHub Pages');
  });

  it('VULNERABLE only when the provider serves its unclaimed page', () => {
    const f = classifyTakeover(
      facts({ cname: 'myapp.github.io', body: "<html>There isn't a GitHub Pages site here.</html>" }),
    );
    expect(f.verdict).toBe('vulnerable');
    expect(f.service).toBe('GitHub Pages');
    expect(f.detail).toMatch(/serve their own content on your domain/);
  });

  it('catches the Heroku and S3 unclaimed pages too', () => {
    expect(classifyTakeover(facts({ cname: 'x.herokuapp.com', body: '<html>No such app</html>' })).verdict).toBe('vulnerable');
    expect(classifyTakeover(facts({ cname: 'b.s3.amazonaws.com', body: '<Error><Code>NoSuchBucket</Code></Error>' })).verdict).toBe('vulnerable');
  });

  it('a CNAME whose target does not resolve is DANGLING even on an unknown provider', () => {
    const f = classifyTakeover(facts({ cname: 'old-thing.example-host.com', cnameResolves: false }));
    expect(f.verdict).toBe('dangling');
    expect(f.detail).toMatch(/does not resolve/);
  });

  it('an unknown provider that resolves and serves content is SAFE, not a guess', () => {
    const f = classifyTakeover(facts({ cname: 'edge.somecdn.example', body: '<html>content</html>' }));
    expect(f.verdict).toBe('safe');
    expect(f.service).toBeUndefined();
  });

  it('does not fire on a page that merely mentions the provider', () => {
    const f = classifyTakeover(
      facts({ cname: 'myapp.github.io', body: '<html>We host our docs on GitHub Pages. Welcome!</html>' }),
    );
    expect(f.verdict).toBe('safe');
  });

  it('every service defines both a cname pattern and an unclaimed fingerprint', () => {
    for (const s of SERVICES) {
      expect(s.cname).toBeInstanceOf(RegExp);
      expect(s.unclaimed).toBeInstanceOf(RegExp);
      expect(s.name.length).toBeGreaterThan(0);
    }
  });
});
