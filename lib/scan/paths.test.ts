import { describe, it, expect } from 'vitest';
import { isHtmlFallback, classifyPath, gradePaths, SENSITIVE_PATHS, type PathFinding, unreachablePath, type PathProbe } from './paths';

const probe = (path: string) => SENSITIVE_PATHS.find((p) => p.path === path)!;

describe('isHtmlFallback', () => {
  it('flags the SPA app-shell, not a real config file', () => {
    expect(isHtmlFallback('text/html; charset=utf-8', '')).toBe(true);
    expect(isHtmlFallback('', '<!doctype html><html>…')).toBe(true);
    expect(isHtmlFallback('text/plain', 'API_KEY=abc')).toBe(false);
  });
});

describe('classifyPath (shape matching, not just 200)', () => {
  it('.env: real env pairs = exposed; SPA fallback = safe', () => {
    expect(classifyPath(probe('/.env'), 200, 'text/plain', 'SUPABASE_KEY=eyJ\nSTRIPE=sk_live_x').exposed).toBe(true);
    expect(classifyPath(probe('/.env'), 200, 'text/html', '<!doctype html><html></html>').exposed).toBe(false);
    expect(classifyPath(probe('/.env'), 404, 'text/plain', 'Not found').exposed).toBe(false);
  });

  it('.git/config: git markers = exposed', () => {
    expect(classifyPath(probe('/.git/config'), 200, 'text/plain', '[core]\n[remote "origin"]\n\turl = git@…').exposed).toBe(true);
    expect(classifyPath(probe('/.git/config'), 200, 'text/html', '<html>app</html>').exposed).toBe(false);
  });

  it('.git/HEAD: a ref line = exposed', () => {
    expect(classifyPath(probe('/.git/HEAD'), 200, 'text/plain', 'ref: refs/heads/main').exposed).toBe(true);
  });

  it('backup.sql: SQL dump markers = exposed', () => {
    expect(classifyPath(probe('/backup.sql'), 200, 'application/sql', 'CREATE TABLE users (id int);\nINSERT INTO users …').exposed).toBe(true);
    expect(classifyPath(probe('/backup.sql'), 200, 'text/html', '<html></html>').exposed).toBe(false);
  });
});

describe('gradePaths', () => {
  const mk = (over: Partial<PathFinding>): PathFinding => ({ path: '/x', label: 'x', severity: 'high', exposed: true, ...over });

  it('no exposed files -> A', () => {
    const r = gradePaths([mk({ exposed: false })]);
    expect(r.grade).toBe('A');
    expect(r.exposed).toHaveLength(0);
  });

  it('a single exposed secret file -> F (one high breach)', () => {
    const r = gradePaths([mk({ path: '/.env', severity: 'high', exposed: true })]);
    expect(r.grade).toBe('F');
    expect(r.summary).toMatch(/publicly served/);
  });
});

describe('directory listing', () => {
  const probe = SENSITIVE_PATHS.find((p) => p.path === '/uploads/')!;
  it('flags a real Apache/nginx autoindex page', () => {
    expect(classifyPath(probe, 200, 'text/html', '<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><pre><a href="../">../</a></pre></body></html>').exposed).toBe(true);
    expect(classifyPath(probe, 200, 'text/html', '<html><body>Directory listing for /uploads/</body></html>').exposed).toBe(true);
  });
  it('does NOT fire on an SPA shell or a page that merely says "index"', () => {
    expect(classifyPath(probe, 200, 'text/html', '<!doctype html><html><title>My App</title><div id=root></div></html>').exposed).toBe(false);
    expect(classifyPath(probe, 200, 'text/html', '<html><h1>Index of our products</h1></html>').exposed).toBe(false);
    expect(classifyPath(probe, 404, 'text/html', 'not found').exposed).toBe(false);
  });
});

/**
 * The launch-day scenario: ten simultaneous GETs at /.env and /.git/config from
 * a datacentre IP is exactly what a WAF blocks, and the probe timeout is short
 * against a stranger's slow origin. Every probe then failed, and the old code
 * returned exposed:false for each — which graded A and printed "No sensitive
 * files are publicly served ✅". A clean bill of health for a site we never
 * successfully asked a single question.
 */
describe('probes that could not run', () => {
  const probe = (path: string): PathProbe => ({
    path,
    label: path,
    severity: 'high',
    match: () => false,
  });

  it('never claims the all-clear when a probe never answered', () => {
    const r = gradePaths([unreachablePath(probe('/.env')), classifyPath(probe('/.git/config'), 404, '', '')]);
    expect(r.summary).not.toMatch(/No sensitive files are publicly served/);
    expect(r.summary).toMatch(/1 of 2/);
  });

  it('still prints the all-clear when everything really was checked', () => {
    const r = gradePaths([classifyPath(probe('/.env'), 404, '', ''), classifyPath(probe('/.git/config'), 404, '', '')]);
    expect(r.summary).toMatch(/No sensitive files are publicly served/);
  });

  it('does NOT accuse the site just because we could not reach it', () => {
    // The opposite failure — flipping unreachable to exposed — is worse: a false
    // accusation screenshotted on launch day is unrecoverable.
    const f = unreachablePath(probe('/.env'));
    expect(f.exposed).toBe(false);
    expect(f.checked).toBe(false);
    expect(gradePaths([f]).exposed).toEqual([]);
    expect(gradePaths([f]).grade).toBe('A');
  });
});
