import { describe, it, expect } from 'vitest';
import { isHtmlFallback, classifyPath, gradePaths, SENSITIVE_PATHS, type PathFinding } from './paths';

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
