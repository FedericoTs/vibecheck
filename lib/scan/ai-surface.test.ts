import { describe, it, expect } from 'vitest';
import {
  looksAuthGated,
  looksRateLimited,
  llmProxyVerdict,
  mcpVerdict,
  classifyAiProbe,
  gradeAiSurface,
  AI_PROBES,
  type ProbeReply,
  type AiFinding,
} from './ai-surface';

const reply = (status: number, body: unknown = '', contentType = 'application/json'): ProbeReply => ({
  status,
  contentType,
  body: typeof body === 'string' ? body : JSON.stringify(body),
});

describe('auth/rate-limit recognition', () => {
  it('treats 401/403 and auth-shaped errors as gated', () => {
    expect(looksAuthGated(401, '')).toBe(true);
    expect(looksAuthGated(403, '')).toBe(true);
    expect(looksAuthGated(200, '{"error":"Missing API key"}')).toBe(true);
    expect(looksAuthGated(200, '{"reply":"hello!"}')).toBe(false);
  });
  it('counts rate limiting as a real control', () => {
    expect(looksRateLimited(429)).toBe(true);
    expect(looksRateLimited(200)).toBe(false);
  });
});

describe('llmProxyVerdict — the credit-drain check', () => {
  it('EXPOSED when it answers an anonymous request', () => {
    const v = llmProxyVerdict(reply(200, { reply: 'Hello! How can I help?' }));
    expect(v.verdict).toBe('exposed');
    expect(v.detail).toMatch(/spend your API credits/);
  });

  it('EXPOSED when the provider itself errors — the call reached the model unauthenticated', () => {
    const v = llmProxyVerdict(reply(400, { error: { type: 'invalid_request_error', message: 'messages: required' } }));
    expect(v.verdict).toBe('exposed');
    expect(v.detail).toMatch(/without auth/);
  });

  it('PROTECTED behind auth or rate limiting', () => {
    expect(llmProxyVerdict(reply(401, '')).verdict).toBe('protected');
    expect(llmProxyVerdict(reply(200, { error: 'Unauthorized' })).verdict).toBe('protected');
    expect(llmProxyVerdict(reply(429, '')).verdict).toBe('protected');
  });

  it('ABSENT when the route does not exist', () => {
    expect(llmProxyVerdict(reply(404, 'Not found')).verdict).toBe('absent');
    expect(llmProxyVerdict(reply(405, '')).verdict).toBe('absent');
  });

  it('INCONCLUSIVE — validates input but reveals no auth state (never an accusation)', () => {
    const v = llmProxyVerdict(reply(400, { error: 'messages is required' }));
    expect(v.verdict).toBe('inconclusive');
  });

  it('REGRESSION: an HTML error page is not an AI endpoint', () => {
    // github.com answers POST /api/chat with 422 text/html; the old rule called
    // that "inconclusive" and printed four noise rows for a site with no AI at all.
    expect(llmProxyVerdict(reply(422, '<html>error</html>', 'text/html')).verdict).toBe('absent');
    // and an HTML 200 must never be reported as an open proxy
    expect(llmProxyVerdict(reply(200, '<html>hello</html>', 'text/html')).verdict).toBe('absent');
  });
});

describe('mcpVerdict — the Knostic finding', () => {
  it('EXPOSED when tools/list answers anonymously', () => {
    const v = mcpVerdict(reply(200, { jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'query_db' }, { name: 'send_email' }] } }));
    expect(v.verdict).toBe('exposed');
    expect(v.detail).toMatch(/lists 2 tools/);
  });

  it('INCONCLUSIVE when an MCP server answers but refuses to list', () => {
    const v = mcpVerdict(reply(200, { jsonrpc: '2.0', error: { code: -32601, message: 'Method not found' } }));
    expect(v.verdict).toBe('inconclusive');
  });

  it('PROTECTED / ABSENT for gated and missing servers', () => {
    expect(mcpVerdict(reply(401, '')).verdict).toBe('protected');
    expect(mcpVerdict(reply(404, 'nope')).verdict).toBe('absent');
  });

  it('an ordinary HTML page at /sse is not an MCP finding', () => {
    expect(mcpVerdict(reply(200, '<!doctype html><html></html>', 'text/html')).verdict).toBe('absent');
  });

  it('an event stream is only INCONCLUSIVE — plenty of apps use SSE for other things', () => {
    const v = mcpVerdict(reply(200, 'data: hello', 'text/event-stream'));
    expect(v.verdict).toBe('inconclusive');
  });
});

describe('classifyAiProbe + gradeAiSurface', () => {
  const probe = (p: string) => AI_PROBES.find((x) => x.path === p)!;

  it('routes each probe to the right verdict logic', () => {
    expect(classifyAiProbe(probe('/api/chat'), reply(200, { reply: 'hi' })).verdict).toBe('exposed');
    expect(classifyAiProbe(probe('/mcp'), reply(200, { result: { tools: [] } })).verdict).toBe('exposed');
  });

  it('grades: clean is an A, one open AI endpoint is a serious drop', () => {
    const mk = (verdict: AiFinding['verdict']): AiFinding => ({ path: '/api/chat', label: 'x', kind: 'llm-proxy', verdict });
    expect(gradeAiSurface([mk('absent'), mk('protected')]).grade).toBe('A');
    expect(gradeAiSurface([mk('exposed')]).grade).toBe('D');
    expect(gradeAiSurface([mk('exposed'), mk('exposed')]).grade).toBe('F');
    expect(gradeAiSurface([mk('inconclusive')]).grade).toBe('A'); // never counts against you
  });
});
