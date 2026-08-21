import type { Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * The agentic attack surface — the 2026 surface every other vibe scanner misses.
 *
 * Two things happened at once: AI-built apps started shipping LLM proxies and
 * MCP servers, and attackers started scanning for them. Censys counted 12,520
 * internet-exposed MCP services in late April 2026 and 21,000+ a week later;
 * Knostic mapped 1,862 via Shodan and found every manually verified one served
 * its tool list to anonymous callers.
 *
 * Two classes of finding here, both observable from a URL:
 *
 *  1. An UNAUTHENTICATED LLM PROXY. Almost every AI-built app with a chat
 *     feature proxies to OpenAI/Anthropic from its own backend. Ship that
 *     without auth or rate limiting and any stranger can spend your API credits
 *     — or use your key as a free relay. Cheap to check, extremely common, and
 *     nobody in this category checks it.
 *  2. An EXPOSED MCP SERVER. `tools/list` answered anonymously hands an attacker
 *     your capability map and often your internal API shape.
 *
 * Probing is deliberately minimal and non-destructive: we send the smallest
 * possible request and read the SHAPE of the reply. We never run a real
 * completion (that would spend the owner's money), never call an MCP tool, and
 * never send anything that could mutate state.
 */

export type AiProbeKind = 'llm-proxy' | 'mcp';

export interface AiSurfaceProbe {
  path: string;
  label: string;
  kind: AiProbeKind;
}

/**
 * 'unreachable' means the probe never got an answer — timeout, refused
 * connection, or a WAF blocking a datacentre IP. It must stay distinct from
 * 'absent', which is a positive claim that the route is not there. Only one of
 * those is a pass.
 */
export type AiVerdict = 'exposed' | 'protected' | 'absent' | 'inconclusive' | 'unreachable';

export interface AiFinding {
  path: string;
  label: string;
  kind: AiProbeKind;
  verdict: AiVerdict;
  detail?: string;
}

export interface AiSurfaceResult {
  host: string;
  findings: AiFinding[];
  exposed: AiFinding[];
  grade: Grade;
  score: number;
  summary: string;
}

export const AI_PROBES: AiSurfaceProbe[] = [
  { path: '/api/chat', label: 'AI chat endpoint (/api/chat)', kind: 'llm-proxy' },
  { path: '/api/ai', label: 'AI endpoint (/api/ai)', kind: 'llm-proxy' },
  { path: '/api/completion', label: 'AI completion endpoint (/api/completion)', kind: 'llm-proxy' },
  { path: '/api/generate', label: 'AI generation endpoint (/api/generate)', kind: 'llm-proxy' },
  { path: '/mcp', label: 'MCP server (/mcp)', kind: 'mcp' },
  { path: '/sse', label: 'MCP server (/sse)', kind: 'mcp' },
  { path: '/.well-known/mcp', label: 'MCP discovery (/.well-known/mcp)', kind: 'mcp' },
];

export interface ProbeReply {
  status: number;
  contentType: string;
  body: string;
}

/** Auth gates look the same everywhere: a 401/403, or an error naming auth. */
export function looksAuthGated(status: number, body: string): boolean {
  if (status === 401 || status === 403) return true;
  const s = body.slice(0, 2000).toLowerCase();
  return /(unauthor|forbidden|not authenticated|missing.{0,12}(token|api key|session)|sign in|login required|permission denied)/.test(s);
}

/** Rate limiting is a real control — treat a 429 as protected, not exposed. */
export function looksRateLimited(status: number): boolean {
  return status === 429;
}

/**
 * Did an LLM proxy actually accept our request? We send an empty/minimal body,
 * so a well-built endpoint answers 400 "missing messages" — that is a LIVE but
 * VALIDATING endpoint, not an open one. Only a 200, or a model/token-shaped
 * error, indicates it would really run a completion for a stranger.
 */
export function llmProxyVerdict(reply: ProbeReply): { verdict: AiVerdict; detail?: string } {
  const { status, contentType, body } = reply;
  if (status === 404 || status === 405 || status === 501) return { verdict: 'absent' };
  if (looksAuthGated(status, body)) return { verdict: 'protected', detail: 'requires authentication' };
  if (looksRateLimited(status)) return { verdict: 'protected', detail: 'rate limited' };

  // An LLM proxy is a JSON API. Plenty of sites answer POSTs to unknown paths
  // with an HTML error page (github.com returns 422 text/html for /api/chat),
  // and treating that as an AI endpoint produced rows of pure noise.
  const isJson = /application\/(json|.*\+json)/i.test(contentType);
  if (!isJson) return { verdict: 'absent' };

  const s = body.slice(0, 4000).toLowerCase();
  // Provider errors prove the request reached a real model call unauthenticated.
  const providerEcho = /(openai|anthropic|gpt-|claude-|gemini|model_not_found|insufficient_quota|invalid_request_error|max_tokens|completion)/.test(s);

  if (status === 200) {
    return { verdict: 'exposed', detail: 'answers anonymous requests — anyone could spend your API credits' };
  }
  if (status === 400 && providerEcho) {
    return { verdict: 'exposed', detail: 'reaches the model provider without auth — only the payload was rejected' };
  }
  if (status === 400 || status === 422) {
    return { verdict: 'inconclusive', detail: 'endpoint exists and validates input; auth could not be determined' };
  }
  return { verdict: 'absent' };
}

/**
 * MCP speaks JSON-RPC. An anonymous `tools/list` that returns a result is the
 * Knostic finding: the server hands its capability map to strangers.
 */
export function mcpVerdict(reply: ProbeReply): { verdict: AiVerdict; detail?: string } {
  const { status, contentType, body } = reply;
  if (status === 404 || status === 405 || status === 501) return { verdict: 'absent' };
  if (looksAuthGated(status, body)) return { verdict: 'protected', detail: 'requires authentication' };

  const s = body.slice(0, 8000);
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(s);
  } catch {
    /* SSE or non-JSON */
  }
  const obj = parsed as { result?: { tools?: unknown[] }; jsonrpc?: string; error?: { message?: string } } | null;

  if (obj?.result?.tools && Array.isArray(obj.result.tools)) {
    const n = obj.result.tools.length;
    return { verdict: 'exposed', detail: `lists ${n} tool${n === 1 ? '' : 's'} to anonymous callers` };
  }
  if (obj?.jsonrpc || obj?.error) {
    return { verdict: 'inconclusive', detail: 'an MCP server answered, but would not list its tools' };
  }
  if (status === 200 && /text\/event-stream/i.test(contentType)) {
    return { verdict: 'inconclusive', detail: 'an event stream is served here; it may be an MCP transport' };
  }
  return { verdict: 'absent' };
}

export function classifyAiProbe(probe: AiSurfaceProbe, reply: ProbeReply): AiFinding {
  const base = { path: probe.path, label: probe.label, kind: probe.kind };
  const v = probe.kind === 'mcp' ? mcpVerdict(reply) : llmProxyVerdict(reply);
  return { ...base, ...v };
}

export function gradeAiSurface(findings: AiFinding[], host = ''): AiSurfaceResult {
  const exposed = findings.filter((f) => f.verdict === 'exposed');
  const score = Math.max(0, 100 - exposed.length * 50);
  return {
    host,
    findings,
    exposed,
    grade: scoreToGrade(score),
    score,
    summary:
      exposed.length === 0
        ? 'No unprotected AI or MCP endpoints found ✅'
        : `${exposed.length} AI endpoint(s) usable by anyone ⚠️`,
  };
}
