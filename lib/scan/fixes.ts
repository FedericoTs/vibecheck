import type { Report, CheckItem } from './report';

/**
 * Remediation guidance — the half a scanner usually leaves out.
 *
 * Our audience largely cannot fix an RLS policy by hand; handing them a red ✗
 * and walking away is most of the way to useless. So every failing check maps
 * to concrete guidance, and the whole report collapses into ONE prompt they can
 * paste back into the tool that built the app (Lovable, Cursor, v0, Bolt,
 * Claude Code).
 *
 * Deliberately deterministic templates — no LLM call, so this stays free,
 * instant, and impossible to hallucinate a wrong fix with.
 */

/** Guidance keyed by category, used when nothing more specific matches. */
const CATEGORY_FIX: Record<string, string> = {
  supabase:
    'Enable Row Level Security on this table and add a policy scoping every row to its owner/tenant: `alter table <t> enable row level security;` then `create policy "own rows" on <t> for select using (auth.uid() = user_id);`. RLS is per-command, so add matching policies for insert/update/delete too — a correct select policy still leaves writes open.',
  firebase:
    'Tighten the Firestore/Realtime Database rules so reads require an authenticated, authorised user. Replace any `allow read, write: if true` with rules that check `request.auth != null` AND that the document belongs to the caller (e.g. `request.auth.uid == resource.data.userId`).',
  routes:
    'Add a server-side authentication and authorisation check to this route. Checking auth only in the browser is not a control — the request must be rejected on the server. For an admin route, verify both that the user is signed in and that they hold the admin role.',
  secrets:
    'This key is readable by anyone who opens devtools. Rotate/revoke it immediately (treat it as compromised), then move the call that uses it to a server-side route or edge function and read the key from a server environment variable. Never prefix a secret with NEXT_PUBLIC_ / VITE_ / REACT_APP_ — that ships it to the browser.',
  paths:
    'Stop serving this file publicly. Remove it from the deployed output (add it to .gitignore / .vercelignore / your build ignore list) and redeploy. If it contained credentials, rotate them — assume they were read.',
  headers:
    "Add this response header at the edge — in next.config.js headers(), a _headers file, or your host's header settings.",
  fundamentals: 'Add the missing tag to the page <head>.',
  lighthouse:
    'Improve this Lighthouse category — the report at pagespeed.web.dev lists the specific opportunities for this page.',
};

/** More specific guidance when the label tells us exactly what failed. */
const LABEL_FIX: Array<[RegExp, string]> = [
  [/storage bucket/i, 'Make the buckets private and add Storage policies so only the owning user can read their objects. Anonymous visitors should not be able to list buckets at all.'],
  [/database functions|rpc/i, 'Review each publicly-callable function and revoke execute from the anon role for anything not meant to be public: `revoke execute on function <fn> from anon;`. Pay special attention to SECURITY DEFINER functions, which run with the owner privileges.'],
  [/source map/i, 'Disable source maps in your production build (Next.js: `productionBrowserSourceMaps: false`; Vite: `build.sourcemap: false`) so your original source is not downloadable.'],
  [/content-security-policy/i, "Add a Content-Security-Policy header. Start with `default-src 'self'` plus the specific origins you actually use, then tighten."],
  [/strict-transport/i, 'Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.'],
  [/clickjacking|x-frame/i, "Add `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`) so your app cannot be embedded in an attacker page."],
  [/x-content-type/i, 'Add `X-Content-Type-Options: nosniff`.'],
  [/referrer-policy/i, 'Add `Referrer-Policy: strict-origin-when-cross-origin`.'],
  [/server stack|x-powered-by/i, 'Remove the `X-Powered-By` header (Next.js: `poweredByHeader: false`).'],
  [/cors/i, 'Do not combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Echo back a specific allowed origin instead, or drop credentials.'],
  [/cookie/i, 'Set your session cookies with `Secure; HttpOnly; SameSite=Lax` so they cannot be read by JavaScript or sent over plain http.'],
  [/realtime database/i, 'Lock down the Realtime Database rules — a default `".read": true` exposes your entire database. Require auth and scope each path to its owner.'],
  [/user list api|customer api|orders api/i, 'This endpoint returns records to anonymous callers. Require a valid session on the server and filter the query to only the rows that caller may see.'],
  [/viewport/i, 'Add `<meta name="viewport" content="width=device-width, initial-scale=1">` so the page works on phones.'],
  [/page title/i, 'Add a descriptive <title> to the page.'],
  [/description/i, 'Add a `<meta name="description">` summarising the page in ~150 characters.'],
  [/open graph|og:/i, 'Add Open Graph tags (og:title, og:description, og:image) so shared links render a preview card.'],
];

/** The fix text for one failing check. */
export function fixFor(categoryKey: string, check: CheckItem): string {
  for (const [re, text] of LABEL_FIX) {
    if (re.test(check.label)) return text;
  }
  return CATEGORY_FIX[categoryKey] ?? 'Review this finding and remediate it.';
}

/** Every failing SECURITY check, paired with its guidance. */
export function failingChecks(report: Report): Array<{ category: string; check: CheckItem; fix: string }> {
  const out: Array<{ category: string; check: CheckItem; fix: string }> = [];
  for (const c of report.categories) {
    if (c.group !== 'security') continue; // security first — basics/perf are secondary
    for (const check of c.checks) {
      if (!check.pass) out.push({ category: c.label, check, fix: fixFor(c.key, check) });
    }
  }
  return out;
}

/**
 * One prompt, ready to paste into the tool that built the app.
 *
 * Explicit about rotation because that is the step people skip: moving a key
 * server-side does not undo the fact that it was already public.
 */
export function buildFixPrompt(report: Report, url?: string): string {
  const issues = failingChecks(report);
  if (issues.length === 0) return 'My security scan came back clean — no changes needed.';

  const lines: string[] = [];
  lines.push(
    `I ran a security scan on my app${url ? ` (${url})` : ''} and it found ${issues.length} issue${issues.length === 1 ? '' : 's'}. ` +
      'Please fix them one at a time, starting with the first. After each fix, briefly explain what you changed and why.',
  );
  lines.push('');
  issues.forEach((it, i) => {
    lines.push(`${i + 1}. [${it.category}] ${it.check.label}`);
    if (it.check.detail) lines.push(`   What the scan saw: ${it.check.detail}`);
    lines.push(`   How to fix: ${it.fix}`);
    lines.push('');
  });

  const hasSecret = issues.some((i) => /secret|key|connection string/i.test(i.check.label));
  lines.push('Important:');
  lines.push('- Do not just hide these behind client-side checks. The fix has to hold on the server.');
  if (hasSecret) {
    lines.push('- Any exposed key must be ROTATED as well as moved. It has been public, so treat it as compromised — moving it server-side alone does not undo the exposure.');
  }
  lines.push('- After the changes, redeploy and re-run the scan to confirm.');
  return lines.join('\n');
}
