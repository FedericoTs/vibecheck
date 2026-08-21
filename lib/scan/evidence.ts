/**
 * Reproducible evidence for a finding.
 *
 * WHY THIS EXISTS
 * ---------------
 * The audit of this scanner found that every false accusation came from checks
 * that INFER, and none from the one check that EXECUTES AND OBSERVES — the
 * database probe, which hands the user the literal request it ran. The lesson
 * generalises further than it was applied: roughly forty checks here already
 * execute and observe, then throw the observation away and render a sentence
 * where they could render the request.
 *
 * A sentence is arguable. `curl -sI https://yourapp.com/.env` returning 200 is
 * not. This module turns an observation the scanner already made into a command
 * the owner can paste into their own terminal and re-run against their own app.
 *
 * TWO RULES, BOTH ENFORCED BELOW
 * ------------------------------
 * 1. NEVER embed a credential. Keys travel as headers and are the user's own
 *    publishable ones; the command carries a placeholder, never the value.
 * 2. NEVER emit a command we cannot safely quote. Every interpolated value is
 *    wrapped in single quotes, and a value that could break out of them is
 *    refused outright rather than escaped. A mis-quoted command presented to a
 *    user as "proof" is worse than no proof, and this is a security tool.
 */

export interface CheckEvidence {
  /** What re-running it proves. */
  label: string;
  /** A copy-pasteable shell command. Never contains a secret. */
  command: string;
}

/**
 * The only characters that can break out of POSIX single quotes.
 *
 * Inside single quotes everything else is literal — `&`, `$`, `;`, backticks and
 * spaces are all inert — so the dangers are the closing quote itself and control
 * characters, chiefly a newline, which would terminate the quoted string and put
 * whatever follows on its own line as a second command.
 *
 * Listing more than this is not extra safety, it is a silent failure: `&` and
 * `=` appear in every PostgREST probe URL, so an over-broad rule would refuse to
 * show evidence for exactly the check that needs it most.
 */
const UNSAFE_FOR_SHELL = /['\u0000-\u001f\u007f]/;

/**
 * Single-quote a value for a POSIX shell, or refuse.
 *
 * We reject rather than escape. Everything interpolated here is a hostname, a
 * path, or a header name that we ourselves probed — anything exotic in one of
 * them means our own input handling is wrong, and the right response to that is
 * to show no evidence rather than a command we are not certain of.
 */
export function shellQuote(value: string): string | null {
  if (!value || UNSAFE_FOR_SHELL.test(value)) return null;
  return `'${value}'`;
}

/** `https://host/path`, with scheme and slashes normalised. */
export function originUrl(host: string, path = ''): string | null {
  if (!host) return null;
  const clean = host.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  if (!clean) return null;
  const suffix = path ? (path.startsWith('/') ? path : `/${path}`) : '';
  return `https://${clean}${suffix}`;
}

/** A file that should not have been fetchable. Headers only, so nothing downloads. */
export function fileEvidence(host: string, path: string): CheckEvidence | null {
  const url = originUrl(host, path);
  const quoted = url && shellQuote(url);
  if (!quoted) return null;
  return {
    label: 'Run this yourself — a 200 means anyone can fetch it',
    command: `curl -sI ${quoted}`,
  };
}

/** A route that answered without asking who you are. */
export function routeEvidence(host: string, path: string): CheckEvidence | null {
  const url = originUrl(host, path);
  const quoted = url && shellQuote(url);
  if (!quoted) return null;
  return {
    label: 'Run this yourself — no login and no redirect means it is open',
    command: `curl -sI ${quoted}`,
  };
}

/**
 * A missing response header. Proving an ABSENCE is the one case where the value
 * of the command is that it prints nothing.
 */
export function headerEvidence(host: string, headerKey: string): CheckEvidence | null {
  const url = originUrl(host);
  const quoted = url && shellQuote(url);
  const key = shellQuote(`^${headerKey}:`);
  if (!quoted || !key) return null;
  return {
    label: 'Run this yourself — no output means the header is not being sent',
    command: `curl -sI ${quoted} | grep -i ${key}`,
  };
}

/** A DNS record: anyone can read it, and nobody can dispute it. */
export function dnsEvidence(host: string, kind: 'spf' | 'dmarc'): CheckEvidence | null {
  const domain = host.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  const name = shellQuote(kind === 'dmarc' ? `_dmarc.${domain}` : domain);
  if (!domain || !name) return null;
  return {
    label:
      kind === 'dmarc'
        ? 'Run this yourself — empty means no DMARC policy is published'
        : 'Run this yourself — empty means no SPF record is published',
    command: `dig +short TXT ${name}`,
  };
}

/**
 * A published source map. Truncated deliberately: the point is to show the
 * original source is retrievable, not to dump it into someone's terminal.
 */
export function sourceMapEvidence(url: string): CheckEvidence | null {
  const quoted = shellQuote(url);
  if (!quoted) return null;
  return {
    label: 'Run this yourself — your original source comes back',
    command: `curl -s ${quoted} | head -c 400`,
  };
}

/**
 * A readable Firestore collection.
 *
 * The web API key is public by design, but it is still the user's value, so it
 * is a placeholder here for the same reason the Supabase anon key is. The URL
 * already carries `?pageSize=1`, so the key appends cleanly.
 */
export function firestoreEvidence(probeUrl: string): CheckEvidence | null {
  const quoted = shellQuote(`${probeUrl}&key=<your web api key>`);
  if (!quoted) return null;
  return {
    label: 'Run this yourself — documents come back with no login',
    command: `curl -s ${quoted}`,
  };
}

/**
 * The database probe. The anon key is the user's own publishable key and travels
 * as a header, but it is still THEIR value, so the command carries a
 * placeholder — the same rule the proof headline follows.
 */
export function tableEvidence(probeUrl: string): CheckEvidence | null {
  const quoted = shellQuote(probeUrl);
  if (!quoted) return null;
  return {
    label: 'Run this yourself — count the rows that come back',
    command: `curl ${quoted} -H 'apikey: <your anon key>'`,
  };
}
