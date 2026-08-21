import { findSecrets } from './secrets';

/**
 * Dockerfile security linting — the honest "container security" slice for the
 * repo mode. Most vibe-coded apps deploy to Vercel/Netlify and have no
 * Dockerfile, so this only speaks up for the subset that containerise; for them
 * the defaults matter (a container running as root, an unpinned base image that
 * silently changes under you, a secret baked into a layer).
 *
 * Pure and unit-tested; the route runs it only when the repo actually has a
 * Dockerfile.
 */

export interface DockerFinding {
  severity: 'high' | 'medium';
  label: string;
  detail: string;
}

/**
 * Extensions that mean the file is source, config or prose — never a Dockerfile.
 * `dockerfile.ts` is code that deals WITH Dockerfiles; `Dockerfile.md` is
 * documentation about one.
 */
const CODE_OR_DOC_EXT = /\.(tsx?|jsx?|mjs|cjs|py|rb|go|rs|java|php|cs|swift|kts?|mdx?|txt|json|ya?ml|toml|lock|html?|css|s[ac]ss|sh|bat|ps1|snap|map)$/i;

/**
 * Is this path actually a Dockerfile?
 *
 * The original filter was `/(^|\/)Dockerfile(\.[\w.-]+)?$/i`, written to catch
 * `Dockerfile.prod`. Case-insensitively it also matched `lib/scan/dockerfile.ts`
 * — this scanner's OWN source — so the linter ran over its own pattern
 * definitions and reported them as container findings, grading this repo F on
 * four issues that do not exist. It simultaneously MISSED `prod.Dockerfile`,
 * a real and common convention.
 *
 * A security tool's source is the most predictable false-positive magnet there
 * is: it necessarily contains every pattern it hunts for. So the rule is
 * name-based AND content-checked, and errs toward missing a Dockerfile rather
 * than inventing one.
 */
export function isDockerfilePath(path: string): boolean {
  const base = path.split('/').pop() ?? '';
  if (CODE_OR_DOC_EXT.test(base)) return false;
  if (/^dockerfile$/i.test(base)) return true; // Dockerfile
  if (/^dockerfile\.[\w-]+$/i.test(base)) return true; // Dockerfile.prod
  return /\.dockerfile$/i.test(base); // prod.Dockerfile
}

/**
 * A second, content-level gate. FROM is the only mandatory Dockerfile
 * instruction, so a file without one is not a Dockerfile whatever it is called.
 */
export function looksLikeDockerfile(content: string): boolean {
  return /^[ \t]*FROM[ \t]+\S/im.test(content);
}

export function lintDockerfile(content: string): DockerFinding[] {
  const out: DockerFinding[] = [];
  const lines = content
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));

  // Runs as root? (no USER, or the final USER is root/0)
  const users = lines.filter((l) => /^USER\s+/i.test(l)).map((l) => l.replace(/^USER\s+/i, '').trim().toLowerCase());
  const lastUser = users[users.length - 1];
  if (!lastUser || lastUser === 'root' || lastUser === '0') {
    out.push({
      severity: 'high',
      label: 'Container runs as root',
      detail: lastUser
        ? 'the final USER is root — a container escape then lands the attacker as root'
        : 'no USER directive, so the container runs as root by default',
    });
  }

  // Unpinned base image.
  //
  // In a multi-stage build, `FROM builder` refers to an earlier stage declared
  // with `AS builder` — not a registry image — and Docker itself resolves a
  // stage name in preference to an image. Reading those as untagged base images
  // made every multi-stage Dockerfile fail this check, which is most real ones.
  // So collect the stage names first and skip anything that resolves to one.
  const fromLines = lines.filter((l) => /^FROM\s+/i.test(l));
  const stageNames = new Set(
    fromLines.map((l) => l.match(/\s+as\s+(\S+)/i)?.[1]?.toLowerCase()).filter((n): n is string => !!n),
  );
  for (const l of fromLines) {
    const img = l
      .replace(/^FROM\s+/i, '')
      // Strip the flags that may precede the image (--platform=…, --from=…).
      .replace(/^(--\S+\s+)+/i, '')
      .split(/\s+as\s+/i)[0]
      .trim();
    if (/^scratch$/i.test(img)) continue;
    if (stageNames.has(img.toLowerCase())) continue; // an earlier stage, not an image
    // `FROM ${NODE_VERSION}` is pinned by a build ARG we cannot resolve — not
    // evidence of a missing tag.
    if (/^\$\{?\w+\}?$/.test(img)) continue;
    if (/:latest$/i.test(img) || !/[:@]/.test(img)) {
      out.push({
        severity: 'medium',
        label: 'Base image not pinned',
        detail: `${img} uses :latest or no tag — pin a version or digest so builds are reproducible and patchable`,
      });
    }
  }

  // ADD from a remote URL (runs unverified content into the image)
  if (lines.some((l) => /^ADD\s+https?:\/\//i.test(l))) {
    out.push({
      severity: 'medium',
      label: 'ADD fetches a remote URL',
      detail: 'ADD from a URL pulls unverified content into your image — use COPY for local files, or curl with a checksum',
    });
  }

  // Piping a download straight into a shell at build time
  if (lines.some((l) => /(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/i.test(l))) {
    out.push({
      severity: 'medium',
      label: 'Pipes a download straight to a shell',
      detail: 'curl | sh runs unverified remote code during the build — download, verify a checksum, then execute',
    });
  }

  // Hard-coded secrets in the Dockerfile itself (ENV/ARG defaults are baked into layers)
  const seen = new Set<string>();
  for (const s of findSecrets(content)) {
    const key = s.id + ':' + s.redacted;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ severity: 'high', label: `${s.label} hard-coded in the Dockerfile`, detail: s.redacted });
  }

  return out;
}
