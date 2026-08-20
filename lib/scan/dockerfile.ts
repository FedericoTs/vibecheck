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

  // Unpinned base image
  for (const l of lines.filter((l) => /^FROM\s+/i.test(l))) {
    const img = l.replace(/^FROM\s+/i, '').split(/\s+as\s+/i)[0].trim();
    if (/^scratch$/i.test(img)) continue;
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
