import { scoreToGrade } from '@/lib/scan/grade';

export const runtime = 'edge';

/**
 * An embeddable SVG badge: `<img src="https://…/badge?g=A">`.
 *
 * Two jobs. It gives people something to show off when they pass — until now
 * only FAILING was shareable, which is a strange incentive for a security tool
 * — and every embed is a backlink from a real app back to vibecheck.
 *
 * Deliberately stateless: the grade is in the URL and rendered as-is. We are NOT
 * claiming "verified by vibecheck" — we have no database, so we could not honour
 * that claim, and a badge that implies verification we never performed would be
 * exactly the kind of overclaim this tool exists to catch. The badge reads
 * "scanned with vibecheck", which is true of anyone who ran a scan.
 */

const COLOR: Record<string, string> = {
  A: '#3fb950',
  B: '#3fb950',
  C: '#d29922',
  D: '#f85149',
  F: '#f85149',
};

function esc(s: string): string {
  return s.replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' })[c]!);
}

export async function GET(request: Request): Promise<Response> {
  const raw = (new URL(request.url).searchParams.get('g') ?? 'A').toUpperCase();
  const grade = /^[A-F]$/.test(raw) && raw !== 'E' ? raw : scoreToGrade(100);
  const color = COLOR[grade] ?? '#8b949e';

  const label = 'security';
  const value = esc(grade);
  const labelW = 96;
  const valueW = 30;
  const w = labelW + valueW;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${label}: ${value}">
  <title>vibecheck ${label}: ${value}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelW}" height="20" fill="#0d1117"/>
    <rect x="${labelW}" width="${valueW}" height="20" fill="${color}"/>
    <rect width="${w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelW / 2}" y="14">vibecheck ${label}</text>
    <text x="${labelW + valueW / 2}" y="14" font-weight="bold">${value}</text>
  </g>
</svg>`;

  return new Response(svg, {
    headers: {
      'content-type': 'image/svg+xml',
      // Badges are embedded in READMEs and footers — cache hard, it never changes per grade.
      'cache-control': 'public, max-age=86400, s-maxage=86400, immutable',
    },
  });
}
