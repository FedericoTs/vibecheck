export const runtime = 'edge';

/**
 * An embeddable SVG badge: `<img src="https://…/badge?g=A&d=Aug%202026">`.
 *
 * Two jobs. It gives people something honest to show off when they pass — until
 * now only FAILING was shareable, a strange incentive for a security tool — and
 * every embed is a backlink from a real app back to vibecheck.
 *
 * Deliberately stateless and deliberately NOT a "verified / secure" seal:
 *  - We have no database, so we cannot stand behind a live "verified" claim, and
 *    a badge implying a guarantee we never made is exactly the overclaim this tool
 *    exists to catch. So the badge states a narrow, true observation — "no public
 *    exposure" — never "secure".
 *  - It is date-stamped (?d=), because a scan is a point in time, not a standing
 *    promise. An app can drift after it earns the badge; the date makes that honest
 *    instead of hiding it behind a stale letter grade.
 */

function esc(s: string): string {
  return s.replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' })[c]!);
}

export function GET(request: Request): Response {
  const url = new URL(request.url);
  const raw = (url.searchParams.get('g') ?? 'A').toUpperCase();
  const grade = /^[ABCDF]$/.test(raw) ? raw : 'A';
  const clean = grade === 'A' || grade === 'B';
  const color = clean ? '#3fb950' : grade === 'C' ? '#d29922' : '#f85149';
  const claim = clean ? 'no public exposure' : grade === 'C' ? 'gaps found' : 'exposed';
  // Date is caller-supplied and baked in at copy time (e.g. "Aug 2026"); sanitise hard.
  const date = (url.searchParams.get('d') ?? '').replace(/[^A-Za-z0-9 .,-]/g, '').slice(0, 20).trim();
  const value = date ? `${claim} · ${date}` : claim;

  const label = 'vibecheck';
  const cw = 6.3;
  const pad = 20;
  const labelW = Math.round(label.length * cw + pad);
  const valueW = Math.round(value.length * cw + pad);
  const w = labelW + valueW;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="vibecheck: ${esc(value)}">
  <title>vibecheck — ${esc(value)}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelW}" height="20" fill="#0d1117"/>
    <rect x="${labelW}" width="${valueW}" height="20" fill="${color}"/>
    <rect width="${w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelW / 2}" y="14">${label}</text>
    <text x="${labelW + valueW / 2}" y="14" font-weight="bold">${esc(value)}</text>
  </g>
</svg>`;

  return new Response(svg, {
    headers: {
      'content-type': 'image/svg+xml',
      // Embedded in READMEs/footers; each grade+date combination is immutable.
      'cache-control': 'public, max-age=86400, s-maxage=86400, immutable',
    },
  });
}
