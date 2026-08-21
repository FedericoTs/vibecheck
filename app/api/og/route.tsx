import { ImageResponse } from 'next/og';

export const runtime = 'nodejs';

const GRADE_COLOR: Record<string, string> = { A: '#48c98b', B: '#48c98b', C: '#e6b25e', D: '#f2565b', F: '#f2565b' };
const CANVAS = '#0b0b0d';
const INK = '#ededf0';
const MUTED = '#8b8b95';
const LINE = '#212127';
const DANGER = '#f2565b';

// Cache the OG image at the edge. It's deterministic per URL (grade + issue count),
// so crawlers — Twitterbot, iMessage, Slack, Discord — get an instant CDN hit instead
// of re-rendering (~1.8s) on every fetch, which also makes card previews more reliable.
const OG_CACHE = 'public, max-age=0, s-maxage=86400, stale-while-revalidate=604800';

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        background: CANVAS,
        color: INK,
        padding: '68px 72px',
        fontFamily: 'sans-serif',
        position: 'relative',
      }}
    >
      {/* mesh accent — soft brand-colour glow on the right, masked out before it reaches the text */}
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          display: 'flex',
          background:
            'linear-gradient(90deg, #0b0b0d 24%, rgba(11,11,13,0) 60%), radial-gradient(760px 760px at 100% 12%, rgba(72,201,139,0.22), rgba(72,201,139,0) 60%), radial-gradient(620px 620px at 92% 96%, rgba(242,86,91,0.16), rgba(242,86,91,0) 58%), radial-gradient(520px 520px at 72% 52%, rgba(230,178,94,0.10), rgba(230,178,94,0) 60%)',
        }}
      />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 42, fontWeight: 700, letterSpacing: -1 }}>vibecheck</div>
        <div style={{ fontSize: 20, letterSpacing: 4, color: MUTED }}>SECURITY REPORT CARD</div>
      </div>
      {children}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderTop: `1px solid ${LINE}`,
          paddingTop: 28,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', fontSize: 30 }}>
          <span>See what a stranger can read from your app</span>
          <span style={{ color: MUTED, marginLeft: 10 }}>— free</span>
        </div>
        <div style={{ fontSize: 24, color: MUTED }}>open source</div>
      </div>
    </div>
  );
}

export function GET(req: Request): ImageResponse {
  const { searchParams } = new URL(req.url);
  const raw = (searchParams.get('g') ?? '').toUpperCase();
  const hasGrade = ['A', 'B', 'C', 'D', 'F'].includes(raw);

  if (!hasGrade) {
    // hero card (home page)
    return new ImageResponse(
      (
        <Shell>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: 108, fontWeight: 800, lineHeight: 1.02, letterSpacing: -2 }}>
              Is your app
            </div>
            <div style={{ fontSize: 108, fontWeight: 800, lineHeight: 1.02, letterSpacing: -2, color: DANGER }}>
              leaking?
            </div>
            <div style={{ fontSize: 32, color: MUTED, marginTop: 20 }}>
              A security report card for AI-built apps
            </div>
          </div>
        </Shell>
      ),
      { width: 1200, height: 630, headers: { 'cache-control': OG_CACHE } },
    );
  }

  const issues = Math.max(0, Math.min(999, parseInt(searchParams.get('i') ?? '0', 10) || 0));
  const passed = Math.max(0, Math.min(999, parseInt(searchParams.get('p') ?? '0', 10) || 0));
  const color = GRADE_COLOR[raw];
  // Checks that could not run. A shared card is a public claim, and "No issues
  // found" from a partial scan is a claim we did not earn — so the card says
  // outright that it is partial rather than quietly rounding up to clean.
  const skipped = Math.max(0, Math.min(99, parseInt(searchParams.get('s') ?? '0', 10) || 0));
  const issueText =
    issues === 0 ? (skipped > 0 ? 'No issues in what ran' : 'No issues found') : `${issues} issue${issues === 1 ? '' : 's'} found`;

  return new ImageResponse(
    (
      <Shell>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <div style={{ display: 'flex', width: 14, height: 232, background: color, marginRight: 48 }} />
            <div style={{ fontSize: 258, fontWeight: 800, color, lineHeight: 1, marginRight: 52 }}>{raw}</div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <div style={{ fontSize: 56, fontWeight: 600 }}>{issueText}</div>
              {/*
                A bare letter is not a credential — it says nothing about what
                was examined, so it is neither credible nor worth posting. The
                number of checks that actually passed is what turns the grade
                into evidence, and it is the same figure shown in the report.
              */}
              {/* One template literal, not `{passed} checks passed` — satori
                  counts that as two child nodes and rejects any div holding
                  more than one without an explicit display. */}
              {passed > 0 && <div style={{ fontSize: 34, marginTop: 12 }}>{`${passed} checks passed`}</div>}
              {skipped > 0 && (
                <div style={{ fontSize: 26, color: '#e0a33e', marginTop: 10 }}>
                  {`partial scan — ${skipped} check${skipped === 1 ? '' : 's'} could not run`}
                </div>
              )}
              <div style={{ fontSize: 26, color: MUTED, marginTop: 10 }}>on an AI-built app</div>
            </div>
          </div>
          {/* What the grade stands for. Static: it describes the TOOL, never the
              scanned app, so it discloses nothing about the target. */}
          <div style={{ display: 'flex', fontSize: 21, color: MUTED, marginTop: 26, lineHeight: 1.4 }}>
            database exposure · keys in the bundle · dev builds shipped live · source maps · hidden
            text aimed at AI · vulnerable libraries · headers
          </div>
        </div>
      </Shell>
    ),
    { width: 1200, height: 630, headers: { 'cache-control': OG_CACHE } },
  );
}
