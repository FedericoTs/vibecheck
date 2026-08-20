import { ImageResponse } from 'next/og';

export const runtime = 'nodejs';

const GRADE_COLOR: Record<string, string> = { A: '#48c98b', B: '#48c98b', C: '#e6b25e', D: '#f2565b', F: '#f2565b' };
const CANVAS = '#0b0b0d';
const INK = '#ededf0';
const MUTED = '#8b8b95';
const LINE = '#212127';
const DANGER = '#f2565b';

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
      { width: 1200, height: 630 },
    );
  }

  const issues = Math.max(0, Math.min(999, parseInt(searchParams.get('i') ?? '0', 10) || 0));
  const color = GRADE_COLOR[raw];
  const issueText = issues === 0 ? 'No issues found' : `${issues} issue${issues === 1 ? '' : 's'} found`;

  return new ImageResponse(
    (
      <Shell>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <div style={{ display: 'flex', width: 14, height: 300, background: color, marginRight: 56 }} />
          <div style={{ fontSize: 340, fontWeight: 800, color, lineHeight: 1, marginRight: 60 }}>{raw}</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: 60, fontWeight: 600 }}>{issueText}</div>
            <div style={{ fontSize: 30, color: MUTED, marginTop: 10 }}>on an AI-built app</div>
          </div>
        </div>
      </Shell>
    ),
    { width: 1200, height: 630 },
  );
}
