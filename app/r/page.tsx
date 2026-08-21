import type { Metadata } from 'next';
import Link from 'next/link';

type SP = Promise<{ g?: string; i?: string; p?: string; s?: string }>;

function parse(sp: { g?: string; i?: string; p?: string; s?: string }) {
  const g = (sp.g ?? 'F').toUpperCase();
  const grade = ['A', 'B', 'C', 'D', 'F'].includes(g) ? g : 'F';
  const issues = Math.max(0, Math.min(999, parseInt(sp.i ?? '0', 10) || 0));
  // How many checks passed. It is what makes a grade mean something, so it
  // travels with the link and is shown on both the card and this page.
  const passed = Math.max(0, Math.min(999, parseInt(sp.p ?? '0', 10) || 0));
  // Checks that could not run. A shared page is a public claim, so zero issues
  // on a partial scan must not unfurl as "no public exposure found".
  const skipped = Math.max(0, Math.min(99, parseInt(sp.s ?? '0', 10) || 0));
  return { grade, issues, passed, skipped };
}

function tone(grade: string): string {
  if (grade === 'A' || grade === 'B') return 'text-safe border-safe/40';
  if (grade === 'C') return 'text-warn border-warn/40';
  return 'text-danger border-danger/50';
}

export async function generateMetadata({ searchParams }: { searchParams: SP }): Promise<Metadata> {
  const { grade, issues, passed, skipped } = parse(await searchParams);
  const title = `This app scored ${grade} on vibecheck`;
  const description =
    issues > 0
      ? `${issues} security issue${issues === 1 ? '' : 's'} found on an AI-built app. Check yours — it's free.`
      : skipped > 0
        ? `${passed} checks passed, ${skipped} could not run — a partial scan. Check yours — it's free.`
        : passed > 0
          ? `${passed} checks passed — no public exposure found. Check yours — it's free.`
          : "Check yours — it's free.";
  const og = `/api/og?g=${grade}&i=${issues}&p=${passed}&s=${skipped}`;
  return {
    title,
    description,
    // Thin, near-duplicate per-query share pages — keep them out of the index,
    // but crawlable (default follow) so social unfurlers still fetch the OG card.
    robots: { index: false },
    openGraph: { title, description, images: [{ url: og, width: 1200, height: 630 }], type: 'website' },
    twitter: { card: 'summary_large_image', title, description, images: [og] },
  };
}

export default async function ResultPage({ searchParams }: { searchParams: SP }) {
  const { grade, issues, passed, skipped } = parse(await searchParams);
  const issueText =
    issues > 0
      ? `${issues} issue${issues === 1 ? '' : 's'} found`
      : skipped > 0
        ? 'No issues in what ran'
        : 'No issues found';

  return (
    <main className="mx-auto w-full max-w-2xl px-5 py-10 sm:py-16">
      <div className="mb-14 flex items-center justify-between kicker">
        <span>vibecheck ▸ shared result</span>
        <Link href="/" className="text-faint hover:text-ink transition-colors">
          vibecheck ↗
        </Link>
      </div>

      <p className="kicker mb-6">Someone ran a security scan on an AI-built app</p>

      <div className="flex items-stretch border border-line bg-panel">
        <div className={`flex w-28 shrink-0 items-center justify-center border-r text-7xl font-semibold font-mono ${tone(grade)}`}>
          {grade}
        </div>
        <div className="flex flex-col justify-center p-5">
          <p className="kicker mb-1">Their score</p>
          <p className="font-display text-lg leading-snug">{issueText}</p>
          {/* `passed` counts every check; `issues` counts failing SECURITY
              checks only — so they do not sum to a total and must not be
              presented as if they did. */}
          {passed > 0 && <p className="mt-1 font-mono text-xs text-faint">{passed} checks passed</p>}
        </div>
      </div>

      <div className="mt-10">
        <h1 className="font-display text-4xl sm:text-5xl font-semibold tracking-tight leading-[1.05]">
          Is <span className="text-danger">your</span> app leaking?
        </h1>
        <p className="mt-4 max-w-md text-muted leading-relaxed">
          Find out in seconds — see exactly what a stranger can read from your app. Runs in your
          browser, no signup — your scan is never stored.
        </p>
        {/* What the grade actually stands for. A letter with nothing behind it
            is not persuasive; the specifics are. */}
        <ul className="mt-6 grid gap-x-6 gap-y-1.5 font-mono text-xs text-muted sm:grid-cols-2">
          <li>· database tables anyone can read</li>
          <li>· API keys shipped in the bundle</li>
          <li>· a development build served live</li>
          <li>· source maps that rebuild your code</li>
          <li>· hidden text aimed at AI readers</li>
          <li>· libraries with known CVEs</li>
        </ul>
        <Link
          href="/"
          className="mt-6 inline-block border border-ink bg-ink px-6 py-3 font-mono text-xs font-medium uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink"
        >
          scan your app →
        </Link>
      </div>

      <footer className="mt-16 border-t border-line pt-5 kicker text-faint">
        free · open source · no signup · no cookies · MIT
      </footer>
    </main>
  );
}
