import type { Metadata } from 'next';
import Link from 'next/link';

type SP = Promise<{ g?: string; i?: string }>;

function parse(sp: { g?: string; i?: string }) {
  const g = (sp.g ?? 'F').toUpperCase();
  const grade = ['A', 'B', 'C', 'D', 'F'].includes(g) ? g : 'F';
  const issues = Math.max(0, Math.min(999, parseInt(sp.i ?? '0', 10) || 0));
  return { grade, issues };
}

function tone(grade: string): string {
  if (grade === 'A' || grade === 'B') return 'text-safe border-safe/40';
  if (grade === 'C') return 'text-warn border-warn/40';
  return 'text-danger border-danger/50';
}

export async function generateMetadata({ searchParams }: { searchParams: SP }): Promise<Metadata> {
  const { grade, issues } = parse(await searchParams);
  const title = `This app scored ${grade} on vibecheck`;
  const description =
    issues > 0
      ? `${issues} security issue${issues === 1 ? '' : 's'} found on an AI-built app. Check yours — it's free.`
      : "Check yours — it's free.";
  const og = `/api/og?g=${grade}&i=${issues}`;
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
  const { grade, issues } = parse(await searchParams);
  const issueText =
    issues === 0 ? 'No issues found' : `${issues} issue${issues === 1 ? '' : 's'} found`;

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
