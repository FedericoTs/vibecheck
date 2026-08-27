import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { loadReport, RETENTION_DAYS } from '@/lib/report-store';
import { SavedReportView } from '@/components/saved-report';

type Params = Promise<{ slug: string }>;

/**
 * A saved report is UNLISTED, not public.
 *
 * noindex keeps it out of search, and nothing on the site enumerates saved
 * reports. But secrecy-by-URL is shallow: a link pasted anywhere is a link
 * anyone can follow. That is why the social buttons on this page share the
 * stats-only card instead of this page, and why saving requires someone to
 * confirm they are allowed to test the site in the first place.
 */
export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { slug } = await params;
  const saved = await loadReport(slug);
  return {
    title: saved ? `${saved.host} — saved vibecheck report` : 'Report not found',
    // No description, no OG image: an unfurl in a group chat should not leak the
    // grade of a site whose owner shared the link with one person.
    robots: { index: false, follow: false },
  };
}

export default async function SavedReportPage({ params }: { params: Params }) {
  const { slug } = await params;
  const saved = await loadReport(slug);
  if (!saved) notFound();

  return (
    <main className="mx-auto w-full max-w-7xl px-5 py-10 sm:py-16">
      <div className="mb-10 flex items-center justify-between kicker">
        <Link href="/" className="-my-2 py-2 text-muted transition-colors hover:text-ink">
          ← vibecheck ▸ scan another
        </Link>
        <span className="text-faint">saved report · unlisted</span>
      </div>

      <SavedReportView saved={saved} retentionDays={RETENTION_DAYS} />
    </main>
  );
}
