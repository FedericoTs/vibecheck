import type { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = {
  title: 'Terms & privacy',
  description: 'How vibecheck works, acceptable use, and privacy — in plain language.',
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-10">
      <h2 className="font-mono text-sm font-medium uppercase tracking-wider text-ink">{title}</h2>
      <div className="mt-3 space-y-3 text-sm leading-relaxed text-muted">{children}</div>
    </section>
  );
}

export default function LegalPage() {
  return (
    <main className="mx-auto w-full max-w-2xl px-5 py-16">
      <div className="mb-10 flex items-center justify-between kicker">
        <span>vibecheck ▸ terms &amp; privacy</span>
        <Link href="/" className="text-faint transition-colors hover:text-ink">
          vibecheck ↗
        </Link>
      </div>

      <h1 className="font-display text-4xl font-semibold tracking-tight">Terms &amp; privacy</h1>
      <p className="mt-4 text-sm text-faint">
        Plain language, because that&rsquo;s the whole point of the tool. Last updated 21 August 2026.
      </p>

      <Section title="How it works">
        <p>
          vibecheck is a <span className="text-ink">self-scan</span> tool: you point it at your own app and it shows
          you what a stranger can already see. It performs <span className="text-ink">no attacks</span> — no injection,
          no authentication bypass, no writes, and no attempt to reach anything private.
        </p>
        <ul className="space-y-2">
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              The URL checks read only <span className="text-ink">publicly-accessible content</span> — the same pages,
              headers, and files any visitor, browser, or search crawler can already fetch.
            </span>
          </li>
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              The database check runs entirely in <span className="text-ink">your own browser</span>, using the
              anon/public key your app already ships. It mirrors exactly what any anonymous visitor can read — a
              mirror, not an exploit. Your key and your data never reach our servers.
            </span>
          </li>
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              A public GitHub repo is read from its public source; a mobile app you upload is unzipped and scanned in
              your browser and never leaves your device.
            </span>
          </li>
        </ul>
      </Section>

      <Section title="Acceptable use">
        <p>
          Only scan applications you <span className="text-ink">own or are explicitly authorized to test</span>. You
          are responsible for your use of vibecheck and for having the right to scan any target you enter. Do not use
          it to probe, attack, or gain unauthorized access to systems you do not control. It exists for checking your
          own apps and for legitimate, authorized security testing.
        </p>
      </Section>

      <Section title="Privacy">
        <ul className="space-y-2">
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              We store <span className="text-ink">nothing about your scan</span> — not the URL you entered, not your
              keys, not the findings — <span className="text-ink">unless you press Save</span>.
            </span>
          </li>
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              If you do press Save, we store that one report: the site&rsquo;s hostname, the grade, the counts and the
              findings, at an <span className="text-ink">unlisted link</span> nothing on this site links to or indexes.
              We never store your keys. It is deleted automatically after 90 days, and anyone who has the link can read
              it — so send it to your team rather than posting it.
            </span>
          </li>
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              The database probes run client-side, so your keys and data never touch our servers.
            </span>
          </li>
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              We use privacy-friendly, <span className="text-ink">cookieless</span> analytics (Vercel Web Analytics). No
              cookies, no cross-site tracking, no personal data, no account.
            </span>
          </li>
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              When a scan finishes we count the <span className="text-ink">shape of the result</span>: the scan mode, the
              grade, how many checks passed and failed, which backend family the app uses (Supabase, Firebase,
              both, or none), and a yes/no for each kind of problem — was a database reachable, was any table
              readable by an anonymous key, were dev artifacts served, and so on.{' '}
              <span className="text-ink">
                We never record the URL, your keys, hostnames, table or column names, file paths, or row counts.
              </span>{' '}
              That is not a promise about our intentions: the rule is that every recorded value must be a yes/no, a
              number, or one of a few fixed words — which no hostname or table name can be — and it is enforced in code
              and covered by tests you can read in{' '}
              <a
                href="https://github.com/FedericoTs/vibecheck/blob/main/lib/scan/telemetry.ts"
                className="text-ink underline-offset-4 hover:underline"
              >
                lib/scan/telemetry.ts
              </a>
              .
            </span>
          </li>
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              Why we count it: so we can eventually publish aggregate findings — &ldquo;of N apps scanned, X% exposed at
              least one table to an anonymous key&rdquo;. Nobody can answer that today. It only works if the counting
              happens as scans run, because we keep nothing to go back and mine. Counts only, never an app.
            </span>
          </li>
          <li className="flex gap-2">
            <span className="text-faint">·</span>
            <span>
              No signup. The only personal data we ever store is your email, and only if you volunteer it to join the
              optional monitoring waitlist — used solely to email you about that feature.
            </span>
          </li>
        </ul>
      </Section>

      <Section title="No warranty, not advice">
        <p>
          vibecheck is provided <span className="text-ink">&ldquo;as is&rdquo;</span>, without warranty of any kind.
          Its findings are observations from the outside — not a penetration test, and not security, legal, or
          compliance advice. A clean result does not guarantee your app is secure. Use your own judgment and, where it
          matters, a professional review.
        </p>
      </Section>

      <Section title="Open source">
        <p>
          vibecheck is free and open source (MIT) — you can read exactly what it does and self-host it:{' '}
          <a href="https://github.com/FedericoTs/vibecheck" className="text-ink underline-offset-4 hover:underline">
            github.com/FedericoTs/vibecheck
          </a>
          .
        </p>
      </Section>

      <Section title="Contact">
        <p>
          Built by Federico Sciuca. Questions:{' '}
          <a href="mailto:federicosciuca@droplab.io" className="text-ink underline-offset-4 hover:underline">
            federicosciuca@droplab.io
          </a>
          .
        </p>
      </Section>

      <div className="mt-14 border-t border-line pt-6">
        <Link
          href="/"
          className="inline-block border border-ink bg-ink px-5 py-2.5 font-mono text-xs font-medium uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink"
        >
          ← back to the scanner
        </Link>
      </div>
    </main>
  );
}
