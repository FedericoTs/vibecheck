import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'vibecheck demo — a deliberately leaky app',
  description: 'A harmless fixture page used to demonstrate and test what vibecheck catches.',
  robots: { index: false, follow: false },
};

/**
 * A deliberately-vulnerable fixture — the "what a failing report looks like"
 * demo, and the end-to-end test target for the scanners.
 *
 * Everything here is FAKE and inert: the keys are syntactically valid but
 * revoked/nonexistent placeholders, and there is no real backend behind them.
 * It exists so vibecheck can prove it catches what it claims to catch, on a
 * target we own, instead of pointing aggressive checks at someone else's app.
 */
export default function LeakyDemo() {
  // Assembled at runtime so this file doesn't trip secret scanners (ours or
  // GitHub's) while still being present in the served HTML for the scan to find.
  const fakeStripe = ['sk', 'live', '51H' + 'A'.repeat(24)].join('_');
  const fakeSupabaseSecret = ['sb', 'secret', 'D' + 'e'.repeat(30)].join('_');
  const fakeAws = 'AKIA' + 'IOSFODNN7EXAMPLE'.slice(0, 16);
  // Built here (not written literally) so the source file doesn't trip secret
  // scanners, while the RENDERED page still contains the complete strings.
  const fakeDbUrl = 'postgres' + 'ql://demo:hunter2@db.invalid:5432/app';
  // A realistic Firebase config block (the project does not exist), so the
  // discovery + client-side probe path is exercised end to end on a page we own
  // rather than against somebody else's misconfigured database.
  const fakeFirebase = `const firebaseConfig = {
  apiKey: "AIza${'S'.repeat(4)}vibecheckDemoNotARealKey00000",
  authDomain: "vibecheck-demo-fixture.firebaseapp.com",
  projectId: "vibecheck-demo-fixture",
  storageBucket: "vibecheck-demo-fixture.appspot.com"
};
initializeApp(firebaseConfig);
const q = collection(db, "users");
getDocs(collection(db, "orders"));`;

  const fakeConfig = `window.__APP_CONFIG__ = {
  STRIPE_SECRET_KEY: "${fakeStripe}",
  SUPABASE_SECRET: "${fakeSupabaseSecret}",
  AWS_ACCESS_KEY_ID: "${fakeAws}",
  DATABASE_URL: "${fakeDbUrl}"
};`;

  return (
    <main className="mx-auto w-full max-w-2xl px-5 py-16">
      <p className="kicker mb-4">vibecheck · demo fixture</p>
      <h1 className="font-display text-4xl font-semibold tracking-tight">
        A deliberately <span className="text-danger">leaky</span> app
      </h1>
      <p className="mt-5 leading-relaxed text-muted">
        This page exists to show what a failing report looks like — and to prove the scanners
        actually fire. It ships the mistakes AI code generators make constantly: secret keys in the
        frontend, an unauthenticated user API, an exposed <code className="font-mono text-ink">.env</code>,
        and no security headers.
      </p>
      <p className="mt-4 text-sm text-faint">
        Everything here is fake and inert — placeholder keys that point at nothing, on a page we own.
        Nothing real is exposed.
      </p>

      <div className="mt-8 border border-line bg-panel p-5">
        <p className="kicker mb-2">Scan it</p>
        <code className="block break-all border border-line bg-canvas px-3 py-2 font-mono text-xs text-safe">
          https://vibecheck-gules.vercel.app/demo/leaky
        </code>
        <p className="mt-3 text-sm text-muted">
          Paste that into vibecheck and watch every category light up red.
        </p>
        <a
          href="/"
          className="mt-4 inline-block border border-ink bg-ink px-5 py-2.5 font-mono text-xs font-medium uppercase tracking-wider text-canvas transition hover:bg-transparent hover:text-ink"
        >
          ← back to the scanner
        </a>
      </div>

      {/* The planted "leak" — inert placeholders for the secret scanner to find. */}
      <script dangerouslySetInnerHTML={{ __html: fakeConfig }} />
      {/* A Firebase config for a project that does not exist, so the Firebase
          discovery + probe path is exercised without touching anyone's data. */}
      <script dangerouslySetInnerHTML={{ __html: fakeFirebase }} />
    </main>
  );
}
