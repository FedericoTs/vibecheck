'use client';

import { useState } from 'react';
import { scanSupabase } from '@/lib/scan/supabase';
import type { SupabaseScanResult, Grade } from '@/lib/scan/types';

const GRADE_COLOR: Record<Grade, string> = {
  A: 'text-emerald-400 border-emerald-400/40 bg-emerald-400/10',
  B: 'text-green-400 border-green-400/40 bg-green-400/10',
  C: 'text-amber-400 border-amber-400/40 bg-amber-400/10',
  D: 'text-orange-400 border-orange-400/40 bg-orange-400/10',
  F: 'text-red-400 border-red-400/50 bg-red-400/10',
};

export default function Home() {
  const [url, setUrl] = useState('');
  const [anonKey, setAnonKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SupabaseScanResult | null>(null);

  async function onScan(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    try {
      setResult(await scanSupabase({ url, anonKey }));
    } finally {
      setLoading(false);
    }
  }

  const exposed = result?.findings.filter((f) => f.exposed) ?? [];

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-100 flex flex-col items-center px-4 py-16">
      <div className="w-full max-w-xl">
        <header className="text-center mb-10">
          <h1 className="text-4xl sm:text-5xl font-semibold tracking-tight">
            Is your app <span className="text-red-400">leaking?</span>
          </h1>
          <p className="mt-4 text-neutral-400 leading-relaxed">
            AI-built apps ship the same bug over and over: database tables anyone can read.
            Paste your Supabase project and see exactly what a stranger can pull — in seconds.
          </p>
        </header>

        <form onSubmit={onScan} className="space-y-3 rounded-2xl border border-neutral-800 bg-neutral-900/60 p-5">
          <label className="block text-sm text-neutral-400">
            Supabase project URL
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://xxxx.supabase.co"
              className="mt-1 w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 text-neutral-100 placeholder-neutral-600 outline-none focus:border-neutral-500"
            />
          </label>
          <label className="block text-sm text-neutral-400">
            Anon (public) key
            <input
              value={anonKey}
              onChange={(e) => setAnonKey(e.target.value)}
              placeholder="eyJhbGciOi… — the public key from your app"
              className="mt-1 w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-xs text-neutral-100 placeholder-neutral-600 outline-none focus:border-neutral-500"
            />
          </label>
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-red-500 py-2.5 font-medium text-white transition hover:bg-red-400 disabled:opacity-50"
          >
            {loading ? 'Scanning…' : 'Scan my app'}
          </button>
          <p className="pt-1 text-center text-xs text-neutral-500">
            🔒 Runs 100% in your browser. Your key and data never touch our servers.
          </p>
        </form>

        {result && (
          <section className="mt-8 rounded-2xl border border-neutral-800 bg-neutral-900/60 p-6">
            {result.ok ? (
              <>
                <div className="flex items-center gap-4">
                  <div className={`flex h-16 w-16 items-center justify-center rounded-xl border text-3xl font-bold ${GRADE_COLOR[result.grade]}`}>
                    {result.grade}
                  </div>
                  <div>
                    <div className="font-medium">{result.host}</div>
                    <div className="text-sm text-neutral-400">{result.summary}</div>
                  </div>
                </div>

                {exposed.length > 0 && (
                  <div className="mt-6">
                    <div className="mb-2 text-sm font-medium text-red-400">Readable by anyone</div>
                    <ul className="divide-y divide-neutral-800 rounded-lg border border-neutral-800">
                      {exposed.map((f) => (
                        <li key={f.table} className="flex items-center justify-between px-3 py-2 text-sm">
                          <span className="font-mono">{f.table}</span>
                          <span className="text-neutral-500">
                            {f.rowsVisible != null ? `${f.rowsVisible.toLocaleString()} rows` : 'readable'}
                          </span>
                        </li>
                      ))}
                    </ul>
                    <div className="mt-5 rounded-lg border border-neutral-800 bg-neutral-950 p-4 text-sm text-neutral-300">
                      <div className="font-medium text-neutral-100">Stop this shipping again</div>
                      <p className="mt-1 text-neutral-400">
                        Add a guard test to your CI so a cross-tenant leak fails the build:
                      </p>
                      <code className="mt-2 block rounded bg-neutral-900 px-3 py-2 font-mono text-xs text-emerald-300">
                        npx tenant-guard prove
                      </code>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="text-sm text-neutral-300">{result.error}</div>
            )}
          </section>
        )}

        <footer className="mt-12 text-center text-xs text-neutral-600">
          Free &amp; open source · no signup · no telemetry
        </footer>
      </div>
    </main>
  );
}
