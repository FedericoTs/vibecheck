import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { safeFetch } from '@/lib/scan/fetch';
import { scriptUrls, fetchScript as fetchText, MAX_BYTES } from '@/lib/scan/bundle';
import { findSecrets, gradeSecrets, countPublicGoogleKeys, type SecretFinding } from '@/lib/scan/secrets';
import { scanSourceMaps } from '@/lib/scan/sourcemap';
import { discoverSupabase } from '@/lib/scan/discover';
import { extractDatabases } from '@/lib/scan/firebase';
import { discoverFirebase, extractCollections } from '@/lib/scan/firebase';
import { scanLibraries } from '@/lib/scan/libs';

export const runtime = 'nodejs';

export async function POST(request: Request): Promise<Response> {
  const limited = rateLimitResponse(request.headers);
  if (limited) return limited;

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
  const rawUrl = typeof (body as { url?: unknown })?.url === 'string' ? (body as { url: string }).url : '';

  let target: URL;
  try {
    target = await assertPublicUrl(rawUrl);
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 400 });
  }

  let html = '';
  let finalUrl = target;
  try {
    const { response, url } = await safeFetch(target);
    finalUrl = url;
    html = (await response.text()).slice(0, MAX_BYTES);
  } catch {
    return NextResponse.json({ error: 'Could not reach that URL' }, { status: 502 });
  }

  // Scan the HTML (inline scripts + window.__ENV blobs live here) and the bundles.
  const all: SecretFinding[] = [...findSecrets(html)];
  const scripts = scriptUrls(html, finalUrl);
  const bundles = await Promise.all(scripts.map(fetchText));
  for (const b of bundles) all.push(...findSecrets(b));

  // Locate the backend the app already exposes publicly, so the browser can run
  // the database check without the user pasting anything. We only find it here —
  // the probes themselves still run client-side.
  let allCode = [html, ...bundles].join('\n');
  let discovered = discoverSupabase(allCode);
  let firebase = discoverFirebase(allCode);

  // Many apps have a static marketing homepage and load their backend client
  // only on the app routes, so the landing page alone yields nothing. Fall back
  // to the usual entry points before giving up.
  if (!discovered && !firebase) {
    for (const entry of ['/login', '/dashboard', '/app', '/signin']) {
      try {
        const entryHtml = await fetchText(new URL(entry, finalUrl).toString());
        if (!entryHtml) continue;
        const entryScripts = scriptUrls(entryHtml, finalUrl).filter((s) => !scripts.includes(s));
        const entryBundles = await Promise.all(entryScripts.slice(0, 12).map(fetchText));
        const entryCode = [entryHtml, ...entryBundles].join('\n');
        discovered = discoverSupabase(entryCode);
        firebase = discoverFirebase(entryCode);
        if (discovered || firebase) {
          allCode += '\n' + entryCode;
          break;
        }
      } catch {
        /* entry route unavailable — try the next */
      }
    }
  }
  const firebaseCollections = firebase ? extractCollections(allCode) : [];
  // Rules deploy per database, so a named one must be probed too.
  const firebaseDatabases = firebase ? extractDatabases(allCode) : [];

  // Are the source maps published? A .js.map republishes the original source —
  // comments, unminified logic, and secrets that minification hid. We both flag
  // the exposure AND scan the restored source, because a key invisible in the
  // shipped bundle can be readable in the map.
  //
  // The map URL comes from each chunk's own sourceMappingURL annotation,
  // resolved against that chunk. Appending '.map' to the chunk URL (what this
  // used to do) finds nothing on any modern bundler, because the map is not
  // named after the chunk.
  const mapScan = await scanSourceMaps(
    scripts.map((url, i) => ({ url, code: bundles[i] ?? '' })).filter((c) => c.code).slice(0, 6),
    fetchText,
    // A secret found ONLY in the source map — tag it so the finding is honest
    // about where it came from.
    (source) => {
      all.push(...findSecrets(source).map((f) => ({ ...f, label: `${f.label} (in an exposed source map)` })));
    },
  );
  const exposedMaps = mapScan.exposed.map((e) => e.chunk);

  // Dedupe across HTML + every bundle.
  const seen = new Set<string>();
  const findings = all.filter((f) => {
    const k = f.id + ':' + f.redacted;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return NextResponse.json({
    ...gradeSecrets(findings, finalUrl.host),
    sourceMaps: {
      exposed: exposedMaps,
      mapUrls: mapScan.exposed.map((e) => e.mapUrl).filter((u) => u && u !== 'inline'),
      checked: mapScan.checked > 0,
      annotated: mapScan.annotated,
      unresolved: mapScan.unresolved,
      firstPartyFiles: mapScan.exposed.reduce((n, e) => n + e.firstPartyFiles, 0),
      sample: mapScan.exposed.flatMap((e) => e.sampleSources).slice(0, 3),
    },
    publicGoogleKeys: countPublicGoogleKeys(allCode),
    libraries: scanLibraries(allCode, finalUrl.host),
    discovered,
    firebase,
    firebaseCollections,
    firebaseDatabases,
  });
}
