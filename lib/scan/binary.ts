import { findSecrets, type SecretFinding } from './secrets';
import { discoverSupabase } from './discover';
import { discoverFirebase, type FirebaseConfig } from './firebase';

/**
 * Mobile-app binary analysis (.apk / .ipa).
 *
 * We don't decompile — we don't need to. AI generators produce React
 * Native / Expo / Flutter apps, and those ship their JS bundle and their
 * Firebase config (google-services.json / GoogleService-Info.plist) as readable
 * files INSIDE the archive, which is just a ZIP. So the same detectors that read
 * a web bundle read a mobile one: a committed Supabase/Firebase config and a
 * hard-coded secret look identical whether they came from a browser bundle or an
 * .apk. Everything native and compiled is skipped.
 *
 * The config we recover can then be probed CLIENT-SIDE, exactly like the web and
 * backend scans, so the trust model is unchanged.
 */

/** Entries worth decoding: JS bundles, config files, plists, env — not native code. */
const SCANNABLE_ENTRY =
  /(index\.(android|ios)\.bundle$|main\.jsbundle$|\.jsbundle$|\.js$|google-services\.json$|GoogleService-Info\.plist$|\.plist$|\.env(\.[\w-]+)?$|firebase[\w.-]*\.json$|app\.config\.js$)/i;
/** Directories that are never text config (resources, native libs, signatures). */
const IGNORE_ENTRY = /(^|\/)(META-INF|lib|res\/(drawable|mipmap|raw)|assets\/fonts|Frameworks)\//i;

const MAX_ENTRY_BYTES = 8_000_000;
const MAX_TOTAL_BYTES = 12_000_000;

/** Decode the text from the entries worth scanning, bounded so a huge apk can't OOM us. */
export function extractScannableText(files: Record<string, Uint8Array>): { text: string; scanned: number } {
  const dec = new TextDecoder('utf-8', { fatal: false });
  const parts: string[] = [];
  let total = 0;
  let scanned = 0;
  for (const [name, bytes] of Object.entries(files)) {
    if (!SCANNABLE_ENTRY.test(name) || IGNORE_ENTRY.test('/' + name)) continue;
    if (!bytes || bytes.length === 0 || bytes.length > MAX_ENTRY_BYTES) continue;
    parts.push(dec.decode(bytes));
    scanned += 1;
    total += bytes.length;
    if (total > MAX_TOTAL_BYTES) break;
  }
  return { text: parts.join('\n'), scanned };
}

export interface BinaryScanResult {
  ok: boolean;
  filesScanned: number;
  secrets: SecretFinding[];
  /** Supabase project the binary embeds, for a follow-up client-side probe. */
  discovered: { url: string; anonKey: string } | null;
  firebase: FirebaseConfig | null;
  error?: string;
}

/** Run the existing detectors over the extracted text. Pure — the unzip is in the route. */
export function analyzeBinaryText(text: string): Pick<BinaryScanResult, 'secrets' | 'discovered' | 'firebase'> {
  // Dedupe secrets across the concatenated bundle.
  const seen = new Set<string>();
  const secrets = findSecrets(text).filter((f) => {
    const k = f.id + ':' + f.redacted;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return {
    secrets,
    discovered: discoverSupabase(text),
    firebase: discoverFirebase(text),
  };
}
