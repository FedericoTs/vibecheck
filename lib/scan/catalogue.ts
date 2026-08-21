import { SENSITIVE_PATHS } from './paths';
import { ROUTE_PROBES } from './routes';
import { AI_PROBES } from './ai-surface';
import { SECRET_RULES } from './secrets';
import { CRAWLERS } from './visibility';

/**
 * How many distinct things the scanner knows how to look for.
 *
 * WHY THIS IS NOT THE SAME AS THE NUMBER IN A REPORT
 * --------------------------------------------------
 * A report shows the checks that APPLIED to one app: no Firebase project means
 * no Firebase checks, an unreachable database means no table probes, and so on.
 * That is the honest per-app number and it stays the headline. But quoting it
 * alone understates the tool by roughly half — a scan of a plain marketing site
 * legitimately runs ~60 of these — and every comparable tool advertises the size
 * of its catalogue instead. Showing both is the accurate answer to "how thorough
 * is this?", and it costs nothing in precision.
 *
 * DERIVED, NEVER HAND-COUNTED
 * ---------------------------
 * Everything countable is counted from the actual probe arrays, so adding a
 * secret pattern or a path probe moves this number automatically. The remaining
 * groups are checks constructed inline by their graders rather than declared in
 * a list; those are recorded here as literals and pinned by catalogue.test.ts,
 * which fails if a grader's real output drifts from the number claimed. A
 * marketing figure that quietly rots is worse than no figure.
 */

/** Checks whose graders build them inline, so they cannot be counted from an array. */
const INLINE_CHECKS = {
  /** gradeHeaders: CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, X-Powered-By, csp-effective, CORS, cookie flags. */
  headers: 9,
  /** gradeTransport: https, redirect, HSTS age, preload, mixed content, cert chain, subdomain takeover. */
  transport: 7,
  /** gradeFundamentals: title, description, favicon, viewport, lang, 404, compression, caching. */
  fundamentals: 8,
  /** gradeVisibility: no-JS content, JSON-LD, canonical, sitemap, readability, headings, alt text, AI policy, llms.txt. */
  visibility: 9,
  /** gradePrivacy: consent gate, trackers before consent, cookie banner, policy link, EU host, data-transfer signals. */
  privacy: 6,
  /** gradeEmailAuth: SPF, DMARC, DMARC enforcement, platform-domain exemption. */
  email: 4,
  /** Supabase: table read, storage buckets, public RPC, auth config. */
  supabase: 4,
  /** Firebase: RTDB open, Firestore collections, named databases. */
  firebase: 3,
  /** One-off analyses that each produce a check: smuggling, dev server, scaffold, source maps. */
  standalone: 4,
} as const;

/** Per-area counts. Arrays are measured; inline groups are pinned by a test. */
export const CATALOGUE = {
  secretPatterns: SECRET_RULES.length,
  sensitivePaths: SENSITIVE_PATHS.length,
  routeProbes: ROUTE_PROBES.length,
  aiEndpointProbes: AI_PROBES.length,
  crawlersProfiled: CRAWLERS.length,
  ...INLINE_CHECKS,
} as const;

/** Total distinct checks in the catalogue. */
export const CATALOGUE_TOTAL: number = Object.values(CATALOGUE).reduce((sum, n) => sum + n, 0);

/**
 * A deliberately conservative figure for public copy.
 *
 * Rounded DOWN to the nearest ten, so the claim is always true even if a rule is
 * removed between a deploy and someone reading the page. Overstating coverage in
 * a security tool is the same sin as overstating a finding.
 */
export const CATALOGUE_CLAIM: number = Math.floor(CATALOGUE_TOTAL / 10) * 10;
