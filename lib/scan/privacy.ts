import type { Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * EU privacy signals — the lane no competing vibe scanner touches.
 *
 * Every rival is US-centric and security-only, but a large share of AI-built
 * apps ship to EU users, and the ePrivacy/GDPR failures they ship are
 * mechanical and observable from a single page load: analytics cookies dropped
 * before anyone clicks anything, trackers firing pre-consent, Google Fonts
 * pulled from Google's servers (which hands the visitor's IP to a US company —
 * the Munich court awarded damages for exactly that in 2022).
 *
 * IMPORTANT FRAMING: this reports OBSERVATIONS, never legal conclusions. We say
 * "an analytics cookie was set before any consent was given", never "you are
 * GDPR non-compliant" — compliance depends on your legal basis, your users, and
 * facts a scanner cannot see. Overclaiming here would be both wrong and the
 * fastest way to lose the trust the whole tool trades on.
 */

export interface PrivacyCheck {
  key: string;
  label: string;
  pass: boolean;
  severity: 'high' | 'medium' | 'low';
  detail?: string;
}

export interface PrivacyResult {
  host: string;
  checks: PrivacyCheck[];
  failed: PrivacyCheck[];
  grade: Grade;
  score: number;
  summary: string;
}

/** Third-party trackers that set cookies / profile visitors. */
const TRACKERS: Array<[RegExp, string]> = [
  [/google-analytics\.com|googletagmanager\.com|\bgtag\s*\(/i, 'Google Analytics'],
  [/connect\.facebook\.net|facebook\.com\/tr/i, 'Meta Pixel'],
  [/static\.hotjar\.com|hotjar\.com\/c\//i, 'Hotjar'],
  [/cdn\.mxpnl\.com|mixpanel/i, 'Mixpanel'],
  [/cdn\.segment\.com|segment\.io/i, 'Segment'],
  [/amplitude\.com\/libs|cdn\.amplitude/i, 'Amplitude'],
  [/clarity\.ms/i, 'Microsoft Clarity'],
  [/analytics\.tiktok\.com/i, 'TikTok Pixel'],
  [/snap\.licdn\.com|ads\.linkedin\.com/i, 'LinkedIn Insight'],
  [/static\.ads-twitter\.com|analytics\.twitter\.com/i, 'X/Twitter Pixel'],
  [/widget\.intercom\.io|intercomcdn/i, 'Intercom'],
  [/doubleclick\.net|googlesyndication/i, 'Google Ads'],
];

/**
 * Cookieless, EU-friendly analytics. Explicitly NOT flagged — treating these
 * the same as a Meta Pixel would punish exactly the right choice.
 */
const PRIVACY_FRIENDLY = /plausible\.io|usefathom\.com|umami|cabin\.tech|simpleanalytics|vercel\.com\/analytics|va\.vercel-scripts/i;

/** Cookie names that are unambiguously analytics/advertising, not "strictly necessary". */
const TRACKING_COOKIES = /^(_ga|_gid|_gat|_fbp|_fbc|_hj[A-Za-z]*|_gcl_au|__utm[a-z]|_pk_|mp_[a-f0-9]+|ajs_|amplitude_|_clck|_clsk|IDE|test_cookie)/i;

/** Consent-manager fingerprints (CMPs + hand-rolled banners). */
const CONSENT_SIGNALS = /cookiebot|onetrust|cookieyes|termly|iubenda|klaro|osano|usercentrics|cookie-?consent|cookieconsent|didomi|quantcast|consentmanager|(we use|this (site|website) uses) cookies|accept (all )?cookies|manage (cookie )?preferences/i;

const PRIVACY_LINK = /href=["'][^"']*(privacy|datenschutz|privacidad|confidentialit|informativa)[^"']*["']|>\s*(privacy(\s+policy)?|datenschutz|cookie policy)\s*</i;

/** Parse cookie names out of one or more Set-Cookie header values. */
export function cookieNames(setCookie: string | undefined): string[] {
  if (!setCookie) return [];
  // Header values may be joined by newlines (undici) or comma-separated.
  return setCookie
    .split(/\n|,(?=\s*[A-Za-z0-9_\-.]+=)/)
    .map((c) => c.trim().split('=')[0].trim())
    .filter(Boolean);
}

export function findTrackers(html: string): string[] {
  const out = new Set<string>();
  for (const [re, name] of TRACKERS) if (re.test(html)) out.add(name);
  return [...out];
}

export function usesPrivacyFriendlyAnalytics(html: string): boolean {
  return PRIVACY_FRIENDLY.test(html);
}

/** Google-hosted fonts hand the visitor's IP to Google before any consent. */
export function usesGoogleHostedFonts(html: string): boolean {
  return /fonts\.googleapis\.com|fonts\.gstatic\.com/i.test(html);
}

export function hasConsentBanner(html: string): boolean {
  return CONSENT_SIGNALS.test(html);
}

export function hasPrivacyLink(html: string): boolean {
  return PRIVACY_LINK.test(html);
}

const PENALTY = { high: 30, medium: 15, low: 7 } as const;

export function analyzePrivacy(html: string, setCookie: string | undefined, host = ''): PrivacyResult {
  const cookies = cookieNames(setCookie);
  const trackingCookies = cookies.filter((c) => TRACKING_COOKIES.test(c));
  const trackers = findTrackers(html);
  const banner = hasConsentBanner(html);
  const friendly = usesPrivacyFriendlyAnalytics(html);

  const checks: PrivacyCheck[] = [
    {
      key: 'tracking-cookies-preconsent',
      label: 'No tracking cookies before consent',
      pass: trackingCookies.length === 0,
      severity: 'high',
      detail:
        trackingCookies.length > 0
          ? `set on first load, before any click: ${trackingCookies.slice(0, 4).join(', ')}`
          : cookies.length > 0
            ? `${cookies.length} cookie(s) set, none of them analytics/advertising`
            : 'no cookies set on first load',
    },
    {
      key: 'trackers-preconsent',
      label: 'No third-party trackers before consent',
      pass: trackers.length === 0,
      severity: 'high',
      detail:
        trackers.length > 0
          ? `loads on first visit, before any choice: ${trackers.join(', ')}`
          : friendly
            ? 'only cookieless, EU-friendly analytics detected'
            : 'none detected',
    },
    {
      key: 'consent-banner',
      label: 'Consent banner present when it needs one',
      // Only expected when something actually tracks. No trackers = nothing to consent to.
      pass: trackers.length === 0 && trackingCookies.length === 0 ? true : banner,
      severity: 'medium',
      detail:
        trackers.length === 0 && trackingCookies.length === 0
          ? 'nothing tracking, so no banner needed'
          : banner
            ? 'a consent mechanism was detected'
            : 'trackers load but no consent mechanism was found',
    },
    {
      key: 'google-fonts',
      label: 'Fonts self-hosted (not fetched from Google)',
      pass: !usesGoogleHostedFonts(html),
      severity: 'medium',
      detail: usesGoogleHostedFonts(html)
        ? "loading fonts from Google sends every visitor's IP to Google before any consent — a German court awarded damages over exactly this"
        : 'no Google-hosted fonts detected',
    },
    {
      key: 'privacy-policy',
      label: 'Privacy policy linked',
      pass: hasPrivacyLink(html),
      severity: 'medium',
      detail: hasPrivacyLink(html) ? 'a privacy policy link was found' : 'no privacy policy link found on this page',
    },
  ];

  const failed = checks.filter((c) => !c.pass);
  const score = Math.max(0, 100 - failed.reduce((n, c) => n + PENALTY[c.severity], 0));
  return {
    host,
    checks,
    failed,
    grade: scoreToGrade(score),
    score,
    summary:
      failed.length === 0
        ? 'No EU privacy problems visible on this page ✅'
        : `${failed.length} EU privacy signal(s) worth a look ⚠️`,
  };
}
