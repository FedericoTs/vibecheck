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

/** The privacy word in the languages we recognise, for both link forms below. */
const PRIVACY_WORD = 'privacy|datenschutz|privacidad|confidentialit|informativa';

/**
 * A privacy policy is linked if EITHER the href points at a privacy-ish path,
 * OR an anchor's own text mentions privacy.
 *
 * The anchor-text form must tolerate the very common combined page — a single
 * `<a href="/legal">terms &amp; privacy</a>` — so it matches the word ANYWHERE
 * in the link text rather than requiring the text to be exactly "privacy".
 * Requiring an exact match reported "no privacy policy link found" on sites that
 * plainly had one (this tool's own footer among them), which is cry-wolf on a
 * GDPR check. Matching is still scoped INSIDE an anchor, so ordinary body copy
 * like "we respect your privacy" does not count. One level of nested markup
 * (`<a><span>Privacy</span></a>`) is allowed, and the text run is length-bounded
 * to keep the regex linear.
 */
const PRIVACY_LINK = new RegExp(
  `href=["'][^"']*(?:${PRIVACY_WORD})[^"']*["']` +
    `|<a\\b[^>]*>(?:\\s*<[^>]{0,200}>)?[^<]{0,200}\\b(?:${PRIVACY_WORD})`,
  'i',
);

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

/**
 * Known AI / chat-assistant widgets. Matching specific vendor scripts keeps this
 * precise — a page that merely says "chat" is not enough.
 */
const CHATBOT_WIDGETS: Array<[RegExp, string]> = [
  [/widget\.intercom\.io|intercomcdn/i, 'Intercom'],
  [/js\.driftt?\.com/i, 'Drift'],
  [/client\.crisp\.chat/i, 'Crisp'],
  [/code\.tidio\.co/i, 'Tidio'],
  [/static\.zdassets\.com|zopim/i, 'Zendesk'],
  [/embed\.tawk\.to/i, 'Tawk.to'],
  [/chatbase\.co/i, 'Chatbase'],
  [/cdn\.voiceflow\.com/i, 'Voiceflow'],
  [/landbot\.io|landbot\.online/i, 'Landbot'],
  [/botpress\.cloud/i, 'Botpress'],
  [/js\.usemessages\.com|hs-scripts/i, 'HubSpot'],
  [/widget\.manychat/i, 'ManyChat'],
  [/webchat\.botframework/i, 'Azure Bot'],
];

/** A custom in-app AI chat (the vibe-coded case) — copy that says it is AI. */
const AI_CHAT_HINT = /(ai assistant|ai chat(bot)?|chat with (our )?ai|ask (our )?ai|ai[- ]powered chat|talk to (our )?ai)/i;

/** Wording that would satisfy Art. 50 — telling the user they are dealing with AI. */
const AI_DISCLOSURE = /(artificial intelligence|ai assistant|automated (assistant|chat|agent|response)|automatically generated|generated by ai|ai[- ]?(bot|chatbot|agent|generated|powered)|virtual assistant|powered by ai|this is an? ai|you('|'?re| are) (chatting|talking|speaking) (with|to) (an? )?(ai|bot|virtual|automated))/i;

/** Is there an AI / chat assistant on this page, and (roughly) what kind? */
export function detectChatbot(html: string): { present: boolean; vendor?: string } {
  const h = html.slice(0, 400_000);
  for (const [re, name] of CHATBOT_WIDGETS) if (re.test(h)) return { present: true, vendor: name };
  if (AI_CHAT_HINT.test(h)) return { present: true };
  return { present: false };
}

/** Does the served HTML disclose that the chat is AI? (May also be inside the widget.) */
export function hasAiDisclosure(html: string): boolean {
  return AI_DISCLOSURE.test(html.slice(0, 400_000));
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

  // ── EU AI Act Article 50 (in force since 2 Aug 2026) — reported, not graded ──
  // A chatbot's AI disclosure is often rendered INSIDE the widget, which we
  // cannot see from the page HTML, so failing on its absence would cry wolf.
  // Instead we surface the obligation whenever a chat feature is detected — the
  // only vibe scanner that does, and squarely in the EU lane we own.
  const chatbot = detectChatbot(html);
  if (chatbot.present) {
    const disclosed = hasAiDisclosure(html);
    checks.push({
      key: 'ai-disclosure',
      label: 'AI chat disclosed to EU users (AI Act Art. 50)',
      pass: true, // advisory — we cannot see inside a third-party widget
      severity: 'low',
      detail: disclosed
        ? `${chatbot.vendor ?? 'A chat feature'} detected, and the page states it is AI. Since 2 Aug 2026 the EU AI Act requires this — looks handled.`
        : `${chatbot.vendor ?? 'A chat feature'} detected. Since 2 Aug 2026 the EU AI Act (Art. 50) requires telling EU users they are talking to AI — make sure your chat says so (the notice may already live inside the widget).`,
    });
  }

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
