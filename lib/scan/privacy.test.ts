import { describe, it, expect } from 'vitest';
import {
  cookieNames,
  findTrackers,
  usesPrivacyFriendlyAnalytics,
  usesGoogleHostedFonts,
  hasConsentBanner,
  hasPrivacyLink,
  analyzePrivacy,
} from './privacy';

const check = (r: ReturnType<typeof analyzePrivacy>, key: string) => r.checks.find((c) => c.key === key)!;

describe('cookieNames', () => {
  it('parses names from joined Set-Cookie values', () => {
    expect(cookieNames('_ga=GA1.2.x; Path=/\n_fbp=fb.1.y; Path=/')).toEqual(['_ga', '_fbp']);
    expect(cookieNames('session=abc; HttpOnly')).toEqual(['session']);
    expect(cookieNames(undefined)).toEqual([]);
  });
});

describe('detectors', () => {
  it('finds the common trackers', () => {
    expect(findTrackers('<script src="https://www.googletagmanager.com/gtm.js"></script>')).toContain('Google Analytics');
    expect(findTrackers('<script src="https://connect.facebook.net/en_US/fbevents.js">')).toContain('Meta Pixel');
    expect(findTrackers('<p>hello</p>')).toEqual([]);
  });

  it('does NOT punish cookieless, EU-friendly analytics', () => {
    const html = '<script src="https://plausible.io/js/script.js"></script>';
    expect(findTrackers(html)).toEqual([]);
    expect(usesPrivacyFriendlyAnalytics(html)).toBe(true);
  });

  it('spots Google-hosted fonts and consent banners and privacy links', () => {
    expect(usesGoogleHostedFonts('<link href="https://fonts.googleapis.com/css2?family=Inter">')).toBe(true);
    expect(usesGoogleHostedFonts('<link href="/fonts/inter.woff2">')).toBe(false);
    expect(hasConsentBanner('<div>We use cookies to improve your experience</div>')).toBe(true);
    expect(hasConsentBanner('<script src="https://cdn.cookiebot.com/uc.js">')).toBe(true);
    expect(hasConsentBanner('<p>welcome</p>')).toBe(false);
    expect(hasPrivacyLink('<a href="/privacy">Privacy Policy</a>')).toBe(true);
    expect(hasPrivacyLink('<a href="/datenschutz">Datenschutz</a>')).toBe(true);
    expect(hasPrivacyLink('<a href="/about">About</a>')).toBe(false);
  });
});

describe('analyzePrivacy', () => {
  it('flags analytics cookies dropped before any interaction', () => {
    const r = analyzePrivacy('<html></html>', '_ga=GA1.2.abc; Path=/\n_gid=GA1.2.def', 'app.eu');
    const c = check(r, 'tracking-cookies-preconsent');
    expect(c.pass).toBe(false);
    expect(c.detail).toMatch(/before any click/);
    expect(r.grade).not.toBe('A');
  });

  it('does not flag a plain session cookie as tracking', () => {
    const r = analyzePrivacy('<html></html>', 'session=abc; HttpOnly; Secure');
    const c = check(r, 'tracking-cookies-preconsent');
    expect(c.pass).toBe(true);
    expect(c.detail).toMatch(/none of them analytics/);
  });

  it('flags trackers loading pre-consent, and the Google Fonts transfer', () => {
    const html = '<script src="https://www.googletagmanager.com/gtm.js"></script><link href="https://fonts.googleapis.com/css2">';
    const r = analyzePrivacy(html, undefined);
    expect(check(r, 'trackers-preconsent').pass).toBe(false);
    expect(check(r, 'google-fonts').pass).toBe(false);
    expect(check(r, 'google-fonts').detail).toMatch(/German court/);
  });

  it('does not demand a consent banner from a site that tracks nothing', () => {
    const r = analyzePrivacy('<html><a href="/privacy">Privacy</a></html>', undefined);
    const c = check(r, 'consent-banner');
    expect(c.pass).toBe(true);
    expect(c.detail).toMatch(/nothing tracking/);
  });

  it('DOES expect a banner once something tracks', () => {
    const r = analyzePrivacy('<script src="https://connect.facebook.net/x.js"></script>', undefined);
    expect(check(r, 'consent-banner').pass).toBe(false);
  });

  it('a clean, self-hosted, cookieless page passes everything', () => {
    const html = '<html><link href="/fonts/inter.woff2"><script src="https://plausible.io/js/script.js"></script><a href="/privacy">Privacy</a></html>';
    const r = analyzePrivacy(html, 'session=x; HttpOnly');
    expect(r.failed).toHaveLength(0);
    expect(r.grade).toBe('A');
    expect(r.summary).toMatch(/No EU privacy problems/);
  });

  it('never states a legal conclusion — only what was observed', () => {
    const r = analyzePrivacy('<script src="https://www.google-analytics.com/analytics.js"></script>', '_ga=x');
    const text = JSON.stringify(r).toLowerCase();
    expect(text).not.toMatch(/non-?compliant|violation|illegal|unlawful|breach of/);
    expect(text).toMatch(/before any click|before any choice/);
  });
});
