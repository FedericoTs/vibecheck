/**
 * One plain line per category: what we looked at, and why it matters.
 *
 * A report that is only a grade and a column of ticks tells someone whether to
 * feel good, not what was examined. For most of this audience — people who
 * shipped an app an AI wrote for them — "Exposed files: A ✓" means nothing
 * until you say we asked their server for .env and .git/config and it refused.
 *
 * Rules for writing these: name the concrete thing we fetched or read, say what
 * a stranger would get if it went wrong, and never use a word the reader would
 * have to look up. No "misconfiguration", no "posture", no "surface".
 */
export const CATEGORY_BLURB: Record<string, string> = {
  supabase:
    'We asked your database for rows using the public key your app ships in its own JavaScript — the same key any visitor can read out of your bundle.',
  firebase:
    'We asked your Firestore collections and Realtime Database for documents as an anonymous visitor, using the config your app publishes.',
  secrets:
    'We read the HTML and every JavaScript file your site serves, looking for keys that were meant to stay on your server — Stripe, AWS, OpenAI, database passwords.',
  libs: 'We matched the JavaScript libraries your page loads against public vulnerability advisories.',
  ai: 'We checked whether AI and MCP endpoints — chat proxies, agent tools, model APIs — answer a stranger without a login.',
  routes:
    'We asked for admin and debug pages, both a standard list and the routes your own bundle names, and checked whether they let us in.',
  paths:
    'We asked your server for files that should never be public — .env, .git/config, database dumps, backups — and checked what came back.',
  headers:
    'We read the headers your server sends and checked the ones that stop other sites framing you, sniffing your content, or running injected scripts.',
  transport: 'We checked that http redirects to https, that HSTS is set, and that your domain is not open to takeover.',
  email:
    'We read your DNS records to see whether someone can send email that appears to come from your domain.',
  privacy:
    'We loaded your site as a first-time EU visitor and recorded what ran before anyone clicked anything — trackers, cookies, third-party scripts.',
  devserver:
    'We checked whether a development build or dev-only endpoints are being served in production, which leaks source and internals.',
  smuggling:
    'We decoded invisible Unicode characters in your page — text a human cannot see but an AI reading your site will obey.',
  scaffold:
    'We checked whether your app still ships the title, description and metadata its generator created, which is the tell of an unfinished deploy.',
  accessibility:
    'We read your markup the way assistive technology does — looking for form fields with no label, buttons that announce nothing but their role, a viewport that forbids zooming, and duplicate ids that break the references a screen reader follows.',
  visibility:
    'We checked what search engines and AI crawlers can actually read, and which of them you allow — this decides whether ChatGPT or Claude can cite you.',
  fundamentals: 'Basic hygiene a browser and a crawler both expect: title, description, favicon, viewport, compression.',
  lighthouse: "Google's own Lighthouse audit — performance, accessibility, best practices and SEO, measured on a real page load.",
};

/** The line to show under a category heading, or '' when we have nothing useful to add. */
export function categoryBlurb(key: string): string {
  return CATEGORY_BLURB[key] ?? '';
}
