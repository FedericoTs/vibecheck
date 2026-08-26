/**
 * Accessibility — the static half, and only the static half.
 *
 * AI generators ship inaccessible markup about as reliably as they ship missing
 * RLS: a div that behaves like a button, an icon-only link with no name, a
 * viewport that forbids zooming. Those are real barriers for real people and
 * nobody tells the person who shipped them.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO
 * ----------------------------------
 * No rendered checks. Computed colour contrast, axe-core violations and tap
 * target sizes all need a real browser laying the page out, and every one of
 * them misfires without it: contrast needs the cascade resolved, tap targets
 * need box geometry. Guessing at them from source is exactly the
 * pattern-match-and-conclude shape that produced every false accusation this
 * scanner has ever made. Everything below is decided by parsing markup that was
 * literally served, so a finding is a fact about the document, not a prediction
 * about the render.
 *
 * That limit is stated on the report rather than hidden: automated tooling
 * covers roughly half of WCAG at best, and a pass here is not a claim of
 * conformance.
 *
 * Reuses the HTML the fundamentals scan already fetched — no extra requests.
 */

import type { Grade } from './types';
import { scoreToGrade } from './grade';
import type { Severity } from './report';

export interface A11yCheck {
  key: string;
  label: string;
  pass: boolean;
  severity: Severity;
  detail?: string;
  /** False = shown but never counted, for things with a legitimate explanation. */
  graded?: boolean;
}

export interface AccessibilityResult {
  host: string;
  checks: A11yCheck[];
  grade: Grade;
  score: number;
  summary: string;
}

/* ── helpers ─────────────────────────────────────────────────────────── */

/** Strip comments, <script> and <style> so their contents never match a probe. */
function stripNoise(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<script\b[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[\s\S]*?<\/style>/gi, '');
}

/** Attribute lookup on a single start tag, quoted or bare. */
function attr(tag: string, name: string): string | null {
  const quoted = new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i').exec(tag);
  if (quoted) return quoted[1];
  const bare = new RegExp(`\\b${name}\\s*=\\s*([^\\s>"']+)`, 'i').exec(tag);
  return bare ? bare[1] : null;
}

/** True when the tag carries any attribute that gives it an accessible name. */
function hasNameAttr(tag: string): boolean {
  for (const a of ['aria-label', 'aria-labelledby', 'title']) {
    const v = attr(tag, a);
    if (v && v.trim()) return true;
  }
  return false;
}

/** Character ranges covered by <label>…</label>, for wrapped-input detection. */
function labelRanges(html: string): [number, number][] {
  const out: [number, number][] = [];
  for (const m of html.matchAll(/<label\b[^>]*>[\s\S]*?<\/label>/gi)) {
    if (m.index !== undefined) out.push([m.index, m.index + m[0].length]);
  }
  return out;
}

const inRange = (i: number, ranges: [number, number][]) => ranges.some(([a, b]) => i >= a && i < b);

/** Inputs that are not user-facing form fields and need no label. */
const UNLABELLED_OK = /^(hidden|submit|button|image|reset)$/i;

/* ── the checks ──────────────────────────────────────────────────────── */

/**
 * Every form field can be named.
 *
 * A field whose only visible cue is a placeholder announces nothing once the
 * user starts typing, and announces nothing at all to a screen reader in some
 * combinations. We accept a for/id label, a wrapping label, aria-label,
 * aria-labelledby or title — deliberately generous, because a false accusation
 * here is worse than a missed one.
 */
function checkFormLabels(html: string): A11yCheck {
  const ranges = labelRanges(html);
  const labelledIds = new Set<string>();
  for (const m of html.matchAll(/<label\b[^>]*>/gi)) {
    const target = attr(m[0], 'for');
    if (target) labelledIds.add(target);
  }

  let unnamed = 0;
  let total = 0;
  const examples: string[] = [];

  for (const m of html.matchAll(/<(input|select|textarea)\b[^>]*>/gi)) {
    const tag = m[0];
    const kind = (m[1] || '').toLowerCase();
    const type = attr(tag, 'type') ?? (kind === 'input' ? 'text' : kind);
    if (kind === 'input' && UNLABELLED_OK.test(type)) continue;
    total += 1;

    const id = attr(tag, 'id');
    const named =
      hasNameAttr(tag) ||
      (id && labelledIds.has(id)) ||
      (m.index !== undefined && inRange(m.index, ranges));

    if (!named) {
      unnamed += 1;
      if (examples.length < 3) examples.push(type);
    }
  }

  return {
    key: 'form-labels',
    label: 'Form fields have labels',
    pass: unnamed === 0,
    severity: 'high',
    detail:
      total === 0
        ? 'no form fields on this page'
        : unnamed === 0
          ? `all ${total} field${total === 1 ? '' : 's'} named`
          : `${unnamed} of ${total} field${total === 1 ? '' : 's'} have no label, aria-label or title (${examples.join(', ')})`,
  };
}

/**
 * Every button and link says what it is.
 *
 * The icon-only button is the single most common generated-markup failure: it
 * looks obvious on screen and is announced as "button" and nothing else. An
 * <svg><title> counts, because that is a real accessible name.
 */
function checkControlNames(html: string): A11yCheck {
  let unnamed = 0;
  let total = 0;

  const scan = (re: RegExp, requireHref: boolean) => {
    for (const m of html.matchAll(re)) {
      const openTag = m[0].slice(0, m[0].indexOf('>') + 1);
      if (requireHref && !attr(openTag, 'href')) continue; // an <a> with no href is not a link
      if (attr(openTag, 'aria-hidden') === 'true') continue;
      total += 1;

      const inner = m[1] ?? '';
      // An <svg><title> or an aria-label on any descendant is a genuine name.
      const svgTitled = /<title\b[^>]*>\s*\S/i.test(inner);
      const childLabelled = /\b(aria-label|aria-labelledby)\s*=\s*["'][^"']*\S/i.test(inner);
      const text = inner.replace(/<[^>]*>/g, '').replace(/&[a-z]+;/gi, ' ').trim();

      if (!text && !svgTitled && !childLabelled && !hasNameAttr(openTag)) unnamed += 1;
    }
  };

  scan(/<button\b[^>]*>([\s\S]*?)<\/button>/gi, false);
  scan(/<a\b[^>]*>([\s\S]*?)<\/a>/gi, true);

  return {
    key: 'control-names',
    label: 'Buttons and links have names',
    pass: unnamed === 0,
    severity: 'high',
    detail:
      total === 0
        ? 'no buttons or links found'
        : unnamed === 0
          ? `all ${total} control${total === 1 ? '' : 's'} named`
          : `${unnamed} of ${total} announce nothing but their role — icon-only controls with no text or aria-label`,
  };
}

/**
 * The page can be zoomed.
 *
 * user-scalable=no and a maximum-scale below 2 stop someone enlarging text on a
 * phone. Both are copied into generated templates constantly and neither has a
 * legitimate use on a content page. Fully deterministic from the meta tag.
 */
function checkZoom(html: string): A11yCheck {
  const meta = /<meta[^>]+name=["']viewport["'][^>]*>/i.exec(html)?.[0] ?? '';
  const content = meta ? (attr(meta, 'content') ?? '') : '';
  const blocked = /user-scalable\s*=\s*(no|0)/i.test(content);
  const maxScale = /maximum-scale\s*=\s*([\d.]+)/i.exec(content);
  const capped = maxScale ? parseFloat(maxScale[1]) < 2 : false;

  return {
    key: 'zoom',
    label: 'Zoom is not disabled',
    pass: !blocked && !capped,
    severity: 'high',
    detail: blocked
      ? 'viewport sets user-scalable=no, so the page cannot be pinch-zoomed'
      : capped
        ? `viewport caps maximum-scale at ${maxScale?.[1]}, which blocks meaningful enlargement`
        : meta
          ? 'viewport allows zooming'
          : 'no viewport meta tag to restrict zooming',
  };
}

/**
 * No positive tabindex.
 *
 * Any value above 0 pulls an element to the front of the tab order for the
 * whole page, so focus jumps somewhere unexpected. 0 and -1 are both fine and
 * widely correct, so only positives are counted.
 */
function checkTabindex(html: string): A11yCheck {
  let positive = 0;
  for (const m of html.matchAll(/\btabindex\s*=\s*["']?(-?\d+)/gi)) {
    if (parseInt(m[1], 10) > 0) positive += 1;
  }
  return {
    key: 'tabindex',
    label: 'No forced tab order',
    pass: positive === 0,
    severity: 'medium',
    detail:
      positive === 0
        ? 'tab order follows the document'
        : `${positive} element${positive === 1 ? '' : 's'} use a positive tabindex, which jumps focus out of document order`,
  };
}

/**
 * No duplicate id attributes.
 *
 * Invalid in every version of HTML, and it silently breaks the two things
 * accessibility depends on most: label[for] and aria-labelledby both resolve to
 * the first match, so the second field ends up sharing or losing its name.
 */
function checkDuplicateIds(html: string): A11yCheck {
  const seen = new Set<string>();
  const dupes = new Set<string>();
  for (const m of html.matchAll(/<[a-z][^>]*\bid\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
    const id = m[1].trim();
    if (!id) continue;
    if (seen.has(id)) dupes.add(id);
    else seen.add(id);
  }
  const list = [...dupes].slice(0, 3).join(', ');
  return {
    key: 'duplicate-ids',
    label: 'No duplicate element ids',
    pass: dupes.size === 0,
    severity: 'medium',
    detail:
      dupes.size === 0
        ? `${seen.size} unique id${seen.size === 1 ? '' : 's'}`
        : `${dupes.size} id${dupes.size === 1 ? '' : 's'} used more than once (${list}) — label and aria references resolve to the first one only`,
  };
}

/** Embedded frames announce what they contain rather than "iframe". */
function checkIframeTitles(html: string): A11yCheck {
  let untitled = 0;
  let total = 0;
  for (const m of html.matchAll(/<iframe\b[^>]*>/gi)) {
    const tag = m[0];
    if (attr(tag, 'aria-hidden') === 'true') continue;
    total += 1;
    const t = attr(tag, 'title');
    if (!t || !t.trim()) untitled += 1;
  }
  return {
    key: 'iframe-title',
    label: 'Embedded frames are titled',
    pass: untitled === 0,
    severity: 'medium',
    detail:
      total === 0
        ? 'no iframes on this page'
        : untitled === 0
          ? `all ${total} titled`
          : `${untitled} of ${total} iframe${total === 1 ? '' : 's'} have no title attribute`,
  };
}

/** The language of the page, so a screen reader picks the right voice. */
function checkLang(html: string): A11yCheck {
  const tag = /<html\b[^>]*>/i.exec(html)?.[0] ?? '';
  const lang = tag ? attr(tag, 'lang') : null;
  return {
    key: 'lang',
    label: 'Page language is declared',
    pass: Boolean(lang && lang.trim()),
    severity: 'medium',
    detail: lang ? `lang="${lang}"` : 'no lang attribute on <html>, so pronunciation falls back to the reader default',
  };
}

/** A main landmark, so a keyboard user can skip straight to the content. */
function checkLandmark(html: string): A11yCheck {
  const found = /<main[\s>]/i.test(html) || /\brole\s*=\s*["']main["']/i.test(html);
  return {
    key: 'main-landmark',
    label: 'Main content landmark',
    pass: found,
    severity: 'medium',
    detail: found ? 'page exposes a main landmark' : 'no <main> element or role="main" on the page',
  };
}

/**
 * A skip link, reported but never graded.
 *
 * Plenty of perfectly accessible pages route around this with landmarks alone,
 * and we cannot tell from markup whether the first link is visually positioned
 * as a skip link. Worth surfacing, not worth accusing anyone over — so it uses
 * the same reported-not-graded state as an unreachable probe.
 */
function checkSkipLink(html: string): A11yCheck {
  const first = /<a\b[^>]*href\s*=\s*["']#[^"']+["'][^>]*>/i.exec(html);
  const found = Boolean(first);
  return {
    key: 'skip-link',
    label: 'Skip-to-content link',
    pass: found,
    severity: 'low',
    graded: false,
    detail: found
      ? 'an in-page anchor is present near the top of the document'
      : 'no in-page anchor found — a skip link lets keyboard users jump past the nav, though landmarks can serve the same purpose',
  };
}

/* ── assembly ────────────────────────────────────────────────────────── */

const PENALTY: Record<Severity, number> = { critical: 40, high: 22, medium: 12, low: 5 };

export function analyzeAccessibility(html: string, host: string): AccessibilityResult {
  const clean = stripNoise(html);

  const checks: A11yCheck[] = [
    checkFormLabels(clean),
    checkControlNames(clean),
    checkZoom(clean),
    checkLang(clean),
    checkLandmark(clean),
    checkTabindex(clean),
    checkDuplicateIds(clean),
    checkIframeTitles(clean),
    checkSkipLink(clean),
  ];

  const failed = checks.filter((c) => !c.pass && c.graded !== false);
  const score = Math.max(0, 100 - failed.reduce((n, c) => n + PENALTY[c.severity], 0));

  return {
    host,
    checks,
    grade: scoreToGrade(score),
    score,
    summary: failed.length === 0 ? 'no automated barriers found' : `${failed.length} automated barrier${failed.length === 1 ? '' : 's'} found`,
  };
}
