/**
 * Invisible instructions hidden in the page, aimed at AI readers.
 *
 * ── The technique ──────────────────────────────────────────────────────────
 * The Unicode "Tags" block, U+E0000–U+E007F, mirrors printable ASCII: U+E0020
 * is TAG SPACE, U+E007E is TAG TILDE, and the character at U+E00xx corresponds
 * to the ASCII character at 0xxx. Browsers render these as absolutely nothing —
 * no glyph, no width, no selection. But a language model tokenizing the page
 * sees recoverable text.
 *
 * So a page can carry an instruction that a human physically cannot see and an
 * agent may well obey. This cuts both ways: the site may be a VECTOR aimed at
 * agents that visit it, or it may itself have been INJECTED — through a CMS
 * field, a comment, or a copy-pasted block from a poisoned source.
 *
 * ── Why this is deterministic, not a heuristic ─────────────────────────────
 * There is no scoring and no classifier. Decoding is arithmetic (codepoint −
 * 0xE0000), and the grading rule is a grammar question with a yes/no answer.
 *
 * What it does NOT do is grade on the mere PRESENCE of tag characters. The
 * first version of this check allowlisted the three RGI flags — England,
 * Scotland, Wales — and treated everything else in the block as smuggled. That
 * was wrong, and an adversarial review caught it against a live site: UTS #51
 * Annex C makes valid ANY tag_spec that is a CLDR subdivision_id or 3-digit
 * region subtag with idStatus regular, deprecated or macroregion — thousands of
 * sequences, not three. An emoji reference page serving US state flags was
 * reported as carrying 63 hidden instructions. A false accusation of exactly
 * the kind this tool exists not to make.
 *
 * The rule instead keys on the CHARACTER CLASS of what survives after every
 * structurally valid sequence is stripped:
 *
 *   - conformant alphabet (digits 0-9, lowercase a-z, CANCEL TAG) → REPORTED.
 *     Emoji reference sites publish these legitimately, sometimes split across
 *     markup so the sequence never appears contiguously in the served bytes.
 *   - anything else — TAG SPACE, punctuation, or the capitals U+E0041–U+E005A
 *     that ED-14a explicitly reserves — → GRADED. These cannot occur in any
 *     conformant sequence, and real smuggled prose is full of them.
 *
 * That asymmetry is the whole design: a check that stays silent on ambiguous
 * lowercase runs and only fires on the by-spec impossible.
 *
 * Sources (retrieved 2026-08-20):
 *   https://www.unicode.org/Public/UNIDATA/Blocks.txt   → "E0000..E007F; Tags"
 *   https://unicode.org/Public/emoji/latest/emoji-sequences.txt
 *   UTS #51 ED-14a (tag_spec grammar; reserved capitals) and Annex C (the
 *   CLDR subdivision constraint) — https://www.unicode.org/reports/tr51/
 *
 * ── What is deliberately NOT graded ────────────────────────────────────────
 * Zero-width and bidirectional characters are counted and reported, never
 * graded. ZWJ (U+200D) is structural in emoji and orthographically REQUIRED in
 * Arabic, Persian and many Indic scripts; U+FEFF appears as a stray BOM in
 * countless build outputs. Grading those would punish correct multilingual
 * text, which is the opposite of the point.
 */

/** Start of the Unicode Tags block. Decoding is `codepoint - TAG_BASE`. */
const TAG_BASE = 0xe0000;
/** The subrange that mirrors printable ASCII (TAG SPACE .. TAG TILDE). */
const TAG_PRINTABLE_START = 0xe0020;
const TAG_PRINTABLE_END = 0xe007e;
/** CANCEL TAG — the terminator of an emoji tag sequence. */
const TAG_CANCEL = 0xe007f;

/**
 * Codepoints that CAN legitimately appear inside a conformant emoji tag
 * sequence, per UTS #51 Annex C: digits 0-9 and lowercase a-z, plus the
 * terminator.
 *
 * Everything else in the Tags block is by-spec impossible in a conformant
 * sequence — TAG SPACE, all punctuation, and U+E0041–U+E005A, which ED-14a
 * explicitly reserves ("they are not used currently and are reserved for future
 * extensions"). That distinction is what this check grades on.
 */
function isConformantTagChar(cp: number): boolean {
  return (
    (cp >= 0xe0030 && cp <= 0xe0039) || // TAG DIGIT ZERO .. NINE
    (cp >= 0xe0061 && cp <= 0xe007a) || // TAG LATIN SMALL LETTER A .. Z
    cp === TAG_CANCEL
  );
}

/**
 * A structurally valid emoji tag sequence: the black-flag base, a run of
 * digits/lowercase, and the CANCEL TAG terminator, within the 32-codepoint
 * limit Annex C imposes.
 *
 * This is deliberately NOT the RGI list. Annex C makes valid any tag_spec that
 * is a CLDR subdivision_id or 3-digit region subtag with idStatus regular,
 * deprecated or macroregion — thousands of them, not the three that are
 * Recommended for General Interchange. An earlier version of this check
 * allowlisted only the RGI three and consequently reported 63 "hidden
 * instructions" on an emoji reference page serving perfectly valid US state
 * flags. Matching the grammar rather than the recommended set is the fix.
 */
const VALID_TAG_SEQUENCE = /\u{1F3F4}[\u{E0030}-\u{E0039}\u{E0061}-\u{E007A}]{2,30}\u{E007F}/gu;

/**
 * Variation Selectors Supplement. A single selector after a base character is a
 * legitimate Ideographic Variation Sequence in CJK text, but selectors do not
 * stack — so a RUN of two or more is non-conformant by construction, and is the
 * documented way to smuggle arbitrary bytes through an emoji.
 */
const VS_SUPPLEMENT_START = 0xe0100;
const VS_SUPPLEMENT_END = 0xe01ef;

/** Zero-width and bidi controls: reported for transparency, never graded. */
const INVISIBLE_CONTROLS = /[​‌‍⁠﻿‪-‮⁦-⁩]/gu;

export interface SmuggledPayload {
  /** The ASCII text that was hidden, decoded verbatim. */
  decoded: string;
  /** How many tag codepoints made it up. */
  codepoints: number;
  /** Visible text surrounding the payload, so the owner can locate it. */
  context: string;
}

export interface SmugglingResult {
  /**
   * Hidden text that CANNOT be a conformant Unicode sequence — it uses spaces,
   * punctuation, capitals or stacked variation selectors. This is the graded
   * finding, and it has no legitimate surface.
   */
  payloads: SmuggledPayload[];
  /** Structurally valid emoji tag sequences skipped — proves the grammar ran. */
  emojiSequencesSkipped: number;
  /**
   * Leftover tag characters that are still within the conformant alphabet
   * (lowercase and digits). Emoji reference sites publish these legitimately,
   * often split across markup, so they are REPORTED and never graded.
   */
  conformantResidue: number;
  /** Zero-width / bidi characters present. Reported only. */
  invisibleControls: number;
  /**
   * True when the document was mostly script-driven, so our view of it is
   * partial. The caller must not render a clean pass in that case.
   */
  limitedCoverage: boolean;
}

/**
 * Remove element content that would double-count or mislead.
 *
 * Next.js serialises the RSC payload into inline <script> blocks, so the page's
 * own visible text appears twice in the HTML. Scanning both would report every
 * payload twice. Style and template content is stripped for the same reason.
 */
export function stripNonTextElements(html: string): string {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<template\b[^>]*>[\s\S]*?<\/template>/gi, ' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ');
}

/**
 * Decode numeric HTML entities that land inside the Tags block.
 *
 * A payload can be delivered as `&#xE0041;` or `&#917569;` and the browser will
 * turn it into a tag character. Only the Tags range is decoded — this is not a
 * general entity decoder, and nothing outside that range is touched.
 */
export function decodeTagEntities(text: string): string {
  return text.replace(/&#(x[0-9a-f]+|\d+);/gi, (whole, body: string) => {
    const cp = body[0].toLowerCase() === 'x' ? parseInt(body.slice(1), 16) : parseInt(body, 10);
    if (Number.isNaN(cp) || cp < TAG_BASE || cp > TAG_CANCEL) return whole;
    return String.fromCodePoint(cp);
  });
}

/**
 * Strip every structurally valid emoji tag sequence, whether or not it is one
 * of the three RGI flags. Returns how many were removed.
 */
export function removeEmojiTagSequences(text: string): { text: string; removed: number } {
  let removed = 0;
  const out = text.replace(VALID_TAG_SEQUENCE, () => {
    removed++;
    return '';
  });
  return { text: out, removed };
}

/** Decode a run of tag characters into the ASCII it mirrors. */
function decodeRun(run: number[]): string {
  return run
    .filter((cp) => cp >= TAG_PRINTABLE_START && cp <= TAG_PRINTABLE_END)
    .map((cp) => String.fromCodePoint(cp - TAG_BASE))
    .join('');
}

/** Collapse markup and whitespace into readable context. */
function visibleContext(text: string, at: number): string {
  const window = text.slice(Math.max(0, at - 60), at + 60);
  return window
    .replace(/<[^>]*>/g, ' ')
    .replace(/[\u{E0000}-\u{E007F}]/gu, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 90);
}

/**
 * Find instructions hidden in the Tags block.
 *
 * @param html            the served HTML
 * @param limitedCoverage true when the page is a JS-only shell, so a clean
 *                        result must not be presented as a pass
 */
export function findSmuggledText(html: string, limitedCoverage = false): SmugglingResult {
  const decoded = decodeTagEntities(stripNonTextElements(html));
  const { text, removed } = removeEmojiTagSequences(decoded);

  const payloads: SmuggledPayload[] = [];
  let conformantResidue = 0;
  let run: number[] = [];
  let runStart = 0;
  let i = 0;

  const flush = (): void => {
    if (!run.length) {
      return;
    }
    // THE GRADING RULE. Presence of tag characters proves nothing — valid
    // subdivision flags leave residue when markup splits them apart. What
    // cannot occur in any conformant sequence is a character outside the
    // digits/lowercase/terminator alphabet: a space, punctuation, or one of the
    // capitals ED-14a reserves. Real smuggled prose is full of exactly those.
    const nonConformant = run.filter((cp) => !isConformantTagChar(cp));
    if (nonConformant.length > 0) {
      const value = decodeRun(run);
      if (value.trim().length >= 2) {
        payloads.push({ decoded: value, codepoints: run.length, context: visibleContext(text, runStart) });
      }
    } else {
      conformantResidue += run.length;
    }
    run = [];
  };

  // Runs of stacked variation selectors, decoded separately: a selector is
  // legitimate only immediately after a base character, and they do not stack,
  // so two or more in a row is non-conformant by construction.
  let vsRun: number[] = [];
  let vsStart = 0;
  const flushVs = (): void => {
    if (vsRun.length >= 2) {
      const bytes = vsRun.map((cp) => cp - VS_SUPPLEMENT_START + 16);
      const printable = bytes
        .filter((b) => b >= 0x20 && b <= 0x7e)
        .map((b) => String.fromCharCode(b))
        .join('');
      payloads.push({
        decoded: printable.trim().length >= 2 ? printable : `${vsRun.length} hidden bytes`,
        codepoints: vsRun.length,
        context: visibleContext(text, vsStart),
      });
    }
    vsRun = [];
  };

  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= TAG_BASE && cp <= TAG_CANCEL) {
      if (!run.length) runStart = i;
      run.push(cp);
      flushVs();
    } else if (cp >= VS_SUPPLEMENT_START && cp <= VS_SUPPLEMENT_END) {
      if (!vsRun.length) vsStart = i;
      vsRun.push(cp);
      flush();
    } else {
      flush();
      flushVs();
    }
    i += ch.length;
  }
  flush();
  flushVs();

  return {
    payloads,
    emojiSequencesSkipped: removed,
    conformantResidue,
    invisibleControls: (text.match(INVISIBLE_CONTROLS) ?? []).length,
    limitedCoverage,
  };
}
