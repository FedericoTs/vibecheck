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
 * There is no scoring and no classifier here. Either the bytes are in the Tags
 * block or they are not, and decoding is arithmetic: codepoint − 0xE0000.
 *
 * The only legitimate use of this block in real text is the RGI emoji tag
 * sequences, and that is a CLOSED SET OF EXACTLY THREE, confirmed against the
 * Unicode data files:
 *
 *   1F3F4 E0067 E0062 E0065 E006E E0067 E007F  flag: England
 *   1F3F4 E0067 E0062 E0073 E0063 E0074 E007F  flag: Scotland
 *   1F3F4 E0067 E0062 E0077 E006C E0073 E007F  flag: Wales
 *
 * Sources (retrieved 2026-08-20):
 *   https://www.unicode.org/Public/UNIDATA/Blocks.txt   → "E0000..E007F; Tags"
 *   https://unicode.org/Public/emoji/latest/emoji-sequences.txt
 *                                                       → RGI_Emoji_Tag_Sequence
 *   Annex C of UTS #51 describes the sequence structure.
 *
 * Because that allowlist is an exact, finite set rather than a shape, a
 * correctly-rendered Welsh flag cannot produce a finding, and nothing else in
 * ordinary text uses this block at all. No benign framework, CDN or WAF emits
 * tag characters.
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
 * The complete set of legitimate tag sequences in Unicode, as codepoint arrays.
 * Verified against emoji-sequences.txt — there are exactly three.
 */
const RGI_TAG_SEQUENCES: number[][] = [
  [0x1f3f4, 0xe0067, 0xe0062, 0xe0065, 0xe006e, 0xe0067, 0xe007f], // England
  [0x1f3f4, 0xe0067, 0xe0062, 0xe0073, 0xe0063, 0xe0074, 0xe007f], // Scotland
  [0x1f3f4, 0xe0067, 0xe0062, 0xe0077, 0xe006c, 0xe0073, 0xe007f], // Wales
];

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
  /** Decoded hidden instructions. Non-empty means a hard finding. */
  payloads: SmuggledPayload[];
  /** Legitimate emoji tag sequences skipped — proves the allowlist ran. */
  emojiSequencesSkipped: number;
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

/** Strip the three legitimate emoji tag sequences. Returns the count removed. */
export function removeEmojiTagSequences(text: string): { text: string; removed: number } {
  let out = text;
  let removed = 0;
  for (const seq of RGI_TAG_SEQUENCES) {
    const literal = seq.map((cp) => String.fromCodePoint(cp)).join('');
    let idx = out.indexOf(literal);
    while (idx !== -1) {
      removed++;
      out = out.slice(0, idx) + out.slice(idx + literal.length);
      idx = out.indexOf(literal);
    }
  }
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
  let run: number[] = [];
  let runStart = 0;
  let i = 0;

  const flush = (): void => {
    if (run.length) {
      const value = decodeRun(run);
      // A lone stray tag character carries no message; require real content.
      if (value.trim().length >= 2) {
        payloads.push({ decoded: value, codepoints: run.length, context: visibleContext(text, runStart) });
      }
      run = [];
    }
  };

  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= TAG_BASE && cp <= TAG_CANCEL) {
      if (!run.length) runStart = i;
      run.push(cp);
    } else {
      flush();
    }
    i += ch.length;
  }
  flush();

  return {
    payloads,
    emojiSequencesSkipped: removed,
    invisibleControls: (text.match(INVISIBLE_CONTROLS) ?? []).length,
    limitedCoverage,
  };
}
