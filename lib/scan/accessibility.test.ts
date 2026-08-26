import { describe, it, expect } from 'vitest';
import { analyzeAccessibility } from './accessibility';

const run = (body: string, head = '') =>
  analyzeAccessibility(`<html lang="en"><head>${head}</head><body><main>${body}</main></body></html>`, 'my.app');

const get = (html: string, key: string) => {
  const r = analyzeAccessibility(html, 'my.app');
  return r.checks.find((c) => c.key === key)!;
};
const check = (body: string, key: string, head = '') => {
  const r = run(body, head);
  return r.checks.find((c) => c.key === key)!;
};

describe('form labels', () => {
  it('accepts a for/id label', () => {
    expect(check('<label for="e">Email</label><input id="e" type="email">', 'form-labels').pass).toBe(true);
  });

  it('accepts a WRAPPING label — the most common correct pattern', () => {
    expect(check('<label>Email <input type="email"></label>', 'form-labels').pass).toBe(true);
  });

  it('accepts aria-label and title', () => {
    expect(check('<input type="text" aria-label="Search">', 'form-labels').pass).toBe(true);
    expect(check('<input type="text" title="Search">', 'form-labels').pass).toBe(true);
  });

  it('ignores hidden and submit inputs, which need no label', () => {
    const c = check('<input type="hidden" name="csrf"><input type="submit" value="Go">', 'form-labels');
    expect(c.pass).toBe(true);
    expect(c.detail).toMatch(/no form fields/);
  });

  it('fails a field whose only cue is a placeholder', () => {
    const c = check('<input type="email" placeholder="Email">', 'form-labels');
    expect(c.pass).toBe(false);
    expect(c.detail).toMatch(/1 of 1/);
  });

  it('covers select and textarea too', () => {
    expect(check('<select><option>a</option></select>', 'form-labels').pass).toBe(false);
    expect(check('<textarea></textarea>', 'form-labels').pass).toBe(false);
  });
});

describe('control names', () => {
  it('accepts a button with text', () => {
    expect(check('<button>Save</button>', 'control-names').pass).toBe(true);
  });

  it('accepts an icon button named by aria-label', () => {
    expect(check('<button aria-label="Close"><svg></svg></button>', 'control-names').pass).toBe(true);
  });

  it('accepts an icon button named by an svg title', () => {
    expect(check('<button><svg><title>Close</title></svg></button>', 'control-names').pass).toBe(true);
  });

  it('fails an icon-only button that announces nothing', () => {
    const c = check('<button><svg><path d="M0 0"/></svg></button>', 'control-names');
    expect(c.pass).toBe(false);
    expect(c.detail).toMatch(/icon-only/);
  });

  it('does not accuse an <a> with no href — that is not a link', () => {
    expect(check('<a><svg></svg></a>', 'control-names').pass).toBe(true);
  });

  it('skips aria-hidden controls, which are not in the accessibility tree', () => {
    expect(check('<button aria-hidden="true"><svg></svg></button>', 'control-names').pass).toBe(true);
  });
});

describe('zoom', () => {
  const vp = (content: string) => `<meta name="viewport" content="${content}">`;

  it('fails user-scalable=no', () => {
    const c = check('', 'zoom', vp('width=device-width, user-scalable=no'));
    expect(c.pass).toBe(false);
    expect(c.detail).toMatch(/pinch-zoomed/);
  });

  it('fails a maximum-scale below 2', () => {
    expect(check('', 'zoom', vp('width=device-width, maximum-scale=1')).pass).toBe(false);
  });

  it('passes a normal responsive viewport', () => {
    expect(check('', 'zoom', vp('width=device-width, initial-scale=1')).pass).toBe(true);
  });

  it('passes a generous maximum-scale', () => {
    expect(check('', 'zoom', vp('width=device-width, maximum-scale=5')).pass).toBe(true);
  });
});

describe('tab order', () => {
  it('allows tabindex 0 and -1', () => {
    expect(check('<div tabindex="0"></div><div tabindex="-1"></div>', 'tabindex').pass).toBe(true);
  });

  it('flags a positive tabindex', () => {
    expect(check('<div tabindex="3"></div>', 'tabindex').pass).toBe(false);
  });
});

describe('duplicate ids', () => {
  it('passes unique ids', () => {
    expect(check('<p id="a"></p><p id="b"></p>', 'duplicate-ids').pass).toBe(true);
  });

  it('flags a repeated id and names it', () => {
    const c = check('<p id="a"></p><p id="a"></p>', 'duplicate-ids');
    expect(c.pass).toBe(false);
    expect(c.detail).toContain('a');
  });
});

describe('iframes', () => {
  it('passes a titled iframe', () => {
    expect(check('<iframe title="Map" src="/m"></iframe>', 'iframe-title').pass).toBe(true);
  });

  it('flags an untitled one', () => {
    expect(check('<iframe src="/m"></iframe>', 'iframe-title').pass).toBe(false);
  });

  it('ignores an aria-hidden iframe', () => {
    expect(check('<iframe src="/m" aria-hidden="true"></iframe>', 'iframe-title').pass).toBe(true);
  });
});

describe('lang and landmark', () => {
  it('reads the lang attribute', () => {
    expect(get('<html lang="en-GB"><body></body></html>', 'lang').pass).toBe(true);
    expect(get('<html><body></body></html>', 'lang').pass).toBe(false);
  });

  it('accepts either <main> or role="main"', () => {
    expect(get('<html><body><main>x</main></body></html>', 'main-landmark').pass).toBe(true);
    expect(get('<html><body><div role="main">x</div></body></html>', 'main-landmark').pass).toBe(true);
    expect(get('<html><body><div>x</div></body></html>', 'main-landmark').pass).toBe(false);
  });
});

describe('noise is never scanned', () => {
  it('ignores markup inside comments, script and style', () => {
    const html = `<html lang="en"><body><main>
      <!-- <input type="text"> -->
      <script>var s = '<button></button>';</script>
      <style>/* <iframe></iframe> */</style>
    </main></body></html>`;
    const r = analyzeAccessibility(html, 'my.app');
    expect(r.checks.find((c) => c.key === 'form-labels')!.pass).toBe(true);
    expect(r.checks.find((c) => c.key === 'control-names')!.pass).toBe(true);
    expect(r.checks.find((c) => c.key === 'iframe-title')!.pass).toBe(true);
  });
});

describe('scoring', () => {
  it('gives a clean accessible page an A', () => {
    const r = analyzeAccessibility(
      `<html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"></head>
       <body><main><label>Email <input type="email"></label><button>Save</button></main></body></html>`,
      'my.app',
    );
    expect(r.grade).toBe('A');
    expect(r.score).toBe(100);
    expect(r.summary).toMatch(/no automated barriers/);
  });

  it('drops the grade when high-severity barriers stack up', () => {
    const r = analyzeAccessibility(
      `<html><head><meta name="viewport" content="user-scalable=no"></head>
       <body><div><input type="email" placeholder="Email"><button><svg></svg></button></div></body></html>`,
      'my.app',
    );
    expect(r.score).toBeLessThan(60);
    expect(['D', 'F']).toContain(r.grade);
  });

  it('never lets the reported-not-graded skip link move the score', () => {
    const withAnchor = analyzeAccessibility(
      `<html lang="en"><head><meta name="viewport" content="width=device-width"></head><body><main><a href="#c">Skip</a></main></body></html>`,
      'my.app',
    );
    const without = analyzeAccessibility(
      `<html lang="en"><head><meta name="viewport" content="width=device-width"></head><body><main><p>hi</p></main></body></html>`,
      'my.app',
    );
    expect(withAnchor.score).toBe(without.score);
    expect(without.checks.find((c) => c.key === 'skip-link')!.graded).toBe(false);
  });
});
