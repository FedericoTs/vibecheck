import { describe, it, expect } from 'vitest';
import { cmpVersion, detectLibraries, assessLibraries, gradeLibs, scanLibraries } from './libs';

describe('cmpVersion', () => {
  it('compares numerically, not lexically', () => {
    expect(cmpVersion('3.10.0', '3.9.0')).toBe(1); // 10 > 9
    expect(cmpVersion('0.19.0', '0.21.2')).toBe(-1);
    expect(cmpVersion('1.5.0', '1.6.0')).toBe(-1);
    expect(cmpVersion('3.5.0', '3.5.0')).toBe(0);
    expect(cmpVersion('2.29', '2.29.4')).toBe(-1); // missing part = 0
  });
});

describe('detectLibraries', () => {
  it('reads a version from a filename', () => {
    expect(detectLibraries('<script src="/js/jquery-3.4.1.min.js">')).toEqual([{ name: 'jQuery', version: '3.4.1' }]);
  });
  it('reads a version from a banner', () => {
    expect(detectLibraries('/*! jQuery JavaScript Library v1.11.0 */')).toEqual([{ name: 'jQuery', version: '1.11.0' }]);
  });
  it('does NOT confuse jquery-ui with jquery', () => {
    const libs = detectLibraries('<script src="jquery-ui-1.12.1.min.js">');
    expect(libs).toEqual([{ name: 'jQuery UI', version: '1.12.1' }]);
  });
  it('reads a version from the moment banner', () => {
    expect(detectLibraries('//! moment.js\n//! version : 2.24.0')).toEqual([{ name: 'Moment.js', version: '2.24.0' }]);
  });
  it('returns nothing when no version is knowable (never guesses)', () => {
    expect(detectLibraries('minified blob with no version and jQuery calls like $(".x")')).toEqual([]);
  });
});

describe('assessLibraries', () => {
  it('flags a vulnerable jQuery with the right CVE, severity and fix', () => {
    const { findings } = assessLibraries('jquery-3.4.1.min.js');
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ library: 'jQuery', version: '3.4.1', severity: 'high', fixedIn: '3.5.0' });
    expect(findings[0].cves).toContain('CVE-2020-11022');
  });
  it('does NOT flag a patched version', () => {
    const r = assessLibraries('jquery-3.5.1.min.js');
    expect(r.detected).toBe(1);
    expect(r.findings).toHaveLength(0);
  });
  it('flags Handlebars RCE as critical', () => {
    const { findings } = assessLibraries('handlebars-4.7.6.min.js');
    expect(findings[0]).toMatchObject({ library: 'Handlebars', severity: 'critical', fixedIn: '4.7.7' });
    expect(findings[0].cves).toContain('CVE-2021-23369');
  });
  it('keeps 0.x and 1.x axios advisories separate', () => {
    expect(assessLibraries('axios-0.19.0.min.js').findings[0]).toMatchObject({ severity: 'high', fixedIn: '0.21.2' });
    expect(assessLibraries('axios-1.5.0.min.js').findings[0]).toMatchObject({ severity: 'medium', fixedIn: '1.6.0' });
    expect(assessLibraries('axios-1.6.0.min.js').findings).toHaveLength(0);
  });
  it('sorts findings most-severe first', () => {
    const { findings } = assessLibraries('jquery-3.4.1.js handlebars-4.7.6.js');
    expect(findings.map((f) => f.severity)).toEqual(['critical', 'high']);
  });
});

describe('gradeLibs + scanLibraries', () => {
  it('grades by worst severity', () => {
    expect(gradeLibs([{ library: 'x', version: '1', severity: 'critical', cves: [], summary: '', fixedIn: '2' }])).toBe('D');
    expect(gradeLibs([{ library: 'x', version: '1', severity: 'high', cves: [], summary: '', fixedIn: '2' }])).toBe('C');
    expect(gradeLibs([{ library: 'x', version: '1', severity: 'medium', cves: [], summary: '', fixedIn: '2' }])).toBe('B');
    expect(gradeLibs([])).toBe('A');
  });
  it('a clean modern stack passes', () => {
    const r = scanLibraries('jquery-3.7.1.min.js bootstrap-5.3.2.min.js', 'example.com');
    expect(r.grade).toBe('A');
    expect(r.detected).toBe(2);
    expect(r.summary).toMatch(/none with known vulnerabilities/);
  });
});
