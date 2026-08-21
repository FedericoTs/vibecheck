import { describe, expect, it } from 'vitest';
import { CATALOGUE, CATALOGUE_TOTAL, CATALOGUE_CLAIM } from './catalogue';
import { gradeHeaders } from './headers';
import { SENSITIVE_PATHS } from './paths';
import { ROUTE_PROBES } from './routes';
import { AI_PROBES } from './ai-surface';
import { SECRET_RULES } from './secrets';
import { CRAWLERS } from './visibility';

/**
 * A catalogue size is a public claim about thoroughness. If it drifts from what
 * the scanner actually does, it becomes marketing rather than a fact — the exact
 * failure this tool exists to call out in other people's apps.
 */
describe('catalogue', () => {
  it('counts the probe arrays rather than trusting a hand-written number', () => {
    expect(CATALOGUE.secretPatterns).toBe(SECRET_RULES.length);
    expect(CATALOGUE.sensitivePaths).toBe(SENSITIVE_PATHS.length);
    expect(CATALOGUE.routeProbes).toBe(ROUTE_PROBES.length);
    expect(CATALOGUE.aiEndpointProbes).toBe(AI_PROBES.length);
    expect(CATALOGUE.crawlersProfiled).toBe(CRAWLERS.length);
  });

  /**
   * The one inline group with a grader that runs on empty input. If someone adds
   * a header check without updating the literal, this fails — which is the
   * point, because that is how a claimed number silently becomes false.
   */
  it('pins the inline header count against what gradeHeaders actually returns', () => {
    expect(gradeHeaders({}, 'example.com').checks).toHaveLength(CATALOGUE.headers);
  });

  it('totals the parts, and never claims more than it has', () => {
    const sum = Object.values(CATALOGUE).reduce((a, b) => a + b, 0);
    expect(CATALOGUE_TOTAL).toBe(sum);
    // The public figure is rounded DOWN, so it can only ever understate.
    expect(CATALOGUE_CLAIM).toBeLessThanOrEqual(CATALOGUE_TOTAL);
    expect(CATALOGUE_CLAIM % 10).toBe(0);
  });

  it('is big enough to be worth quoting, which is the whole reason it exists', () => {
    expect(CATALOGUE_TOTAL).toBeGreaterThan(90);
  });
});
