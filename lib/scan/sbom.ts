import type { Dep } from './deps';

/**
 * CycloneDX SBOM (Software Bill of Materials) generation.
 *
 * We already resolve the full dependency tree for the OSV scan, so producing a
 * standard, downloadable inventory is nearly free — and increasingly required:
 * the EU Cyber Resilience Act will oblige products sold in the EU to ship an
 * SBOM, which puts this squarely in the EU lane the rest of the tool leans on.
 *
 * Output is CycloneDX 1.5 (the widely-supported format); pure and testable, so
 * the download can be built client-side from the scan result.
 */

export interface CycloneComponent {
  type: 'library';
  name: string;
  version: string;
  purl: string;
  'bom-ref': string;
}

export interface CycloneBom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  version: 1;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string }>;
    component: { type: 'application'; name: string };
  };
  components: CycloneComponent[];
}

/** A Package URL (purl) for a dependency, per the spec (scoped npm names encode the @). */
export function purl(d: Dep): string {
  const eco = d.ecosystem === 'npm' ? 'npm' : d.ecosystem === 'PyPI' ? 'pypi' : 'golang';
  let name = d.name;
  if (d.ecosystem === 'npm' && name.startsWith('@')) {
    name = '%40' + name.slice(1); // @scope/pkg -> %40scope/pkg
  }
  return `pkg:${eco}/${name}@${d.version}`;
}

/** Build a CycloneDX 1.5 SBOM from the resolved dependency list. */
export function toCycloneDX(deps: Dep[], projectName: string, timestamp: string): CycloneBom {
  const seen = new Set<string>();
  const components: CycloneComponent[] = [];
  for (const d of deps) {
    const ref = purl(d);
    if (seen.has(ref)) continue;
    seen.add(ref);
    components.push({ type: 'library', name: d.name, version: d.version, purl: ref, 'bom-ref': ref });
  }
  // Deterministic order so re-running produces an identical file.
  components.sort((a, b) => a['bom-ref'].localeCompare(b['bom-ref']));
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp,
      tools: [{ vendor: 'vibecheck', name: 'vibecheck' }],
      component: { type: 'application', name: projectName },
    },
    components,
  };
}
