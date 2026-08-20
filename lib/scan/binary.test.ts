import { describe, it, expect } from 'vitest';
import { extractScannableText, analyzeBinaryText } from './binary';

const enc = (s: string) => new TextEncoder().encode(s);

describe('extractScannableText', () => {
  it('reads JS bundles + config files, skips native code and resources', () => {
    const files: Record<string, Uint8Array> = {
      'assets/index.android.bundle': enc('const url="https://x.supabase.co";'),
      'assets/google-services.json': enc('{"project_info":{"project_id":"my-app"}}'),
      'classes.dex': enc('BINARY-DEX-NOISE'),
      'lib/arm64-v8a/libapp.so': enc('NATIVE'),
      'res/drawable/icon.xml': enc('<vector/>'),
      'META-INF/CERT.RSA': enc('signature'),
    };
    const { text, scanned } = extractScannableText(files);
    expect(scanned).toBe(2);
    expect(text).toContain('supabase.co');
    expect(text).toContain('project_id');
    expect(text).not.toContain('NATIVE');
    expect(text).not.toContain('BINARY-DEX');
  });

  it('is bounded and tolerates empty/huge entries', () => {
    const files: Record<string, Uint8Array> = {
      'main.jsbundle': enc('ok'),
      'huge.js': new Uint8Array(9_000_000), // over the per-entry cap
      'empty.json': new Uint8Array(0),
    };
    const { scanned } = extractScannableText(files);
    expect(scanned).toBe(1); // only main.jsbundle
  });
});

describe('analyzeBinaryText', () => {
  it('finds a committed secret + the Supabase config from a React Native bundle', () => {
    const key = 'sb' + '_secret_' + 'A'.repeat(24);
    const anon = 'sb' + '_publishable_' + 'B'.repeat(24);
    const text = `const SUPABASE_URL="https://abcdefghij.supabase.co";const KEY="${anon}";const SVC="${key}";`;
    const r = analyzeBinaryText(text);
    expect(r.discovered?.url).toBe('https://abcdefghij.supabase.co');
    expect(r.discovered?.anonKey).toMatch(/^sb_publishable_/);
    expect(r.secrets.map((s) => s.id)).toContain('supabase-secret'); // service key IS a leak
  });

  it('recovers a Firebase config from google-services.json content', () => {
    const text = 'firebaseConfig authDomain "my-app.firebaseapp.com" projectId "my-app" apiKey "AIzaSyA1234567890abcdefghijklmnopqrstuv" initializeApp';
    const r = analyzeBinaryText(text);
    expect(r.firebase?.projectId).toBe('my-app');
  });

  it('a clean bundle yields nothing', () => {
    const r = analyzeBinaryText('export default function App(){return null}');
    expect(r.secrets).toEqual([]);
    expect(r.discovered).toBe(null);
    expect(r.firebase).toBe(null);
  });
});

describe('round trip — a real zip through fflate (the .apk path)', () => {
  it('unzips a synthetic apk and finds the planted secret + config', async () => {
    const { zipSync, unzipSync } = await import('fflate');
    const enc2 = (s: string) => new TextEncoder().encode(s);
    const key = 'sk' + '_live_' + 'Z'.repeat(24);
    const apk = zipSync({
      'assets/index.android.bundle': enc2(`var u="https://mobileapp.supabase.co",k="sb_publishable_${'C'.repeat(24)}",stripe="${key}";`),
      'classes.dex': enc2('binary noise not scanned'),
      'lib/x/libapp.so': enc2('native'),
    });
    const files = unzipSync(apk);
    const { text, scanned } = extractScannableText(files);
    expect(scanned).toBe(1); // only the bundle
    const r = analyzeBinaryText(text);
    expect(r.discovered?.url).toBe('https://mobileapp.supabase.co');
    expect(r.secrets.map((s) => s.id)).toContain('stripe-secret');
  });
});
