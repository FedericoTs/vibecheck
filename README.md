# vibecheck

**Is your AI-built app leaking? Paste your app, get a security report card — in seconds.**

AI code generators (Lovable, Bolt, v0, …) ship the same bugs over and over: database
tables anyone can read, secrets baked into the client bundle, missing security headers.
vibecheck shows you exactly what a stranger can already see — as a shareable grade.

> Status: **early build.** The flagship Supabase scan works; the rest of the report
> card is on the roadmap below.

## The flagship scan — Supabase public-read exposure

The [CVE-2025-48757](https://nvd.nist.gov/vuln/detail/CVE-2025-48757) class: a Supabase
table with Row Level Security off (or a permissive policy) is readable by **any visitor**
using the `anon` key — and that key already ships in your app's frontend. vibecheck uses
*your own* anon key to list every exposed table and how many rows a stranger can pull.

**It's a mirror, not an exploit.** The anon key is already public (it's in your client
bundle); vibecheck only shows you what any visitor can already read. And it runs **100%
in your browser** — your key and any row data never touch a server. Self-scan only.

## Roadmap (the full report card)

- [x] Supabase public-read / RLS exposure (client-side)
- [ ] Security headers (CSP, HSTS, X-Frame-Options, …)
- [ ] Secrets leaked in the client JS bundle (`service_role` keys, API tokens)
- [ ] Exposed paths (`.env`, `.git/config`, source maps, debug routes)
- [ ] Overall A–F grade + shareable result image
- [ ] Funnel: found a leak? → [`npx tenant-guard`](https://github.com/FedericoTs/tenant-guard) to stop it shipping again

## Develop

```bash
npm install
npm run dev      # http://localhost:3000
npm test         # scan-engine unit tests (vitest)
npm run build
```

The scan engine lives in [`lib/scan/`](lib/scan/) as pure, dependency-injected functions
(the network `fetch` is injected), so every rule is unit-tested without a live project.

## Licence

MIT. By Federico Sciuca. Free, open source, no signup, no telemetry.
