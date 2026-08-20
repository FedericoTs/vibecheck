import type { NextConfig } from "next";

// We grade other people's security headers, so our own must pass. These are the
// four we flag that carry no behavioural risk for this app; Content-Security-Policy
// is deliberately NOT set here because a meaningful one needs per-request nonces
// (Next streams inline RSC payload scripts) and a broken CSP is worse than none.
const SECURITY_HEADERS = [
  // Stops this app being framed inside a malicious page. The badge is consumed
  // as an <img>, which X-Frame-Options does not affect.
  { key: "X-Frame-Options", value: "DENY" },
  // Stops the browser MIME-sniffing responses into executable types.
  { key: "X-Content-Type-Options", value: "nosniff" },
  // Limits what URL data leaks to third parties.
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // Nothing here needs camera/mic/geolocation.
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), browsing-topics=()" },
];

const nextConfig: NextConfig = {
  // Pin the workspace root to this project so Next ignores unrelated lockfiles
  // higher up the filesystem (avoids the "inferred workspace root" warning).
  turbopack: {
    root: import.meta.dirname,
  },
  // Don't advertise the stack — we flag X-Powered-By on other people's apps.
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: SECURITY_HEADERS }];
  },
};

export default nextConfig;
