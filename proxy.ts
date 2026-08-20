import { NextResponse, type NextRequest } from 'next/server';
import { buildCsp, generateNonce } from '@/lib/csp';

/**
 * Emit a per-request nonce and the Content-Security-Policy.
 *
 * Next.js reads the nonce out of the Content-Security-Policy header on the
 * REQUEST and stamps it onto the inline scripts it emits (the streamed RSC
 * payload), which is why the header is set on both the forwarded request and
 * the response.
 */
export function proxy(request: NextRequest): NextResponse {
  const nonce = generateNonce();
  const csp = buildCsp({ nonce });

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('content-security-policy', csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('content-security-policy', csp);
  return response;
}

export const config = {
  matcher: [
    /**
     * Documents only. Static assets and the scan API are excluded: a nonce is
     * per-request, so running this on immutable /_next/static responses would
     * make them uncacheable for no security gain. Prefetches are skipped for
     * the same reason.
     */
    {
      source: '/((?!api/|_next/static|_next/image|icon.svg|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
