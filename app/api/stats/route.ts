import { NextResponse } from 'next/server';
import { getStats, statsEnabled } from '@/lib/stats';

export const runtime = 'nodejs';

export async function GET(): Promise<Response> {
  const enabled = statsEnabled();
  const stats = enabled ? await getStats() : null;
  return NextResponse.json(
    { enabled, ...(stats ?? { total: 0, leaking: 0, secrets: 0 }) },
    // Cache the counter briefly so the homepage doesn't hammer the store.
    { headers: { 'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=300' } },
  );
}
