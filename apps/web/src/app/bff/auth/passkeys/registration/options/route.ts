import type { NextRequest } from 'next/server';
import type { NextResponse } from 'next/server';

import { passkeyOptions } from '../../../../../../a6/server/passkey-bff';

export async function POST(request: NextRequest): Promise<NextResponse> {
  return passkeyOptions(request, 'registration');
}
