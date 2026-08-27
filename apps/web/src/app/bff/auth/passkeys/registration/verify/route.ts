import type { NextRequest } from 'next/server';
import type { NextResponse } from 'next/server';

import { passkeyVerify } from '../../../../../../a6/server/passkey-bff';

export async function POST(request: NextRequest): Promise<NextResponse> {
  return passkeyVerify(request, 'registration');
}
