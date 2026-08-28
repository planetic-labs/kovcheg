import type { NextRequest } from 'next/server';
import type { NextResponse } from 'next/server';

import { startOidcAuthorization } from '../../../../../a6/server/oidc-bff';

export async function GET(request: NextRequest): Promise<NextResponse> {
  return startOidcAuthorization(request);
}
