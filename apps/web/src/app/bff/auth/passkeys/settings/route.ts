import type { NextRequest } from 'next/server';
import { passkeySettings } from '../../../../../a6/server/passkey-bff';

export function GET(request: NextRequest) {
  return passkeySettings(request);
}
