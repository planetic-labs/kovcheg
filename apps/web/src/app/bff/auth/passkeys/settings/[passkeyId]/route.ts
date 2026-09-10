import type { NextRequest } from 'next/server';
import { passkeySettings } from '../../../../../../a6/server/passkey-bff';

export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ passkeyId: string }> },
) {
  return passkeySettings(request, (await context.params).passkeyId);
}
