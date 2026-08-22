import { createServiceHealth } from '@kovcheg/contracts';

import { loadWebRuntimeConfig } from '../../../runtime-config';

export function GET(): Response {
  loadWebRuntimeConfig();
  return Response.json(createServiceHealth('web', 'ready'));
}
