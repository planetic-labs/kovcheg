import { createServiceHealth } from '@kovcheg/contracts';

import { loadWebRuntimeConfig } from '../../../runtime-config';

export function GET(): Response {
  return Response.json(createServiceHealth('web', 'live', { build: loadWebRuntimeConfig().build }));
}
